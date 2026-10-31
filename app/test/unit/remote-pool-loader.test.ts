import { afterEach, describe, expect, it, vi } from 'vitest';
import type { RemotePoolLoadResult } from '../../src/ports/remote-pool-source';
import { HttpRemotePoolSource, type HttpRemotePoolSourceOptions } from '../../src/adapters/http/remote-pool-source';
import { RemotePoolLoader } from '../../src/application/remote-pool-loader';

function textResponse(body: string, init: ResponseInit = {}): Response {
  return new Response(body, { status: 200, ...init });
}

function redirectResponse(location: string, status = 302): Response {
  return new Response(null, { status, headers: { location } });
}

function abortablePendingFetch(): typeof fetch {
  return (async (_input: RequestInfo | URL, init?: RequestInit) =>
    await new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    })) as typeof fetch;
}

describe('RemotePoolLoader', () => {
  it('normalises remote pool text and reports the final URL', async () => {
    const loader = createLoader({
      timeoutMs: 1_000,
      fetchImpl: (async () =>
        textResponse('# 注释\n203.0.113.10:443\n\nnot a target\n203.0.113.10:443\n203.0.113.11:443,AS64500,US,v4\n')) as typeof fetch,
    });

    // 复用领域层的清洗规则：丢弃无效行与注释、按地址去重、补齐四字段格式。
    await expect(loader.load('https://example.com/pool.txt')).resolves.toEqual({
      ok: true,
      content: '203.0.113.10:443,null,null,null\n203.0.113.11:443,AS64500,US,v4',
      finalUrl: 'https://example.com/pool.txt',
    });
  });

  it('follows redirects but re-validates every hop', async () => {
    const seen: string[] = [];
    const loader = createLoader({
      timeoutMs: 1_000,
      fetchImpl: (async (input: RequestInfo | URL) => {
        seen.push(String(input));
        return seen.length === 1
          ? redirectResponse('/mirror/pool.txt')
          : textResponse('203.0.113.10:443');
      }) as typeof fetch,
    });

    await expect(loader.load('https://example.com/pool.txt')).resolves.toMatchObject({
      ok: true,
      finalUrl: 'https://example.com/mirror/pool.txt',
    });
    expect(seen).toEqual(['https://example.com/pool.txt', 'https://example.com/mirror/pool.txt']);
  });

  it('refuses a redirect that points at a private address', async () => {
    const seen: string[] = [];
    const loader = createLoader({
      timeoutMs: 1_000,
      fetchImpl: (async (input: RequestInfo | URL) => {
        seen.push(String(input));
        return redirectResponse('http://169.254.169.254/latest/meta-data/');
      }) as typeof fetch,
    });

    await expect(loader.load('https://example.com/pool.txt')).resolves.toEqual({ ok: false, reason: 'blocked-host' });
    // 只请求了第一跳：内网目标根本不会被访问。
    expect(seen).toEqual(['https://example.com/pool.txt']);
  });

  it('stops redirect loops with a clear failure', async () => {
    const loader = createLoader({
      timeoutMs: 1_000,
      maxRedirects: 2,
      fetchImpl: (async () => redirectResponse('https://example.com/loop')) as typeof fetch,
    });

    await expect(loader.load('https://example.com/loop')).resolves.toEqual({ ok: false, reason: 'too-many-redirects' });
  });

  it('rejects oversized payloads from header and from body', async () => {
    const headerLoader = createLoader({
      timeoutMs: 1_000,
      maxBytes: 8,
      fetchImpl: (async () => textResponse('203.0.113.10:443', { headers: { 'content-length': '4096' } })) as typeof fetch,
    });
    await expect(headerLoader.load('https://example.com/pool.txt')).resolves.toEqual({ ok: false, reason: 'too-large' });

    const bodyLoader = createLoader({
      timeoutMs: 1_000,
      maxBytes: 8,
      fetchImpl: (async () => textResponse('203.0.113.10:443')) as typeof fetch,
    });
    await expect(bodyLoader.load('https://example.com/pool.txt')).resolves.toEqual({ ok: false, reason: 'too-large' });
  });

  it('maps HTTP errors and unreachable hosts', async () => {
    const notFound = createLoader({
      timeoutMs: 1_000,
      fetchImpl: (async () => new Response('nope', { status: 404 })) as typeof fetch,
    });
    await expect(notFound.load('https://example.com/pool.txt')).resolves.toEqual({ ok: false, reason: 'http-error' });

    const offline = createLoader({
      timeoutMs: 1_000,
      fetchImpl: (async () => {
        throw new TypeError('network down');
      }) as typeof fetch,
    });
    await expect(offline.load('https://example.com/pool.txt')).resolves.toEqual({ ok: false, reason: 'network-error' });
  });

  it('reports its own timeout as timeout', async () => {
    const loader = createLoader({ timeoutMs: 20, fetchImpl: abortablePendingFetch() });
    await expect(loader.load('https://example.com/slow.txt')).resolves.toEqual({ ok: false, reason: 'timeout' });
  });

  it('distinguishes caller cancellation from its own timeout', async () => {
    const loader = createLoader({ timeoutMs: 5_000, fetchImpl: abortablePendingFetch() });
    const controller = new AbortController();
    const pending = loader.load('https://example.com/slow.txt', { signal: controller.signal });
    controller.abort();

    await expect(pending).resolves.toEqual({ ok: false, reason: 'network-error' });
  });
});
function createLoader(options: HttpRemotePoolSourceOptions): RemotePoolLoader {
  return new RemotePoolLoader(new HttpRemotePoolSource(options));
}

/** 不依赖 mock fetch 自动传播 signal，验证正文等待本身也可取消。 */
function streamResponse(chunks: readonly Uint8Array[] = [], complete = false, init: ResponseInit = {}) {
  let controller: ReadableStreamDefaultController<Uint8Array>;
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({
    start(value) {
      controller = value;
      for (const chunk of chunks) value.enqueue(chunk);
      if (complete) value.close();
    },
    cancel,
  });
  return {
    response: new Response(body, init), body, cancel,
    finish: () => { try { controller.close(); } catch { /* 已被取消或关闭。 */ } },
  };
}

describe('remote response body boundaries', () => {
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });
  const url = 'https://example.com/pool.txt';
  const encode = (text: string) => new TextEncoder().encode(text);

  it('keeps its timeout active after headers and cancels a stalled body', async () => {
    vi.useFakeTimers();
    const stream = streamResponse();
    let signal: AbortSignal | null | undefined;
    const source = new HttpRemotePoolSource({ timeoutMs: 20,
      fetchImpl: (async (_input: RequestInfo | URL, init?: RequestInit) => { signal = init?.signal; return stream.response; }) as typeof fetch });
    const pending = source.load(url);
    try {
      await vi.advanceTimersByTimeAsync(21);
      expect(signal?.aborted).toBe(true);
      await expect(pending).resolves.toEqual({ ok: false, reason: 'timeout' });
      expect(stream.cancel).toHaveBeenCalledTimes(1);
      expect(stream.body.locked).toBe(false);
      expect(vi.getTimerCount()).toBe(0);
    } finally { stream.finish(); }
  });

  it('propagates caller cancellation while reading the body', async () => {
    vi.useFakeTimers();
    const stream = streamResponse([encode('partial')]);
    const controller = new AbortController();
    let signal: AbortSignal | null | undefined;
    const source = new HttpRemotePoolSource({ timeoutMs: 5_000,
      fetchImpl: (async (_input: RequestInfo | URL, init?: RequestInit) => { signal = init?.signal; return stream.response; }) as typeof fetch });
    const pending = source.load(url, { signal: controller.signal });
    try {
      await vi.advanceTimersByTimeAsync(0);
      controller.abort();
      await vi.advanceTimersByTimeAsync(0);
      expect(signal?.aborted).toBe(true);
      await expect(pending).resolves.toEqual({ ok: false, reason: 'network-error' });
      expect(stream.cancel).toHaveBeenCalledTimes(1);
      expect(stream.body.locked).toBe(false);
      expect(vi.getTimerCount()).toBe(0);
    } finally { stream.finish(); }
  });

  it('does not fetch when the caller was already cancelled', async () => {
    const fetchImpl = vi.fn(async () => textResponse('203.0.113.10:443'));
    const source = new HttpRemotePoolSource({ timeoutMs: 1_000, fetchImpl: fetchImpl as typeof fetch });
    const controller = new AbortController();
    controller.abort();
    await expect(source.load(url, { signal: controller.signal })).resolves.toEqual({ ok: false, reason: 'network-error' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('counts UTF-8 bytes rather than characters', async () => {
    const stream = streamResponse([encode('备注')], true);
    const source = new HttpRemotePoolSource({ timeoutMs: 1_000, maxBytes: 5,
      fetchImpl: (async () => stream.response) as typeof fetch });
    await expect(source.load(url)).resolves.toEqual({ ok: false, reason: 'too-large' });
    expect(stream.body.locked).toBe(false);
  });

  it('stops a chunked body immediately when the byte limit is exceeded', async () => {
    vi.useFakeTimers();
    const stream = streamResponse([encode('1234'), encode('56')]);
    const source = new HttpRemotePoolSource({ timeoutMs: 1_000, maxBytes: 5,
      fetchImpl: (async () => stream.response) as typeof fetch });
    let result: RemotePoolLoadResult | undefined;
    const pending = source.load(url).then(value => { result = value; });
    try {
      await vi.advanceTimersByTimeAsync(0);
      expect(result).toEqual({ ok: false, reason: 'too-large' });
      await pending;
      expect(stream.cancel).toHaveBeenCalledTimes(1);
      expect(stream.body.locked).toBe(false);
      expect(vi.getTimerCount()).toBe(0);
    } finally { stream.finish(); }
  });

  it('decodes split UTF-8 chunks and permits the exact byte limit', async () => {
    const text = '# 备注\n203.0.113.10:443';
    const bytes = encode(text);
    const stream = streamResponse(Array.from(bytes, byte => Uint8Array.of(byte)), true);
    const source = new HttpRemotePoolSource({ timeoutMs: 1_000, maxBytes: bytes.byteLength,
      fetchImpl: (async () => stream.response) as typeof fetch });
    await expect(source.load(url)).resolves.toEqual({ ok: true, content: text, finalUrl: url });
    expect(stream.body.locked).toBe(false);
  });

  it.each([
    [{ status: 502 }, 'http-error'],
    [{ headers: { 'content-length': '999' } }, 'too-large'],
    [{ status: 302, headers: { location: 'http://127.0.0.1/private' } }, 'blocked-host'],
  ] as const)('cancels discarded response bodies: %j', async (init, reason) => {
    vi.useFakeTimers();
    const stream = streamResponse([], false, init);
    const source = new HttpRemotePoolSource({ timeoutMs: 1_000, maxBytes: 5,
      fetchImpl: (async () => stream.response) as typeof fetch });
    try {
      await expect(source.load(url)).resolves.toEqual({ ok: false, reason });
      expect(stream.cancel).toHaveBeenCalledTimes(1);
      expect(stream.body.locked).toBe(false);
      expect(vi.getTimerCount()).toBe(0);
    } finally { stream.finish(); }
  });

  it('discards a redirect body before loading the validated destination', async () => {
    const stream = streamResponse([], false, { status: 302, headers: { location: '/mirror.txt' } });
    const fetchImpl = vi.fn().mockResolvedValueOnce(stream.response).mockResolvedValueOnce(textResponse('203.0.113.10:443'));
    const source = new HttpRemotePoolSource({ timeoutMs: 1_000, fetchImpl: fetchImpl as typeof fetch });
    try {
      await expect(source.load(url)).resolves.toMatchObject({ ok: true, finalUrl: 'https://example.com/mirror.txt' });
      expect(stream.cancel).toHaveBeenCalledTimes(1);
      expect(fetchImpl).toHaveBeenCalledTimes(2);
    } finally { stream.finish(); }
  });

  it('cleans timers and detaches the caller after a successful body read', async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const remove = vi.spyOn(controller.signal, 'removeEventListener');
    let signal: AbortSignal | null | undefined;
    const source = new HttpRemotePoolSource({ timeoutMs: 20,
      fetchImpl: (async (_input: RequestInfo | URL, init?: RequestInit) => { signal = init?.signal; return textResponse('203.0.113.10:443'); }) as typeof fetch });
    await expect(source.load(url, { signal: controller.signal })).resolves.toMatchObject({ ok: true });
    expect(vi.getTimerCount()).toBe(0);
    expect(remove).toHaveBeenCalledWith('abort', expect.any(Function));
    controller.abort();
    await vi.advanceTimersByTimeAsync(21);
    expect(signal?.aborted).toBe(false);
  });
});
