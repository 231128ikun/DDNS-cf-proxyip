import { describe, expect, it } from 'vitest';
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
    const loader = new RemotePoolLoader({
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
    const loader = new RemotePoolLoader({
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
    const loader = new RemotePoolLoader({
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
    const loader = new RemotePoolLoader({
      timeoutMs: 1_000,
      maxRedirects: 2,
      fetchImpl: (async () => redirectResponse('https://example.com/loop')) as typeof fetch,
    });

    await expect(loader.load('https://example.com/loop')).resolves.toEqual({ ok: false, reason: 'too-many-redirects' });
  });

  it('rejects oversized payloads from header and from body', async () => {
    const headerLoader = new RemotePoolLoader({
      timeoutMs: 1_000,
      maxBytes: 8,
      fetchImpl: (async () => textResponse('203.0.113.10:443', { headers: { 'content-length': '4096' } })) as typeof fetch,
    });
    await expect(headerLoader.load('https://example.com/pool.txt')).resolves.toEqual({ ok: false, reason: 'too-large' });

    const bodyLoader = new RemotePoolLoader({
      timeoutMs: 1_000,
      maxBytes: 8,
      fetchImpl: (async () => textResponse('203.0.113.10:443')) as typeof fetch,
    });
    await expect(bodyLoader.load('https://example.com/pool.txt')).resolves.toEqual({ ok: false, reason: 'too-large' });
  });

  it('maps HTTP errors and unreachable hosts', async () => {
    const notFound = new RemotePoolLoader({
      timeoutMs: 1_000,
      fetchImpl: (async () => new Response('nope', { status: 404 })) as typeof fetch,
    });
    await expect(notFound.load('https://example.com/pool.txt')).resolves.toEqual({ ok: false, reason: 'http-error' });

    const offline = new RemotePoolLoader({
      timeoutMs: 1_000,
      fetchImpl: (async () => {
        throw new TypeError('network down');
      }) as typeof fetch,
    });
    await expect(offline.load('https://example.com/pool.txt')).resolves.toEqual({ ok: false, reason: 'network-error' });
  });

  it('reports its own timeout as timeout', async () => {
    const loader = new RemotePoolLoader({ timeoutMs: 20, fetchImpl: abortablePendingFetch() });
    await expect(loader.load('https://example.com/slow.txt')).resolves.toEqual({ ok: false, reason: 'timeout' });
  });

  it('distinguishes caller cancellation from its own timeout', async () => {
    const loader = new RemotePoolLoader({ timeoutMs: 5_000, fetchImpl: abortablePendingFetch() });
    const controller = new AbortController();
    const pending = loader.load('https://example.com/slow.txt', { signal: controller.signal });
    controller.abort();

    await expect(pending).resolves.toEqual({ ok: false, reason: 'network-error' });
  });
});