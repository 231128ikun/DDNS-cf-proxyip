import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NativeProbeAdapter, type ProbeConnect, type ProbeSocket } from '../../src/adapters/probe/native';
import { alive, dead, unknown } from '../../src/domain/probe-result';
import type { ProbeAdapter } from '../../src/ports/probe';
import { parseProxyTarget } from '../../src/domain/proxy-target';
import { createWorker, type InvocationReply, type InvocationProps, type InvocationRequestInit } from '../../src/worker';
import type { RuntimeEnv } from '../../src/config/runtime';
import { ApiClient } from '../../web/src/api/client';
import { localWorkerContext } from '../helpers/native-probe';

const address = '203.0.113.10:443';
const target = parseProxyTarget(address)!;
const urls = ['https://ipv4.example/exit', 'https://ipv6.example/exit'] as const;
const env: RuntimeEnv = { CHECK_TIMEOUT: '500', PROBE_IPV4_URL: urls[0], PROBE_IPV6_URL: urls[1], CHECK_API_BACKUP: '' };
const encode = (text: string) => new TextEncoder().encode(text);

type Phase = 'tcp' | 'tls' | 'http' | 'healthy';
function sockets(phase: Phase, closeDelay: number | null) {
  let open = 0, peak = 0, writes = 0;
  const connect = vi.fn((): ProbeSocket => {
    peak = Math.max(peak, ++open);
    let closed!: () => void;
    const done = new Promise<void>(resolve => { closed = resolve; });
    let closing: Promise<void> | undefined;
    return {
      opened: phase === 'tcp' ? new Promise(() => {}) : Promise.resolve({}), closed: done,
      readable: new ReadableStream({ start(controller) {
        if (phase === 'healthy') { controller.enqueue(encode('HTTP/1.1 200 OK\r\n\r\n{"ip":"198.51.100.42"}')); controller.close(); }
      } }), writable: new WritableStream({ write() { writes++; } }),
      close: () => closing ??= closeDelay === null ? new Promise(() => {})
        : new Promise(resolve => setTimeout(() => { open--; closed(); resolve(); }, closeDelay)),
      startTls: () => { throw new Error('unexpected startTls'); },
    };
  });
  const secure = vi.fn(async (socket: ProbeSocket) => phase === 'tls' ? await new Promise<ProbeSocket>(() => {}) : socket);
  return { connect, secure, stats: () => ({ open, peak, writes }) };
}

function nativeClient(io: ReturnType<typeof sockets>, backup?: ProbeAdapter, connect: ProbeConnect = io.connect, runtime: RuntimeEnv = env) {
  const tasks: Promise<unknown>[] = [];
  const worker = createWorker((config, deps) => new NativeProbeAdapter({ urls: config.urls, timeoutMs: config.timeoutMs,
    connect, secure: io.secure, ...(deps?.defer ? { defer: deps.defer } : {}),
    ...(deps?.disableNative ? { disableNative: true } : {}), ...(backup ? { backup } : {}) }));
  const context = localWorkerContext(worker, runtime, task => tasks.push(task));
  const client = new ApiClient({ fetchImpl: (async (url, init) => worker.fetch!(new Request(new URL(String(url), 'https://panel.example'), init) as Parameters<NonNullable<typeof worker.fetch>>[0],
    runtime, context)) as typeof fetch });
  return { client, tasks };
}

function rpcClient(dispatch: (url: string, init: InvocationRequestInit, props: InvocationProps) => Promise<InvocationReply & Partial<Disposable>>, runtime: RuntimeEnv = env) {
  const worker = createWorker();
  const context = { props: {}, waitUntil() {}, passThroughOnException() {}, exports: { default: { dispatch } } } as unknown as ExecutionContext;
  return new ApiClient({ fetchImpl: (async (url, init) => worker.fetch!(new Request(new URL(String(url), 'https://panel.example'), init) as Parameters<NonNullable<typeof worker.fetch>>[0],
    runtime, context)) as typeof fetch });
}
function reply(response: Response): InvocationReply {
  const headers: [string, string][] = [];
  response.headers.forEach((value, key) => headers.push([key, value]));
  return { status: response.status, headers, body: response.body };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

function resolvedAddresses() {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    expect(url.hostname).toBe('cloudflare-dns.com');
    const type = url.searchParams.get('type');
    return Response.json({ Status: 0, Answer: type === 'A'
      ? [10, 11, 12].map(item => ({ type: 1, data: '203.0.113.' + item })) : [] });
  }));
}

describe('native result and managed socket cleanup', () => {
  it.each(['tcp', 'tls', 'http'] as const)('keeps confirmed two-round %s timeouts dead despite slow close', async phase => {
    const io = sockets(phase, 600);
    const { client, tasks } = nativeClient(io);
    const caller = new AbortController();
    const pending = client.checkTarget(address, caller.signal);
    await vi.advanceTimersByTimeAsync(1050);
    expect((await pending).items[0]?.result).toMatchObject({ status: 'dead', code: 'TIMEOUT' });
    expect(caller.signal.aborted).toBe(false);
    expect(io.connect).toHaveBeenCalledTimes(4);
    expect(io.stats().peak).toBe(4);
    expect(io.secure).toHaveBeenCalledTimes(phase === 'tcp' ? 0 : 4);
    expect(io.stats().writes).toBe(phase === 'http' ? 4 : 0);
    await vi.advanceTimersByTimeAsync(600);
    await Promise.all(tasks);
    expect(io.stats().open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['tcp', 'tls', 'http'] as const)('keeps actual caller cancellation during %s unknown', async phase => {
    const io = sockets(phase, 600);
    const { client, tasks } = nativeClient(io);
    const caller = new AbortController();
    const pending = client.checkTarget(address, caller.signal);
    await vi.advanceTimersByTimeAsync(10);
    caller.abort();
    await vi.advanceTimersByTimeAsync(10);
    expect((await pending).items[0]?.result).toMatchObject({ status: 'unknown', code: 'CANCELLED' });
    expect(io.connect).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(600);
    await Promise.all(tasks);
    expect(io.stats().open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('bounds stalled cleanup, wakes queued work unknown, and never hands out unclosed slots', async () => {
    const io = sockets('tcp', null);
    const tasks: Promise<boolean>[] = [];
    const adapter = new NativeProbeAdapter({ urls, timeoutMs: 500, connect: io.connect, secure: io.secure,
      defer: task => tasks.push(task) });
    const pending = Promise.all(Array.from({ length: 6 }, () => adapter.probe(target)));
    await vi.advanceTimersByTimeAsync(1600);
    const results = await pending;
    expect(results.every(result => result.status === 'unknown')).toBe(true);
    expect(results.some(result => result.code === 'CANCELLED')).toBe(false);
    expect(results.every(result => result.message?.includes('收尾异常'))).toBe(true);
    expect(io.connect).toHaveBeenCalledTimes(4);
    expect(io.stats().peak).toBe(4);
    await Promise.all(tasks);
    expect(await adapter.probe(target)).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
    expect(io.connect).toHaveBeenCalledTimes(4);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('waits for closure before reusing a slot even when results return before cleanup', async () => {
    let open = 0, peak = 0;
    const tasks: Promise<boolean>[] = [];
    const connect: ProbeConnect = () => {
      peak = Math.max(peak, ++open);
      return { opened: Promise.resolve({}), closed: Promise.resolve(),
        readable: new ReadableStream({ start(controller) { controller.enqueue(encode('HTTP/1.1 200 OK\r\n\r\n{"ip":"198.51.100.42"}')); controller.close(); } }),
        writable: new WritableStream(), close: () => new Promise(resolve => setTimeout(() => { open--; resolve(); }, 20)),
        startTls: () => { throw new Error('unexpected startTls'); } };
    };
    const adapter = new NativeProbeAdapter({ urls, timeoutMs: 500, connect, secure: async socket => socket,
      defer: task => tasks.push(task) });
    const pending = Promise.all(Array.from({ length: 12 }, () => adapter.probe(target)));
    await vi.advanceTimersByTimeAsync(200);
    expect((await pending).every(result => result.status === 'alive')).toBe(true);
    await Promise.all(tasks);
    expect(peak).toBe(4);
    expect(open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('shared invocation socket handoff', () => {
  it.each(['tcp', 'tls', 'http'] as const)('keeps multi-address %s timeouts confirmed without overlapping RPC sockets', async phase => {
    resolvedAddresses();
    const io = sockets(phase, 600);
    const { client, tasks } = nativeClient(io);
    const pending = client.checkTarget('nodes.example');
    await vi.advanceTimersByTimeAsync(4300);
    expect(io.connect).toHaveBeenCalledTimes(12);
    const report = await pending;
    expect(report.items).toHaveLength(3);
    expect(report.items.every(item => item.result.status === 'dead' && item.result.code === 'TIMEOUT')).toBe(true);
    expect(io.stats().peak).toBe(4);
    await vi.advanceTimersByTimeAsync(600);
    await Promise.all(tasks);
    expect(io.stats().open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('waits for slow closure between fast successful RPC results', async () => {
    resolvedAddresses();
    const io = sockets('healthy', 600);
    const { client, tasks } = nativeClient(io);
    const pending = client.checkTarget('nodes.example');
    await vi.advanceTimersByTimeAsync(50);
    expect(io.connect).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1200);
    expect((await pending).items.every(item => item.result.status === 'alive')).toBe(true);
    expect(io.connect).toHaveBeenCalledTimes(6);
    expect(io.stats().peak).toBe(2);
    await vi.advanceTimersByTimeAsync(600);
    await Promise.all(tasks);
    expect(io.stats().open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['alive', 'dead'] as const)('stops new native RPC sockets after stalled closure while allowing backup %s', async status => {
    resolvedAddresses();
    const io = sockets('healthy', null);
    const backup = { name: 'backup', probe: vi.fn(async candidate => status === 'alive' ? alive(candidate) : dead(candidate)) } satisfies ProbeAdapter;
    const { client, tasks } = nativeClient(io, backup);
    const pending = client.checkTarget('nodes.example');
    await vi.advanceTimersByTimeAsync(1100);
    const report = await pending;
    expect(report.items[0]?.result.status).toBe('alive');
    expect(report.items.slice(1).map(item => item.result.status)).toEqual(status === 'alive' ? ['alive', 'alive'] : ['unknown', 'unknown']);
    expect(backup.probe).toHaveBeenCalledTimes(2);
    expect(io.connect).toHaveBeenCalledTimes(2);
    expect(io.stats().peak).toBe(2);
    await Promise.all(tasks);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['alive', 'dead'] as const)('allows an independent backup after adapter-local cleanup failure: %s', async status => {
    const io = sockets('healthy', null);
    const tasks: Promise<boolean>[] = [];
    const backup = { name: 'backup', probe: vi.fn(async candidate => status === 'alive' ? alive(candidate) : dead(candidate)) } satisfies ProbeAdapter;
    const adapter = new NativeProbeAdapter({ urls, timeoutMs: 500, connect: io.connect, secure: io.secure, backup,
      defer: task => tasks.push(task) });
    expect((await adapter.probe(target)).status).toBe('alive');
    await vi.advanceTimersByTimeAsync(1050);
    expect(await Promise.all(tasks)).toEqual([false, false]);
    const result = await adapter.probe(target);
    expect(result.status).toBe(status === 'alive' ? 'alive' : 'unknown');
    expect(backup.probe).toHaveBeenCalledTimes(1);
    expect(io.connect).toHaveBeenCalledTimes(2);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('cancels a queued address without starting its RPC or breaking the preceding lease', async () => {
    resolvedAddresses();
    const io = sockets('tcp', 600);
    const { client, tasks } = nativeClient(io);
    const caller = new AbortController();
    const pending = client.checkTarget('nodes.example', caller.signal);
    await vi.advanceTimersByTimeAsync(50);
    caller.abort();
    await vi.advanceTimersByTimeAsync(50);
    expect((await pending).items.every(item => item.result.status === 'unknown' && item.result.code === 'CANCELLED')).toBe(true);
    expect(io.connect).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(600);
    await Promise.all(tasks);
    expect(io.stats().open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });
});

function memoryKv(config?: object) {
  const content = '# 标题\n' + address + ',AS64500,JP,v4 # 用户备注';
  const data = new Map([['ip_pool_default', content], ['ip_pool_trash', '# 原垃圾桶']]);
  if (config) data.set('app_config', JSON.stringify(config));
  const put = vi.fn(async (key: string, value: string) => { data.set(key, value); });
  const kv = { get: async (key: string) => data.get(key) ?? null, put,
    list: async () => ({ keys: [], list_complete: true }) } as unknown as KVNamespace;
  return { kv, data, put, content };
}
function maintenanceConfig() {
  return { tgEnabled: false, checkApiBackup: '', settings: { CHECK_TIMEOUT: 500 },
    zones: [{ baseDomain: 'example.com', zoneId: 'fixture-zone', apiKey: 'fixture-token' }],
    targets: ['A', 'TXT'].map((mode, index) => ({ domain: 'target' + index + '.example.com', mode, zoneIndex: 0, minActive: 1 })) };
}
function closureReceipt() {
  return new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new Uint8Array([1])); controller.close(); } });
}

describe('runtime preparation and cancellation safety', () => {
  it.each([1100, null])('keeps an unfinished asynchronous socket factory unknown: %s', async delay => {
    const io = sockets('healthy', 0);
    const factory = vi.fn(async () => {
      await new Promise<void>(resolve => { if (delay !== null) setTimeout(resolve, delay); });
      return io.connect();
    });
    const { client, tasks } = nativeClient(io, undefined, factory);
    const pending = client.checkTarget(address);
    await vi.advanceTimersByTimeAsync(1050);
    expect((await pending).items[0]?.result).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
    expect(factory).toHaveBeenCalledTimes(4);
    expect(io.connect).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1100);
    await Promise.all(tasks);
    expect(io.stats().open).toBe(0);
    expect(io.connect).toHaveBeenCalledTimes(delay === null ? 0 : 4);
    expect(io.secure).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('does not trash an address while its socket factory is still preparing', async () => {
    const storage = memoryKv();
    const io = sockets('healthy', 0);
    const factory = vi.fn(async () => { await new Promise(resolve => setTimeout(resolve, 1100)); return io.connect(); });
    const { client, tasks } = nativeClient(io, undefined, factory, { ...env, IP_DATA: storage.kv });
    const pending = client.cleanPool('ip_pool_default');
    await vi.waitFor(() => expect(factory).toHaveBeenCalled());
    await vi.advanceTimersByTimeAsync(1050);
    expect(await pending).toMatchObject({ trashed: 0, unknown: 1 });
    expect(storage.data.get('ip_pool_default')).toBe(storage.content);
    expect(storage.data.get('ip_pool_trash')).toBe('# 原垃圾桶');
    expect(storage.put).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1100);
    await Promise.all(tasks);
    expect(io.stats().open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('retains A and TXT DNS records when socket preparation times out', async () => {
    const storage = memoryKv(maintenanceConfig());
    const io = sockets('healthy', 0);
    const factory: ProbeConnect = async () => { await new Promise(resolve => setTimeout(resolve, 1100)); return io.connect(); };
    const requests = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      expect(url.hostname).toBe('api.cloudflare.com');
      expect(input instanceof Request ? input.method : init?.method ?? 'GET').toBe('GET');
      const type = url.searchParams.get('type');
      return Response.json({ success: true, result: type === 'AAAA' ? [] : [{ id: 'fixture-record', type,
        name: url.searchParams.get('name'), content: type === 'TXT' ? '"' + address + '"' : '203.0.113.10' }] });
    });
    vi.stubGlobal('fetch', requests);
    const { client, tasks } = nativeClient(io, undefined, factory, { ...env, IP_DATA: storage.kv });
    const pending = client.runMaintenance();
    await vi.advanceTimersByTimeAsync(4500);
    const report = await pending;
    expect(report.results).toHaveLength(2);
    expect(report.results.every(item => !item.dnsUpdated && item.probeErrors > 0)).toBe(true);
    expect(storage.put).not.toHaveBeenCalled();
    expect(storage.data.get('ip_pool_trash')).toBe('# 原垃圾桶');
    await Promise.all(tasks);
    expect(io.stats().open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['reject', 'hang'] as const)('bounds a non-2xx response cancellation and hands off the queue: %s', async mode => {
    resolvedAddresses();
    const cancel = vi.fn(() => mode === 'hang' ? new Promise<void>(() => {}) : Promise.reject(new Error('cancel failed')));
    const dispose = vi.fn();
    const flags: boolean[] = [];
    const client = rpcClient(async (_url, init, props) => {
      flags.push(props.disableNative === true);
      if (flags.length === 1) return { status: 503, headers: [], body: new ReadableStream({ cancel }), closed: closureReceipt(), [Symbol.dispose]: dispose };
      const candidate = parseProxyTarget(JSON.parse(init.body!).proxyip)!;
      return { ...reply(Response.json({ ok: true, items: [{ address: candidate.authority, result: alive(candidate) }] })), closed: closureReceipt() };
    });
    const pending = client.checkTarget('nodes.example');
    await vi.advanceTimersByTimeAsync(1700);
    const report = await pending;
    expect(report.items[0]?.result).toMatchObject({ status: 'unknown', code: 'CHECK_REQUEST_ERROR' });
    expect(flags).toEqual([false, true, true]);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(dispose).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1500);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('keeps the cleanup fuse scoped to one grouped address', async () => {
    const flags: boolean[] = [];
    const client = rpcClient(async (_url, init, props) => {
      flags.push(props.disableNative === true);
      const candidate = parseProxyTarget(JSON.parse(init.body!).proxyip as string)!;
      return {
        ...reply(Response.json({ ok: true, items: [{ address: candidate.authority, result: alive(candidate) }] })),
        closed: flags.length === 1
          ? new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new Uint8Array([0])); controller.close(); } })
          : closureReceipt(),
      };
    });

    const report = await client.checkBatch('203.0.113.10:443\n203.0.113.11:443', undefined, undefined, 1);

    expect(flags).toEqual([false, false]);
    expect(report.items.map(item => item.status)).toEqual(['alive', 'alive']);
  });

  it('bounds maintenance response cancellation before the next target', async () => {
    const storage = memoryKv(maintenanceConfig());
    const flags: boolean[] = [];
    const cancel = vi.fn(() => new Promise<void>(() => {}));
    const client = rpcClient(async (_url, _init, props) => {
      expect(props.command).toBeDefined();
      flags.push(props.disableNative === true);
      return { status: 503, headers: [], body: flags.length === 1 ? new ReadableStream({ cancel }) : null, closed: closureReceipt() };
    }, { ...env, IP_DATA: storage.kv });
    const pending = client.runMaintenance();
    await vi.advanceTimersByTimeAsync(1700);
    expect((await pending).results).toHaveLength(2);
    expect(flags).toEqual([false, true]);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(storage.put).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1500);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('internal invocation deadline arbitration', () => {
  it('reports internal deadline instead of the child cancellation result', async () => {
    const worker = createWorker(() => ({ name: 'waiting', probe: async (candidate, context = {}) => new Promise(resolve => {
      context.signal?.addEventListener('abort', () => resolve(unknown(candidate, 'CANCELLED', '检测已取消')), { once: true });
    }) }));
    const tasks: Promise<unknown>[] = [];
    const context = localWorkerContext(worker, env, task => tasks.push(task));
    const client = new ApiClient({ fetchImpl: (async (url, init) => worker.fetch!(new Request(new URL(String(url), 'https://panel.example'), init) as Parameters<NonNullable<typeof worker.fetch>>[0], env, context)) as typeof fetch });
    const pending = client.checkTarget(address);
    await vi.advanceTimersByTimeAsync(2050);
    expect((await pending).items[0]?.result).toMatchObject({ status: 'unknown', code: 'CHECK_REQUEST_ERROR', message: '检测调用超时，候选状态未知' });
    await Promise.all(tasks);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('does not accept a late valid result and disposes the late RPC reply', async () => {
    const dispose = vi.fn();
    const client = rpcClient(async () => { await new Promise(resolve => setTimeout(resolve, 2100));
      return { ...reply(Response.json({ ok: true, items: [{ address, result: alive(target) }] })), [Symbol.dispose]: dispose }; });
    const pending = client.checkTarget(address);
    await vi.advanceTimersByTimeAsync(2050);
    expect((await pending).items[0]?.result).toMatchObject({ status: 'unknown', code: 'CHECK_REQUEST_ERROR' });
    await vi.advanceTimersByTimeAsync(100);
    expect(dispose).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('bounds response body reading and cancels the RPC stream on deadline', async () => {
    const cancel = vi.fn();
    const dispose = vi.fn();
    const client = rpcClient(async () => ({ status: 200, headers: [], body: new ReadableStream({ cancel }), [Symbol.dispose]: dispose }));
    const pending = client.checkTarget(address);
    await vi.advanceTimersByTimeAsync(2050);
    expect((await pending).items[0]?.result).toMatchObject({ status: 'unknown', code: 'CHECK_REQUEST_ERROR', message: '检测调用超时，候选状态未知' });
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(dispose).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    new Response('unavailable', { status: 503 }), new Response('not json'),
    Response.json({ ok: true, items: [] }),
    Response.json({ ok: true, items: [{ address: '203.0.113.11:443', result: alive(target) }] }),
  ])('keeps invalid invocation responses unknown', async response => {
    const pending = rpcClient(async () => reply(response)).checkTarget(address);
    await vi.advanceTimersByTimeAsync(10);
    expect((await pending).items[0]?.result).toMatchObject({ status: 'unknown', code: 'CHECK_REQUEST_ERROR' });
    expect(vi.getTimerCount()).toBe(0);
  });
});
