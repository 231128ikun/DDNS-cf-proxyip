import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NativeProbeAdapter, type ProbeSocket } from '../../src/adapters/probe/native';
import { secureProbeSocket } from '../../src/adapters/probe/tls';
import { createWorker } from '../../src/worker';
import type { RuntimeEnv } from '../../src/config/runtime';
import { ApiClient } from '../../web/src/api/client';
import { localWorkerContext } from '../helpers/native-probe';

// 只替换握手与证书数据，保留生产 TLS 包装器、关闭和 RPC 生命周期。
vi.mock('subtls', () => ({
  TrustedCert: { databaseFromPEM: async () => ({}) },
  LazyReadFunctionReadQueue: class {
    constructor(read: () => Promise<Uint8Array | undefined>) { this.read = read; }
    readonly read: () => Promise<Uint8Array | undefined>;
  },
  startTls: vi.fn(async () => {
    let sent = false;
    return { write: async () => {}, read: async () => {
      if (sent) return undefined;
      sent = true;
      return new TextEncoder().encode('HTTP/1.1 200 OK\r\n\r\n{"ip":"198.51.100.42"}');
    } };
  }),
}));

const env: RuntimeEnv = { CHECK_TIMEOUT: '500', PROBE_IPV4_URL: 'https://ipv4.example/', PROBE_IPV6_URL: 'https://ipv6.example/', CHECK_API_BACKUP: '' };
type Failure = 'close' | 'cancel' | 'hung-cancel';
function sockets(failure: Failure) {
  let open = 0, peak = 0;
  const close = vi.fn(async () => { if (failure === 'close') throw new Error('socket close failed'); open--; });
  const cancel = vi.fn(() => failure === 'cancel' ? Promise.reject(new Error('reader cancel failed'))
    : failure === 'hung-cancel' ? new Promise<void>(() => {}) : Promise.resolve());
  const raw: ProbeSocket[] = [];
  const connect = vi.fn(() => {
    peak = Math.max(peak, ++open);
    const socket: ProbeSocket = { opened: Promise.resolve({}), closed: Promise.resolve(), close,
      readable: new ReadableStream({ cancel }), writable: new WritableStream(),
      startTls() { throw new Error('unused'); } };
    raw.push(socket);
    return socket;
  });
  return { connect, close, cancel, raw, stats: () => ({ open, peak }) };
}
function client(io: ReturnType<typeof sockets>, runtime: RuntimeEnv = env) {
  const tasks: Promise<unknown>[] = [];
  const worker = createWorker((config, deps) => new NativeProbeAdapter({ urls: config.urls, timeoutMs: config.timeoutMs,
    connect: io.connect, ...(deps?.defer ? { defer: deps.defer } : {}), ...(deps?.disableNative ? { disableNative: true } : {}) }));
  const context = localWorkerContext(worker, runtime, task => tasks.push(task));
  const client = new ApiClient({ fetchImpl: (async (url, init) => worker.fetch!(
    new Request(new URL(String(url), 'https://panel.example'), init) as Parameters<NonNullable<typeof worker.fetch>>[0], runtime, context)) as typeof fetch });
  return { client, tasks };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.hostname === 'curl.se') return new Response('-----BEGIN CERTIFICATE-----\nfixture');
    expect(url.hostname).toBe('cloudflare-dns.com');
    return Response.json({ Status: 0, Answer: url.searchParams.get('type') === 'A'
      ? [10, 11, 12].map(item => ({ type: 1, data: '203.0.113.' + item })) : [] });
  }));
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

describe('production TLS wrapper cleanup', () => {
  it.each(['close', 'cancel'] as const)('propagates %s failure and releases stream locks', async failure => {
    const io = sockets(failure);
    const socket = io.connect();
    const wrapped = await secureProbeSocket(socket, 'probe.example');
    const first = wrapped.close();
    expect(wrapped.close()).toBe(first);
    await expect(first).rejects.toThrow(failure === 'close' ? 'socket close failed' : 'reader cancel failed');
    expect(io.close).toHaveBeenCalledTimes(1);
    expect(io.cancel).toHaveBeenCalledTimes(1);
    expect(socket.readable.locked).toBe(false);
    expect(socket.writable.locked).toBe(false);
  });

  it.each(['close', 'cancel', 'hung-cancel'] as const)('does not hand off native sockets after wrapped %s failure', async failure => {
    const io = sockets(failure);
    const { client: api, tasks } = client(io);
    const pending = api.checkTarget('nodes.example');
    await vi.advanceTimersByTimeAsync(1200);
    const report = await pending;
    expect(report.items.map(item => item.result.status)).toEqual(['alive', 'unknown', 'unknown']);
    expect(io.connect).toHaveBeenCalledTimes(2);
    expect(io.stats().peak).toBe(2);
    expect(io.close).toHaveBeenCalledTimes(2);
    expect(io.cancel).toHaveBeenCalledTimes(2);
    await Promise.all(tasks);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('carries unsafe TLS closure across A and TXT maintenance targets', async () => {
    const config = { tgEnabled: false, checkApiBackup: '', settings: { CHECK_TIMEOUT: 500 },
      zones: [{ baseDomain: 'example.com', zoneId: 'fixture-zone', apiKey: 'fixture-token' }],
      targets: ['A', 'TXT'].map((mode, index) => ({ domain: 'target' + index + '.example.com', mode, zoneIndex: 0, minActive: 0 })) };
    const data = new Map([['app_config', JSON.stringify(config)], ['ip_pool_default', '203.0.113.10:443\n203.0.113.20:443'], ['ip_pool_trash', '# 原垃圾桶']]);
    const put = vi.fn(async (key: string, value: string) => { data.set(key, value); });
    const kv = { get: async (key: string) => data.get(key) ?? null, put,
      list: async () => ({ keys: [], list_complete: true }) } as unknown as KVNamespace;
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.hostname === 'curl.se') return new Response('-----BEGIN CERTIFICATE-----\nfixture');
      expect(url.hostname).toBe('api.cloudflare.com');
      expect(input instanceof Request ? input.method : init?.method ?? 'GET').toBe('GET');
      const type = url.searchParams.get('type');
      return Response.json({ success: true, result: type === 'AAAA' ? [] : [{ id: 'fixture-record', type,
        name: url.searchParams.get('name'), content: type === 'TXT' ? '"203.0.113.20:443"' : '203.0.113.10' }] });
    }));
    const io = sockets('close');
    const { client: api, tasks } = client(io, { ...env, IP_DATA: kv });
    const pending = api.runMaintenance();
    await vi.advanceTimersByTimeAsync(1200);
    const report = await pending;
    expect(report.results).toHaveLength(2);
    expect(report.results[0]?.activeCount).toBe(1);
    expect(report.results[1]?.probeErrors).toBeGreaterThan(0);
    expect(report.results.every(item => !item.dnsUpdated)).toBe(true);
    expect(io.connect).toHaveBeenCalledTimes(2);
    expect(io.stats().peak).toBe(2);
    expect(put.mock.calls.every(([key]) => key === 'ip_pool_default')).toBe(true);
    expect(data.get('ip_pool_default')).toContain('203.0.113.20:443');
    expect(data.get('ip_pool_trash')).toBe('# 原垃圾桶');
    await Promise.all(tasks);
    expect(vi.getTimerCount()).toBe(0);
  });
});
