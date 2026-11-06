import { afterEach, describe, expect, it, vi } from 'vitest';
import { createWorker } from '../../src/worker';
import { createProbeAdapterFromConfig, createSubrequestBudget } from '../../src/config/runtime';
import type { ProbeSocket } from '../../src/adapters/probe/native';
import { FetchBudgetError } from '../../src/util/fetch';
import { ApiClient } from '../../web/src/api/client';

vi.mock('../../src/adapters/probe/tls', () => {
  const loads = new WeakMap<typeof fetch, Promise<unknown>>();
  return { secureProbeSocket: async (socket: ProbeSocket, _host: string, _roots: unknown, _handshake: unknown, fetchRoots: typeof fetch) => {
    if (!loads.has(fetchRoots)) loads.set(fetchRoots, fetchRoots('https://roots.example/certificates').then(response => response.text()));
    await loads.get(fetchRoots);
    return socket;
  } };
});

afterEach(() => vi.unstubAllGlobals());

function fixture(concurrency: number) {
  const targets = ['TXT', 'A', 'A', 'TXT', 'TXT', 'TXT'].map((mode, index) => ({
    domain: `target${index === 3 ? 1 : index}.example.com`, mode, zoneIndex: 0, minActive: 3, enabled: true,
  }));
  const address = (index: number, item: number) => `203.0.113.${index * 3 + item + 1}`;
  const store = new Map([
    ['app_config', JSON.stringify({ tgEnabled: false, checkApiBackup: '', settings: { CONCURRENT_CHECKS: concurrency },
      zones: [{ baseDomain: 'example.com', zoneId: 'fixture-zone', apiKey: 'fixture-token' }], targets })],
    ['ip_pool_default', '# 标题\n' + Array.from({ length: 2410 }, (_, index) => `${index < 18 ? address(Math.floor(index / 3), index % 3) : `198.18.${Math.floor(index / 250)}.${index % 250 + 1}`}:443,AS64500,US,v4 # 备注 ${index}`).join('\n')],
    ['ip_pool_trash', '198.51.100.1:443,null,null,null # 已有备注'],
  ]);
  const dns = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    if (url.hostname === 'roots.example') return new Response('test roots');
    expect(url.hostname).toBe('api.cloudflare.com');
    expect(init?.method ?? 'GET').toBe('GET');
    const type = url.searchParams.get('type');
    const index = targets.findIndex(target => target.domain === url.searchParams.get('name') && target.mode === (type === 'TXT' ? 'TXT' : 'A'));
    expect(index).toBeGreaterThanOrEqual(0);
    const result = type === 'AAAA' ? [] : type === 'TXT'
      ? [{ id: `txt${index}`, type, name: targets[index]!.domain, content: '"' + Array.from({ length: 3 }, (_, item) => address(index, item) + ':443').join(',') + '"' }]
      : Array.from({ length: 3 }, (_, item) => ({ id: `a${index}-${item}`, type, name: targets[index]!.domain, content: address(index, item) }));
    return Response.json({ success: true, result });
  });
  vi.stubGlobal('fetch', dns);
  let open = 0;
  let peak = 0;
  const connect = vi.fn((): ProbeSocket => {
    open++;
    peak = Math.max(peak, open);
    const body = JSON.stringify({ ip: '198.51.100.42', asn: 64500, country: 'US', colo: 'NRT' });
    const bytes = new TextEncoder().encode(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    let closed = false;
    return { opened: Promise.resolve({} as SocketInfo), closed: Promise.resolve(),
      readable: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }),
      writable: new WritableStream({ write() {} }), async close() { if (!closed) { closed = true; open--; } },
      startTls() { throw new Error('unused'); } };
  });
  const kv = { get: async (key: string) => store.get(key) ?? null, list: async () => ({ keys: [], list_complete: true }),
    put: async (key: string, value: string) => { store.set(key, value); } } as unknown as KVNamespace;
  const worker = createWorker((config, deps) => createProbeAdapterFromConfig(config, { ...deps, connect }));
  const tasks: Promise<unknown>[] = [];
  const context = { waitUntil: (promise: Promise<unknown>) => tasks.push(promise), passThroughOnException() {} } as unknown as ExecutionContext;
  const client = new ApiClient({ fetchImpl: async (input, init) => worker.fetch!(
    new Request(new URL(String(input), 'https://panel.example'), init) as Parameters<NonNullable<typeof worker.fetch>>[0], { IP_DATA: kv }, context) as Promise<Response> });
  return { client, worker, kv, context, tasks, store, connect, dns, peak: () => peak, open: () => open };
}

describe('native maintenance HTTP and connection budgets', () => {
  it.each([1, 8, 32, 128])('finishes six targets and eighteen current addresses at concurrency %s', async concurrency => {
    const f = fixture(concurrency);
    const lines: Array<{ message: string; targetKey?: string }> = [];
    const result = await f.client.runMaintenance(undefined, line => lines.push(line));
    expect(result.results.map(item => item.activeCount)).toEqual([3, 3, 3, 3, 3, 3]);
    expect(result.probeErrors).toBe(0);
    expect(result.completed).toBe(true);
    expect(f.connect).toHaveBeenCalledTimes(36);
    expect(f.dns.mock.calls).toHaveLength(9);
    expect(f.peak()).toBeLessThanOrEqual(4);
    expect(f.open()).toBe(0);
    expect(f.store.get('ip_pool_default')).toContain('# 标题');
    expect(f.store.get('ip_pool_default')).toContain('# 备注 2409');
    expect(f.store.get('ip_pool_trash')).toContain('# 已有备注');
    const first = lines.findIndex(line => line.targetKey === 'target0.example.com|TXT');
    const next = lines.findIndex(line => line.message.includes('target1.example.com (A/AAAA) · 读取'));
    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThan(next);
    expect(lines.filter(line => line.targetKey && line.message.startsWith('完成：'))).toHaveLength(6);
  });

  it('warns and notifies on partial exits without removing healthy DNS or pool entries', async () => {
    const f = fixture(8);
    const config = JSON.parse(f.store.get('app_config')!);
    f.store.set('app_config', JSON.stringify({ ...config, tgEnabled: true, tgToken: 'fixture-token', tgId: '123' }));
    const beforePool = f.store.get('ip_pool_default');
    const beforeTrash = f.store.get('ip_pool_trash');
    const send = vi.fn(async () => Response.json({ ok: true }));
    const upstream = globalThis.fetch;
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) =>
      new URL(String(input)).hostname === 'api.telegram.org' ? send() : upstream(input, init));
    f.connect.mockImplementationOnce(() => { throw new Error('TCP Loop detected'); });
    const result = await f.client.runMaintenance();
    expect(result).toMatchObject({ changed: false, insufficient: false, probeErrors: 1, completed: false,
      notification: { sent: true } });
    expect(result.results[0]?.activeCount).toBe(3);
    expect(result.results[0]?.lines?.join('\n')).toContain('[PARTIAL_EXIT]');
    expect(result.results[0]?.lines?.at(-1)).toContain('存在异常');
    expect(result.message).toContain('检测异常');
    expect(send).toHaveBeenCalledTimes(1);
    expect(f.store.get('ip_pool_default')).toBe(beforePool);
    expect(f.store.get('ip_pool_trash')).toBe(beforeTrash);
    expect(f.open()).toBe(0);
  });

  it('uses the same native budget rules for scheduled maintenance', async () => {
    const f = fixture(8);
    await f.worker.scheduled!({} as ScheduledController, { IP_DATA: f.kv }, f.context);
    await Promise.all(f.tasks);
    expect(f.connect).toHaveBeenCalledTimes(36);
    expect(f.dns.mock.calls).toHaveLength(9);
    expect(f.peak()).toBeLessThanOrEqual(4);
    expect(f.open()).toBe(0);
  });

  it('cancels queued probes and prevents maintenance writes when the request is aborted', async () => {
    const f = fixture(8);
    const before = new Map(f.store);
    const abort = new AbortController();
    await expect(f.client.runMaintenance(abort.signal, line => {
      if (line.message.includes('开始检测当前解析')) abort.abort();
    })).rejects.toThrow('维护执行中断');
    await Promise.all(f.tasks);
    expect(f.connect.mock.calls.length).toBeLessThanOrEqual(4);
    expect(f.open()).toBe(0);
    expect(f.store).toEqual(before);
    expect(f.dns.mock.calls.filter(([input]) => new URL(String(input)).hostname === 'api.cloudflare.com')).toHaveLength(1);
  });

  it('does not impose the HTTP quota on addresses expanded from a domain', async () => {
    const f = fixture(8);
    const upstream = globalThis.fetch;
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.hostname === 'cloudflare-dns.com') {
        const answers = url.searchParams.get('type') === 'A'
          ? Array.from({ length: 40 }, (_, index) => ({ type: 1, data: `203.0.113.${index + 1}` })) : [];
        return Response.json({ Status: 0, Answer: answers });
      }
      return upstream(input, init);
    });
    const result = await f.client.checkTarget('large.example.com');
    expect(result.items).toHaveLength(40);
    expect(result.items.every(item => item.result.status === 'alive')).toBe(true);
    expect(f.connect).toHaveBeenCalledTimes(80);
    expect(f.peak()).toBeLessThanOrEqual(4);
    expect(f.open()).toBe(0);
  });

  it('only debits actual HTTP requests and keeps DNS and notification reserves', async () => {
    const fetchImpl = vi.fn(async () => Response.json({ ok: true }));
    const budget = createSubrequestBudget(fetchImpl);
    for (let index = 0; index < 36; index++) await budget.probeFetch('https://probe.example/');
    await expect(budget.probeFetch('https://probe.example/')).rejects.toBeInstanceOf(FetchBudgetError);
    for (let index = 36; index < 44; index++) await budget.dnsFetch('https://dns.example/');
    await expect(budget.dnsFetch('https://dns.example/')).rejects.toBeInstanceOf(FetchBudgetError);
    for (let index = 44; index < 48; index++) await budget.notifyFetch('https://notify.example/');
    await expect(budget.notifyFetch('https://notify.example/')).rejects.toBeInstanceOf(FetchBudgetError);
    expect(fetchImpl).toHaveBeenCalledTimes(48);
    expect(fetchImpl.mock.calls.every(call => (call as unknown as [unknown, RequestInit])[1].redirect === 'manual')).toBe(true);
  });
});
