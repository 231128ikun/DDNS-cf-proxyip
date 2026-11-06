import { afterEach, describe, expect, it, vi } from 'vitest';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createWorker, dispatchWorkerInvocation, type InvocationProps, type InvocationRequestInit } from '../../src/worker';
import { createProbeAdapterFromConfig, createSubrequestBudget } from '../../src/config/runtime';
import type { ProbeSocket } from '../../src/adapters/probe/native';
import { FetchBudgetError } from '../../src/util/fetch';
import { ApiClient } from '../../web/src/api/client';

const trust = vi.hoisted(() => ({ ready: false, loads: new WeakMap<typeof fetch, Promise<unknown>>() }));
vi.mock('../../src/adapters/probe/tls', () => ({
  secureProbeSocket: async (socket: ProbeSocket, _host: string, _roots: unknown, _handshake: unknown, fetchRoots: typeof fetch) => {
    if (!trust.ready) {
      if (!trust.loads.has(fetchRoots)) trust.loads.set(fetchRoots, fetchRoots('https://roots.example/certificates').then(response => response.text()));
      await trust.loads.get(fetchRoots);
      trust.ready = true;
    }
    return socket;
  },
}));

afterEach(() => vi.unstubAllGlobals());

function fixture(concurrency: number, targetCount = 6, externalLimit = Number.POSITIVE_INFINITY, allUnknown = false) {
  trust.ready = false;
  trust.loads = new WeakMap();
  const modes = ['TXT', 'A', 'A', 'TXT', 'TXT', 'TXT', 'A'];
  const targets = Array.from({ length: targetCount }, (_, index) => ({
    domain: 'target' + (index === 3 && !allUnknown ? 1 : index) + '.example.com', mode: allUnknown ? 'TXT' : modes[index % modes.length]!, zoneIndex: 0, minActive: 3, enabled: true,
  }));
  const address = (index: number, item: number) => {
    const number = index * 3 + item + 1;
    return number <= 250 ? '203.0.113.' + number : '198.18.1.' + (number - 250);
  };
  const store = new Map([
    ['app_config', JSON.stringify({ tgEnabled: false, checkApiBackup: '', settings: { CONCURRENT_CHECKS: concurrency },
      zones: [{ baseDomain: 'example.com', zoneId: 'fixture-zone', apiKey: 'fixture-token' }], targets })],
    ['ip_pool_default', '# 标题\n' + Array.from({ length: 2410 }, (_, index) => (index < targetCount * 3
      ? address(Math.floor(index / 3), index % 3) : '198.18.' + Math.floor(index / 250) + '.' + (index % 250 + 1))
      + ':443,AS64500,US,v4 # 备注 ' + index).join('\n')],
    ['ip_pool_trash', '198.51.100.1:443,null,null,null # 已有备注'],
  ]);
  const scopes = new AsyncLocalStorage<{ used: number; internal: number; blocked: number }>();
  const invocations: Array<{ used: number; internal: number; blocked: number }> = [];
  const inInvocation = <T>(run: () => Promise<T>): Promise<T> => {
    const scope = { used: 0, internal: 0, blocked: 0 };
    invocations.push(scope);
    return scopes.run(scope, run);
  };
  const charge = () => {
    const scope = scopes.getStore();
    if (!scope) return;
    if (scope.used >= externalLimit) { scope.blocked++; throw new Error('Too many subrequests by single Worker invocation.'); }
    scope.used++;
  };
  const chargeInternal = () => {
    const scope = scopes.getStore();
    if (!scope) return;
    if (scope.internal >= 1_000) { scope.blocked++; throw new Error('Too many subrequests by single Worker invocation.'); }
    scope.internal++;
  };
  const requestUrl = (input: RequestInfo | URL) => new URL(input instanceof Request ? input.url : String(input));
  const records = new Map(targets.flatMap((target, index) => target.mode === 'TXT'
    ? [{ id: 'txt' + index, type: 'TXT', name: target.domain,
      content: '"' + Array.from({ length: 3 }, (_, item) => address(index, item) + ':443').join(',') + '"' }]
    : Array.from({ length: 3 }, (_, item) => ({ id: 'a' + index + '-' + item, type: 'A', name: target.domain, content: address(index, item) })))
    .map(record => [record.id, record]));
  const writes: string[] = [];
  let failWrites = false;
  const dns = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    charge();
    const url = requestUrl(input);
    if (url.hostname === 'roots.example') return new Response('test roots');
    expect(url.hostname).toBe('api.cloudflare.com');
    const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
    if (method !== 'GET') {
      writes.push(method);
      if (failWrites) return Response.json({ success: false }, { status: 503 });
      const id = url.pathname.split('/').at(-1)!;
      if (method === 'DELETE') { records.delete(id); return Response.json({ success: true, result: { id } }); }
      const data = (input instanceof Request ? await input.clone().json() : JSON.parse(String(init?.body))) as { type: string; name: string; content: string };
      const record = { ...data, id: method === 'PUT' ? id : 'new-' + writes.length };
      records.set(record.id, record);
      return Response.json({ success: true, result: record });
    }
    const result = [...records.values()].filter(record => record.type === url.searchParams.get('type') && record.name === url.searchParams.get('name'));
    return Response.json({ success: true, result });
  });
  vi.stubGlobal('fetch', dns);
  let open = 0;
  let peak = 0;
  const deadHosts = new Set<string>();
  const connect = vi.fn((socketAddress: SocketAddress, _options: SocketOptions): ProbeSocket => {
    charge();
    if (allUnknown) throw new Error('TCP Loop detected');
    if (deadHosts.has(socketAddress.hostname)) throw new Error('connection refused');
    open++;
    peak = Math.max(peak, open);
    const body = JSON.stringify({ ip: '198.51.100.42', asn: 64500, country: 'US', colo: 'NRT' });
    const bytes = new TextEncoder().encode('HTTP/1.1 200 OK\r\nContent-Length: ' + body.length + '\r\n\r\n' + body);
    let closed = false;
    return { opened: Promise.resolve({} as SocketInfo), closed: Promise.resolve(),
      readable: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }),
      writable: new WritableStream({ write() {} }), async close() { if (!closed) { closed = true; open--; } },
      startTls() { throw new Error('unused'); } };
  });
  const kv = { get: async (key: string) => { chargeInternal(); return store.get(key) ?? null; },
    list: async () => { chargeInternal(); return { keys: [], list_complete: true }; },
    put: async (key: string, value: string) => { chargeInternal(); store.set(key, value); } } as unknown as KVNamespace;
  const worker = createWorker((config, deps) => createProbeAdapterFromConfig(config, { ...deps, connect }));
  const tasks: Promise<unknown>[] = [];
  const context = { waitUntil: (promise: Promise<unknown>) => tasks.push(promise), passThroughOnException() {},
    exports: { default: { dispatch: (url: string, init: InvocationRequestInit, props: InvocationProps, cancelled: ReadableStream<Uint8Array>) => {
      chargeInternal();
      return inInvocation(() => dispatchWorkerInvocation(worker, { IP_DATA: kv }, context, url, init, props, cancelled));
    } } } } as unknown as ExecutionContext;
  const invoke = (request: Request, props?: unknown): Promise<Response> => inInvocation(() => worker.fetch!(
    request as Parameters<NonNullable<typeof worker.fetch>>[0], { IP_DATA: kv }, { ...context, props } as ExecutionContext) as Promise<Response>);
  const client = new ApiClient({ fetchImpl: async (input, init) => invoke(new Request(new URL(String(input), 'https://panel.example'), init)) });
  const scheduled = () => inInvocation(async () => { await worker.scheduled!({} as ScheduledController, { IP_DATA: kv }, context); await Promise.all(tasks); });
  const cloudflareCalls = () => dns.mock.calls.filter(([input]) => requestUrl(input).hostname === 'api.cloudflare.com');
  return { client, worker, kv, context, tasks, store, connect, dns, scheduled, invocations, requestUrl, cloudflareCalls,
    writes, records, dead: (host: string) => deadHosts.add(host), failWrites: () => { failWrites = true; },
    peak: () => peak, open: () => open };
}

describe('native maintenance invocation boundaries', () => {
  it('keeps 100 targets with twelve unknown candidates each below every invocation quota', async () => {
    const log = vi.spyOn(console, 'info').mockImplementation(() => undefined);
    try {
      const f = fixture(8, 100, 50, true);
      const trash = f.store.get('ip_pool_trash');
      const result = await f.client.runMaintenance();
      expect(result.results).toHaveLength(100);
      expect(result).toMatchObject({ completed: false, insufficient: true, changed: false, probeErrors: 1500 });
      expect(result.results.every(target => target.candidates?.checked === 12 && target.candidates.unknown === 12)).toBe(true);
      expect(f.invocations.every(scope => scope.used <= 50 && scope.internal <= 1_000 && scope.blocked === 0)).toBe(true);
      expect(f.invocations[0]!.internal).toBeLessThan(200);
      expect(f.writes).toEqual([]);
      expect(f.store.get('ip_pool_trash')).toBe(trash);
      expect(f.open()).toBe(0);
    } finally { log.mockRestore(); }
  }, 15_000);

  it.each(['manual', 'scheduled'])('completes seven targets under a 50-operation quota: %s', async mode => {
    const f = fixture(8, 7, 50);
    if (mode === 'manual') {
      const result = await f.client.runMaintenance();
      expect(result.results.map(item => item.activeCount)).toEqual([3, 3, 3, 3, 3, 3, 3]);
      expect(result).toMatchObject({ completed: true, probeErrors: 0, changed: false });
    } else await f.scheduled();
    expect(f.connect).toHaveBeenCalledTimes(42);
    expect(f.invocations.length).toBeGreaterThan(21);
    expect(f.invocations.every(scope => scope.used <= 50 && scope.blocked === 0)).toBe(true);
    expect(f.open()).toBe(0);
    expect(f.store.get('ip_pool_default')).toContain('# 备注 2409');
    expect(f.store.get('ip_pool_trash')).toContain('# 已有备注');
  });

  it.each(['203.0.113.8 8443', '203.0.113.8\t8443', '203.0.113.8：8443',
    '203.0.113.8:8443,AS64500,US,v4 # 备注', '203.0.113.8 8443 # 备注',
    'https://203.0.113.8:8443/probe?mode=fast;extra=demo'])('keeps loose ports through ApiClient, resolution and the isolated native call: %s', async input => {
    const f = fixture(8, 7, 50);
    const result = await f.client.checkTarget(input);
    expect(result.items).toHaveLength(1);
    expect(result.items[0]).toMatchObject({ address: '203.0.113.8:8443', result: { status: 'alive' } });
    expect(f.connect.mock.calls.every(([address]) => address.port === 8443)).toBe(true);
    expect(f.cloudflareCalls()).toHaveLength(0);
  });

  it.each(['A', 'TXT'])('applies confirmed replacements and archives only dead entries through isolated calls: %s', async mode => {
    const f = fixture(8, mode === 'A' ? 7 : 6, 50);
    const last = mode === 'A' ? 20 : 17;
    const dead = '203.0.113.' + (last + 1);
    f.dead(dead);
    const result = await f.client.runMaintenance();
    const target = result.results.at(-1)!;
    expect(result).toMatchObject({ completed: true, changed: true, probeErrors: 0 });
    expect(target.activeCount).toBe(3);
    expect(target.dns?.removed).toContain(mode === 'A' ? dead : dead + ':443');
    expect(target.dns?.added).toHaveLength(1);
    const added = target.dns!.added[0]!;
    expect(target.dns?.before).not.toContain(added);
    expect(target.dns?.after).toContain(added);
    expect(f.store.get('ip_pool_default')).toContain(mode === 'A' ? added + ':443' : added);
    expect(f.writes).toEqual(mode === 'A' ? ['DELETE', 'POST'] : ['PUT']);
    expect(f.store.get('ip_pool_default')).not.toContain(dead + ':443');
    expect(f.store.get('ip_pool_default')).toContain('# 备注 2409');
    expect(f.store.get('ip_pool_trash')).toContain(dead + ':443');
    expect(f.invocations.every(scope => scope.blocked === 0)).toBe(true);
    expect(f.open()).toBe(0);
  });

  it('does not report planned DNS replacements as confirmed when writes fail', async () => {
    const f = fixture(8, 7, 50);
    f.dead('203.0.113.21');
    f.failWrites();
    const before = new Map(f.records);
    const result = await f.client.runMaintenance();
    expect(result).toMatchObject({ completed: false, changed: false });
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.results.at(-1)?.dns?.after).toEqual(result.results.at(-1)?.dns?.before);
    expect(f.records).toEqual(before);
    expect(f.open()).toBe(0);
  });

  it.each([1, 8, 32, 128])('finishes six targets and eighteen current addresses at concurrency %s', async concurrency => {
    const f = fixture(concurrency);
    const lines: Array<{ message: string; targetKey?: string }> = [];
    const result = await f.client.runMaintenance(undefined, line => lines.push(line));
    expect(result.results.map(item => item.activeCount)).toEqual([3, 3, 3, 3, 3, 3]);
    expect(result.probeErrors).toBe(0);
    expect(result.completed).toBe(true);
    expect(f.connect).toHaveBeenCalledTimes(36);
    expect(f.cloudflareCalls()).toHaveLength(8);
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
      f.requestUrl(input).hostname === 'api.telegram.org' ? send() : upstream(input, init));
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

  it('uses the same native invocation rules for scheduled maintenance', async () => {
    const f = fixture(8);
    await f.scheduled();
    expect(f.connect).toHaveBeenCalledTimes(36);
    expect(f.cloudflareCalls()).toHaveLength(8);
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
    expect(f.cloudflareCalls()).toHaveLength(1);
  });

  it('propagates cancellation to a native connection that is already pending', async () => {
    const f = fixture(8);
    const abort = new AbortController();
    const before = new Map(f.store);
    const original = f.connect.getMockImplementation()!;
    f.connect.mockImplementation((address, options) => {
      const socket = original(address, options);
      let rejectOpened!: (error: Error) => void;
      const opened = new Promise<SocketInfo>((_, reject) => { rejectOpened = reject; });
      queueMicrotask(() => abort.abort());
      return { ...socket, opened, close: async () => { rejectOpened(new Error('connection closed')); await socket.close(); } };
    });
    await expect(f.client.runMaintenance(abort.signal, () => undefined)).rejects.toThrow();
    await Promise.all(f.tasks);
    expect(f.connect).toHaveBeenCalled();
    expect(f.open()).toBe(0);
    expect(f.store).toEqual(before);
    expect(f.writes).toEqual([]);
  });

  it('isolates addresses expanded from a domain instead of sharing its native quota', async () => {
    const f = fixture(8, 7, 50);
    const upstream = globalThis.fetch;
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = f.requestUrl(input);
      if (url.hostname === 'cloudflare-dns.com') {
        const answers = url.searchParams.get('type') === 'A'
          ? Array.from({ length: 40 }, (_, index) => ({ type: 1, data: '203.0.113.' + (index + 1) })) : [];
        return Response.json({ Status: 0, Answer: answers });
      }
      return upstream(input, init);
    });
    const result = await f.client.checkTarget('large.example.com');
    expect(result.items).toHaveLength(40);
    expect(result.items.every(item => item.result.status === 'alive')).toBe(true);
    expect(f.connect).toHaveBeenCalledTimes(80);
    expect(f.invocations.every(scope => scope.blocked === 0)).toBe(true);
    expect(f.peak()).toBeLessThanOrEqual(4);
    expect(f.open()).toBe(0);
  });

  it('bounds actual HTTP requests and keeps DNS and notification reserves', async () => {
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
