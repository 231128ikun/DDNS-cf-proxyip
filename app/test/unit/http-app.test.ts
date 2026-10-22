import { describe, expect, it, vi } from 'vitest';
import { CheckPoolText } from '../../src/application/check-pool';
import { DomainBindings } from '../../src/application/domain-bindings';
import { CheckProxy } from '../../src/application/check-proxy';
import { CheckTarget } from '../../src/application/check-target';
import { ResolveTarget } from '../../src/application/resolve-target';
import { PoolService } from '../../src/application/pool-service';
import { RemotePoolLoader } from '../../src/application/remote-pool-loader';
import { createDefaultConfig, type AppConfig, type ConfigResponse } from '../../src/contracts/config';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY } from '../../src/contracts/pool';
import { alive, type ProbeResult } from '../../src/domain/probe-result';
import type { MaintenanceJobResult } from '../../src/jobs/maintenance-job';
import type { ProxyTarget } from '../../src/domain/proxy-target';
import type { DnsLookup } from '../../src/ports/dns-lookup';
import type { ProbeAdapter } from '../../src/ports/probe';
import { createHttpApp, type ConfigGateway, type MaintenanceRunner } from '../../src/transport/http';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';

/** POST JSON 用例在所有路由测试里重复，抽成一处，避免每个用例再写一遍头部。 */
function postJson(
  app: ReturnType<typeof createHttpApp>,
  path: string,
  body: unknown,
  headers: Readonly<Record<string, string>> = {},
): Promise<Response> {
  return app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

class FakeProbeAdapter implements ProbeAdapter {
  readonly name = 'fake';

  async probe(target: ProxyTarget): Promise<ProbeResult> {
    return alive(target, { endpoint: 'fake', exitIp: '198.51.100.8', exitFamily: 'ipv4' });
  }
}

/** 测试里探测入口默认不解析域名；需要解析的用例自己传入 lookup 桩。 */
function createCheckTarget(
  adapter: ProbeAdapter = new FakeProbeAdapter(),
  lookup: DnsLookup = { query: async () => ({ ok: true, values: [] }) },
): CheckTarget {
  return new CheckTarget({ resolver: new ResolveTarget(lookup), checkProxy: new CheckProxy(adapter) });
}

function createApp() {
  return createHttpApp({
    checkTarget: createCheckTarget(),
    version: 'test',
  });
}

describe('HTTP app', () => {
  it('returns health information', async () => {
    const response = await createApp().request('/api/health');
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ ok: true, version: 'test' });
  });

  it('checks a direct target through the adapter', async () => {
    const response = await postJson(createApp(), '/api/check', { proxyip: '203.0.113.10:443' });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      ok: true,
      input: '203.0.113.10:443',
      source: { kind: 'direct' },
      items: [{ address: '203.0.113.10:443', result: { status: 'alive', exitIp: '198.51.100.8' } }],
      skipped: [],
    });
  });

  it('resolves txt targets before probing', async () => {
    const lookup: DnsLookup = {
      async query(_name, type) {
        if (type !== 'TXT') return { ok: true, values: [] };
        return { ok: true, values: ['"203.0.113.10:443,203.0.113.11:443"'] };
      },
    };
    const app = createHttpApp({ checkTarget: createCheckTarget(new FakeProbeAdapter(), lookup), version: 'test' });

    const response = await postJson(app, '/api/check', { proxyip: 'txt@example.com' });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      source: { kind: 'txt', host: 'example.com', addresses: ['203.0.113.10:443', '203.0.113.11:443'] },
      items: [{ address: '203.0.113.10:443' }, { address: '203.0.113.11:443' }],
    });
  });

  it('reports unresolvable domains as input errors', async () => {
    const lookup: DnsLookup = {
      async query() {
        return { ok: false, code: 'DNS_STATUS', message: 'DoH 返回状态 3' };
      },
    };
    const app = createHttpApp({ checkTarget: createCheckTarget(new FakeProbeAdapter(), lookup), version: 'test' });

    const response = await postJson(app, '/api/check', { proxyip: 'missing.example.com' });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: expect.stringContaining('域名解析失败') });
  });

  it('returns 404 for unknown routes', async () => {
    const page = await createApp().request('/dashboard');
    expect(page.status).toBe(404);
    await expect(page.json()).resolves.toEqual({ error: 'not found' });

    const api = await createApp().request('/api/missing');
    expect(api.status).toBe(404);
    await expect(api.json()).resolves.toEqual({ error: 'not found' });
  });
});

describe('HTTP app pool routes', () => {
  it('lists, reads, writes, creates, renames, orders and deletes pools', async () => {
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: '203.0.113.10:443' });
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      pools: new PoolService(catalog),
    });

    const list = await app.request('/api/pools');
    expect(list.status).toBe(200);
    await expect(list.json()).resolves.toMatchObject({
      pools: [
        { key: DEFAULT_POOL_KEY, count: 1 },
        { key: TRASH_POOL_KEY, count: 0 },
      ],
    });

    const create = await app.request('/api/pools', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ displayName: '香港池' }),
    });
    expect(create.status).toBe(200);
    await expect(create.json()).resolves.toMatchObject({ key: 'ip_pool_001', displayName: '香港池' });

    const save = await app.request('/api/pools/ip_pool_001', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: '198.51.100.7:443\r\n\r\n', mode: 'replace' }),
    });
    expect(save.status).toBe(200);
    await expect(save.json()).resolves.toMatchObject({ ok: true, mode: 'replace', count: 1 });
    expect(catalog.data.get('ip_pool_001')).toBe('198.51.100.7:443,null,null,null');

    const rename = await app.request('/api/pools/ip_pool_001', {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ displayName: 'HK' }),
    });
    expect(rename.status).toBe(200);
    expect(catalog.names.get('ip_pool_001')).toBe('HK');

    const order = await app.request('/api/pools/order', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ order: [TRASH_POOL_KEY, 'ip_pool_001', DEFAULT_POOL_KEY] }),
    });
    expect(order.status).toBe(200);
    expect(catalog.order).toEqual([DEFAULT_POOL_KEY, 'ip_pool_001', TRASH_POOL_KEY]);

    const read = await app.request('/api/pools/ip_pool_001');
    await expect(read.json()).resolves.toEqual({ key: 'ip_pool_001', content: '198.51.100.7:443,null,null,null' });

    const remove = await app.request('/api/pools/ip_pool_001', { method: 'DELETE' });
    expect(remove.status).toBe(200);
    expect(catalog.data.has('ip_pool_001')).toBe(false);
  });

  it('rejects pool keys outside the ip_pool_ whitelist', async () => {
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      pools: new PoolService(new MemoryPoolCatalog()),
    });

    const response = await app.request('/api/pools/app_config', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: '203.0.113.10:443' }),
    });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: 'IP 池标识无效' });
  });

  it('refuses to write the trash pool through the save route', async () => {
    const catalog = new MemoryPoolCatalog({ [TRASH_POOL_KEY]: '203.0.113.9:443' });
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      pools: new PoolService(catalog),
    });

    const response = await app.request(`/api/pools/${TRASH_POOL_KEY}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: '203.0.113.10:443' }),
    });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: '垃圾桶只能由维护和洗库流程写入' });
    expect(catalog.data.get(TRASH_POOL_KEY)).toBe('203.0.113.9:443');
  });

  it('restores and clears trash through explicit routes', async () => {
    const catalog = new MemoryPoolCatalog({
      [TRASH_POOL_KEY]: '203.0.113.10:443,AS64500,US,v4 # dead 来自 ip_pool_001',
    });
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      pools: new PoolService(catalog),
    });

    const restore = await app.request('/api/pools/trash/restore', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ addresses: ['203.0.113.10:443'], restoreToSource: true }),
    });
    expect(restore.status).toBe(200);
    await expect(restore.json()).resolves.toMatchObject({ ok: true, restored: 1 });

    await catalog.write(TRASH_POOL_KEY, '203.0.113.11:443 # dead');
    const clear = await app.request('/api/pools/trash/clear', { method: 'POST' });
    expect(clear.status).toBe(200);
    expect(catalog.data.get(TRASH_POOL_KEY)).toBe('');
  });

  it('returns 503 when pool storage is not bound', async () => {
    const response = await createApp().request('/api/pools');
    expect(response.status).toBe(503);
  });

  it('checks batch text through the shared pool parser', async () => {
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      checkPool: new CheckPoolText(new CheckProxy(new FakeProbeAdapter())),
    });

    const response = await app.request('/api/check/batch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: '203.0.113.10:443\nnot a target' }),
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      total: 1,
      alive: 1,
      dead: 0,
      unknown: 0,
      invalid: ['not a target'],
      items: [{ address: '203.0.113.10:443', status: 'alive' }],
    });
  });

  it('streams batch progress events before the final report', async () => {
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      checkPool: new CheckPoolText(new CheckProxy(new FakeProbeAdapter()), 1),
    });

    const response = await postJson(
      app,
      '/api/check/batch',
      { text: '203.0.113.10:443\n203.0.113.11:443' },
      { accept: 'application/x-ndjson' },
    );
    const events = (await response.text()).trim().split('\n').map((line) => JSON.parse(line) as Record<string, unknown>);

    expect(response.headers.get('content-type')).toContain('application/x-ndjson');
    expect(events.map((event) => event.type)).toEqual(['progress', 'progress', 'complete']);
    expect(events[0]).toMatchObject({ type: 'progress', completed: 1, total: 2, item: { address: '203.0.113.10:443' } });
    expect(events[2]).toMatchObject({ type: 'complete', report: { total: 2, alive: 2 } });
  });

  it('delivers the first result while later probes are still running', async () => {
    let releaseFirst = (): void => {};
    let releaseSecond = (): void => {};
    let markSecondStarted = (): void => {};
    const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const secondGate = new Promise<void>((resolve) => { releaseSecond = resolve; });
    const secondStarted = new Promise<void>((resolve) => { markSecondStarted = resolve; });
    const adapter: ProbeAdapter = {
      name: 'gated',
      async probe(target) {
        if (target.authority === '203.0.113.10:443') await firstGate;
        else {
          markSecondStarted();
          await secondGate;
        }
        return alive(target, { exitFamily: 'ipv4' });
      },
    };
    const app = createHttpApp({
      checkTarget: createCheckTarget(adapter),
      version: 'test',
      checkPool: new CheckPoolText(new CheckProxy(adapter), 1),
    });
    const response = await postJson(
      app,
      '/api/check/batch',
      { text: '203.0.113.10:443\n203.0.113.11:443' },
      { accept: 'application/x-ndjson' },
    );
    const reader = response.body?.getReader();
    if (!reader) throw new Error('response stream is missing');

    const firstRead = reader.read();
    releaseFirst();
    const firstChunk = await firstRead;
    expect(firstChunk.done).toBe(false);
    expect(JSON.parse(new TextDecoder().decode(firstChunk.value))).toMatchObject({
      type: 'progress',
      completed: 1,
      item: { address: '203.0.113.10:443' },
    });

    await secondStarted;
    const secondRead = reader.read();
    let secondResolved = false;
    void secondRead.then(() => { secondResolved = true; });
    await Promise.resolve();
    expect(secondResolved).toBe(false);
    releaseSecond();
    const secondChunk = await secondRead;
    expect(JSON.parse(new TextDecoder().decode(secondChunk.value))).toMatchObject({
      type: 'progress',
      completed: 2,
      item: { address: '203.0.113.11:443' },
    });
    await reader.cancel();
  });
});

describe('HTTP app batch request limits', () => {
  it('rejects a single batch above the safe Worker subrequest limit', async () => {
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      checkPool: new CheckPoolText(new CheckProxy(new FakeProbeAdapter())),
    });
    const text = Array.from({ length: 9 }, (_, index) => `203.0.113.${index + 10}:443`).join('\n');

    const response = await postJson(app, '/api/check/batch', { text });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: '单次批量检测最多 8 个地址' });
  });
});

describe('HTTP app config routes', () => {
  function createConfigGateway(initial: AppConfig) {
    const gateway: ConfigGateway & { current: AppConfig } = {
      current: initial,
      async resolve() {
        return { config: gateway.current, source: 'kv' };
      },
      async save(config) {
        gateway.current = config;
      },
    };
    return gateway;
  }

  function createConfigApp(config: AppConfig) {
    const gateway = createConfigGateway(config);
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      config: gateway,
    });
    return { app, gateway };
  }

  const stored: AppConfig = {
    ...createDefaultConfig(),
    apiKey: 'cf-token',
    zoneId: 'zone-1',
    tgToken: 'tg-token',
    tgId: '42',
    tgEnabled: false,
    checkApi: 'https://probe.example/?proxyip={proxyip}',
    checkApiBackup: '',
    projectUrl: 'https://example.com/project',
  };

  it('masks secrets instead of echoing them', async () => {
    const { app } = createConfigApp(stored);
    const response = await app.request('/api/config');
    expect(response.status).toBe(200);

    const raw = await response.text();
    const body = JSON.parse(raw) as ConfigResponse;
    expect(body).toMatchObject({
      source: 'kv',
      config: {
        zoneId: 'zone-1',
        tgId: '42',
        tgEnabled: false,
        checkApi: 'https://probe.example/?proxyip={proxyip}',
        checkApiBackup: '',
        projectUrl: 'https://example.com/project',
        secrets: { apiKey: true, tgToken: true },
      },
    });
    for (const secret of ['cf-token', 'tg-token']) expect(raw).not.toContain(secret);
  });

  it('inherits omitted secrets and clears them when sent as empty strings', async () => {
    const { app, gateway } = createConfigApp(stored);

    const partial = await app.request('/api/config', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        checkApi: 'https://next.example/?proxyip={proxyip}',
        settings: { CHECK_TIMEOUT: 5_000 },
      }),
    });
    expect(partial.status).toBe(200);
    expect(gateway.current).toMatchObject({
      apiKey: 'cf-token',
      tgToken: 'tg-token',
      checkApi: 'https://next.example/?proxyip={proxyip}',
      settings: { CHECK_TIMEOUT: 5_000 },
    });

    const cleared = await app.request('/api/config', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ apiKey: '', checkApi: '', checkApiBackup: '' }),
    });
    expect(cleared.status).toBe(200);
    expect(gateway.current.apiKey).toBe('');
    expect(gateway.current.checkApi).toBe('');
    expect(gateway.current.checkApiBackup).toBe('');
    expect(gateway.current.tgToken).toBe('tg-token');
  });

  it('rejects invalid configuration with 400', async () => {
    const { app, gateway } = createConfigApp(createDefaultConfig());

    const duplicate = await app.request('/api/config', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        zones: [
          { name: 'A', baseDomain: 'same.example.com', zoneId: 'zone-a', apiKey: 'key-a' },
          { name: 'B', baseDomain: 'same.example.com', zoneId: 'zone-b', apiKey: 'key-b' },
        ],
      }),
    });
    expect(duplicate.status).toBe(400);
    await expect(duplicate.json()).resolves.toEqual({ error: '权限配置存在重复目标维护域名：same.example.com' });

    const malformed = await app.request('/api/config', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: 'not json',
    });
    expect(malformed.status).toBe(400);
    // 校验失败不应写回存储。
    expect(gateway.current).toEqual(createDefaultConfig());
  });
  it('returns 503 when config storage is not bound', async () => {
    expect((await createApp().request('/api/config')).status).toBe(503);
  });

});

describe('HTTP app remote load route', () => {
  function createRemoteApp(loader?: RemotePoolLoader) {
    return createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      ...(loader ? { remotePoolLoader: loader } : {}),
    });
  }

  function loaderReturning(body: string, init: ResponseInit = {}): RemotePoolLoader {
    return new RemotePoolLoader({
      timeoutMs: 1_000,
      fetchImpl: (async () => new Response(body, { status: 200, ...init })) as typeof fetch,
    });
  }

  it('returns the downloaded pool text with a line count', async () => {
    const app = createRemoteApp(loaderReturning('203.0.113.10:443\n203.0.113.11:443\n'));
    const response = await app.request('/api/remote-load', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com/pool.txt' }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      url: 'https://example.com/pool.txt',
      content: '203.0.113.10:443,null,null,null\n203.0.113.11:443,null,null,null',
      count: 2,
    });
  });

  it('maps loader failures onto status codes', async () => {
    const cases: ReadonlyArray<readonly [RemotePoolLoader, string, number]> = [
      [loaderReturning(''), 'http://127.0.0.1/pool.txt', 400],
      [loaderReturning('', { headers: { 'content-length': String(2 * 1024 * 1024) } }), 'https://example.com/big.txt', 413],
      [loaderReturning('nope', { status: 404 }), 'https://example.com/missing.txt', 502],
    ];

    for (const [loader, url, status] of cases) {
      const response = await createRemoteApp(loader).request('/api/remote-load', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      expect(response.status, url).toBe(status);
    }
  });

  it('returns 503 when the loader is not bound and 400 for a malformed body', async () => {
    const unavailable = await createRemoteApp().request('/api/remote-load', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com/pool.txt' }),
    });
    expect(unavailable.status).toBe(503);

    const malformed = await createRemoteApp(loaderReturning('x')).request('/api/remote-load', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'not json',
    });
    expect(malformed.status).toBe(400);
  });
});
describe('HTTP app domain binding and maintenance routes', () => {
  const data = {
    zones: [],
    targets: [
      {
        target: { mode: 'A' as const, domain: 'a.example.com', port: 443, minActive: 1, exitFilter: 'any' as const, countries: [], asns: [] },
        zoneIndex: null,
        enabled: true,
      },
    ],
    poolMapping: { 'a.example.com|A': 'ip_pool_002' },
    poolNames: { ip_pool_002: '香港池' },
  };

  function createBindings(stored: Record<string, string> = {}) {
    let order: readonly string[] = [];
    const repository = {
      read: async () => ({ ...stored }),
      write: async (mapping: Readonly<Record<string, string>>) => {
        stored = { ...mapping };
      },
      readOrder: async () => [...order],
      writeOrder: async (next: readonly string[]) => {
        order = [...next];
      },
    };
    return {
      bindings: new DomainBindings({ load: async () => data }, repository),
      stored: () => ({ ...stored }),
      order: () => [...order],
    };
  }

  it('lists and updates domain bindings through the shared application service', async () => {
    const { bindings, stored } = createBindings({ 'a.example.com|A': 'ip_pool_default' });
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      domainBindings: bindings,
    });

    const listed = await app.request('/api/domain-bindings');
    expect(listed.status).toBe(200);
    await expect(listed.json()).resolves.toEqual({
      items: [{ key: 'a.example.com|A', domain: 'a.example.com', mode: 'A', poolKey: 'ip_pool_002', poolName: '香港池', enabled: true }],
    });

    const saved = await app.request('/api/domain-bindings', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ mapping: { 'a.example.com|A': 'ip_pool_003' } }),
    });
    expect(saved.status).toBe(200);
    await expect(saved.json()).resolves.toEqual({ ok: true });
    expect(stored()).toEqual({ 'a.example.com|A': 'ip_pool_003' });
  });

  it('saves the domain binding display order through the same resource', async () => {
    const { bindings, order } = createBindings();
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      domainBindings: bindings,
    });

    const saved = await app.request('/api/domain-bindings/order', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ order: ['a.example.com|A'] }),
    });
    expect(saved.status).toBe(200);
    await expect(saved.json()).resolves.toEqual({ ok: true });
    expect(order()).toEqual(['a.example.com|A']);

    const stale = await app.request('/api/domain-bindings/order', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ order: ['a.example.com|A', 'missing.example.com|A'] }),
    });
    expect(stale.status).toBe(400);
    await expect(stale.json()).resolves.toEqual({ error: '管理域名列表已变化，请刷新后重试' });
  });
  it('rejects invalid pool keys and malformed payloads with 400', async () => {
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      domainBindings: createBindings().bindings,
    });

    const invalid = await app.request('/api/domain-bindings', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ mapping: { 'a.example.com|A': 'not-a-pool' } }),
    });
    expect(invalid.status).toBe(400);
    await expect(invalid.json()).resolves.toEqual({ error: 'IP 池 key 无效：a.example.com|A' });

    const malformed = await app.request('/api/domain-bindings', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ mapping: [] }),
    });
    expect(malformed.status).toBe(400);
  });

  it('returns 503 without binding storage and serves routes without panel key validation', async () => {
    const unavailable = await createApp().request('/api/domain-bindings');
    expect(unavailable.status).toBe(503);

    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      domainBindings: createBindings().bindings,
    });
    expect((await app.request('/api/domain-bindings')).status).toBe(200);
  });

  it('runs manual maintenance with the same runner and never leaks DNS credentials', async () => {
    const job: MaintenanceJobResult = {
      run: {
        results: [
          {
            target: { mode: 'A', domain: 'a.example.com', port: 443, minActive: 1, exitFilter: 'any', countries: [], asns: [] },
            zone: { zoneId: 'secret-zone', apiToken: 'secret-token' },
            poolKey: 'ip_pool_default',
            poolName: '默认池',
            report: null,
            error: '模拟维护失败',
          },
        ],
        changed: false,
        insufficient: false,
        errors: ['a.example.com: 模拟维护失败'],
        probeErrors: 0,
        poolStats: { before: {}, after: {}, pools: [], changed: false },
      },
      notification: null,
    };
    const run = vi.fn(async () => job);
    const maintenance: MaintenanceRunner = { run };
    const app = createHttpApp({
      checkTarget: createCheckTarget(),
      version: 'test',
      maintenance,
    });

    const response = await app.request('/api/maintenance/run', { method: 'POST' });
    expect(response.status).toBe(200);
    expect(run).toHaveBeenCalledWith(true);
    const raw = await response.text();
    expect(raw).not.toContain('secret-zone');
    expect(raw).not.toContain('secret-token');
    expect(JSON.parse(raw)).toMatchObject({
      ok: true,
      errors: ['a.example.com: 模拟维护失败'],
      results: [{ domain: 'a.example.com', mode: 'A', error: '模拟维护失败', dnsUpdated: false }],
    });
  });

  it('returns 503 when manual maintenance is not bound', async () => {
    expect((await createApp().request('/api/maintenance/run', { method: 'POST' })).status).toBe(503);
  });
});
