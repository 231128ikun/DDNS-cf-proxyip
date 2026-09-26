import { describe, expect, it, vi } from 'vitest';
import { CheckPoolText } from '../../src/application/check-pool';
import { DomainBindings } from '../../src/application/domain-bindings';
import { CheckProxy } from '../../src/application/check-proxy';
import { PoolService } from '../../src/application/pool-service';
import { RemotePoolLoader } from '../../src/application/remote-pool-loader';
import { createDefaultConfig, type AppConfig, type ConfigResponse } from '../../src/contracts/config';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY } from '../../src/contracts/pool';
import { alive, type ProbeResult } from '../../src/domain/probe-result';
import type { MaintenanceJobResult } from '../../src/jobs/maintenance-job';
import type { ProxyTarget } from '../../src/domain/proxy-target';
import type { ProbeAdapter } from '../../src/ports/probe';
import { createHttpApp, type ConfigGateway, type MaintenanceRunner } from '../../src/transport/http';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';

class FakeProbeAdapter implements ProbeAdapter {
  readonly name = 'fake';

  async probe(target: ProxyTarget): Promise<ProbeResult> {
    return alive(target, { endpoint: 'fake', exitIp: '198.51.100.8', exitFamily: 'ipv4' });
  }
}

function createApp(assets?: Fetcher) {
  return createHttpApp({
    checkProxy: new CheckProxy(new FakeProbeAdapter()),
    version: 'test',
    ...(assets ? { assets } : {}),
  });
}

describe('HTTP app', () => {
  it('returns health information', async () => {
    const response = await createApp().request('/api/health');
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ ok: true, version: 'test' });
  });

  it('checks a target through the adapter', async () => {
    const response = await createApp().request('/api/check?proxyip=203.0.113.10:443');
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ status: 'alive', exitIp: '198.51.100.8' });
  });

  it('enforces the optional auth key', async () => {
    const app = createHttpApp({
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
      version: 'test',
      authKey: 'secret',
    });
    const unauthorized = await app.request('/api/check?proxyip=203.0.113.10:443');
    expect(unauthorized.status).toBe(401);

    const authorized = await app.request('/api/check?proxyip=203.0.113.10:443', {
      headers: { authorization: 'Bearer secret' },
    });
    expect(authorized.status).toBe(200);
  });

  it('serves static assets only for non-API routes', async () => {
    const calls: string[] = [];
    const assets = {
      fetch: async (request: Request) => {
        calls.push(new URL(request.url).pathname);
        return new Response('<html>app</html>', { headers: { 'Content-Type': 'text/html' } });
      },
    } as unknown as Fetcher;
    const app = createApp(assets);

    const page = await app.request('/dashboard');
    expect(page.status).toBe(200);
    await expect(page.text()).resolves.toContain('app');

    const api = await app.request('/api/missing');
    expect(api.status).toBe(404);
    await expect(api.json()).resolves.toEqual({ error: 'not found' });
    expect(calls).toEqual(['/dashboard']);
  });
});

describe('HTTP app pool routes', () => {
  it('lists, reads, writes, creates, renames, orders and deletes pools', async () => {
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: '203.0.113.10:443' });
    const app = createHttpApp({
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
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
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
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

  it('restores and clears trash through explicit routes', async () => {
    const catalog = new MemoryPoolCatalog({
      [TRASH_POOL_KEY]: '203.0.113.10:443,AS64500,US,v4 # dead 来自 ip_pool_001',
    });
    const app = createHttpApp({
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
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

  it('guards pool routes with the shared auth key', async () => {
    const app = createHttpApp({
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
      version: 'test',
      authKey: 'secret',
      pools: new PoolService(new MemoryPoolCatalog()),
    });

    expect((await app.request('/api/pools')).status).toBe(401);
    const authorized = await app.request('/api/pools', { headers: { authorization: 'Bearer secret' } });
    expect(authorized.status).toBe(200);
  });

  it('checks batch text through the shared pool parser', async () => {
    const app = createHttpApp({
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
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
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
      version: 'test',
      config: gateway,
    });
    return { app, gateway };
  }

  const stored: AppConfig = {
    ...createDefaultConfig(),
    apiKey: 'cf-token',
    zoneId: 'zone-1',
    authKey: 'panel-key',
    tgToken: 'tg-token',
    tgId: '42',
    tgEnabled: false,
    checkApi: 'https://probe.example/?proxyip={proxyip}',
    checkApiBackup: '',
    dohApi: 'https://doh.example/dns-query',
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
        dohApi: 'https://doh.example/dns-query',
        projectUrl: 'https://example.com/project',
        secrets: { apiKey: true, authKey: true, tgToken: true },
      },
    });
    for (const secret of ['cf-token', 'tg-token', 'panel-key']) expect(raw).not.toContain(secret);
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
      authKey: 'panel-key',
      tgToken: 'tg-token',
      checkApi: 'https://next.example/?proxyip={proxyip}',
      settings: { CHECK_TIMEOUT: 5_000 },
    });

    const cleared = await app.request('/api/config', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ apiKey: '', authKey: '', checkApi: '', checkApiBackup: '' }),
    });
    expect(cleared.status).toBe(200);
    expect(gateway.current.apiKey).toBe('');
    expect(gateway.current.authKey).toBe('');
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

  it('runs the configured probe for the self-test route', async () => {
    const { app } = createConfigApp(stored);
    const response = await app.request('/api/config/probe/test', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ proxyip: '203.0.113.10:443' }),
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ status: 'alive', exitIp: '198.51.100.8' });

    // 该路由只校验 proxyip 非空，地址语义由领域层决定。
    const invalid = await app.request('/api/config/probe/test', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ proxyip: '   ' }),
    });
    expect(invalid.status).toBe(400);
  });

  it('guards config routes with the shared auth key', async () => {
    const app = createHttpApp({
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
      version: 'test',
      authKey: 'secret',
      config: createConfigGateway(stored),
    });

    expect((await app.request('/api/config')).status).toBe(401);
    expect((await app.request('/api/config', { headers: { authorization: 'Bearer secret' } })).status).toBe(200);
  });
});

describe('HTTP app remote load route', () => {
  function createRemoteApp(loader?: RemotePoolLoader) {
    return createHttpApp({
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
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
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
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
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
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
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
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

  it('returns 503 without binding storage and guards the route with the shared auth key', async () => {
    const unavailable = await createApp().request('/api/domain-bindings');
    expect(unavailable.status).toBe(503);

    const app = createHttpApp({
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
      version: 'test',
      authKey: 'secret',
      domainBindings: createBindings().bindings,
    });
    expect((await app.request('/api/domain-bindings')).status).toBe(401);
    expect((await app.request('/api/domain-bindings', { headers: { authorization: 'Bearer secret' } })).status).toBe(200);
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
      },
      notification: null,
    };
    const run = vi.fn(async () => job);
    const maintenance: MaintenanceRunner = { run };
    const app = createHttpApp({
      checkProxy: new CheckProxy(new FakeProbeAdapter()),
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
