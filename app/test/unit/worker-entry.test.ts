import { describe, expect, it, vi } from 'vitest';

import type { RuntimeEnv } from '../../src/config/runtime';
import { APP_VERSION, createWorker } from '../../src/worker';
import { ApiClient } from '../../web/src/api/client';

/**
 * 发布 Worker 的装配回归：面板由 Cloudflare 静态资源分发（`wrangler.toml` 的 `[assets]`），
 * Worker 只负责 `/api/*`，这里验证路由、版本、鉴权与缺少 KV 时的降级。
 */
const env: RuntimeEnv = { CHECK_API: 'https://check.example/?proxyip={proxyip}' };
const context = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
} as unknown as ExecutionContext;

async function request(path: string, init?: RequestInit, runtimeEnv: RuntimeEnv = env): Promise<Response> {
  const input = new Request(`https://panel.example${path}`, init) as Parameters<NonNullable<ExportedHandler<RuntimeEnv>['fetch']>>[0];
  return await createWorker().fetch!(input, runtimeEnv, context);
}

describe('发布 Worker 装配', () => {
  it.each([
    ['203.0.113.10:443 # 旧备注', '203.0.113.10:443,null,null,null # 旧备注'],
    ['203.0.113.10:443,AS64500 # 旧备注', '203.0.113.10:443,AS64500,null,null # 旧备注'],
    ['203.0.113.10:443,AS64500,JP # 旧备注', '203.0.113.10:443,AS64500,JP,null # 旧备注'],
    ['[2001:db8::10]:8443,AS64500,JP,v6 # 旧备注', '[2001:db8::10]:8443,AS64500,JP,v6 # 旧备注'],
  ])('keeps legacy pool data through the deployed client/route/storage chain (%s)', async (legacy, expected) => {
    const store = new Map([
      ['app_config', JSON.stringify({ settings: { DOH_TIMEOUT: 9000 } })],
      ['ip_pool_default', legacy],
      ['domain_pool_mapping', JSON.stringify({ 'edge.example.com|A': 'ip_pool_default' })],
      ['ip_pool_names', JSON.stringify({ ip_pool_001: '用户池' })],
    ]);
    const before = new Map(store);
    const writes: string[] = [];
    const kv = { get: async (key: string) => store.get(key) ?? null,
      put: async (key: string, value: string) => { writes.push(key); store.set(key, value); },
    } as unknown as KVNamespace;
    const client = new ApiClient({ fetchImpl: async (input, init) => request(String(input), init, { ...env, IP_DATA: kv }) });
    expect((await client.readPool('ip_pool_default')).content).toBe(legacy);
    await client.saveConfig({ tgId: 'fixture-chat' });
    const address = legacy.startsWith('[') ? '[2001:db8::10]:8443' : '203.0.113.10:443';
    await client.savePool('ip_pool_default', address + ',null,null,null', 'append');
    expect((await client.readPool('ip_pool_default')).content.trim()).toBe(expected);
    expect((await client.config()).config.settings.DOH_TIMEOUT).toBe(9000);
    expect(new Set(writes)).toEqual(new Set(['app_config', 'ip_pool_default']));
    expect([...store.keys()]).toEqual([...before.keys()]);
    expect(store.get('domain_pool_mapping')).toBe(before.get('domain_pool_mapping'));
    expect(store.get('ip_pool_names')).toBe(before.get('ip_pool_names'));
  });

  it('keeps tokens with a shared Zone ID through a real client save and KV read', async () => {
    const zones = [
      { label: '根域', baseDomain: 'example.com', zoneId: 'shared-fixture-zone', apiKey: 'root-fixture-token' },
      { label: '子域', baseDomain: 'child.example.com', zoneId: 'shared-fixture-zone', apiKey: 'child-fixture-token' },
    ];
    const store = new Map([['app_config', JSON.stringify({ zones })]]);
    const kv = { get: async (key: string) => store.get(key) ?? null,
      put: async (key: string, value: string) => { store.set(key, value); } } as unknown as KVNamespace;
    const client = new ApiClient({ fetchImpl: async (input, init) => request(String(input), init, { ...env, IP_DATA: kv }) });
    const saved = await client.saveConfig({ zones: [...zones].reverse().map(zone => ({ ...zone, name: zone.label, apiKey: '' })) });
    expect(saved.config.zones.map(zone => zone.hasApiKey)).toEqual([true, true]);
    expect(JSON.parse(store.get('app_config')!).zones.map((zone: { apiKey: string }) => zone.apiKey))
      .toEqual(['child-fixture-token', 'root-fixture-token']);
    expect((await client.config()).config.zones.map(zone => zone.hasApiKey)).toEqual([true, true]);
    expect([...store.keys()]).toEqual(['app_config']);
  });

  it('rejects an ambiguous masked zone update before writing KV', async () => {
    const stored = JSON.stringify({ zones: [
      { label: '根域', baseDomain: 'example.com', zoneId: 'shared-fixture-zone', apiKey: 'root-fixture-token' },
      { label: '子域', baseDomain: 'child.example.com', zoneId: 'shared-fixture-zone', apiKey: 'child-fixture-token' },
    ] });
    const put = vi.fn();
    const kv = { get: async (key: string) => key === 'app_config' ? stored : null, put } as unknown as KVNamespace;
    const client = new ApiClient({ fetchImpl: async (input, init) => request(String(input), init, { ...env, IP_DATA: kv }) });
    await expect(client.saveConfig({ zones: [{ name: '改名', label: '改名', baseDomain: 'renamed.example.com',
      zoneId: 'shared-fixture-zone', apiKey: '' }] })).rejects.toMatchObject({ status: 400 });
    expect(put).not.toHaveBeenCalled();
  });

  it('keeps saved concurrency and DNS timeout when the client updates another runtime setting', async () => {
    const store = new Map([['app_config', JSON.stringify({ settings: { CONCURRENT_CHECKS: 7, DOH_TIMEOUT: 9_000 } })]]);
    const kv = { get: async (key: string) => store.get(key) ?? null,
      put: async (key: string, value: string) => { store.set(key, value); } } as unknown as KVNamespace;
    const client = new ApiClient({ fetchImpl: async (input, init) => request(String(input), init, { ...env, IP_DATA: kv }) });
    const saved = await client.saveConfig({ settings: { CHECK_TIMEOUT: 8_000 } });
    expect(saved.config.settings).toMatchObject({ CONCURRENT_CHECKS: 7, DOH_TIMEOUT: 9_000, CHECK_TIMEOUT: 8_000 });
    expect((await client.config()).config.settings).toMatchObject({ CONCURRENT_CHECKS: 7, DOH_TIMEOUT: 9_000, CHECK_TIMEOUT: 8_000 });
    expect([...store.keys()]).toEqual(['app_config']);
  });

  it.each(['新的备注', ''])('keeps credential-only rows and target references when an unidentified masked update is rejected (%j)', async (label) => {
    const zones = [
      { name: '旧权限', label: '旧权限', baseDomain: '', zoneId: '', apiKey: 'legacy-fixture-token' },
      { name: '第二权限', label: '第二权限', baseDomain: 'example.net', zoneId: 'second-fixture-zone', apiKey: 'second-fixture-token' },
    ];
    const stored = JSON.stringify({ zones, targets: [{ domain: 'edge.example.com', mode: 'A', zoneIndex: 0 }] });
    const store = new Map([['app_config', stored]]);
    const kv = { get: async (key: string) => store.get(key) ?? null,
      put: async (key: string, value: string) => { store.set(key, value); } } as unknown as KVNamespace;
    const client = new ApiClient({ fetchImpl: async (input, init) => request(String(input), init, { ...env, IP_DATA: kv }) });
    await expect(client.saveConfig({ zones: zones.map((zone, index) => ({ ...zone, apiKey: '',
      ...(index === 0 ? { label, name: label } : {}) })) })).rejects.toMatchObject({ status: 400 });
    expect(store.get('app_config')).toBe(stored);
    const read = await client.config();
    expect(read.config.zones.map(zone => zone.hasApiKey)).toEqual([true, true]);
    expect(read.config.targets[0]?.zoneIndex).toBe(0);
    expect([...store.keys()]).toEqual(['app_config']);
  });

  it('uses the saved DoH timeout for a real check request and cancels both lookups', async () => {
    vi.useFakeTimers();
    const signals: AbortSignal[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_input, init?: RequestInit) => {
      signals.push(init!.signal as AbortSignal);
      return await new Promise<Response>((_resolve, reject) => {
        init!.signal!.addEventListener('abort', () => reject(new DOMException('timed out', 'AbortError')), { once: true });
      });
    }));
    try {
      const kv = { get: async (key: string) => key === 'app_config'
        ? JSON.stringify({ settings: { DOH_TIMEOUT: 1_200 } }) : null } as unknown as KVNamespace;
      const pending = request('/api/check', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ proxyip: 'edge.example.com' }),
      }, { ...env, IP_DATA: kv });
      await vi.advanceTimersByTimeAsync(0);
      expect(signals).toHaveLength(2);
      await vi.advanceTimersByTimeAsync(1_199);
      expect(signals.every(signal => !signal.aborted)).toBe(true);
      await vi.advanceTimersByTimeAsync(1);
      expect(signals.every(signal => signal.aborted)).toBe(true);
      const response = await pending;
      expect(response.status).toBe(400);
      await expect(response.json()).resolves.toMatchObject({ error: expect.stringContaining('DoH 查询超时') });
    } finally {
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });

  it('reports the saved panel key requirement and rejects protected APIs', async () => {
    const kv = { get: async (key: string) => key === 'app_config'
      ? JSON.stringify({ authKey: 'fixture-panel-key' }) : null } as unknown as KVNamespace;
    const protectedEnv = { ...env, IP_DATA: kv } as RuntimeEnv;

    const status = await request('/api/auth/status', undefined, protectedEnv);
    expect(status.status).toBe(200);
    await expect(status.json()).resolves.toEqual({ ok: true, enabled: true, authenticated: false });

    const api = await request('/api/health', undefined, protectedEnv);
    expect(api.status).toBe(401);
    await expect(api.json()).resolves.toEqual({ error: '未授权' });

    const wrong = await request('/api/auth/login', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: 'wrong' }),
    }, protectedEnv);
    expect(wrong.status).toBe(401);
  });

  it('accepts the original auth transports and stores a secure panel cookie', async () => {
    const kv = { get: async (key: string) => key === 'app_config'
      ? JSON.stringify({ authKey: 'fixture-panel-key' }) : null } as unknown as KVNamespace;
    const protectedEnv = { ...env, IP_DATA: kv } as RuntimeEnv;

    for (const headers of [
      { Authorization: 'Bearer fixture-panel-key' },
      { 'X-Auth-Key': 'fixture-panel-key' },
      { Cookie: 'ddns_auth=fixture-panel-key' },
    ]) {
      const response = await request('/api/health', { headers }, protectedEnv);
      expect(response.status).toBe(200);
    }

    const login = await request('/api/auth/login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: 'fixture-panel-key' }),
    }, protectedEnv);
    expect(login.status).toBe(200);
    expect(login.headers.get('set-cookie')).toBe(
      'ddns_auth=fixture-panel-key; Path=/; HttpOnly; Secure; SameSite=Lax',
    );
    await expect(login.json()).resolves.toEqual({ ok: true, enabled: true, authenticated: true });

    const query = await request('/api/health?key=fixture-panel-key', undefined, protectedEnv);
    expect(query.status).toBe(200);
    expect(query.headers.get('set-cookie')).toContain('ddns_auth=fixture-panel-key');
  });

  it('masks the panel key and preserves it through a real client save', async () => {
    const stored = JSON.stringify({ authKey: 'fixture-panel-key', checkApi: 'https://old.example/?proxyip=' });
    const store = new Map([['app_config', stored]]);
    const kv = {
      get: async (key: string) => store.get(key) ?? null,
      put: async (key: string, value: string) => { store.set(key, value); },
    } as unknown as KVNamespace;
    const client = new ApiClient({
      fetchImpl: async (input, init) => {
        const headers = new Headers(init?.headers);
        headers.set('X-Auth-Key', 'fixture-panel-key');
        return request(String(input), { ...init, headers }, { ...env, IP_DATA: kv });
      },
    });

    const read = await client.config();
    expect(read.config.secrets.authKey).toBe(true);
    expect(read.config).not.toHaveProperty('authKey');
    await client.saveConfig({ checkApi: 'https://new.example/?proxyip=' });
    expect(JSON.parse(store.get('app_config')!)).toMatchObject({ authKey: 'fixture-panel-key' });
  });

  it.each(['rename', 'delete'])('rejects stale client bindings after a target %s without writing the mapping', async (change) => {
    const storedMapping = JSON.stringify({ 'a.example.com|A': 'ip_pool_default', 'b.example.com|TXT': 'ip_pool_001' });
    const store = new Map([
      ['app_config', JSON.stringify({ targets: [
        { domain: 'a.example.com', mode: 'A', enabled: true },
        { domain: 'b.example.com', mode: 'TXT', enabled: true },
      ] })],
      ['domain_pool_mapping', storedMapping],
    ]);
    const put = vi.fn(async (key: string, value: string) => { store.set(key, value); });
    const kv = { get: async (key: string, options?: { type?: string }) => {
      const value = store.get(key) ?? null;
      return options?.type === 'json' && value !== null ? JSON.parse(value) : value;
    }, put } as unknown as KVNamespace;
    const client = new ApiClient({ fetchImpl: async (input, init) => request(String(input), init, { ...env, IP_DATA: kv }) });
    const before = await client.domainBindings();
    expect(before.items.map(item => item.key)).toEqual(['a.example.com|A', 'b.example.com|TXT']);
    const config = (await client.config()).config;
    const saved = await client.saveConfig({ targets: change === 'delete' ? config.targets.slice(0, 1)
      : config.targets.map((target, index) => index === 1 ? { ...target, domain: 'renamed.example.com' } : target) });
    expect(saved.config.targets.map(target => target.domain)).toEqual(change === 'delete'
      ? ['a.example.com'] : ['a.example.com', 'renamed.example.com']);
    put.mockClear();

    await expect(client.saveDomainBindings({ 'a.example.com|A': 'ip_pool_002', [before.items[1]!.key]: 'ip_pool_002' }))
      .rejects.toMatchObject({ status: 400 });
    expect(put).not.toHaveBeenCalled();
    expect(store.get('domain_pool_mapping')).toBe(storedMapping);

    await client.saveDomainBindings({ 'a.example.com|A': 'ip_pool_002' });
    expect((await client.domainBindings()).items[0]?.poolKey).toBe('ip_pool_002');
    expect(JSON.parse(store.get('domain_pool_mapping')!)).toEqual({
      'a.example.com|A': 'ip_pool_002', 'b.example.com|TXT': 'ip_pool_001',
    });
  });

  it('返回版本信息', async () => {
    const response = await request('/api/health');
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ ok: true, version: APP_VERSION });
  });

  it('页面路径不再经过 Worker，静态资源由 Cloudflare 分发', async () => {
    const response = await request('/config');
    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({ error: 'not found' });
  });

  it('未绑定 KV 时池接口返回 503', async () => {
    await expect(request('/api/pools').then((response) => response.status)).resolves.toBe(503);
  });

});
