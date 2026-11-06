import { describe, expect, it, vi } from 'vitest';

import { createProbeAdapterFromConfig, createSubrequestBudget, type RuntimeEnv } from '../../src/config/runtime';
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

async function request(path: string, init?: RequestInit, runtimeEnv: RuntimeEnv = env, worker = createWorker()): Promise<Response> {
  const input = new Request(`https://panel.example${path}`, init) as Parameters<NonNullable<ExportedHandler<RuntimeEnv>['fetch']>>[0];
  return await worker.fetch!(input, runtimeEnv, context);
}

describe('发布 Worker 装配', () => {
  it.each(['platform', 'budget'] as const)('safely maintains an 89-address pool when probes reach the %s limit', async limit => {
    const current = '203.0.113.1:443';
    const second = '203.0.113.100:443';
    const inventory = Array.from({ length: 89 }, (_, index) => `203.0.113.${index + 1}:443,null,null,null # 备注 ${index + 1}`);
    const trash = '198.51.100.2:443,null,null,null # 原有备注';
    const store = new Map([
      ['app_config', JSON.stringify({ tgEnabled: true, tgToken: 'test-notifier', tgId: 'test-chat', checkApiBackup: limit === 'budget' ? 'https://probe.example/?candidate=' : '',
        zones: [{ baseDomain: 'example.com', zoneId: 'test-zone', apiKey: 'test-token' }],
        targets: [{ domain: 'one.example.com', mode: 'TXT', zoneIndex: 0, minActive: 1 },
          { domain: 'two.example.com', mode: 'A', zoneIndex: 0, minActive: 1 },
          { domain: 'three.example.com', mode: 'A', zoneIndex: 0, minActive: 0 }] })],
      ['ip_pool_default', inventory.join('\n')], ['ip_pool_trash', trash],
    ]);
    const kv = { get: async (key: string) => store.get(key) ?? null,
      list: async () => ({ keys: [], list_complete: true }),
      put: async (key: string, value: string) => { store.set(key, value); } } as unknown as KVNamespace;
    const connect = vi.fn(() => { throw new Error(limit === 'platform'
      ? 'Too many subrequests by single Worker invocation.' : 'connection refused'); });
    const dnsWrites: string[] = [];
    const notify = vi.fn();
    let releaseRead!: () => void;
    const readGate = new Promise<void>(resolve => { releaseRead = resolve; });
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.hostname === 'api.telegram.org') {
        notify();
        return Response.json({ ok: true });
      }
      if (url.hostname === 'budget.example') return Response.json({ ok: true });
      expect(url.hostname).toBe('api.cloudflare.com');
      if (init?.method === 'DELETE') {
        dnsWrites.push(url.pathname.split('/').at(-1)!);
        return Response.json({ success: true, result: {} });
      }
      const type = url.searchParams.get('type');
      if (type === 'TXT') await readGate;
      const name = url.searchParams.get('name');
      const shared = name === 'three.example.com';
      const result = type === 'AAAA' ? [] : [{ id: type === 'TXT' ? 'txt-current' : shared ? 'a-shared' : 'a-current', type, name,
        content: type === 'TXT' ? `"${current}"` : shared ? '203.0.113.1' : '203.0.113.100' }];
      return Response.json({ success: true, result });
    }));
    try {
      const worker = createWorker((config, deps) => {
        const budget = deps?.budget ?? createSubrequestBudget();
        if (limit === 'budget' && deps?.budget) {
          for (let index = 0; index < 35; index++) void budget.probeFetch('https://budget.example/');
        }
        return createProbeAdapterFromConfig(config, { budget, connect });
      });
      const client = new ApiClient({ fetchImpl: async (input, init) => request(String(input), init, { IP_DATA: kv }, worker) });
      const progress: string[] = [];
      const run = await client.runMaintenance(undefined, line => {
        progress.push(line.message);
        if (progress.length === 1) {
          expect(notify).not.toHaveBeenCalled();
          expect(connect).not.toHaveBeenCalled();
          releaseRead();
        }
      });
      expect(progress[0]).toBe('one.example.com (TXT) · 读取库存和 DNS');
      expect(progress).toContain('one.example.com (TXT) · 当前解析已返回 1/1');
      expect(progress.at(-1)).toBe('处理维护通知');
      expect(run.notification).toMatchObject({ sent: true });
      expect(notify).toHaveBeenCalledTimes(1);
      expect(run.results[1]!.dns?.after).toEqual([second.split(':')[0]]);
      const code = limit === 'platform' ? 'SUBREQUEST_LIMIT' : 'PROBE_BUDGET_EXHAUSTED';
      expect(run.results[0]!.candidateErrors).toEqual(expect.arrayContaining([expect.objectContaining({ code })]));
      expect(run.results[0]!.candidates?.remaining).toBeGreaterThan(70);
      expect(dnsWrites).toEqual([]);
      expect(run.results[0]!.dns?.after).toEqual([current]);
      expect(store.get('ip_pool_trash')).toBe(trash);
      expect(store.get('ip_pool_default')).toBe(inventory.join('\n'));
      if (limit === 'platform') expect(connect.mock.calls.length).toBeLessThanOrEqual(2);
      else expect(connect.mock.calls.length).toBeGreaterThan(2);
    } finally { vi.unstubAllGlobals(); }
  });

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
    expect(new Set(writes)).toEqual(new Set(expected === legacy ? ['app_config'] : ['app_config', 'ip_pool_default']));
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

  it('rejects invalid target writes through the client and keeps the stored configuration unchanged', async () => {
    const stored = JSON.stringify({ targets: [{ domain: 'edge.example.com', mode: 'A', baseDomain: '', prefix: '' }] });
    const store = new Map([['app_config', stored]]);
    const put = vi.fn(async (key: string, value: string) => { store.set(key, value); });
    const kv = { get: async (key: string) => store.get(key) ?? null, put } as unknown as KVNamespace;
    const client = new ApiClient({ fetchImpl: async (input, init) => request(String(input), init, { ...env, IP_DATA: kv }) });
    const before = await client.config();
    const target = before.config.targets[0]!;
    await expect(client.saveConfig({ targets: [{ ...target, domain: 'a'.repeat(254) }] })).rejects.toMatchObject({ status: 400 });
    expect(put).not.toHaveBeenCalled();
    expect(store.get('app_config')).toBe(stored);
    expect((await client.config()).config.targets).toEqual(before.config.targets);
    await expect(client.saveConfig({ targets: [{ ...target, domain: 'next.example.com' }] }))
      .resolves.toMatchObject({ config: { targets: [{ domain: 'next.example.com' }] } });
    expect(put).toHaveBeenCalledTimes(1);
    expect(JSON.parse(store.get('app_config')!).targets[0].domain).toBe('next.example.com');
  });

  it('checks DNS record ownership through the client, Worker and actual DNS adapter', async () => {
    const stored = JSON.stringify({ zones: [{ baseDomain: 'example.com', zoneId: 'fixture-zone', apiKey: 'fixture-token' }],
      targets: [{ domain: 'a.example.com', mode: 'A', zoneIndex: 0 }, { domain: 'a.example.com', mode: 'TXT', zoneIndex: 0 }] });
    const kv = { get: async (key: string) => key === 'app_config' ? stored : null } as unknown as KVNamespace;
    const records = new Map([
      ['a1', { id: 'a1', type: 'A', name: 'a.example.com', content: '203.0.113.10' }],
      ['a6', { id: 'a6', type: 'AAAA', name: 'a.example.com', content: '2001:db8::10' }],
      ['txt1', { id: 'txt1', type: 'TXT', name: 'a.example.com', content: '"203.0.113.10:443"' }],
      ['foreign', { id: 'foreign', type: 'A', name: 'b.example.com', content: '203.0.113.20' }],
    ]);
    const deleted: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      expect(url.origin).toBe('https://api.cloudflare.com');
      if (init?.method === 'DELETE') {
        const id = url.pathname.split('/').at(-1)!;
        deleted.push(id);
        records.delete(id);
        return Response.json({ success: true, result: { id } });
      }
      return Response.json({ success: true, result: [...records.values()].filter(record =>
        record.name === url.searchParams.get('name') && record.type === url.searchParams.get('type')) });
    }));
    try {
      const client = new ApiClient({ fetchImpl: async (input, init) => request(String(input), init, { ...env, IP_DATA: kv }) });
      for (const id of ['foreign', 'txt1', 'missing']) {
        await expect(client.deleteRecord('a.example.com|A', id)).rejects.toMatchObject({ status: 400 });
      }
      expect(deleted).toEqual([]);
      await expect(client.deleteRecord('a.example.com|A', 'a1')).resolves.toEqual({ ok: true });
      await expect(client.deleteRecord('a.example.com|A', 'a6')).resolves.toEqual({ ok: true });
      await expect(client.deleteRecord('a.example.com|TXT', 'txt1', '203.0.113.10:443')).resolves.toEqual({ ok: true });
      expect(deleted).toEqual(['a1', 'a6', 'txt1']);
      expect([...records.keys()]).toEqual(['foreign']);
    } finally { vi.unstubAllGlobals(); }
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

  it('reads configuration once per request and does not reuse it across requests', async () => {
    const store = new Map([['app_config', JSON.stringify({ settings: { CONCURRENT_CHECKS: 24, BACKEND_CONCURRENT_CHECKS: 1 } })]]);
    const get = vi.fn(async (key: string) => store.get(key) ?? null);
    const kv = { get, put: async (key: string, value: string) => { store.set(key, value); } } as unknown as KVNamespace;
    const worker = createWorker();
    const client = new ApiClient({ fetchImpl: async (input, init) => worker.fetch!(
      new Request(new URL(String(input), 'https://panel.example'), init) as Parameters<NonNullable<typeof worker.fetch>>[0],
      { ...env, IP_DATA: kv }, context,
    ) as Promise<Response> });
    expect((await client.config()).config.settings.CONCURRENT_CHECKS).toBe(24);
    expect(get.mock.calls.filter(([key]) => key === 'app_config')).toHaveLength(1);
    get.mockClear();
    const saved = await client.saveConfig({ settings: { CONCURRENT_CHECKS: 7 } });
    expect(saved.config.settings.CONCURRENT_CHECKS).toBe(7);
    expect(saved.config.settings).not.toHaveProperty('BACKEND_CONCURRENT_CHECKS');
    expect(JSON.parse(store.get('app_config')!).settings).not.toHaveProperty('BACKEND_CONCURRENT_CHECKS');
    expect(get.mock.calls.filter(([key]) => key === 'app_config')).toHaveLength(1);
    store.set('app_config', JSON.stringify({ settings: { CONCURRENT_CHECKS: 9 } }));
    expect((await client.config()).config.settings.CONCURRENT_CHECKS).toBe(9);
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

  it('allows password-free setup, then enables, changes and clears the password through the panel API', async () => {
    const store = new Map<string, string>();
    const kv = {
      get: async (key: string) => store.get(key) ?? null,
      put: async (key: string, value: string) => { store.set(key, value); },
    } as unknown as KVNamespace;
    const runtimeEnv: RuntimeEnv = { IP_DATA: kv };
    const status = () => request('/api/auth/status', undefined, runtimeEnv).then(response => response.json());
    const savePassword = (authKey: string, currentKey?: string) => request('/api/config', {
      method: 'PUT', headers: { 'content-type': 'application/json', ...(currentKey ? { 'X-Auth-Key': currentKey } : {}) },
      body: JSON.stringify({ authKey }),
    }, runtimeEnv);

    expect(await status()).toEqual({ ok: true, enabled: false, authenticated: true });
    expect((await request('/api/config', undefined, runtimeEnv)).status).toBe(200);
    expect((await savePassword('fixture-first')).status).toBe(200);
    expect(await status()).toEqual({ ok: true, enabled: true, authenticated: false });
    expect((await request('/api/config', undefined, runtimeEnv)).status).toBe(401);

    expect((await savePassword('fixture-second', 'fixture-first')).status).toBe(200);
    expect((await request('/api/health', { headers: { 'X-Auth-Key': 'fixture-first' } }, runtimeEnv)).status).toBe(401);
    expect((await request('/api/health', { headers: { 'X-Auth-Key': 'fixture-second' } }, runtimeEnv)).status).toBe(200);

    expect((await savePassword('', 'fixture-second')).status).toBe(200);
    expect(await status()).toEqual({ ok: true, enabled: false, authenticated: true });
    expect((await request('/api/config', undefined, runtimeEnv)).status).toBe(200);
    expect([...store.keys()]).toEqual(['app_config']);
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
    await client.saveConfig({ checkApiBackup: 'https://new.example/?proxyip=' });
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

it('removes the inventory preview endpoint without writing KV', async () => {
  const put = vi.fn(async () => undefined);
  const values = new Map([
    ['app_config', JSON.stringify({ checkApi: '', checkApiBackup: '' })],
    ['ip_pool_default', '203.0.113.10:443,AS64500,JP,v4 # keep'],
  ]);
  const kv = { get: async (key: string) => values.get(key) ?? null, put } as unknown as KVNamespace;
  const response = await request('/api/pools/ip_pool_default/preview', { method: 'POST', body: JSON.stringify({ content: '203.0.113.11:443' }) }, { ...env, IP_DATA: kv });
  expect(response.status).toBe(404);
  expect(put).not.toHaveBeenCalled();
  expect(values.get('ip_pool_default')).toBe('203.0.113.10:443,AS64500,JP,v4 # keep');
});
