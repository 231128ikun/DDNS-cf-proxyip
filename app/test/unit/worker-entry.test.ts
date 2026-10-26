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
