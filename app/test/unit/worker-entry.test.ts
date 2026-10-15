import { describe, expect, it } from 'vitest';

import type { RuntimeEnv } from '../../src/config/runtime';
import { APP_VERSION, createWorker } from '../../src/worker';

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

  it('配置面板密钥后 API 需要鉴权', async () => {
    const guarded: RuntimeEnv = { ...env, AUTH_KEY: 'panel-key' };

    const denied = await request('/api/pools', undefined, guarded);
    expect(denied.status).toBe(401);

    const allowed = await request('/api/pools', { headers: { authorization: 'Bearer panel-key' } }, guarded);
    expect(allowed.status).toBe(503);
  });
});