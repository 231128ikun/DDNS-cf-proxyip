import { describe, expect, it } from 'vitest';

import { createBundledAssets, type BundledAssetMap } from '../../src/adapters/assets/bundled-assets';
import type { RuntimeEnv } from '../../src/config/runtime';
import { APP_VERSION, createWorker } from '../../src/worker';

/** 发布 Worker 的装配回归：打包资源提供面板，API 与鉴权能力保持一致。 */
const assets: BundledAssetMap = {
  '/index.html': { contentType: 'text/html; charset=utf-8', base64: Buffer.from('<html>panel</html>').toString('base64'), gzip: false },
  '/assets/index-abc.js': { contentType: 'text/javascript; charset=utf-8', base64: Buffer.from('export const a = 1;').toString('base64'), gzip: false },
};

const env: RuntimeEnv = { CHECK_API: 'https://check.example/?proxyip={proxyip}' };
const context = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
} as unknown as ExecutionContext;

function worker() {
  return createWorker({ assets: createBundledAssets(assets) });
}

async function request(path: string): Promise<Response> {
  const input = new Request(`https://panel.example${path}`) as Parameters<NonNullable<ExportedHandler<RuntimeEnv>['fetch']>>[0];
  return await worker().fetch!(input, env, context);
}

describe('发布 Worker 装配', () => {
  it('使用打包资源提供面板页面', async () => {
    const response = await request('/config');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('text/html; charset=utf-8');
    await expect(response.text()).resolves.toBe('<html>panel</html>');
  });

  it('打包资源同样通过 Worker 的静态资源回退链路返回', async () => {
    const response = await request('/assets/index-abc.js');
    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe('export const a = 1;');
  });

  it('API 与版本信息不受资源来源影响', async () => {
    const response = await request('/api/health');
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ ok: true, version: APP_VERSION });
  });

  it('未绑定 KV 时不提供池接口，但面板仍可访问', async () => {
    await expect(request('/api/pools').then((response) => response.status)).resolves.toBe(503);
    await expect(request('/').then((response) => response.status)).resolves.toBe(200);
  });
});

