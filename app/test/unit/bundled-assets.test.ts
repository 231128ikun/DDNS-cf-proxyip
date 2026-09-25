import { describe, expect, it } from 'vitest';

import { createBundledAssets, type BundledAssetMap } from '../../src/adapters/assets/bundled-assets';

const assets: BundledAssetMap = {
  '/index.html': { contentType: 'text/html; charset=utf-8', base64: encode('<html>panel</html>') },
  '/assets/index-abc.js': { contentType: 'text/javascript; charset=utf-8', base64: encode('export const a = 1;') },
};

const fetcher = createBundledAssets(assets);
const request = (path: string, init?: RequestInit) =>
  fetcher.fetch(new Request(`https://panel.example${path}`, init));

function encode(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64');
}

describe('打包资源适配器', () => {
  it('命中打包资源时返回解码后的内容与长期缓存头', async () => {
    const response = await request('/assets/index-abc.js');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('text/javascript; charset=utf-8');
    expect(response.headers.get('cache-control')).toContain('immutable');
    await expect(response.text()).resolves.toBe('export const a = 1;');
  });

  it('页面路由回退到 SPA 入口，并且不允许被缓存', async () => {
    const response = await request('/config');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('text/html; charset=utf-8');
    expect(response.headers.get('cache-control')).toBe('no-cache');
    await expect(response.text()).resolves.toBe('<html>panel</html>');
  });

  it('根路径与 /index.html 都返回面板入口', async () => {
    await expect((await request('/')).text()).resolves.toBe('<html>panel</html>');
    await expect((await request('/index.html')).text()).resolves.toBe('<html>panel</html>');
  });

  it('带扩展名的缺失资源必须 404，不能回退成 HTML', async () => {
    const response = await request('/assets/index-missing.js');
    expect(response.status).toBe(404);
    await expect(response.text()).resolves.toBe('Not Found');
  });

  it('HEAD 返回同样的响应头但没有响应体', async () => {
    const response = await request('/assets/index-abc.js', { method: 'HEAD' });
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('text/javascript; charset=utf-8');
    await expect(response.text()).resolves.toBe('');
  });

  it('只接受 GET 与 HEAD', async () => {
    const response = await request('/', { method: 'POST' });
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, HEAD');
  });
});

