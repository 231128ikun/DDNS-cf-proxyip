/**
 * 发布资源适配器：把构建期打包的前端产物封装成 HTTP 层需要的 `Fetcher`，
 * 前端源码不进入 Worker 路由代码。
 *
 * 资源表由 `scripts/build-worker.mjs` 生成，key 是请求路径（例如 `/assets/index-xxxx.js`），
 * 值是该文件的 base64，避免把前端源码里的引号和换行带进 Worker 源码。
 */

export interface BundledAsset {
  /** 响应的 Content-Type，按扩展名在构建期确定。 */
  readonly contentType: string;
  /** 文件内容的 base64。 */
  readonly base64: string;
}

export type BundledAssetMap = Readonly<Record<string, BundledAsset>>;

interface DecodedAsset {
  readonly bytes: Uint8Array<ArrayBuffer>;
  readonly contentType: string;
}

const INDEX_PATH = '/index.html';
/** 带内容哈希的资源可以长期缓存；`index.html` 必须每次校验，否则面板会卡在旧版本。 */
const IMMUTABLE_CACHE = 'public, max-age=31536000, immutable';
const REVALIDATE_CACHE = 'no-cache';
const TEXT_HEADERS = { 'content-type': 'text/plain; charset=utf-8' };

export function createBundledAssets(assets: BundledAssetMap): Fetcher {
  // 只在真正被请求时解码，避免每次请求都重新解码整份前端。
  const decoded = new Map<string, DecodedAsset>();

  const load = (path: string): DecodedAsset | null => {
    const cached = decoded.get(path);
    if (cached) return cached;

    const asset = assets[path];
    if (!asset) return null;

    const entry = { bytes: decodeBase64(asset.base64), contentType: asset.contentType };
    decoded.set(path, entry);
    return entry;
  };

  const fetcher = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return new Response('Method Not Allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
      }

      const path = normalizePath(new URL(request.url).pathname);
      const asset = load(path) ?? (isSpaRoute(path) ? load(INDEX_PATH) : null);
      if (!asset) return new Response('Not Found', { status: 404, headers: TEXT_HEADERS });

      return new Response(request.method === 'HEAD' ? null : asset.bytes, {
        headers: {
          'content-type': asset.contentType,
          'cache-control': isHashedAsset(path) ? IMMUTABLE_CACHE : REVALIDATE_CACHE,
        },
      });
    },
  };

  // 打包资源没有 TCP 端口，故意不实现 `Fetcher.connect`；HTTP 层只调用 `fetch`。
  return fetcher as unknown as Fetcher;
}

/** 精确命中失败后，只有“看起来是页面路由”的路径才回退 `index.html`，缺 JS/CSS 必须 404。 */
function isSpaRoute(path: string): boolean {
  return !path.slice(path.lastIndexOf('/') + 1).includes('.');
}

function isHashedAsset(path: string): boolean {
  return path.startsWith('/assets/');
}

function normalizePath(pathname: string): string {
  const collapsed = pathname.replace(/\/{2,}/g, '/');
  return collapsed.startsWith('/') ? collapsed : `/${collapsed}`;
}

function decodeBase64(base64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

