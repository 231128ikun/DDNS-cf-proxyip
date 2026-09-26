/**
 * 发布资源适配器：把构建期打包的前端产物封装成 HTTP 层需要的 `Fetcher`，
 * 前端源码不进入 Worker 路由代码。
 *
 * 资源表由 `scripts/build-worker.mjs` 生成，key 是请求路径（例如 `/assets/index-xxxx.js`），
 * 值是该文件的 base64；文本资源在构建期 gzip，运行时按资源首次请求解压并缓存，避免把
 * 未压缩源码重复写进 Worker。响应本身统一交给 Cloudflare 传输层压缩。
 */

export interface BundledAsset {
  /** 响应的 Content-Type，按扩展名在构建期确定。 */
  readonly contentType: string;
  /** 文件内容的 base64；`gzip` 为 true 时是 gzip 压缩后的字节。 */
  readonly base64: string;
  readonly gzip: boolean;
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
  // 按路径缓存 promise，并发请求同一资源时只解压一次。
  const decoded = new Map<string, Promise<DecodedAsset | null>>();

  const load = (path: string): Promise<DecodedAsset | null> => {
    const cached = decoded.get(path);
    if (cached) return cached;

    const pending = decodeAsset(assets[path]);
    decoded.set(path, pending);
    return pending;
  };

  const fetcher = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return new Response('Method Not Allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
      }

      const path = normalizePath(new URL(request.url).pathname);
      let asset = await load(path);
      if (!asset && isSpaRoute(path)) asset = await load(INDEX_PATH);
      if (!asset) return new Response('Not Found', { status: 404, headers: TEXT_HEADERS });

      const headers: Record<string, string> = {
        'content-type': asset.contentType,
        'cache-control': isHashedAsset(path) ? IMMUTABLE_CACHE : REVALIDATE_CACHE,
      };

      return new Response(request.method === 'HEAD' ? null : asset.bytes, { headers });
    },
  };

  // 打包资源没有 TCP 端口，故意不实现 `Fetcher.connect`；HTTP 层只调用 `fetch`。
  return fetcher as unknown as Fetcher;
}

async function decodeAsset(asset: BundledAsset | undefined): Promise<DecodedAsset | null> {
  if (!asset) return null;

  const stored = decodeBase64(asset.base64);
  const bytes = asset.gzip ? await gunzip(stored) : stored;
  return { bytes, contentType: asset.contentType };
}

async function gunzip(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
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