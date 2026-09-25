import { cleanPoolText } from '../domain/pool-text';
import { validateRemoteUrl, type RemoteUrlRejection } from '../domain/remote-url';

export const DEFAULT_MAX_REMOTE_BYTES = 512 * 1024;
export const DEFAULT_MAX_REDIRECTS = 3;

export type RemoteLoadFailure =
  | RemoteUrlRejection
  | 'too-many-redirects'
  | 'http-error'
  | 'timeout'
  | 'network-error'
  | 'too-large';

export type RemotePoolLoadResult =
  | { readonly ok: true; readonly content: string; readonly finalUrl: string }
  | { readonly ok: false; readonly reason: RemoteLoadFailure };

export interface RemotePoolLoaderOptions {
  readonly timeoutMs: number;
  readonly maxBytes?: number;
  readonly maxRedirects?: number;
  readonly fetchImpl?: typeof fetch;
}

export interface RemoteLoadRequestOptions {
  readonly signal?: AbortSignal;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * 远程 IP 池加载用例。
 *
 * 由 Worker 代前端请求远程 TXT，前端永远不直接访问第三方地址：
 * - 每一跳（含重定向目标）都重新做公网校验，防止 302 到内网绕过黑名单；
 * - 显式超时与响应体上限，避免被慢接口或超大文件拖垮 Worker。
 */
export class RemotePoolLoader {
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly maxRedirects: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: RemotePoolLoaderOptions) {
    this.timeoutMs = options.timeoutMs;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_REMOTE_BYTES;
    this.maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async load(rawUrl: string, options: RemoteLoadRequestOptions = {}): Promise<RemotePoolLoadResult> {
    let target = validateRemoteUrl(rawUrl);
    if (!target.ok) return { ok: false, reason: target.reason };

    for (let hop = 0; hop <= this.maxRedirects; hop += 1) {
      const response = await this.fetchOnce(target.url, options);
      if (!response.ok) return response;

      const location = response.value.headers.get('location');
      if (REDIRECT_STATUSES.has(response.value.status) && location) {
        const next = validateRedirect(location, target.url);
        if (!next.ok) return { ok: false, reason: next.reason };
        target = next;
        continue;
      }

      return await this.readBody(response.value, target.url.toString());
    }

    return { ok: false, reason: 'too-many-redirects' };
  }

  private async fetchOnce(
    url: URL,
    options: RemoteLoadRequestOptions,
  ): Promise<{ readonly ok: true; readonly value: Response } | { readonly ok: false; readonly reason: RemoteLoadFailure }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const abortUpstream = () => controller.abort();
    options.signal?.addEventListener('abort', abortUpstream, { once: true });

    try {
      // redirect: 'manual' 让每一跳都由这里重新校验，而不是交给运行时自动跟随。
      const response = await this.fetchImpl(url.toString(), {
        redirect: 'manual',
        signal: controller.signal,
        headers: { accept: 'text/plain, text/*;q=0.9, */*;q=0.8' },
      });
      if (REDIRECT_STATUSES.has(response.status) && response.headers.get('location')) return { ok: true, value: response };
      if (!response.ok) return { ok: false, reason: 'http-error' };
      return { ok: true, value: response };
    } catch {
      // 本地定时器触发才是超时；调用方主动取消同样按网络错误处理，由上层决定文案。
      return this.timedOut(options.signal, controller.signal)
        ? { ok: false, reason: 'timeout' }
        : { ok: false, reason: 'network-error' };
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', abortUpstream);
    }
  }

  private async readBody(response: Response, finalUrl: string): Promise<RemotePoolLoadResult> {
    const declared = Number(response.headers.get('content-length') ?? Number.NaN);
    if (Number.isFinite(declared) && declared > this.maxBytes) return { ok: false, reason: 'too-large' };

    let text: string;
    try {
      text = await response.text();
    } catch {
      return { ok: false, reason: 'network-error' };
    }
    if (text.length > this.maxBytes) return { ok: false, reason: 'too-large' };

    return { ok: true, content: cleanPoolText(text), finalUrl };
  }

  /** 只有本地超时控制器被触发、且调用方没有主动取消，才算超时。 */
  private timedOut(upstream: AbortSignal | undefined, local: AbortSignal): boolean {
    return local.aborted && !upstream?.aborted;
  }
}

function validateRedirect(location: string, base: URL): ReturnType<typeof validateRemoteUrl> {
  try {
    return validateRemoteUrl(new URL(location, base).toString());
  } catch {
    return { ok: false, reason: 'invalid-url' };
  }
}