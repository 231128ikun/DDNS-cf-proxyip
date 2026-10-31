import { validateRemoteUrl } from '../../domain/remote-url';
import type { RemotePoolLoadResult, RemoteLoadRequestOptions, RemotePoolSource } from '../../ports/remote-pool-source';
import { appFetch } from '../../util/fetch';
import { createRequestTimeout } from '../../util/request-timeout';

const DEFAULT_MAX_REMOTE_BYTES = 512 * 1024;
const DEFAULT_MAX_REDIRECTS = 3;

export interface HttpRemotePoolSourceOptions {
  readonly timeoutMs: number;
  readonly maxBytes?: number;
  readonly maxRedirects?: number;
  readonly fetchImpl?: typeof fetch;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * 远程 IP 池的 HTTP 适配器。
 *
 * 由 Worker 代前端请求远程 TXT，前端永远不直接访问第三方地址：
 * - 每一跳（含重定向目标）都重新做公网校验，防止 302 到内网绕过黑名单；
 * - 超时覆盖响应头与正文，按字节限制正文，避免慢接口或超大文件拖垮 Worker。
 */
export class HttpRemotePoolSource implements RemotePoolSource {
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly maxRedirects: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: HttpRemotePoolSourceOptions) {
    this.timeoutMs = options.timeoutMs;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_REMOTE_BYTES;
    this.maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    this.fetchImpl = options.fetchImpl ?? appFetch;
  }

  async load(rawUrl: string, options: RemoteLoadRequestOptions = {}): Promise<RemotePoolLoadResult> {
    let target = validateRemoteUrl(rawUrl);
    if (!target.ok) return { ok: false, reason: target.reason };

    for (let hop = 0; hop <= this.maxRedirects; hop += 1) {
      const timeout = createRequestTimeout(this.timeoutMs, options.signal);
      let response: Response | undefined;
      try {
        timeout.signal.throwIfAborted();
        // 每跳自行校验，而不是交给运行时自动跟随。
        response = await this.fetchImpl(target.url.toString(), {
          redirect: 'manual', signal: timeout.signal,
          headers: { accept: 'text/plain, text/*;q=0.9, */*;q=0.8' },
        });
        timeout.signal.throwIfAborted();
        const location = response.headers.get('location');
        if (REDIRECT_STATUSES.has(response.status) && location) {
          const next = validateRedirect(location, target.url);
          if (!next.ok) return { ok: false, reason: next.reason };
          target = next;
          continue;
        }
        if (!response.ok) return { ok: false, reason: 'http-error' };
        return await this.readBody(response, target.url.toString(), timeout.signal);
      } catch {
        return { ok: false, reason: timeout.didTimeout() ? 'timeout' : 'network-error' };
      } finally {
        // 废弃响应不等待远端结束；已开始读取的正文由 readBody 负责清理。
        if (response?.body && !response.bodyUsed && !response.body.locked) {
          void response.body.cancel().catch(() => undefined);
        }
        timeout.cleanup();
      }
    }

    return { ok: false, reason: 'too-many-redirects' };
  }

  private async readBody(response: Response, finalUrl: string, signal: AbortSignal): Promise<RemotePoolLoadResult> {
    const declared = Number(response.headers.get('content-length') ?? Number.NaN);
    if (Number.isFinite(declared) && declared > this.maxBytes) return { ok: false, reason: 'too-large' };
    if (!response.body) return { ok: true, content: '', finalUrl };

    const reader = response.body.getReader();
    // 取消 reader 会立即结束挂起的 read；不等待可能永不结束的底层 cancel。
    const cancel = () => { void reader.cancel(signal.reason).catch(() => undefined); };
    signal.addEventListener('abort', cancel, { once: true });
    let complete = false;
    try {
      signal.throwIfAborted();
      const decoder = new TextDecoder();
      const chunks: string[] = [];
      let bytes = 0;
      while (true) {
        const chunk = await reader.read();
        signal.throwIfAborted();
        if (chunk.done) {
          complete = true;
          return { ok: true, content: chunks.join('') + decoder.decode(), finalUrl };
        }
        bytes += chunk.value.byteLength;
        if (bytes > this.maxBytes) return { ok: false, reason: 'too-large' };
        chunks.push(decoder.decode(chunk.value, { stream: true }));
      }
    } finally {
      signal.removeEventListener('abort', cancel);
      if (!complete) cancel();
      reader.releaseLock();
    }
  }
}

function validateRedirect(location: string, base: URL): ReturnType<typeof validateRemoteUrl> {
  try {
    return validateRemoteUrl(new URL(location, base).toString());
  } catch {
    return { ok: false, reason: 'invalid-url' };
  }
}
