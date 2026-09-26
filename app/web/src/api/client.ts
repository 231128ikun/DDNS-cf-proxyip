import type { PoolCheckResponse } from '../../../src/contracts/pool-check';
import type {
  CreatePoolResponse,
  PoolContentResponse,
  PoolSaveMode,
  PoolSaveResponse,
  PoolsResponse,
  RestoreTrashResponse,
} from '../../../src/contracts/pool';
import type {
  ApiErrorResponse,
  HealthResponse,
  ProbeResponse,
} from '../../../src/contracts/probe';
import type { ConfigResponse, ConfigUpdateRequest, ProbeTestRequest } from '../../../src/contracts/config';
import type { RemoteLoadResponse } from '../../../src/contracts/remote-load';
import type { DomainBindingsResponse, MaintenanceRunResponse } from '../../../src/contracts/maintenance';

export interface ApiClientOptions {
  readonly baseUrl?: string;
  readonly authKey?: string;
  readonly fetchImpl?: typeof fetch;
}

export interface OkResponse {
  readonly ok: true;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export class ApiClient {
  private readonly baseUrl: string;
  private readonly authKey: string | undefined;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ApiClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? '').replace(/\/+$/, '');
    this.authKey = options.authKey?.trim() || undefined;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async health(signal?: AbortSignal): Promise<HealthResponse> {
    return await this.request<HealthResponse>('/api/health', 'GET', undefined, signal);
  }

  async check(proxyip: string, signal?: AbortSignal): Promise<ProbeResponse> {
    return await this.request<ProbeResponse>('/api/check', 'POST', { proxyip }, signal);
  }

  /** 批量检测复用服务端解析与并发控制，前端不再重复实现 IP 池文本解析。 */
  async checkBatch(text: string, signal?: AbortSignal): Promise<PoolCheckResponse> {
    return await this.request<PoolCheckResponse>('/api/check/batch', 'POST', { text }, signal);
  }

  async pools(signal?: AbortSignal): Promise<PoolsResponse> {
    return await this.request<PoolsResponse>('/api/pools', 'GET', undefined, signal);
  }

  async readPool(key: string, signal?: AbortSignal): Promise<PoolContentResponse> {
    return await this.request<PoolContentResponse>(poolPath(key), 'GET', undefined, signal);
  }

  async savePool(
    key: string,
    content: string,
    mode: PoolSaveMode = 'replace',
    signal?: AbortSignal,
  ): Promise<PoolSaveResponse> {
    return await this.request<PoolSaveResponse>(poolPath(key), 'PUT', { content, mode }, signal);
  }

  async createPool(displayName: string, signal?: AbortSignal): Promise<CreatePoolResponse> {
    return await this.request<CreatePoolResponse>('/api/pools', 'POST', { displayName }, signal);
  }

  async renamePool(key: string, displayName: string, signal?: AbortSignal): Promise<OkResponse> {
    return await this.request<OkResponse>(poolPath(key), 'PATCH', { displayName }, signal);
  }

  async savePoolOrder(order: readonly string[], signal?: AbortSignal): Promise<OkResponse> {
    return await this.request<OkResponse>('/api/pools/order', 'PUT', { order }, signal);
  }

  async clearTrash(signal?: AbortSignal): Promise<OkResponse> {
    return await this.request<OkResponse>('/api/pools/trash/clear', 'POST', undefined, signal);
  }

  async restoreTrash(
    addresses: readonly string[],
    options: { readonly restoreToSource?: boolean; readonly targetPool?: string } = {},
    signal?: AbortSignal,
  ): Promise<RestoreTrashResponse> {
    return await this.request<RestoreTrashResponse>('/api/pools/trash/restore', 'POST', {
      addresses,
      ...(options.restoreToSource === undefined ? {} : { restoreToSource: options.restoreToSource }),
      ...(options.targetPool === undefined ? {} : { targetPool: options.targetPool }),
    }, signal);
  }

  async removePool(key: string, signal?: AbortSignal): Promise<OkResponse> {
    return await this.request<OkResponse>(poolPath(key), 'DELETE', undefined, signal);
  }

  async config(signal?: AbortSignal): Promise<ConfigResponse> {
    return await this.request<ConfigResponse>('/api/config', 'GET', undefined, signal);
  }

  /** 未提交的密钥字段由服务端沿用旧值，前端只提交用户改动的密钥。 */
  async saveConfig(config: ConfigUpdateRequest, signal?: AbortSignal): Promise<ConfigResponse> {
    return await this.request<ConfigResponse>('/api/config', 'PUT', config, signal);
  }

  async testProbe(request: ProbeTestRequest, signal?: AbortSignal): Promise<ProbeResponse> {
    return await this.request<ProbeResponse>('/api/config/probe/test', 'POST', request, signal);
  }

  /** 远程加载由 Worker 代理，前端不直接访问第三方地址，避免绕过 SSRF 校验。 */
  async remoteLoad(url: string, signal?: AbortSignal): Promise<RemoteLoadResponse> {
    return await this.request<RemoteLoadResponse>('/api/remote-load', 'POST', { url }, signal);
  }

  /** 域名池绑定与手动维护：白名单与执行编排都在服务端，前端只提交整体映射。 */
  async domainBindings(signal?: AbortSignal): Promise<DomainBindingsResponse> {
    return await this.request<DomainBindingsResponse>('/api/domain-bindings', 'GET', undefined, signal);
  }

  async saveDomainBindings(
    mapping: Readonly<Record<string, string>>,
    signal?: AbortSignal,
  ): Promise<OkResponse> {
    return await this.request<OkResponse>('/api/domain-bindings', 'PUT', { mapping }, signal);
  }

  /** 只保存显示顺序；服务端会校验提交的 key 是否与实际目标集合一致。 */
  async saveDomainBindingOrder(order: readonly string[], signal?: AbortSignal): Promise<OkResponse> {
    return await this.request<OkResponse>('/api/domain-bindings/order', 'PUT', { order }, signal);
  }

  /** 手动维护与 cron 共用同一个服务端 runner，前端只负责触发并展示结果。 */
  async runMaintenance(signal?: AbortSignal): Promise<MaintenanceRunResponse> {
    return await this.request<MaintenanceRunResponse>('/api/maintenance/run', 'POST', undefined, signal);
  }

  private async request<T>(path: string, method: string, body?: unknown, signal?: AbortSignal): Promise<T> {
    const headers = new Headers({ Accept: 'application/json' });
    if (this.authKey) headers.set('Authorization', `Bearer ${this.authKey}`);
    if (body !== undefined) headers.set('Content-Type', 'application/json');

    const init: RequestInit = { method, headers, credentials: 'same-origin', cache: 'no-store' };
    if (body !== undefined) init.body = JSON.stringify(body);
    if (signal) init.signal = signal;

    const fetchImpl = this.fetchImpl;
    let response: Response;
    try {
      response = await fetchImpl(`${this.baseUrl}${path}`, init);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
      throw new ApiError('无法连接到 Worker API', 0);
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new ApiError(`API 返回了无效响应 (HTTP ${response.status})`, response.status);
    }

    if (!response.ok) {
      const message = isApiError(payload) ? payload.error : `API 请求失败 (HTTP ${response.status})`;
      throw new ApiError(message, response.status);
    }
    return payload as T;
  }
}

/** 池 key 由服务端白名单校验，这里只做 URL 编码，避免出现第二套规则。 */
function poolPath(key: string): string {
  return `/api/pools/${encodeURIComponent(key)}`;
}

function isApiError(value: unknown): value is ApiErrorResponse {
  return value !== null && typeof value === 'object' && 'error' in value && typeof value.error === 'string';
}
