import type {
  PoolCheckProgressEvent,
  PoolCheckResponse,
} from '../../../src/contracts/pool-check';
import {
  TRASH_POOL_KEY,
  type CleanPoolResponse,
  type CleanPoolRequest,
  type CreatePoolResponse,
  type PoolContentResponse,
  type SavePoolRequest,
  type PoolSaveResponse,
  type PoolsResponse,
  type RestoreTrashResponse,
} from '../../../src/contracts/pool';
import type { ApiErrorResponse, CheckTargetResponse, HealthResponse } from '../../../src/contracts/probe';
import type { ConfigResponse, ConfigUpdateRequest } from '../../../src/contracts/config';
import type { AuthStatusResponse } from '../../../src/contracts/auth';
import { DEFAULT_RUNTIME_SETTINGS } from '../../../src/contracts/runtime-settings';
import type { RemoteLoadResponse } from '../../../src/contracts/remote-load';
import { MAINTENANCE_STREAM_TYPE, readMaintenanceStreamResult, type DomainBindingsResponse, type MaintenanceLogLine, type MaintenanceRunResponse } from '../../../src/contracts/maintenance';
import { isRecord } from '../../../src/contracts/parse';
import type { TargetStatusResponse } from '../../../src/contracts/target-status';

export interface ApiClientOptions {
  readonly baseUrl?: string;
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

export function loadBatchCheckModule(): Promise<typeof import('./batch-check')> {
  return import('./batch-check');
}

let changelog: Promise<string> | undefined;
export function loadChangelog(url: string): Promise<string> {
  return changelog ??= fetch(url, { signal: AbortSignal.timeout(8000) }).then(response => {
    if (!response.ok) throw new Error('更新日志暂不可用');
    return response.text();
  }).catch(error => { changelog = undefined; throw error; });
}

export class ApiClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ApiClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? '').replace(/\/+$/, '');
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async authStatus(signal?: AbortSignal): Promise<AuthStatusResponse> {
    return await this.request<AuthStatusResponse>('/api/auth/status', 'GET', undefined, signal);
  }

  async login(key: string, signal?: AbortSignal): Promise<AuthStatusResponse> {
    return await this.request<AuthStatusResponse>('/api/auth/login', 'POST', { key }, signal);
  }

  async health(signal?: AbortSignal): Promise<HealthResponse> {
    return await this.request<HealthResponse>('/api/health', 'GET', undefined, signal);
  }

  /** 探测入口：域名解析与逐地址探测都在服务端完成，前端只负责展示结果。 */
  async checkTarget(proxyip: string, signal?: AbortSignal): Promise<CheckTargetResponse> {
    return await this.request<CheckTargetResponse>('/api/check', 'POST', { proxyip }, signal);
  }

  /**
   * 浏览器限制并发，每个地址单独请求 Worker。
   * 单个 Worker 请求只承担一个目标的主/备探测，避免整批耗尽子请求预算。
   */
  async checkBatch(text: string, signal?: AbortSignal, onProgress?: (event: PoolCheckProgressEvent) => void, concurrency: number = DEFAULT_RUNTIME_SETTINGS.CONCURRENT_CHECKS): Promise<PoolCheckResponse> {
    const { checkBatch } = await loadBatchCheckModule();
    return checkBatch(this, text, signal, onProgress, concurrency);
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
    mode: SavePoolRequest['mode'] = 'append',
    signal?: AbortSignal,
    returnReceipt = false,
  ): Promise<PoolSaveResponse> {
    return await this.request<PoolSaveResponse>(poolPath(key), 'PUT', { content, mode, ...(returnReceipt ? { returnReceipt: true } : {}) }, signal);
  }

  async createPool(displayName: string, signal?: AbortSignal): Promise<CreatePoolResponse> {
    return await this.request<CreatePoolResponse>('/api/pools', 'POST', { displayName }, signal);
  }

  async renamePool(key: string, displayName: string, signal?: AbortSignal): Promise<OkResponse> {
    return await this.request<OkResponse>(poolPath(key), 'PATCH', { displayName }, signal);
  }

  async cleanPool(key: string, signal?: AbortSignal, onProgress?: (event: PoolCheckProgressEvent) => void, concurrency: number = DEFAULT_RUNTIME_SETTINGS.CONCURRENT_CHECKS, onApply?: () => void): Promise<CleanPoolResponse> {
    const source = await this.readPool(key, signal);
    if (source.key !== key) throw new ApiError('返回的 IP 池不符', 0);
    const {readPoolSnapshot, serializePoolEntries, snapshotEntries} = await import('../../../src/domain/pool-snapshot');
    const snapshot = readPoolSnapshot(source.content);
    if (!snapshot.entries.size) throw new ApiError('池中没有有效地址，无需洗库', 0);
    const report = await this.checkBatch(serializePoolEntries(snapshotEntries(snapshot)), signal, onProgress, concurrency);
    signal?.throwIfAborted();
    const invalid = snapshot.invalid.length + report.invalid.length;
    if (invalid) return {ok:true, poolKey:key, checked:report.total, kept:0, trashed:0, unknown:report.unknown + invalid, skipped:true};
    const input: CleanPoolRequest = {content:source.content, report};
    onApply?.();
    const result = await this.request<CleanPoolResponse>(`${poolPath(key)}/clean`, 'POST', input, signal);
    if (result?.ok !== true || result.poolKey !== key || result.checked !== report.total || typeof result.skipped !== 'boolean'
      || (key === TRASH_POOL_KEY && !result.skipped && result.remaining === undefined)
      || ![result.kept, result.trashed, result.unknown, result.remaining ?? 0].every(count => Number.isSafeInteger(count) && count >= 0)) {
      throw new ApiError('未取得有效洗库回执，请核对库存', 0);
    }
    return result;
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

  /** 首次读取兼作鉴权，由登录页处理 401；面板内的读取仍在会话失效时跳转。 */
  async config(signal?: AbortSignal, redirectOnUnauthorized = true): Promise<ConfigResponse> {
    return await this.request<ConfigResponse>('/api/config', 'GET', undefined, signal, redirectOnUnauthorized);
  }

  /** 未提交的密钥字段由服务端沿用旧值，前端只提交用户改动的密钥。 */
  async saveConfig(config: ConfigUpdateRequest, signal?: AbortSignal): Promise<ConfigResponse> {
    return await this.request<ConfigResponse>('/api/config', 'PUT', config, signal);
  }

  /** 远程加载由 Worker 代理，前端不直接访问第三方地址，避免绕过 SSRF 校验。 */
  async remoteLoad(url: string, signal?: AbortSignal): Promise<RemoteLoadResponse> {
    return await this.request<RemoteLoadResponse>('/api/remote-load', 'POST', { url }, signal);
  }

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

  async runMaintenance(signal?: AbortSignal, onProgress?: (line: MaintenanceLogLine) => void): Promise<MaintenanceRunResponse> {
    return await this.request<MaintenanceRunResponse>('/api/maintenance/run', 'POST', undefined, signal, true, onProgress);
  }

  /** “解析实况”只读查询：按域名池绑定 key 读取目标当前 DNS 记录。 */
  async currentStatus(targetKey: string, signal?: AbortSignal): Promise<TargetStatusResponse> {
    return await this.request<TargetStatusResponse>(
      `/api/current-status?target=${encodeURIComponent(targetKey)}`,
      'GET',
      undefined,
      signal,
    );
  }

  /** 手动添加一条记录到选中的维护目标；A/AAAA 添加单条地址，TXT 合并进单条列表。 */
  async addRecord(targetKey: string, value: string, signal?: AbortSignal): Promise<OkResponse> {
    return await this.request<OkResponse>('/api/add-record', 'POST', { target: targetKey, value }, signal);
  }

  /** 手动删除当前维护目标的一条记录；TXT 模式需要额外给出要删除的地址。 */
  async deleteRecord(
    targetKey: string,
    recordId: string,
    address?: string,
    signal?: AbortSignal,
  ): Promise<OkResponse> {
    return await this.request<OkResponse>('/api/delete-record', 'POST', {
      target: targetKey,
      recordId,
      ...(address === undefined ? {} : { address }),
    }, signal);
  }

  private async request<T>(path: string, method: string, body?: unknown, signal?: AbortSignal, redirectOnUnauthorized = true,
    onProgress?: (line: MaintenanceLogLine) => void): Promise<T> {
    const headers = new Headers({ Accept: onProgress ? MAINTENANCE_STREAM_TYPE : 'application/json' });
    if (body !== undefined) headers.set('Content-Type', 'application/json');

    const init: RequestInit = { method, headers, credentials: 'same-origin', cache: 'no-store' };
    if (body !== undefined) init.body = JSON.stringify(body);
    const deadline = method === 'GET' && /^\/api\/(config|health|pools|domain-bindings)$/.test(path)
      ? AbortSignal.timeout(15_000) : undefined;
    if (deadline) init.signal = signal ? AbortSignal.any([signal, deadline]) : deadline;
    else if (signal) init.signal = signal;

    const fetchImpl = this.fetchImpl;
    let response: Response;
    try {
      response = await fetchImpl(`${this.baseUrl}${path}`, init);
    } catch (error) {
      if (deadline?.aborted && !signal?.aborted) throw new ApiError('读取数据超时，请重试', 0);
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
      throw new ApiError('无法连接到 Worker API', 0);
    }

    if (redirectOnUnauthorized && response.status === 401 && !path.startsWith('/api/auth/')) {
      const page = (globalThis as typeof globalThis & {
        readonly window?: { readonly location?: { readonly assign?: (url: string) => void } };
      }).window;
      page?.location?.assign?.('/');
    }

    if (onProgress && response.ok && response.headers.get('Content-Type')?.startsWith(MAINTENANCE_STREAM_TYPE)) {
      return await readMaintenanceStream(response, onProgress) as T;
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      if (deadline?.aborted && !signal?.aborted) throw new ApiError('读取数据超时，请重试', 0);
      throw new ApiError(`API 返回了无效响应 (HTTP ${response.status})`, response.status);
    }

    if (!response.ok) {
      const message = isApiError(payload) ? payload.error : `API 请求失败 (HTTP ${response.status})`;
      throw new ApiError(message, response.status);
    }
    return payload as T;
  }
}

async function readMaintenanceStream(response: Response, onProgress: (line: MaintenanceLogLine) => void): Promise<MaintenanceRunResponse> {
  const reader = response.body?.getReader();
  let failure = '维护响应提前结束';
  try {
    if (reader) {
      const outcome = await readMaintenanceStreamResult<MaintenanceRunResponse>(reader.read.bind(reader), onProgress,
        (value): value is MaintenanceRunResponse => isRecord(value) && value.ok === true && Array.isArray(value.results));
      if ('result' in outcome) return outcome.result;
      if (outcome.remote) throw new ApiError(outcome.message, 0);
      failure = outcome.message;
    }
  } catch (error) {
    if (error instanceof ApiError || (error instanceof DOMException && error.name === 'AbortError')) throw error;
    failure = error instanceof SyntaxError ? '维护响应格式异常' : '维护连接中断';
  } finally { await reader?.cancel().catch(() => {}); }
  throw new ApiError(failure + '，未取得维护完成回执；已返回的目标结果保留，请核对解析与库存', 0);
}

/** 池 key 由服务端白名单校验，这里只做 URL 编码，避免出现第二套规则。 */
function poolPath(key: string): string {
  return `/api/pools/${encodeURIComponent(key)}`;
}

function isApiError(value: unknown): value is ApiErrorResponse {
  return value !== null && typeof value === 'object' && 'error' in value && typeof value.error === 'string';
}
