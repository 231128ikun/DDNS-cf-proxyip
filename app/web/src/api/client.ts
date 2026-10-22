import type {
  PoolCheckItemResponse,
  PoolCheckProgressEvent,
  PoolCheckResponse,
  PoolCheckStreamEvent,
} from '../../../src/contracts/pool-check';
import { MAX_BATCH_REQUEST_TARGETS } from '../../../src/contracts/pool-check';
import { planPoolCheckChunks } from '../../../src/domain/pool-text';
import type {
  CleanPoolResponse,
  CreatePoolResponse,
  PoolContentResponse,
  PoolSaveMode,
  PoolSaveResponse,
  PoolsResponse,
  RestoreTrashResponse,
} from '../../../src/contracts/pool';
import type { ApiErrorResponse, CheckTargetResponse, HealthResponse } from '../../../src/contracts/probe';
import type { ConfigResponse, ConfigUpdateRequest } from '../../../src/contracts/config';
import type { RemoteLoadResponse } from '../../../src/contracts/remote-load';
import type { DomainBindingsResponse, MaintenanceRunResponse } from '../../../src/contracts/maintenance';

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
    readonly retryable = false,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export class ApiClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ApiClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? '').replace(/\/+$/, '');
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async health(signal?: AbortSignal): Promise<HealthResponse> {
    return await this.request<HealthResponse>('/api/health', 'GET', undefined, signal);
  }

  /** 探测入口：域名解析与逐地址探测都在服务端完成，前端只负责展示结果。 */
  async checkTarget(proxyip: string, signal?: AbortSignal): Promise<CheckTargetResponse> {
    return await this.request<CheckTargetResponse>('/api/check', 'POST', { proxyip }, signal);
  }

  /** 按安全上限拆分请求，并合并逐项进度与最终报告。 */
  async checkBatch(
    text: string,
    signal?: AbortSignal,
    onProgress?: (event: PoolCheckProgressEvent) => void,
  ): Promise<PoolCheckResponse> {
    const plan = planPoolCheckChunks(text, MAX_BATCH_REQUEST_TARGETS);
    const items: PoolCheckItemResponse[] = [];
    const invalid: string[] = [];
    let completed = 0;

    for (const chunk of plan.chunks) {
      const report = onProgress
        ? await this.checkBatchChunk(chunk, signal, (event) => {
            onProgress({
              ...event,
              completed: completed + event.completed,
              total: plan.total,
            });
          })
        : await this.request<PoolCheckResponse>('/api/check/batch', 'POST', { text: chunk }, signal);
      items.push(...report.items);
      invalid.push(...report.invalid);
      completed += report.total;
    }

    return {
      total: items.length,
      alive: items.filter((item) => item.status === 'alive').length,
      dead: items.filter((item) => item.status === 'dead').length,
      unknown: items.filter((item) => item.status === 'unknown').length,
      invalid,
      items,
    };
  }

  private async checkBatchChunk(
    text: string,
    signal: AbortSignal | undefined,
    onProgress: (event: PoolCheckProgressEvent) => void,
  ): Promise<PoolCheckResponse> {
    const bufferedProgress: PoolCheckProgressEvent[] = [];
    try {
      const report = await this.streamPoolCheck(text, signal, (event) => {
        bufferedProgress.push(event);
      });
      bufferedProgress.forEach(onProgress);
      return report;
    } catch (error) {
      if (
        signal?.aborted ||
        !(error instanceof ApiError) ||
        !error.retryable
      ) {
        throw error;
      }
    }

    const report = await this.request<PoolCheckResponse>('/api/check/batch', 'POST', { text }, signal);
    report.items.forEach((item, index) => {
      onProgress({ type: 'progress', completed: index + 1, total: report.total, item });
    });
    return report;
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

  /** 一键洗库：读池、批量检测、有效项写回、失效项入桶全部在服务端一次完成。 */
  async cleanPool(key: string, signal?: AbortSignal): Promise<CleanPoolResponse> {
    return await this.request<CleanPoolResponse>(`${poolPath(key)}/clean`, 'POST', undefined, signal);
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

  private async streamPoolCheck(
    text: string,
    signal: AbortSignal | undefined,
    onProgress: (event: PoolCheckProgressEvent) => void,
  ): Promise<PoolCheckResponse> {
    const headers = new Headers({ Accept: 'application/x-ndjson' });
    headers.set('Content-Type', 'application/json');
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/api/check/batch`, {
        method: 'POST',
        headers,
        credentials: 'same-origin',
        cache: 'no-store',
        body: JSON.stringify({ text }),
        ...(signal ? { signal } : {}),
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
      const detail = error instanceof Error && error.message ? `：${error.message}` : '';
      throw new ApiError(`无法连接到 Worker API${detail}`, 0, true);
    }

    if (!response.ok) {
      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new ApiError(`API 返回了无效响应 (HTTP ${response.status})`, response.status);
      }
      throw new ApiError(isApiError(payload) ? payload.error : `API 请求失败 (HTTP ${response.status})`, response.status);
    }
    if (!response.body) throw new ApiError('批量检测接口没有返回进度流', response.status, true);

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let report: PoolCheckResponse | undefined;
    const consumeLine = (line: string): void => {
      const textLine = line.trim();
      if (!textLine) return;
      let value: unknown;
      try {
        value = JSON.parse(textLine);
      } catch {
        throw new ApiError('批量检测进度格式无效', response.status, true);
      }
      const event = parsePoolCheckStreamEvent(value);
      if (!event) throw new ApiError('批量检测进度格式无效', response.status, true);
      if (event.type === 'progress') onProgress(event);
      else if (event.type === 'complete') report = event.report;
      else throw new ApiError(event.error, response.status);
    };

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let newline = buffer.indexOf('\n');
        while (newline >= 0) {
          consumeLine(buffer.slice(0, newline));
          buffer = buffer.slice(newline + 1);
          newline = buffer.indexOf('\n');
        }
      }
      buffer += decoder.decode();
      if (buffer.trim()) consumeLine(buffer);
    } catch (error) {
      if (error instanceof ApiError || (error instanceof DOMException && error.name === 'AbortError')) throw error;
      throw new ApiError('批量检测进度读取失败', response.status, true);
    } finally {
      reader.releaseLock();
    }

    if (!report) throw new ApiError('批量检测未返回最终结果', response.status, true);
    return report;
  }

  private async request<T>(path: string, method: string, body?: unknown, signal?: AbortSignal): Promise<T> {
    const headers = new Headers({ Accept: 'application/json' });
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

function parsePoolCheckStreamEvent(value: unknown): PoolCheckStreamEvent | null {
  if (!isRecord(value)) return null;
  const event = value;
  if (event.type === 'error' && typeof event.error === 'string') {
    return { type: 'error', error: event.error };
  }
  if (event.type === 'progress' && typeof event.completed === 'number' && typeof event.total === 'number') {
    if (!isPoolCheckItemResponse(event.item)) return null;
    return { type: 'progress', completed: event.completed, total: event.total, item: event.item };
  }
  if (event.type === 'complete' && isPoolCheckResponse(event.report)) return { type: 'complete', report: event.report };
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object';
}

function isPoolCheckItemResponse(value: unknown): value is PoolCheckItemResponse {
  if (!isRecord(value)) return false;
  return typeof value.address === 'string' &&
    typeof value.line === 'string' &&
    ['alive', 'dead', 'unknown'].includes(String(value.status)) &&
    ['ipv4', 'ipv6', 'dual', 'unknown'].includes(String(value.exitFamily));
}

function isPoolCheckResponse(value: unknown): value is PoolCheckResponse {
  if (!isRecord(value)) return false;
  return typeof value.total === 'number' &&
    typeof value.alive === 'number' &&
    typeof value.dead === 'number' &&
    typeof value.unknown === 'number' &&
    Array.isArray(value.invalid) &&
    value.invalid.every((item) => typeof item === 'string') &&
    Array.isArray(value.items) &&
    value.items.every(isPoolCheckItemResponse);
}
