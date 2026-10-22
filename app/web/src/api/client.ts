import type {
  PoolCheckItemResponse,
  PoolCheckProgressEvent,
  PoolCheckResponse,
} from '../../../src/contracts/pool-check';
import { formatPoolEntry, parsePoolEntry, parsePoolText, updatePoolEntryFromProbe } from '../../../src/domain/pool-entry';
import { parseProxyTarget } from '../../../src/domain/proxy-target';
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

/** 与 main 的 CONCURRENT_CHECKS 默认值一致；每个槽位同时只占用一个 Worker 请求。 */
export const WEB_CHECK_CONCURRENCY = 32;

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

  /**
   * 与 main 的批量检测模型一致：浏览器限制并发，每个地址单独请求 Worker。
   * 单个 Worker 请求只承担一个目标的主/备探测，避免整批耗尽子请求预算。
   */
  async checkBatch(
    text: string,
    signal?: AbortSignal,
    onProgress?: (event: PoolCheckProgressEvent) => void,
  ): Promise<PoolCheckResponse> {
    const { targets, invalid } = parsePoolCheckTargets(text);
    const itemGroups: Array<readonly PoolCheckItemResponse[]> = new Array(targets.length);
    let completed = 0;
    let total = targets.length;

    await mapWithLimit(targets, WEB_CHECK_CONCURRENCY, async (target, index) => {
      if (signal?.aborted) throw new DOMException('检测已取消', 'AbortError');
      const checked = await this.checkPoolTarget(target, signal);
      itemGroups[index] = checked;
      total += checked.length - 1;
      for (const item of checked) {
        completed += 1;
        onProgress?.({ type: 'progress', completed, total, item });
      }
    });
    const items = itemGroups.flat();

    return {
      total: items.length,
      alive: items.filter((item) => item.status === 'alive').length,
      dead: items.filter((item) => item.status === 'dead').length,
      unknown: items.filter((item) => item.status === 'unknown').length,
      invalid,
      items,
    };
  }

  private async checkPoolTarget(
    target: ParsedPoolCheckTarget,
    signal?: AbortSignal,
  ): Promise<readonly PoolCheckItemResponse[]> {
    let results: CheckTargetResponse['items'] = [];
    try {
      const response = await this.checkTarget(target.target.authority, signal);
      results = Array.isArray(response.items) ? response.items : [];
    } catch (error) {
      if (signal?.aborted || (error instanceof DOMException && error.name === 'AbortError')) throw error;
      results = [{
        address: target.target.authority,
        result: {
          status: 'unknown',
          exitFamily: 'unknown',
          exits: [],
          code: error instanceof ApiError ? `HTTP_${error.status}` : 'REQUEST_FAILED',
          message: error instanceof Error ? error.message : '检测请求异常',
        },
      }];
    }
    if (results.length === 0) {
      results = [{
        address: target.target.authority,
        result: {
          status: 'unknown',
          exitFamily: 'unknown',
          exits: [],
          code: 'EMPTY_RESPONSE',
          message: '检测响应缺少目标结果',
        },
      }];
    }

    return results.map(({ address, result }) => {
      const resolvedTarget = parseProxyTarget(address, 443) ?? target.target;
      const sourceEntry = resolvedTarget.key === target.target.key
        ? target.entry
        : { ...target.entry, address: resolvedTarget.authority };
      const entry = updatePoolEntryFromProbe(sourceEntry, { ...result, target: resolvedTarget });
      const primary = result.exits[0];
      const asn = primary?.asn ?? entry.asn ?? undefined;
      const country = primary?.country ?? entry.country ?? undefined;
      return {
        address,
        status: result.status,
        exitFamily: result.exitFamily,
        ...(result.exitIp ? { exitIp: result.exitIp } : {}),
        ...(result.latencyMs === undefined ? {} : { latencyMs: result.latencyMs }),
        ...(result.code ? { code: result.code } : {}),
        ...(result.message ? { message: result.message } : {}),
        ...(asn ? { asn } : {}),
        ...(country ? { country } : {}),
        line: result.status === 'unknown' ? target.sourceLine : formatPoolEntry(entry),
      };
    });
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

interface ParsedPoolCheckTarget {
  readonly entry: NonNullable<ReturnType<typeof parsePoolEntry>>;
  readonly target: NonNullable<ReturnType<typeof parseProxyTarget>>;
  readonly sourceLine: string;
}

/** 复用池文本与地址规则，只负责把用户输入整理成逐个请求的目标。 */
function parsePoolCheckTargets(text: string): {
  readonly targets: readonly ParsedPoolCheckTarget[];
  readonly invalid: readonly string[];
} {
  const targets: ParsedPoolCheckTarget[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();
  for (const line of parsePoolText(text)) {
    if (!line.entry) {
      invalid.push(line.raw);
      continue;
    }
    const target = parseProxyTarget(line.entry.address, 443);
    if (!target) {
      invalid.push(line.entry.address);
      continue;
    }
    if (seen.has(target.key)) continue;
    seen.add(target.key);
    targets.push({ entry: line.entry, target, sourceLine: line.raw });
  }
  return { targets, invalid };
}

async function mapWithLimit<T>(
  items: readonly T[],
  limit: number,
  task: (item: T, index: number) => Promise<void>,
): Promise<void> {
  let cursor = 0;
  const workers = Array.from({ length: Math.min(Math.max(1, limit), items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      const item = items[index];
      cursor += 1;
      if (item !== undefined) await task(item, index);
    }
  });
  await Promise.all(workers);
}
