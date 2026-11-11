import type { NotifyResult } from './notification';
import type { ExitFamily, ProbeStatus } from '../domain/probe-result';
import type { ExitFilter, TargetMode } from '../domain/managed-target';
import { isRecord } from './parse';
import { readJsonStream, JSON_STREAM_TYPE } from './json-stream';

export interface DomainBindingItem {
  readonly key: string;
  readonly domain: string;
  readonly mode: TargetMode;
  readonly poolKey: string;
  readonly poolName: string;
  readonly enabled: boolean;
}

export interface DomainBindingsResponse {
  readonly items: readonly DomainBindingItem[];
}

export interface SaveDomainBindingsRequest {
  readonly mapping: Readonly<Record<string, string>>;
}

/** 域名池绑定的显示顺序；只影响面板排序，不影响维护执行顺序。 */
export interface SaveDomainBindingOrderRequest {
  readonly order: readonly string[];
}

export interface MaintenanceDnsState {
  readonly before: readonly string[];
  readonly after: readonly string[];
  readonly added: readonly string[];
  readonly removed: readonly string[];
}

export interface MaintenanceCandidateStats {
  readonly total: number;
  readonly checked: number;
  readonly unknown: number;
  readonly remaining: number;
  readonly sourceCount?: number;
}

export interface MaintenanceAddressCheck {
  readonly value: string;
  readonly address: string;
  readonly status: ProbeStatus;
  readonly matchesTarget: boolean;
  readonly exitFamily?: ExitFamily;
  readonly details: string;
  readonly colo?: string;
  readonly latencyMs?: number;
  readonly country?: string;
  readonly asn?: string;
  readonly code?: string;
  readonly message?: string;
}

export interface MaintenanceLogLine {
  readonly tone: 'info' | 'success' | 'warning' | 'error';
  readonly message: string;
  readonly targetKey?: string;
}

export const MAINTENANCE_STREAM_TYPE = JSON_STREAM_TYPE;

/** 浏览器和内部目标调用共用帧解析；读入来源和取消由调用方负责。 */
export async function readMaintenanceStreamResult<Result>(
  read: () => Promise<{ done: boolean; value?: Uint8Array | undefined }>,
  onProgress: (line: MaintenanceLogLine) => void,
  isResult: (value: unknown) => value is Result,
): Promise<{ result: Result } | { message: string; remote: boolean }> {
  return await readJsonStream<{ result: Result } | { message: string; remote: boolean }>(read, event => {
    if (!isRecord(event)) return undefined;
    if (event.type === 'progress') {
      const line = event.line;
      if (!isRecord(line) || typeof line.message !== 'string' || !['info', 'success', 'warning', 'error'].includes(String(line.tone))) {
        throw new SyntaxError('维护进度格式无效');
      }
      onProgress(line as unknown as MaintenanceLogLine);
    } else if (event.type === 'result' && isResult(event.result)) return { result: event.result };
    else if (event.type === 'error' && typeof event.message === 'string') return { message: event.message, remote: true };
    return undefined;
  }) ?? { message: '维护响应提前结束', remote: false };
}

export interface MaintenanceRunResult {
  readonly domain: string;
  readonly mode: TargetMode;
  readonly exitFilter?: ExitFilter;
  readonly poolKey: string;
  readonly poolName: string;
  readonly dnsUpdated: boolean;
  readonly added: number;
  readonly deleted: number;
  readonly probeErrors: number;
  readonly error: string | null;
  readonly errors?: readonly string[];
  readonly dns?: MaintenanceDnsState;
  readonly activeCount?: number;
  readonly minActive?: number;
  readonly port?: number;
  readonly checks?: readonly MaintenanceAddressCheck[];
  readonly candidates?: MaintenanceCandidateStats;
  readonly candidateErrors?: readonly { readonly code: string; readonly message: string; readonly count: number }[];
  readonly archived?: number;
  readonly archivedAddresses?: readonly string[];
  readonly lines?: readonly string[];
  readonly lineTones?: readonly MaintenanceLogLine['tone'][];
}

export interface MaintenanceRunResponse {
  readonly ok: true;
  readonly changed: boolean;
  readonly insufficient: boolean;
  readonly errors: readonly string[];
  readonly probeErrors: number;
  readonly results: readonly MaintenanceRunResult[];
  readonly notification?: NotifyResult | null;
  readonly notificationMessage?: string;
  readonly message?: string;
  readonly completed?: boolean;
}
