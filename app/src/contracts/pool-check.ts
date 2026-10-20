import type { ExitFamily, ProbeStatus } from '../domain/probe-result';

/** 批量检测的响应条目：只保留面板需要的字段，不回传大的原始响应。 */
export interface PoolCheckItemResponse {
  readonly address: string;
  readonly status: ProbeStatus;
  readonly exitFamily: ExitFamily;
  readonly exitIp?: string;
  readonly latencyMs?: number;
  readonly code?: string;
  readonly message?: string;
  readonly asn?: string;
  readonly country?: string;
  /** 已合并检测元数据、可直接入库的池条目文本。 */
  readonly line: string;
}

export interface PoolCheckResponse {
  readonly total: number;
  readonly alive: number;
  readonly dead: number;
  readonly unknown: number;
  readonly invalid: readonly string[];
  readonly items: readonly PoolCheckItemResponse[];
}

export interface PoolCheckProgressEvent {
  readonly type: 'progress';
  readonly completed: number;
  readonly total: number;
  readonly item: PoolCheckItemResponse;
}

export interface PoolCheckCompleteEvent {
  readonly type: 'complete';
  readonly report: PoolCheckResponse;
}

export interface PoolCheckErrorEvent {
  readonly type: 'error';
  readonly error: string;
}

export type PoolCheckStreamEvent = PoolCheckProgressEvent | PoolCheckCompleteEvent | PoolCheckErrorEvent;

export interface CheckPoolRequest {
  readonly text: string;
}
