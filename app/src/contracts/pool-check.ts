import type { ExitFamily, ProbeExit, ProbeStatus } from '../domain/probe-result';

/** 批量检测的响应条目：只保留面板需要的字段，不回传大的原始响应。 */
export interface PoolCheckItemResponse {
  readonly address: string;
  readonly status: ProbeStatus;
  readonly exitFamily: ExitFamily;
  readonly exitIp?: string;
  readonly latencyMs?: number;
  readonly colo?: string;
  readonly exits?: readonly ProbeExit[];
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
  /** 原始逻辑行下标；续检时用它过滤已完成项。 */
  readonly sourceIndex: number;
  /** 一个源域名可能解析成多项，最后一项才表示该源行完成。 */
  readonly sourceComplete: boolean;
}
