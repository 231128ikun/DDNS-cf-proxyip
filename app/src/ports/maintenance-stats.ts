import type { PoolSummary } from '../contracts/pool';

/** 一次维护运行里，各池“距上次成功通知”和“本次结束后”的数量对比。 */
export interface MaintenancePoolStats {
  readonly before: Readonly<Record<string, number>>;
  readonly after: Readonly<Record<string, number>>;
  /** 结束时的池清单，用于通知里显示名称；已删除的池会回退显示 key。 */
  readonly pools: readonly PoolSummary[];
  readonly changed: boolean;
}

/**
 * 维护通知的基线仓储。
 * `loadBaseline` 返回 null 表示还没有可用基线，调用方回退为本次维护前的实际数量。
 */
export interface MaintenanceStatsRepository {
  current(): Promise<readonly PoolSummary[]>;
  loadBaseline(): Promise<Readonly<Record<string, number>> | null>;
  saveBaseline(counts: Readonly<Record<string, number>>): Promise<void>;
}