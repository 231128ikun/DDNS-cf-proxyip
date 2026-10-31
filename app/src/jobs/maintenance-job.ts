import {
  shouldNotifyMaintenance,
  type MaintainManagedTargets,
  type MaintenanceRunReport,
  type MaintenanceRunSummary,
} from '../application/maintain-managed-targets';
import { buildTelegramMaintenanceMessage } from './maintenance-message';
import type { PoolSummary } from '../contracts/pool';
import type { DnsZone } from '../ports/dns-repository';
import type { MaintenanceSource } from '../ports/maintenance-source';
import type { MaintenanceStatsRepository } from '../ports/maintenance-stats';
import type { Notifier, NotifyResult } from '../ports/notifier';

export interface MaintenanceJobOptions {
  readonly source: MaintenanceSource;
  readonly maintainer: MaintainManagedTargets;
  readonly notifier: Notifier;
  readonly stats: MaintenanceStatsRepository;
  readonly fallbackZone: DnsZone;
  readonly isManual: boolean;
  readonly projectUrl?: string;
  readonly now?: () => Date;
}

export interface MaintenanceJobResult {
  readonly run: MaintenanceRunReport;
  readonly notification: NotifyResult | null;
}

/**
 * 定时与手动执行共用的维护编排入口。
 * `before` 使用距上次成功通知的基线；没有基线时回退为本次维护前的实际数量，
 * 避免首次运行误报巨大变化。只有通知成功发送后才把当前数量写回基线。
 */
export async function runMaintenanceJob(options: MaintenanceJobOptions): Promise<MaintenanceJobResult> {
  const [data, currentPools, baseline] = await Promise.all([
    options.source.load(),
    options.stats.current(),
    options.stats.loadBaseline(),
  ]);
  const beforeCounts = baseline ?? poolCounts(currentPools);

  const summary = await options.maintainer.execute(data, options.fallbackZone);
  const afterPools = await options.stats.current();
  const afterCounts = poolCounts(afterPools);
  const run: MaintenanceRunReport = {
    ...summary,
    poolStats: {
      before: beforeCounts,
      after: afterCounts,
      pools: afterPools,
      changed: poolCountsChanged(beforeCounts, afterCounts),
    },
  };

  if (!shouldNotifyMaintenance(run, options.isManual)) return { run, notification: null };

  const notification = await options.notifier.send(buildTelegramMaintenanceMessage(run, {
    isManual: options.isManual,
    ...(options.projectUrl ? { projectUrl: options.projectUrl } : {}),
    ...(options.now ? { now: options.now() } : {}),
  }));
  if (notification.sent) await options.stats.saveBaseline(afterCounts);
  return { run, notification };
}

function poolCounts(pools: readonly PoolSummary[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const pool of pools) counts[pool.key] = pool.count;
  return counts;
}

function poolCountsChanged(
  before: Readonly<Record<string, number>>,
  after: Readonly<Record<string, number>>,
): boolean {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const key of keys) {
    if ((before[key] ?? 0) !== (after[key] ?? 0)) return true;
  }
  return false;
}

export type { MaintenanceRunSummary };
