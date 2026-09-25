import type { MaintainManagedTargets, MaintenanceRunSummary } from '../application/maintain-managed-targets';
import { shouldNotifyMaintenance } from '../application/maintain-managed-targets';
import { buildTelegramMaintenanceMessage } from '../adapters/notify/telegram-message';
import type { DnsZone } from '../ports/dns-repository';
import type { MaintenanceSource } from '../ports/maintenance-source';
import type { Notifier, NotifyResult } from '../ports/notifier';

export interface MaintenanceJobOptions {
  readonly source: MaintenanceSource;
  readonly maintainer: MaintainManagedTargets;
  readonly notifier: Notifier;
  readonly fallbackZone: DnsZone;
  readonly isManual: boolean;
  readonly now?: () => Date;
}

export interface MaintenanceJobResult {
  readonly run: MaintenanceRunSummary;
  readonly notification: NotifyResult | null;
}

/** 定时与未来手动执行共用的维护编排入口。 */
export async function runMaintenanceJob(options: MaintenanceJobOptions): Promise<MaintenanceJobResult> {
  const data = await options.source.load();
  const run = await options.maintainer.execute(data, options.fallbackZone);
  if (!shouldNotifyMaintenance(run, options.isManual)) return { run, notification: null };

  const notification = await options.notifier.send(buildTelegramMaintenanceMessage(run, {
    isManual: options.isManual,
    ...(options.now ? { now: options.now() } : {}),
  }));
  return { run, notification };
}