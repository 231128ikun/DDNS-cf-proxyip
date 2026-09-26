import { getPoolFixedName } from '../contracts/pool';
import { resolvePoolKey } from '../domain/domain-binding';
import type { ManagedTarget } from '../domain/managed-target';
import type { DnsZone } from '../ports/dns-repository';
import type { MaintenanceSourceData, MaintenanceTargetConfig } from '../ports/maintenance-source';
import type { MaintainManagedTargetCommand, MaintenanceReport } from './maintain-managed-target';

/** 批量维护只依赖单目标用例，测试可注入桩，不需要接触 KV 或 Cloudflare。 */
export interface TargetMaintainer {
  execute(command: MaintainManagedTargetCommand): Promise<MaintenanceReport>;
}

export interface MaintainManagedTargetsDependencies {
  readonly maintainer: TargetMaintainer;
}

export interface TargetMaintenanceResult {
  readonly target: ManagedTarget;
  readonly zone: DnsZone;
  readonly poolKey: string;
  readonly poolName: string;
  readonly report: MaintenanceReport | null;
  readonly error: string | null;
}

export interface MaintenanceRunSummary {
  readonly results: readonly TargetMaintenanceResult[];
  readonly changed: boolean;
  readonly insufficient: boolean;
  readonly errors: readonly string[];
  readonly probeErrors: number;
}

export class MaintainManagedTargets {
  constructor(private readonly dependencies: MaintainManagedTargetsDependencies) {}

  async execute(data: MaintenanceSourceData, fallbackZone: DnsZone): Promise<MaintenanceRunSummary> {
    const results: TargetMaintenanceResult[] = [];

    for (const config of data.targets) {
      if (!config.enabled) continue;
      const zone = resolveZone(data.zones, config, fallbackZone);
      const poolKey = resolvePoolKey(data.poolMapping, config.target);
      const poolName = data.poolNames[poolKey] || getPoolFixedName(poolKey);

      try {
        const report = await this.dependencies.maintainer.execute({ target: config.target, zone, poolKey });
        results.push({ target: config.target, zone, poolKey, poolName, report, error: null });
      } catch (error) {
        results.push({
          target: config.target,
          zone,
          poolKey,
          poolName,
          report: null,
          error: error instanceof Error ? error.message : '维护执行失败',
        });
      }
    }

    return summarize(results);
  }
}

export function shouldNotifyMaintenance(run: MaintenanceRunSummary, isManual: boolean): boolean {
  return isManual || run.changed || run.insufficient || run.errors.length > 0 || run.probeErrors > 0;
}

function resolveZone(zones: readonly DnsZone[], config: MaintenanceTargetConfig, fallback: DnsZone): DnsZone {
  const indexed = config.zoneIndex === null ? undefined : zones[config.zoneIndex];
  return {
    apiToken: indexed?.apiToken || fallback.apiToken,
    zoneId: indexed?.zoneId || fallback.zoneId,
  };
}

function summarize(results: readonly TargetMaintenanceResult[]): MaintenanceRunSummary {
  const errors: string[] = [];
  let changed = false;
  let insufficient = false;
  let probeErrors = 0;

  for (const result of results) {
    const domain = result.target.domain;
    if (result.error) errors.push(`${domain}: ${result.error}`);
    if (!result.report) continue;

    changed ||= result.report.dnsUpdated;
    insufficient ||= result.report.plan.exhausted;
    probeErrors += result.report.probeErrors;
    for (const error of result.report.errors) errors.push(`${domain}: ${error}`);
  }

  return { results, changed, insufficient, errors, probeErrors };
}
