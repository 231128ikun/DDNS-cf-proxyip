import { maintenanceDisplayLines, notificationDisplay } from '../domain/maintenance-display';
import type { MaintenanceAddressCheck, MaintenanceRunResponse, MaintenanceRunResult } from '../contracts/maintenance';
import type { NotifyResult } from '../contracts/notification';
import { extractPoolAddressKey, isUnknownMetaValue } from '../domain/pool-entry';
import { probeMatchesTarget } from '../domain/managed-target';
import type { ProbeResult } from '../domain/probe-result';
import { createPublicTextRedactor } from '../contracts/public-text';
import type { MaintenanceRunSummary, TargetMaintenanceResult } from './maintain-managed-targets';

/** 通知、日志与 HTTP 输出共用已确认的维护数据，不把计划当作执行结果。 */
export function toMaintenanceTargetResult(result: TargetMaintenanceResult): MaintenanceRunResult {
  const { target, report, poolKey, poolName, zone } = result;
  const redact = createPublicTextRedactor([zone.apiToken, zone.zoneId]);
  const redactAddress = createPublicTextRedactor([zone.apiToken, zone.zoneId], 512);
  const errors = [result.error, ...(report?.errors ?? [])].filter((value): value is string => Boolean(value)).map(redact);
  if (!report) return { domain: target.domain, mode: target.mode, poolKey, poolName: redact(poolName), dnsUpdated: false,
    added: 0, deleted: 0, probeErrors: 0, error: errors.join('；') || '没有维护结果', errors, minActive: target.minActive };
  const before = [...new Set(report.plan.current.map(item => item.item.value))];
  const after = report.dns?.after ?? (report.dnsUpdated && !report.errors.length ? report.plan.dnsValues : before);
  const dns = report.dns ?? { before, after, added: after.filter(value => !before.includes(value)), removed: before.filter(value => !after.includes(value)) };
  const safeDns = { before: dns.before.map(redactAddress), after: dns.after.map(redactAddress), added: dns.added.map(redactAddress), removed: dns.removed.map(redactAddress) };
  const candidateErrors = new Map<string, { code: string; message: string; count: number }>();
  for (const candidate of report.candidateResults ?? []) {
    if (candidate.result.status !== 'unknown') continue;
    const code = candidate.result.code ?? 'PROBE_ERROR';
    const message = redact(candidate.result.message ?? '检测未取得结论');
    const key = code + ':' + message;
    const previous = candidateErrors.get(key);
    if (previous) previous.count++;
    else candidateErrors.set(key, { code, message, count: 1 });
  }
  const checks = new Map<string, MaintenanceAddressCheck>();
  const addCheck = (value: string, address: string, probe: ProbeResult): void => {
    const countries = [...new Set(probe.exits.map(exit => exit.country).filter((value): value is string => Boolean(value) && !isUnknownMetaValue(value)))];
    const asns = [...new Set(probe.exits.map(exit => exit.asn).filter((value): value is string => Boolean(value) && !isUnknownMetaValue(value)))];
    const details = [countries.join('/').slice(0, 60), asns.map(value => 'AS' + value.replace(/^AS/i, '')).join('/').slice(0, 80),
      probe.colo, probe.latencyMs === undefined ? undefined : '耗时 ' + probe.latencyMs + 'ms'].filter(Boolean).join(' · ');
    checks.set(redactAddress(value), { value: redactAddress(value), address: redactAddress(address), status: probe.status, matchesTarget: probeMatchesTarget(probe, target), details: redact(details),
      ...(probe.colo ? { colo: redact(probe.colo) } : {}), ...(probe.latencyMs === undefined ? {} : { latencyMs: probe.latencyMs }),
      ...(countries.length ? { country: redact(countries.join('/').slice(0, 60)) } : {}),
      ...(asns.length ? { asn: redact(asns.map(value => 'AS' + value.replace(/^AS/i, '')).join('/').slice(0, 80)) } : {}),
      ...(probe.code ? { code: probe.code } : {}), ...(probe.message ? { message: redact(probe.message) } : {}),
    });
  };
  for (const item of report.plan.current) addCheck(item.item.value, item.item.address, item.item.result);
  for (const item of report.candidateResults ?? report.plan.additions) {
    if (dns.added.includes(item.value) || item.result.status !== 'alive') addCheck(item.value, item.address, item.result);
  }
  return { domain: target.domain, mode: target.mode, poolKey, poolName: redact(poolName), dnsUpdated: report.dnsUpdated,
    added: report.added, deleted: report.deleted, probeErrors: report.probeErrors, error: errors.join('；') || null, errors,
    dns: safeDns, activeCount: report.activeCount ?? report.plan.activeCount, minActive: target.minActive,
    ...(target.port ? { port: target.port } : {}), checks: [...checks.values()],
    ...(report.candidates ? { candidates: report.candidates } : {}), candidateErrors: [...candidateErrors.values()],
    archived: report.archived ?? (report.errors.includes('写入垃圾桶失败') ? 0 : report.plan.trash.length),
    archivedAddresses: report.errors.includes('写入垃圾桶失败') ? [] : report.plan.trash.map(item => redactAddress(extractPoolAddressKey(item.entryLine))).filter(Boolean),
  };
}

export function toMaintenanceRunResponse(run: MaintenanceRunSummary, notification?: NotifyResult | null): MaintenanceRunResponse {
  const redact = createPublicTextRedactor(run.results.flatMap(result => [result.zone.apiToken, result.zone.zoneId]));
  const completed = !run.insufficient && !run.errors.length && notification?.reason !== 'failed';
  const message = run.insufficient ? '维护结束：活跃数量未达标' : run.errors.length ? '维护结束：存在执行错误'
    : notification?.reason === 'failed' ? '维护完成，通知发送失败' : run.changed ? 'DNS 已更新' : 'DNS 无需变更';
  return { ok: true, changed: run.changed, insufficient: run.insufficient, errors: run.errors.map(redact), probeErrors: run.probeErrors, completed, message,
    results: run.results.map(result => {
      const summary = toMaintenanceTargetResult(result);
      const { checks: _checks, ...fields } = summary;
      const lines = maintenanceDisplayLines(summary);
      return { ...fields, lines: lines.map(line => line.message), lineTones: lines.map(line => line.tone) };
    }), ...(notification === undefined ? {} : { notification, notificationMessage: notificationDisplay(notification) }),
  };
}
