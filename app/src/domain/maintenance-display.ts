import type { MaintenanceAddressCheck, MaintenanceLogLine, MaintenanceRunResult } from '../contracts/maintenance';
import type { NotifyResult } from '../contracts/notification';
import { isProbeErrorResult } from './probe-result';
import { exitFilterMatches, type ExitFilter } from './managed-target';

/** 公共维护文本只描述确认值、实际变化与异常；日志和通知共用。 */
export function maintenanceDisplayLines(result: MaintenanceRunResult): MaintenanceLogLine[] {
  const lines: MaintenanceLogLine[] = [];
  const add = (message: string, tone: MaintenanceLogLine['tone'] = 'info') => lines.push({ message, tone });
  const mode = result.mode === 'A' ? 'A/AAAA' : 'TXT';
  add(result.domain + ' (' + mode + (result.port ? ' · 检测端口 ' + result.port : '') + ')');
  if (!result.dns) {
    add('维护失败：' + (result.error ?? '未取得解析结果'), 'error');
    return lines;
  }
  const active = result.activeCount ?? 0;
  const minimum = result.minActive ?? 0;
  add('活跃 ' + active + '/' + minimum + ' · IP 池 ' + result.poolName, active < minimum ? 'warning' : 'success');
  const checks = new Map<string, MaintenanceAddressCheck>();
  for (const item of result.checks ?? []) {
    checks.set(item.value, item);
    checks.set(item.address, item);
  }
  if (!result.dns.after.length) add('解析：无');
  for (const value of result.dns.after) {
    const check = checks.get(value);
    add('解析 ' + value + (result.dns.added.includes(value) ? ' [新增]' : '') + ' · ' + checkText(check),
      check?.status === 'dead' ? 'error' : check?.status === 'alive' && check.matchesTarget && !isProbeErrorResult(check) ? 'success' : 'warning');
  }
  for (const value of result.dns.removed) {
    const check = checks.get(value);
    const reason = maintenanceRemovalReason(check, result.exitFilter);
    const diagnostic = check?.code === 'EXIT_RESTRICTED' && check.message ? ' · [EXIT_RESTRICTED] ' + check.message : '';
    add('移除 ' + value + ' · ' + reason + diagnostic, 'warning');
  }
  if (result.dnsUpdated) add('DNS 记录：新增 ' + result.added + '，移除 ' + result.deleted, 'success');
  const removed = new Set(result.dns.removed);
  for (const value of result.archivedAddresses ?? []) {
    if (!removed.has(value)) add('归档 ' + value + ' · ' + maintenanceRemovalReason(checks.get(value)), 'warning');
  }
  if (result.archived) add('归档处理 ' + result.archived + ' 个地址', 'warning');
  const candidates = result.candidates;
  if (candidates && (active < minimum || candidates.unknown > 0)) {
    add('候选检测 ' + candidates.checked + '/' + candidates.total + '，异常 ' + candidates.unknown
      + (candidates.remaining > 0 ? '，未检 ' + candidates.remaining : ''), candidates.unknown ? 'warning' : 'info');
  }
  for (const error of result.candidateErrors ?? []) add('候选异常 ' + error.count + ' 次 [' + error.code + '] ' + error.message, 'warning');
  if (active < minimum && candidates?.total === 0 && candidates.sourceCount) add('来源池 ' + candidates.sourceCount + ' 个地址，无符合端口、出口条件且未在当前 DNS 中的候选');
  if (active < minimum) add(candidates?.remaining ? '未达到最小活跃数；后续候选尚未检测' : '未达到最小活跃数', 'warning');
  for (const error of result.errors ?? (result.error ? [result.error] : [])) add('执行失败：' + error, 'error');
  const warning = hasMaintenanceWarnings(result);
  add((active < minimum ? '未完成' : warning ? '存在异常' : '完成') + '：已确认可用 ' + active + '/' + minimum
    + (result.dnsUpdated ? ' · DNS 已变更' : ' · DNS 无变化'), active < minimum || warning ? 'warning' : 'success');
  return lines;
}

export function hasMaintenanceWarnings(result: MaintenanceRunResult): boolean {
  return result.probeErrors > 0 || Boolean(result.error) || Boolean(result.errors?.length)
    || Boolean(result.candidateErrors?.length) || Boolean(result.candidates?.unknown)
    || Boolean(result.checks?.some(isProbeErrorResult));
}

function checkText(check: MaintenanceAddressCheck | undefined): string {
  if (!check) return '未确认';
  const status = check.status === 'alive' ? check.matchesTarget ? '可用' : isProbeErrorResult(check) ? '筛选未确认' : '筛选不匹配'
    : check.status === 'dead' ? '失效' : '未判定';
  return [status, maintenanceExitLabel(check), check.details,
    (check.status !== 'alive' || isProbeErrorResult(check) || check.code === 'EXIT_RESTRICTED') && check.message
      ? (check.code ? '[' + check.code + '] ' : '') + check.message : '',
  ].filter(Boolean).join(' · ');
}

export function maintenanceExitLabel(check: MaintenanceAddressCheck | undefined): string {
  if (check?.status !== 'alive') return '';
  if (check.exitFamily === 'dual') return '双栈出口';
  if (check.exitFamily !== 'ipv4' && check.exitFamily !== 'ipv6') return '';
  const family = check.exitFamily === 'ipv4' ? 'IPv4' : 'IPv6';
  return (isProbeErrorResult(check) ? '已确认 ' : '仅 ') + family + ' 出口';
}

export function maintenanceRemovalReason(check: MaintenanceAddressCheck | undefined, filter?: ExitFilter): string {
  if (check?.status === 'dead') return check.code === 'TIMEOUT' ? '检测超时' : check.message ?? '检测失效';
  if (check?.status === 'alive' && !check.matchesTarget) {
    return filter && check.exitFamily && !exitFilterMatches(check.exitFamily, filter) ? '出口栈不符合要求' : '筛选不匹配';
  }
  return '记录移除';
}

export function notificationDisplay(result: NotifyResult | null | undefined): string {
  if (!result) return '';
  if (result.sent) return '通知已发送' + (result.total && result.total > 1 ? '（' + result.total + ' 条）' : '');
  if (result.reason === 'disabled') return '通知未启用';
  if (result.reason === 'not_configured') return '通知未配置';
  return '通知发送失败' + (result.code ? ' [' + result.code + ']' : '')
    + (result.delivered ? '（已发送 ' + result.delivered + '/' + result.total + ' 条）' : '');
}
