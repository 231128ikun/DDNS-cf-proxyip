import type { MaintenanceAddressCheck, MaintenanceLogLine, MaintenanceRunResult } from '../contracts/maintenance';
import type { NotifyResult } from '../contracts/notification';

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
      check?.status === 'dead' ? 'error' : check?.status === 'alive' && check.matchesTarget && check.code !== 'PARTIAL_EXIT' ? 'success' : 'warning');
  }
  for (const value of result.dns.removed) {
    const check = checks.get(value);
    const reason = check?.status === 'dead' ? check.code === 'TIMEOUT' ? '检测超时' : '检测失效'
      : check?.status === 'alive' && !check.matchesTarget ? '筛选不匹配' : '记录移除';
    add('移除 ' + value + ' · ' + reason, 'warning');
  }
  if (result.dnsUpdated) add('DNS 记录：新增 ' + result.added + '，移除 ' + result.deleted, 'success');
  const removed = new Set(result.dns.removed);
  for (const value of result.archivedAddresses ?? []) {
    if (!removed.has(value)) add('归档 ' + value + ' · ' + removalReason(checks.get(value)), 'warning');
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
  return lines;
}

function checkText(check: MaintenanceAddressCheck | undefined): string {
  if (!check) return '未确认';
  const status = check.status === 'alive' ? check.matchesTarget ? '可用' : '筛选不匹配' : check.status === 'dead' ? '失效' : '未判定';
  return status + (check.details ? ' · ' + check.details : '')
    + ((check.status !== 'alive' || check.code === 'PARTIAL_EXIT') && check.message ? ' · ' + (check.code ? '[' + check.code + '] ' : '') + check.message : '');
}

function removalReason(check: MaintenanceAddressCheck | undefined): string {
  if (check?.status === 'dead') return check.code === 'TIMEOUT' ? '检测超时' : check.message ?? '检测失效';
  if (check?.status === 'alive' && !check.matchesTarget) return '筛选不匹配';
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
