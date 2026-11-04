import type { MaintenanceRunReport } from '../application/maintain-managed-targets';
import { toMaintenanceTargetResult } from '../application/maintenance-summary';
import type { MaintenanceAddressCheck, MaintenanceRunResult } from '../contracts/maintenance';
import { createPublicTextRedactor } from '../contracts/public-text';
import { formatBeijingTimestamp } from '../util/time';

export interface TelegramMaintenanceMessageOptions {
  readonly isManual: boolean;
  readonly projectUrl?: string;
  readonly now?: Date;
}

/** 完整列出各域名确认的解析地址；长报告由通知适配器按完整行分段。 */
export function buildTelegramMaintenanceMessage(run: MaintenanceRunReport, options: TelegramMaintenanceMessageOptions): string {
  const title = options.isManual ? 'DDNS 手动维护报告' : 'DDNS 自动维护报告';
  const lines = [
    (options.isManual ? '🔧' : '⚙️') + ' <b>' + title + '</b>',
    '⏰ ' + formatBeijingTimestamp(options.now ?? new Date()),
  ];
  if (run.errors.length) lines.push('⚠️ 执行错误 ' + run.errors.length + ' 项');
  if (run.probeErrors) lines.push('⚠️ 检测异常 ' + run.probeErrors + ' 次（未计为失效）');
  if (!run.results.length) lines.push('', '没有启用的维护目标');
  for (const result of run.results) lines.push('', ...formatTarget(toMaintenanceTargetResult(result)));

  const used = new Set(run.results.map(result => result.poolKey));
  const redact = createPublicTextRedactor(run.results.flatMap(result => [result.zone.apiToken, result.zone.zoneId]));
  const keys = [...new Set([...Object.keys(run.poolStats.before), ...Object.keys(run.poolStats.after)])]
    .filter(key => used.has(key) || (run.poolStats.before[key] ?? 0) !== (run.poolStats.after[key] ?? 0));
  if (keys.length) lines.push('', '📦 <b>IP 池库存</b>');
  const names = new Map(run.poolStats.pools.map(pool => [pool.key, pool.name]));
  for (const key of keys) {
    const before = run.poolStats.before[key] ?? 0;
    const after = run.poolStats.after[key] ?? 0;
    lines.push('• ' + escapeHtml(redact(names.get(key) ?? key)) + '：' + after + (after !== before ? '（' + before + ' → ' + after + '）' : ''));
  }
  if (options.isManual && options.projectUrl) {
    try {
      const url = new URL(options.projectUrl);
      if (['https:', 'http:'].includes(url.protocol)) lines.push('', '🔗 <a href="' + escapeHtml(url.origin) + '">打开管理面板</a>');
    } catch { /* 无效链接不进入公开通知。 */ }
  }
  return lines.join('\n');
}

function formatTarget(result: MaintenanceRunResult): string[] {
  const mode = result.mode === 'A' ? 'A/AAAA' + (result.port ? ' · 端口 ' + result.port : '') : 'TXT';
  const lines = ['<b>' + escapeHtml(result.domain) + '</b>', mode + ' · 最小活跃数 ' + (result.minActive ?? 0),
    '📦 使用池：<b>' + escapeHtml(result.poolName) + '</b>'];
  if (!result.dns) {
    lines.push('❌ 维护失败：' + escapeHtml(result.error ?? '未取得解析结果'));
    return lines;
  }
  const active = result.activeCount ?? 0;
  const minimum = result.minActive ?? 0;
  lines.push((active >= minimum ? '✅' : '⚠️') + ' 活跃：' + active + '/' + minimum, '', '📍 <b>当前解析</b>');
  const checks = new Map<string, MaintenanceAddressCheck>();
  for (const item of result.checks ?? []) {
    checks.set(item.value, item);
    checks.set(item.address, item);
  }
  if (!result.dns.after.length) lines.push('• 无解析地址');
  for (const value of result.dns.after) {
    const check = checks.get(value);
    const icon = check?.status === 'alive' && check.matchesTarget ? '✅' : check?.status === 'dead' ? '❌' : '⚠️';
    lines.push(icon + ' <code>' + escapeHtml(value) + '</code>' + (result.dns.added.includes(value) ? ' [新增]' : ''));
    const detail = checkDetails(check);
    if (detail) lines.push('   ' + escapeHtml(detail));
  }
  if (result.dns.removed.length) lines.push('', '📉 <b>移除 ' + result.dns.removed.length + ' 个地址</b>');
  for (const value of result.dns.removed) {
    const check = checks.get(value);
    lines.push('❌ <code>' + escapeHtml(value) + '</code> · ' + escapeHtml(removalReason(check)));
  }
  if (result.dnsUpdated) lines.push('📝 DNS 更新：新增 ' + result.added + '，移除 ' + result.deleted);
  const removed = new Set(result.dns.removed);
  for (const value of result.archivedAddresses ?? []) {
    if (!removed.has(value)) lines.push('🗑️ <code>' + escapeHtml(value) + '</code> · ' + escapeHtml(removalReason(checks.get(value))));
  }
  if (result.archived) lines.push('🗑️ 归档 ' + result.archived + ' 个地址');
  const candidates = result.candidates;
  if (candidates && (active < minimum || candidates.unknown)) {
    lines.push('🔎 候选检测：' + candidates.checked + '/' + candidates.total + '，异常 ' + candidates.unknown
      + (candidates.remaining ? '，未检 ' + candidates.remaining : ''));
  }
  for (const error of result.candidateErrors ?? []) lines.push('⚠️ 候选异常 ' + error.count + ' 次 [' + escapeHtml(error.code) + '] ' + escapeHtml(error.message));
  if (active < minimum && candidates?.total === 0 && candidates.sourceCount) {
    lines.push('⚠️ 来源池 ' + candidates.sourceCount + ' 个地址，无符合条件的候选');
  }
  if (active < minimum) lines.push('⚠️ 未达到最小活跃数' + (candidates?.remaining ? '，后续候选尚未检测' : ''));
  for (const error of result.errors ?? (result.error ? [result.error] : [])) lines.push('⚠️ 执行失败：' + escapeHtml(error));
  return lines;
}

function checkDetails(check: MaintenanceAddressCheck | undefined): string {
  if (!check) return '未确认';
  const status = check.status === 'alive' ? check.matchesTarget ? '可用' : '筛选不匹配'
    : check.status === 'dead' ? '失效' : '未判定';
  const details = check.details?.replace(/耗时 (?=\d+(?:\.\d+)?ms$)/, '') ?? '';
  const label = check.status === 'alive' && check.matchesTarget && details ? '' : status;
  return label + (details ? (label ? ' · ' : '') + details : '')
    + (check.status !== 'alive' && check.message ? ' · ' + (check.code ? '[' + check.code + '] ' : '') + check.message : '');
}

function removalReason(check: MaintenanceAddressCheck | undefined): string {
  if (check?.status === 'dead') return check.code === 'TIMEOUT' ? '检测超时' : check.message ?? '检测失效';
  if (check?.status === 'alive' && !check.matchesTarget) return '筛选不匹配';
  return '记录移除';
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char] ?? char);
}
