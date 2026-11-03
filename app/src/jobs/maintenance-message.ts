import type { MaintenanceRunReport } from '../application/maintain-managed-targets';
import { toMaintenanceTargetResult } from '../application/maintenance-summary';
import { maintenanceDisplayLines } from '../domain/maintenance-display';
import { createPublicTextRedactor } from '../contracts/public-text';
import { formatBeijingTimestamp } from '../util/time';

export interface TelegramMaintenanceMessageOptions {
  readonly isManual: boolean;
  readonly projectUrl?: string;
  readonly now?: Date;
}

/** 完整列出各域名确认的解析地址；长报告由通知适配器分段，不省略地址。 */
export function buildTelegramMaintenanceMessage(run: MaintenanceRunReport, options: TelegramMaintenanceMessageOptions): string {
  const title = options.isManual ? 'DDNS 手动维护报告' : 'DDNS 自动维护报告';
  const lines = ['<b>' + title + '</b>', '时间：' + formatBeijingTimestamp(options.now ?? new Date())];
  if (run.errors.length) lines.push('执行错误 ' + run.errors.length + ' 项');
  if (run.probeErrors) lines.push('检测异常 ' + run.probeErrors + ' 次（未计为失效）');
  if (!run.results.length) lines.push('没有启用的维护目标');
  for (const result of run.results) {
    const summary = toMaintenanceTargetResult(result);
    const [heading, ...details] = maintenanceDisplayLines(summary);
    const escapedDomain = escapeHtml(summary.domain);
    lines.push('', escapeHtml(heading!).replace(escapedDomain, '<code>' + escapedDomain + '</code>'), ...details.map(escapeHtml));
  }
  const used = new Set(run.results.map(result => result.poolKey));
  const redact = createPublicTextRedactor(run.results.flatMap(result => [result.zone.apiToken, result.zone.zoneId]));
  const keys = [...new Set([...Object.keys(run.poolStats.before), ...Object.keys(run.poolStats.after)])]
    .filter(key => used.has(key) || (run.poolStats.before[key] ?? 0) !== (run.poolStats.after[key] ?? 0));
  if (keys.length) lines.push('', 'IP 池库存（本次读取）');
  const names = new Map(run.poolStats.pools.map(pool => [pool.key, pool.name]));
  for (const key of keys) {
    const before = run.poolStats.before[key] ?? 0;
    const after = run.poolStats.after[key] ?? 0;
    lines.push(escapeHtml(redact(names.get(key) ?? key)) + '：' + after + (after !== before ? '（' + before + ' → ' + after + '）' : ''));
  }
  if (options.isManual && options.projectUrl) {
    try {
      const url = new URL(options.projectUrl);
      if (['https:', 'http:'].includes(url.protocol)) lines.push('', '<a href="' + escapeHtml(url.origin) + '">打开管理面板</a>');
    } catch { /* 无效链接不进入公开通知。 */ }
  }
  return lines.join('\n');
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char] ?? char);
}
