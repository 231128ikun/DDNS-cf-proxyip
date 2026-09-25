import type { MaintenanceRunSummary, TargetMaintenanceResult } from '../../application/maintain-managed-targets';
import { formatBeijingTimestamp } from '../../util/time';

export interface TelegramMaintenanceMessageOptions {
  readonly isManual: boolean;
  readonly now?: Date;
}

/** 只消费维护报告已有字段，不重新计算计划或探测结果。 */
export function buildTelegramMaintenanceMessage(
  run: MaintenanceRunSummary,
  options: TelegramMaintenanceMessageOptions,
): string {
  const title = options.isManual ? 'DDNS 手动维护报告' : 'DDNS 自动维护报告';
  const lines = [
    `${options.isManual ? '🔧' : '⚙️'} <b>${title}</b>`,
    `⏰ ${escapeHtml(formatBeijingTimestamp(options.now ?? new Date()))}`,
  ];

  if (run.errors.length > 0) lines.push(`⚠️ <b>执行错误 ${run.errors.length} 项</b>`);
  if (run.probeErrors > 0) lines.push(`⚠️ <b>检测异常 ${run.probeErrors} 次</b>，相关节点未做删除或替换`);
  if (run.results.length === 0) lines.push('没有启用中的维护目标。');

  for (const result of run.results) {
    lines.push('', `━━ <code>${escapeHtml(result.target.domain)}</code> ━━`, formatTarget(result));
  }

  return lines.join('\n');
}

function formatTarget(result: TargetMaintenanceResult): string {
  if (result.error) return `❌ 执行失败：${escapeHtml(result.error)}`;
  if (!result.report) return '❌ 没有维护报告';

  const { report } = result;
  const mode = report.target.mode === 'A' ? `A/AAAA · 端口 ${report.target.port}` : 'TXT';
  const lines = [
    `${mode} · 最小活跃数 ${report.target.minActive}`,
    `📦 使用池：<b>${escapeHtml(result.poolName)}</b>`,
    `${report.plan.exhausted ? '❌' : '✅'} 完成：${report.plan.activeCount}/${report.target.minActive}`,
  ];

  if (report.dnsUpdated) {
    lines.push(`📝 DNS 更新：新增 ${report.added}，移除 ${report.deleted}`);
  } else {
    lines.push('✨ DNS 无变化');
  }

  const additions = report.plan.additions.slice(0, 5).map(({ address }) => address);
  if (additions.length > 0) {
    lines.push(`新增候选：${additions.map((address) => `<code>${escapeHtml(address)}</code>`).join('、')}${report.plan.additions.length > additions.length ? ' …' : ''}`);
  }

  const removed = report.plan.current
    .filter(({ decision }) => decision === 'remove-dead' || decision === 'remove-mismatch')
    .slice(0, 5)
    .map(({ item }) => item.address);
  if (removed.length > 0) lines.push(`移除地址：${removed.map((address) => `<code>${escapeHtml(address)}</code>`).join('、')}`);

  if (report.plan.trash.length > 0) lines.push(`🗑️ 放入垃圾桶：${report.plan.trash.length} 个`);
  if (report.plan.exhausted) lines.push('⚠️ 候选不足，未达到最小活跃数');
  for (const error of report.errors.slice(0, 5)) lines.push(`⚠️ ${escapeHtml(error)}`);

  return lines.join('\n');
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[char] ?? char);
}