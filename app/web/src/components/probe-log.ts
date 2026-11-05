import type { ProbeResponse } from '../../../src/contracts/probe';
import { probeStatusLabel } from './probe-status';

type ProbeLogResult = Pick<ProbeResponse, 'status' | 'code' | 'message' | 'endpoint' | 'diagnostics'>
  & Partial<Pick<ProbeResponse, 'latencyMs' | 'colo' | 'exits'>> & { readonly country?: string };

/** 单节点与批量检测共用同一份异常和复检日志文案。 */
export function formatProbeLog(result: ProbeLogResult): string {
  const label = probeStatusLabel(result.status, result.code);
  if (result.diagnostics?.length) {
    const attempts = result.diagnostics.map(item => `${item.endpoint} [${item.code ?? item.status}] ${item.message}`).join(' → ');
    return `${label}${result.endpoint ? ` · 最终接口 ${result.endpoint}` : ''} · ${attempts}`;
  }
  if (result.status === 'alive' && !result.code && !result.message) {
    const details = [result.latencyMs === undefined ? '' : `${result.latencyMs}ms`, result.colo, result.exits?.[0]?.country ?? result.country].filter(Boolean);
    return [label, ...details].join(' · ');
  }
  return `${label}${result.endpoint ? ` · 接口 ${result.endpoint}` : ''}${result.code ? ` [${result.code}]` : ''}${result.message ? ` · ${result.message}` : ''}`;
}
