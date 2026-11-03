import type { ProbeResponse } from '../../../src/contracts/probe';
import { probeStatusLabel } from './probe-status';

type ProbeLogResult = Pick<ProbeResponse, 'status' | 'code' | 'message' | 'endpoint' | 'diagnostics'>;

/** 单节点、批量和解析实况共用同一份异常与复检日志文案。 */
export function formatProbeLog(result: ProbeLogResult): string {
  const label = probeStatusLabel(result.status, result.code);
  if (result.diagnostics?.length) {
    const attempts = result.diagnostics.map(item => `${item.endpoint} [${item.code ?? item.status}] ${item.message}`).join(' → ');
    return `${label}${result.endpoint ? ` · 最终接口 ${result.endpoint}` : ''} · ${attempts}`;
  }
  return `${label}${result.endpoint ? ` · 接口 ${result.endpoint}` : ''}${result.code ? ` [${result.code}]` : ''}${result.message ? ` · ${result.message}` : ''}`;
}
