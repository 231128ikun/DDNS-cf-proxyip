import type { ProbeResponse } from '../../../src/contracts/probe';
import type { MaintenanceLogLine } from '../../../src/contracts/maintenance';
import { probeStatusLabel } from './probe-status';

type ProbeLogResult = Pick<ProbeResponse, 'status' | 'code' | 'message' | 'endpoint' | 'diagnostics'>
  & Partial<Pick<ProbeResponse, 'latencyMs' | 'colo' | 'exits'>> & { readonly country?: string };
export type ConsoleLog = (message: string, tone?: MaintenanceLogLine['tone'], detail?: string) => void;

const reasons: Readonly<Record<string, string>> = {
  TARGET_CONNECT_ERROR: 'TCP 连接失败', TARGET_TLS_ERROR: 'TLS 验证失败', TARGET_HTTP_ERROR: '候选 HTTP 异常',
  PARTIAL_EXIT: '部分出口异常', PROBE_BUDGET_EXHAUSTED: '检测预算已用尽', SUBREQUEST_LIMIT: 'Worker 子请求额度已用尽',
};

export function logProbe(log: ConsoleLog, source: string, address: string, result: ProbeLogResult): void {
  const { code, diagnostics, endpoint, latencyMs, status } = result;
  const attempts = diagnostics?.map(item => `${item.endpoint} [${item.code ?? item.status}] ${item.message}`).join(' → ');
  const tone = status === 'dead' ? 'error' : status === 'unknown' || attempts ? 'warning' : 'success';
  const detail = attempts
    ? [endpoint && '最终接口 ' + endpoint, attempts].filter(Boolean).join(' · ')
    : [endpoint && (code || result.message || status !== 'alive') && '接口 ' + endpoint + (code ? ' [' + code + ']' : ''),
      !endpoint && code && '[' + code + ']', result.message].filter(Boolean).join(' · ');
  const reason = reasons[code ?? ''] ?? (status === 'unknown' ? '检测接口异常' : attempts ? '含复检记录' : '');
  const summary = detail ? [reason]
    : [latencyMs === undefined ? '' : latencyMs + 'ms', result.colo, result.exits?.[0]?.country ?? result.country];
  log(['[' + source + '] ' + address, probeStatusLabel(status, code), ...summary].filter(Boolean).join(' · '), tone, detail || undefined);
}

export function logMaintenance(log: ConsoleLog, message: string, tone: Parameters<ConsoleLog>[1]): void {
  const diagnostic = /(?: ·)? \[([A-Z][A-Z\d_]+)\] /.exec(message);
  if (!diagnostic) return log('[维护] ' + message, tone);
  const reason = reasons[diagnostic[1]!];
  log('[维护] ' + message.slice(0, diagnostic.index) + (reason ? ' · ' + reason : ''), tone, message.slice(diagnostic.index).replace(/^ (?:· )?/, ''));
}
