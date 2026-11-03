import type { TargetStatusResponse } from '../../../src/contracts/target-status';
import { parseProxyTarget } from '../../../src/domain/proxy-target';
import { parseTxtAddresses } from '../../../src/domain/txt-record';
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

export function shouldLogProbe(result: ProbeLogResult): boolean {
  return result.status !== 'alive' || Boolean(result.diagnostics?.length) || result.code === 'PARTIAL_EXIT';
}

export function formatDnsSnapshot(status: TargetStatusResponse): string {
  const values: string[] = [];
  let invalid = 0;
  for (const record of status.records) {
    const addresses = record.type === 'TXT' ? parseTxtAddresses(record.content) : [record.content];
    for (const address of addresses) {
      const parsed = parseProxyTarget(address);
      if (!parsed || (record.type === 'A' && parsed.family !== 'ipv4') || (record.type === 'AAAA' && parsed.family !== 'ipv6')) { invalid++; continue; }
      values.push(record.type + ' ' + (record.type === 'TXT' ? parsed.authority : parsed.host));
    }
  }
  const text = status.domain + ' (' + (status.mode === 'A' ? 'A/AAAA' : 'TXT') + ')：' + ([...new Set(values)].join('、') || '无解析地址')
    + (invalid ? '；无效记录 ' + invalid : '');
  return text.replace(/\b[a-f0-9]{32}\b/gi, '[resource-id]');
}
