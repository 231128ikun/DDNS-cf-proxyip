import type { ProbeResponse } from '../../../src/contracts/probe';

export function probeStatusLabel(status: ProbeResponse['status'], code?: string): string {
  if (status === 'alive') return '可用';
  if (status === 'dead') return code === 'TIMEOUT' ? '失效（超时）' : '失效';
  if (code === 'HTTP_ERROR') return '未知（HTTP 异常）';
  return '未知';
}
