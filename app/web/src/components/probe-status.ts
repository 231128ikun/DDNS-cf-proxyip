import type { ProbeResponse } from '../../../src/contracts/probe';

export function probeStatusLabel(status: ProbeResponse['status'], code?: string): string {
  if (status === 'alive') return '可用';
  if (status === 'dead') return '失效';
  if (code === 'TIMEOUT') return '未知（超时）';
  if (code === 'HTTP_ERROR') return '未知（HTTP 异常）';
  return '未知';
}
