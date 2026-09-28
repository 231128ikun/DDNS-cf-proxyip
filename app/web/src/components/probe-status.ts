import type { ProbeResponse } from '../../../src/contracts/probe';

/** 探针状态只有三种；仪表盘徽标与配置中心自检共用同一套文案，避免两处各写一份。 */
export function probeStatusLabel(status: ProbeResponse['status']): string {
  if (status === 'alive') return '可用';
  if (status === 'dead') return '失效';
  return '未知';
}
