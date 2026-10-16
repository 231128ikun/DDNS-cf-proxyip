import type { ProbeResponse } from '../../../src/contracts/probe';

/** 探针状态只有三种；需要展示时统一走这里，避免多处各写一套文案。 */
export function probeStatusLabel(status: ProbeResponse['status']): string {
  if (status === 'alive') return '可用';
  if (status === 'dead') return '失效';
  return '未知';
}
