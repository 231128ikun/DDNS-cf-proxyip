import type { PoolCheckItemResponse } from '../../../src/contracts/pool-check';
import type { TargetStatusRecord, TargetStatusResponse } from '../../../src/contracts/target-status';
import { formatProxyAuthority } from '../../../src/domain/proxy-target';
import { parseTxtAddresses } from '../../../src/domain/txt-record';
import type { ApiClient } from '../api/client';

/** 页面只读状态：原始 DNS 记录与现有逐地址检测结果在展示层合并。 */
export interface TargetStatusView extends TargetStatusResponse {
  readonly probes: readonly PoolCheckItemResponse[];
}

// 自动刷新只检测有界的一批记录；其余地址仍可见，显示“未检测”。
export const MAX_CURRENT_STATUS_PROBES = 200;

export function currentStatusRows(status: TargetStatusResponse, port: number | 'any'): readonly {
  readonly record: TargetStatusRecord;
  readonly address: string;
}[] {
  return status.records.flatMap((record) => {
    const addresses = record.type === 'TXT' ? parseTxtAddresses(record.content)
      : [formatProxyAuthority(record.content, port === 'any' ? 443 : port)];
    return addresses.map((address) => ({ record, address }));
  });
}

/** 复用批量检测的并发、取消和 unknown 处理，每个 Worker 请求仍只检测一个地址。 */
export async function loadTargetStatus(
  client: ApiClient, key: string, port: number | 'any', signal?: AbortSignal, concurrency?: number,
): Promise<TargetStatusView> {
  const status = await client.currentStatus(key, signal);
  const addresses = [...new Set(currentStatusRows(status, port).map((row) => row.address))].slice(0, MAX_CURRENT_STATUS_PROBES);
  const checked = await client.checkBatch(addresses.join('\n'), signal, undefined, concurrency);
  return { ...status, probes: checked.items };
}
