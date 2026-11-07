import type { PoolCheckItemResponse } from '../../../src/contracts/pool-check';
import { DEFAULT_RUNTIME_SETTINGS } from '../../../src/contracts/runtime-settings';
import type { TargetStatusRecord, TargetStatusResponse } from '../../../src/contracts/target-status';
import { formatProxyAuthority } from '../../../src/domain/proxy-target';
import { parseTxtAddresses } from '../../../src/domain/txt-record';
import type { ApiClient } from '../api/client';

/** 页面只读状态：原始 DNS 记录与现有逐地址检测结果在展示层合并。 */
export interface TargetStatusView extends TargetStatusResponse {
  readonly probes: readonly PoolCheckItemResponse[];
}

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

/** 解析实况复用逐地址调度、结果校验与取消。 */
export async function loadTargetStatus(
  client: ApiClient, key: string, port: number | 'any', signal?: AbortSignal,
  onProgress?: (status: TargetStatusView) => void,
  concurrency: number = DEFAULT_RUNTIME_SETTINGS.CONCURRENT_CHECKS,
): Promise<TargetStatusView> {
  signal?.throwIfAborted();
  const status = await client.currentStatus(key, signal);
  if (signal?.aborted) throw new DOMException('检测已取消', 'AbortError');
  onProgress?.({ ...status, probes: [] });
  const addresses = [...new Set(currentStatusRows(status, port).map((row) => row.address))];
  const probes: PoolCheckItemResponse[] = [];
  const checked = await client.checkBatch(addresses.join('\n'), signal, ({ item }) => {
    if (signal?.aborted) return;
    probes.push(item);
    onProgress?.({ ...status, probes: [...probes] });
  }, concurrency);
  signal?.throwIfAborted();
  return { ...status, probes: checked.items };
}
