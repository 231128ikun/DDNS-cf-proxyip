import type { TargetConfig } from '../../../src/contracts/config';
import { bindingKey } from '../../../src/domain/domain-binding';
import { errorMessage, isUnavailable } from '../api/errors';
import type { RequestState } from './request-state';
import type { PoolCheckItemResponse } from '../../../src/contracts/pool-check';
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

/** 解析实况全并发检测现有记录；复用批量结果校验与取消，每个请求只检测一个地址。 */
export async function loadTargetStatus(
  client: ApiClient, key: string, port: number | 'any', signal?: AbortSignal,
  onProgress?: (status: TargetStatusView) => void,
): Promise<TargetStatusView> {
  const status = await client.currentStatus(key, signal);
  if (signal?.aborted) throw new DOMException('检测已取消', 'AbortError');
  onProgress?.({ ...status, probes: [] });
  const addresses = [...new Set(currentStatusRows(status, port).map((row) => row.address))];
  const probes: PoolCheckItemResponse[] = [];
  const checked = await client.checkBatch(addresses.join('\n'), signal, ({ item }) => {
    if (signal?.aborted) return;
    probes.push(item);
    onProgress?.({ ...status, probes: [...probes] });
  }, 'all');
  return { ...status, probes: checked.items };
}

export interface TargetStatusesView {
  readonly byKey: Readonly<Record<string, RequestState<TargetStatusView>>>;
}

/** 所有管理域名同时加载，逐域名、逐地址发布结果；切换目标复用已加载状态。 */
export async function loadTargetStatuses(
  client: ApiClient, targets: readonly Pick<TargetConfig, 'domain' | 'mode' | 'port'>[], signal?: AbortSignal,
  onProgress?: (status: TargetStatusesView) => void,
): Promise<TargetStatusesView> {
  if (signal?.aborted) throw new DOMException('检测已取消', 'AbortError');
  const byKey: Record<string, RequestState<TargetStatusView>> = Object.fromEntries(targets.map(target => [bindingKey(target), { status: 'loading' }]));
  const publish = (): void => { if (!signal?.aborted) onProgress?.({ byKey: { ...byKey } }); };
  publish();
  await Promise.all(targets.map(async target => {
    const key = bindingKey(target);
    try {
      const data = await loadTargetStatus(client, key, target.port, signal, data => {
        byKey[key] = { status: 'ready', data, refreshing: true };
        publish();
      });
      if (signal?.aborted) return;
      byKey[key] = { status: 'ready', data };
    } catch (error) {
      if (signal?.aborted) return;
      byKey[key] = { status: 'error', message: errorMessage(error), unavailable: isUnavailable(error) };
    }
    publish();
  }));
  if (signal?.aborted) throw new DOMException('检测已取消', 'AbortError');
  return { byKey };
}
