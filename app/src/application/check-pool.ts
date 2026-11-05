import { readPoolSnapshot, type PoolSnapshot } from '../domain/pool-snapshot';
import { parseRuntimeSetting } from '../contracts/runtime-settings';
import { updatePoolEntryFromProbe, type PoolEntry } from '../domain/pool-entry';
import { parseProxyTarget } from '../domain/proxy-target';
import type { ProbeResult } from '../domain/probe-result';
import type { ProbeContext } from '../ports/probe';
import { mapWithConcurrency } from '../util/concurrency';
import type { CheckProxy } from './check-proxy';

export interface PoolCheckItem {
  /** 规范化后的地址（含端口）。 */
  readonly address: string;
  /** 检测后合并了元数据的池条目，可直接用于入库。 */
  readonly entry: PoolEntry;
  readonly result: ProbeResult;
}

export interface PoolCheckReport {
  readonly snapshot: PoolSnapshot;
  readonly total: number;
  readonly alive: number;
  readonly dead: number;
  readonly unknown: number;
  readonly invalid: readonly string[];
  readonly items: readonly PoolCheckItem[];
}

export interface PoolCheckProgress {
  readonly item: PoolCheckItem;
  readonly completed: number;
  readonly total: number;
}

export type PoolCheckProgressHandler = (progress: PoolCheckProgress) => void;

/** 批量检测一段 IP 池文本：解析、去重、限并发检测，并返回可直接入库的结果。 */
export class CheckPoolText {
  private readonly concurrency: number;

  constructor(
    private readonly checkProxy: CheckProxy,
    concurrency?: number,
  ) {
    this.concurrency = parseRuntimeSetting('CONCURRENT_CHECKS', concurrency);
  }

  async execute(
    text: string,
    context: ProbeContext = {},
    onProgress?: PoolCheckProgressHandler,
  ): Promise<PoolCheckReport> {
    const snapshot = readPoolSnapshot(text);
    const entries = [...snapshot.entries.values()].map(item => item.entry);
    let completed = 0;
    const items = await mapWithConcurrency(entries, this.concurrency, async (entry): Promise<PoolCheckItem> => {
      context.signal?.throwIfAborted();
      const target = parseProxyTarget(entry.address) ?? parseProxyTarget(entry.address, 443);
      const address = target?.authority ?? entry.address;
      const result = await this.checkProxy.execute(address, context);
      const item = { address, entry: updatePoolEntryFromProbe(entry, result), result };
      completed += 1;
      onProgress?.({ item, completed, total: entries.length });
      return item;
    });

    return {
      snapshot,
      total: items.length,
      alive: items.filter((item) => item.result.status === 'alive').length,
      dead: items.filter((item) => item.result.status === 'dead').length,
      unknown: items.filter((item) => item.result.status === 'unknown').length,
      invalid: snapshot.invalid,
      items,
    };
  }
}
