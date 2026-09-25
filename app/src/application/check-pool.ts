import { parsePoolText, updatePoolEntryFromProbe, type PoolEntry } from '../domain/pool-entry';
import { parseProxyTarget } from '../domain/proxy-target';
import type { ProbeResult } from '../domain/probe-result';
import type { ProbeContext } from '../ports/probe';
import { mapWithConcurrency } from '../util/concurrency';
import type { CheckProxy } from './check-proxy';

/** 单次批量检测的目标上限，用来兜住 Worker 子请求与 CPU 预算。 */
export const MAX_BATCH_TARGETS = 200;

export interface PoolCheckItem {
  /** 规范化后的地址（含端口）。 */
  readonly address: string;
  /** 检测后合并了元数据的池条目，可直接用于入库。 */
  readonly entry: PoolEntry;
  readonly result: ProbeResult;
}

export interface PoolCheckReport {
  readonly total: number;
  readonly alive: number;
  readonly dead: number;
  readonly unknown: number;
  readonly invalid: readonly string[];
  readonly items: readonly PoolCheckItem[];
}

/** 批量检测一段 IP 池文本：解析、去重、限并发检测，并返回可直接入库的结果。 */
export class CheckPoolText {
  private readonly concurrency: number;

  constructor(
    private readonly checkProxy: CheckProxy,
    concurrency = 8,
  ) {
    this.concurrency = Math.max(1, Math.min(16, concurrency));
  }

  async execute(text: string, context: ProbeContext = {}): Promise<PoolCheckReport> {
    const { entries, invalid } = collectEntries(text);
    const items = await mapWithConcurrency(entries, this.concurrency, async (entry): Promise<PoolCheckItem> => {
      const target = parseProxyTarget(entry.address) ?? parseProxyTarget(entry.address, 443);
      const address = target?.authority ?? entry.address;
      const result = await this.checkProxy.execute(address, context);
      return { address, entry: updatePoolEntryFromProbe(entry, result), result };
    });

    return {
      total: items.length,
      alive: items.filter((item) => item.result.status === 'alive').length,
      dead: items.filter((item) => item.result.status === 'dead').length,
      unknown: items.filter((item) => item.result.status === 'unknown').length,
      invalid,
      items,
    };
  }
}

function collectEntries(text: string): { entries: readonly PoolEntry[]; invalid: readonly string[] } {
  const entries: PoolEntry[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();

  for (const line of parsePoolText(text)) {
    if (!line.raw.trim()) continue;
    if (!line.entry) {
      invalid.push(line.raw.trim());
      continue;
    }
    if (entries.length >= MAX_BATCH_TARGETS) break;
    const target = parseProxyTarget(line.entry.address);
    if (!target) {
      invalid.push(line.entry.address);
      continue;
    }
    if (seen.has(target.key)) continue;
    seen.add(target.key);
    entries.push(line.entry);
  }

  return { entries, invalid };
}