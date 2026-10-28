import type { PoolCheckItemResponse } from '../../../src/contracts/pool-check';
import { parsePoolEntry, parsePoolText } from '../../../src/domain/pool-entry';
import { parseProxyTarget } from '../../../src/domain/proxy-target';

interface BatchSourceLine {
  readonly raw: string;
  readonly duplicate: boolean;
}

/**
 * 中断后只重跑网络未完成的源行；无法识别的行不需要网络，原样保留。
 * 重复目标与正式检测保持一致，由首次出现的源行代表。
 */
export function remainingBatchText(text: string, completed: ReadonlySet<number>): string {
  return remainingBatch(text, completed).text;
}

export function remainingBatch(
  text: string,
  completed: ReadonlySet<number>,
): { readonly text: string; readonly sourceIndices: readonly number[] } {
  const remaining = sourceLines(text)
    .map((line, index) => ({ ...line, sourceIndex: index }))
    .filter(line => !line.duplicate && !completed.has(line.sourceIndex));
  return {
    text: remaining.map(line => line.raw).join('\n'),
    sourceIndices: remaining.map(line => line.sourceIndex),
  };
}

/** 按原输入顺序合并已完成结果，未完成或无法识别的行仍保留原文。 */
export function mergeBatchProgress(
  text: string,
  groups: ReadonlyMap<number, readonly PoolCheckItemResponse[]>,
): string {
  const output: string[] = [];
  for (const [index, source] of sourceLines(text).entries()) {
    if (source.duplicate) continue;
    const items = groups.get(index);
    if (!items) {
      output.push(source.raw);
      continue;
    }
    for (const item of items) {
      if (item.status === 'alive' || item.status === 'unknown') output.push(item.line);
    }
  }
  return output.join('\n');
}

function sourceLines(text: string): readonly BatchSourceLine[] {
  const seen = new Set<string>();
  return parsePoolText(text).map((line) => {
    const entry = line.entry ?? parsePoolEntry(line.raw);
    const target = entry ? parseProxyTarget(entry.address, 443) : null;
    const duplicate = Boolean(target && seen.has(target.key));
    if (target) seen.add(target.key);
    return { raw: line.raw, duplicate };
  });
}
