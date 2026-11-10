import type { PoolCheckItemResponse } from '../../../src/contracts/pool-check';
import { readPoolSnapshot } from '../../../src/domain/pool-snapshot';

export function createBatchSource(text: string) {
  const snapshot = readPoolSnapshot(text);
  const firstEntries = new Map([...snapshot.entries.values()].map(item => [item.sourceIndex, item]));
  const invalid = new Set(snapshot.invalid);
  const lines = snapshot.lines.flatMap((line, sourceIndex) => {
    const item = firstEntries.get(sourceIndex);
    if (item) return [{ raw: item.raw, sourceIndex, valid: true }];
    return !line.entry || invalid.has(line.raw) ? [{ raw: line.raw, sourceIndex, valid: false }] : [];
  });
  return { text, invalid: snapshot.invalid, lines };
}

export function describeBatch(source: ReturnType<typeof createBatchSource>, groups: ReadonlyMap<number, readonly PoolCheckItemResponse[]>, completed: ReadonlySet<number>) {
  return { source: source.text, items: [...groups.values()].flat(), invalid: source.invalid,
    incomplete: source.lines.filter(line => line.valid && !completed.has(line.sourceIndex)).map(line => line.raw) };
}

/** 未完成来源整组续检；重复条目沿用首次索引及合并后的元数据。 */
export function remainingBatch(
  source: ReturnType<typeof createBatchSource>,
  completed: ReadonlySet<number>,
): { readonly text: string; readonly sourceIndices: readonly number[] } {
  const remaining = source.lines.filter(line => !completed.has(line.sourceIndex));
  return { text: remaining.map(line => line.raw).join('\n'), sourceIndices: remaining.map(line => line.sourceIndex) };
}
