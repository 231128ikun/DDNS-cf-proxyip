import { parsePoolText } from './pool-entry';
import { readPoolSnapshot, serializePoolEntries, snapshotEntries } from './pool-snapshot';

/** 规范化与去重共用池快照的有效元数据合并规则。 */
export function cleanPoolText(text: string): string {
  return serializePoolEntries(snapshotEntries(readPoolSnapshot(String(text ?? ''))));
}
export function countPoolTextLines(text: string): number {
  return parsePoolText(text).filter((line) => line.entry !== null).length;
}
