import { formatPoolEntry, parsePoolText } from './pool-entry';
import { parseProxyTarget } from './proxy-target';

/**
 * 规范化 IP 池文本：丢弃无效行、统一地址写法、按地址去重。
 * 与既有 cleanIPList 行为一致——重复地址保留最后一次出现的条目。
 */
export function cleanPoolText(text: string): string {
  const entries = new Map<string, string>();

  for (const line of parsePoolText(String(text ?? ''))) {
    if (!line.entry) continue;
    const target = parseProxyTarget(line.entry.address, 443);
    if (!target) continue;
    entries.set(target.key, formatPoolEntry({ ...line.entry, address: target.authority }));
  }

  return [...entries.values()].join('\n');
}
export function countPoolTextLines(text: string): number {
  return parsePoolText(text).filter((line) => line.entry !== null).length;
}
