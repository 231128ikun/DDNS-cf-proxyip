import { formatPoolEntry, parsePoolText, serializePoolText, type PoolLine } from './pool-entry';
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

export interface PoolCheckTextPlan {
  readonly chunks: readonly string[];
  readonly total: number;
}

/**
 * 按唯一目标地址拆分检测请求，保留原始备注和无法识别的输入用于最终汇总。
 * 服务端与 Web 客户端共用这一份规则，避免两边出现不同的分批边界。
 */
export function planPoolCheckChunks(text: string, maxTargets: number): PoolCheckTextPlan {
  const limit = Math.max(1, Math.floor(maxTargets));
  const chunks: string[] = [];
  const seen = new Set<string>();
  let lines: PoolLine[] = [];
  let count = 0;

  const flush = (): void => {
    if (lines.length === 0) return;
    chunks.push(serializePoolText(lines));
    lines = [];
    count = 0;
  };

  for (const line of parsePoolText(text)) {
    if (!line.entry) {
      lines.push(line);
      continue;
    }
    const target = parseProxyTarget(line.entry.address, 443);
    if (!target) {
      lines.push(line);
      continue;
    }
    if (seen.has(target.key)) continue;
    if (count >= limit) flush();
    seen.add(target.key);
    lines.push(line);
    count += 1;
  }
  flush();

  return { chunks, total: seen.size };
}
