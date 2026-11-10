import { DEFAULT_POOL_KEY, TRASH_POOL_KEY, NUMBERED_POOL_KEY_RE, isPoolDataKey } from '../contracts/pool';

/** 读取旧排序时补齐有效池；严格保存仍先核对完整库存集合。 */
export function normalizePoolOrder(saved: readonly string[] | null, actualKeys: readonly string[]): readonly string[] {
  const actual = [...new Set(actualKeys.filter(isPoolDataKey))];
  const actualSet = new Set(actual);
  const fallback = [...actual].sort(comparePoolKeys);
  const normalized: string[] = [];
  for (const key of saved ?? fallback) {
    if (actualSet.has(key) && !normalized.includes(key)) normalized.push(key);
  }
  for (const key of fallback) if (!normalized.includes(key)) normalized.push(key);
  return [
    ...(actualSet.has(DEFAULT_POOL_KEY) ? [DEFAULT_POOL_KEY] : []),
    ...normalized.filter(key => key !== DEFAULT_POOL_KEY && key !== TRASH_POOL_KEY),
    ...(actualSet.has(TRASH_POOL_KEY) ? [TRASH_POOL_KEY] : []),
  ];
}

function comparePoolKeys(left: string, right: string): number {
  const rank = (key: string): number => key === DEFAULT_POOL_KEY ? 0 : key === TRASH_POOL_KEY ? 2 : 1;
  const difference = rank(left) - rank(right);
  if (difference !== 0) return difference;
  const leftNumber = NUMBERED_POOL_KEY_RE.exec(left);
  const rightNumber = NUMBERED_POOL_KEY_RE.exec(right);
  if (leftNumber && rightNumber) return Number(leftNumber[1]) - Number(rightNumber[1]);
  return left.localeCompare(right, 'zh-CN', { numeric: true });
}
