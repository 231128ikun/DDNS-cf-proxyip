/** 按保存的 key 排序；未知 key 忽略，未列出的条目按原顺序追加。 */
export function sortByKeyOrder<T extends { readonly key: string }>(
  items: readonly T[],
  order: readonly string[],
): readonly T[] {
  if (order.length === 0) return items;
  const rank = new Map(order.map((key, index) => [key, index]));
  return [...items].sort((left, right) => (rank.get(left.key) ?? order.length) - (rank.get(right.key) ?? order.length));
}
