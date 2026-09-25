/**
 * 显式限制并发的小批量执行器。
 * Worker 里并发必须可控，避免打满子请求配额和 CPU 时间；维护与批量检测共用这一份实现。
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  task: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(Math.max(1, limit), items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      const item = items[index];
      if (item !== undefined) results[index] = await task(item, index);
    }
  });
  await Promise.all(workers);
  return results;
}