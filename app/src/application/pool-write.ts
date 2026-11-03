import type { PoolContentWrite } from '../domain/pool-mutation';

/** KV 多次写入不是事务；保留已完成步骤，便于调用方准确处理部分失败。 */
export class PoolWriteError extends Error {
  constructor(readonly failedPoolKey: string, readonly completedPoolKeys: readonly string[], cause: unknown) {
    super(cause instanceof Error ? cause.message : '写入 IP 池失败', { cause });
    this.name = 'PoolWriteError';
  }
}

export async function executePoolWrites(writes: readonly PoolContentWrite[], write: (key: string, content: string) => Promise<void>): Promise<void> {
  const completed: string[] = [];
  for (const step of writes) {
    if (step.before === step.after) continue;
    try { await write(step.poolKey, step.after); }
    catch (error) { throw new PoolWriteError(step.poolKey, [...completed], error); }
    completed.push(step.poolKey);
  }
}
