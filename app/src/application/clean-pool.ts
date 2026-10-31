import { TRASH_POOL_KEY, type CleanPoolResponse } from '../contracts/pool';
import { formatPoolEntry } from '../domain/pool-entry';
import type { PoolCatalog } from '../ports/pool-catalog';
import type { PoolRepository } from '../ports/pool-repository';
import type { ProbeContext } from '../ports/probe';
import type { CheckPoolText } from './check-pool';
import { PoolInputError, type PoolService } from './pool-service';


/**
 * 一键洗库用例：读池 → 批量检测 → 有效项写回，失效项进垃圾桶。
 *
 * 三条安全规则在服务端一次落地，面板不再自己拼步骤：
 * - 只要还有未确认项（探针异常或无法识别的行），整池不写回也不入桶；
 * - 只有可信探针明确判失效的条目才移入垃圾桶，垃圾桶仍只经过 `addToTrash` 一个入口；
 * - 垃圾桶洗库只做恢复，失效条目留在桶里等下一次判断。
 */
export class CleanPool {
  constructor(
    private readonly dependencies: {
      readonly pools: PoolService;
      readonly catalog: PoolCatalog;
      readonly trash: PoolRepository;
      readonly checkPool: CheckPoolText;
    },
  ) {}

  async execute(poolKey: string, context: ProbeContext = {}): Promise<CleanPoolResponse> {
    const content = await this.dependencies.catalog.read(poolKey);
    if (!content.trim()) throw new PoolInputError('池为空，无需洗库');

    const report = await this.dependencies.checkPool.execute(content, context);
    const unknown = report.unknown + report.invalid.length;
    if (unknown > 0) {
      return { ok: true, poolKey, checked: report.total, kept: 0, trashed: 0, unknown, skipped: true };
    }

    const alive = report.items.filter((item) => item.result.status === 'alive');
    const dead = report.items.filter((item) => item.result.status === 'dead');

    if (poolKey === TRASH_POOL_KEY) {
      const restored = await this.dependencies.pools.restoreTrash(alive.map((item) => item.address), true);
      return { ok: true, poolKey, checked: report.total, kept: restored.restored, trashed: 0, unknown: 0, skipped: false };
    }

    await this.dependencies.pools.save(poolKey, alive.map((item) => formatPoolEntry(item.entry)).join('\n'), 'replace');
    if (dead.length > 0) {
      await this.dependencies.trash.addToTrash(
        dead.map((item) => ({ entryLine: formatPoolEntry(item.entry), reason: '洗库失效', poolKey })),
      );
    }

    return { ok: true, poolKey, checked: report.total, kept: alive.length, trashed: dead.length, unknown: 0, skipped: false };
  }
}