import { TRASH_POOL_KEY, type CleanPoolResponse } from '../contracts/pool';
import { planPoolCleaning } from '../domain/pool-mutation';
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
 * - 可信探针明确判失效或检测超时的条目移入垃圾桶，垃圾桶仍只经过 `addToTrash` 一个入口；
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
    const plan = planPoolCleaning(poolKey, report);
    if (plan.summary.skipped) return { ok: true, poolKey, ...plan.summary };
    if (poolKey === TRASH_POOL_KEY) {
      const restored = plan.restoreAddresses.length
        ? await this.dependencies.pools.restoreTrash(plan.restoreAddresses, true)
        : { restored: 0 };
      return { ok: true, poolKey, ...plan.summary, kept: restored.restored };
    }
    // 入桶成功后才能移除原池条目，写入失败宁可保留副本。
    if (plan.trash.length) await this.dependencies.trash.addToTrash(plan.trash);
    await this.dependencies.pools.save(poolKey, plan.nextText, 'replace');
    return { ok: true, poolKey, ...plan.summary };
  }
}
