import { TRASH_POOL_KEY, type CleanPoolResponse } from '../contracts/pool';
import { isRecord } from '../contracts/parse';
import { isProbeResponse } from '../contracts/probe';
import { planPoolCleaning } from '../domain/pool-mutation';
import { updatePoolEntryFromProbe } from '../domain/pool-entry';
import { readPoolSnapshot, type PoolSnapshot } from '../domain/pool-snapshot';
import { parseProxyTarget } from '../domain/proxy-target';
import type { PoolRepository } from '../ports/pool-repository';
import type { ProbeContext } from '../ports/probe';
import { PoolInputError, type PoolService } from './pool-service';


/** 普通批检负责检测；此处校验操作员提交的报告并统一写库。 */
export class CleanPool {
  constructor(
    private readonly dependencies: {
      readonly pools: PoolService;
      readonly trash: PoolRepository;
    },
  ) {}

  async execute(poolKey: string, input: unknown, context: ProbeContext = {}): Promise<CleanPoolResponse> {
    if (!isRecord(input) || typeof input.content !== 'string') throw new PoolInputError('缺少洗库快照和检测报告');
    const content = await this.dependencies.pools.read(poolKey);
    if (content !== input.content) throw new PoolInputError('检测期间库存已变化，未执行清理，请重新洗库');
    const snapshot = readPoolSnapshot(content);
    if (!snapshot.entries.size) throw new PoolInputError('池中没有有效地址，无需洗库');
    const report = readCleaningReport(input.report, snapshot);
    const plan = planPoolCleaning(poolKey, report, snapshot);
    if (plan.summary.skipped) return { ok: true, poolKey, ...plan.summary };
    context.signal?.throwIfAborted();
    if (poolKey === TRASH_POOL_KEY) {
      const restored = plan.restoreAddresses.length
        ? await this.dependencies.pools.restoreTrash(plan.restoreAddresses, true, undefined, content)
        : { restored: 0 };
      return { ok: true, poolKey, ...plan.summary, kept: restored.restored, remaining: report.dead };
    }
    // 入桶成功后才能移除原池条目，写入失败宁可保留副本。
    if (plan.trash.length) await this.dependencies.trash.addToTrash(plan.trash);
    await this.dependencies.pools.save(poolKey, plan.nextText, 'replace', undefined, content);
    return { ok: true, poolKey, ...plan.summary };
  }
}

/** 使用库存中的备注和元数据，不接受报告中的入库文本或汇总计数。 */
function readCleaningReport(value: unknown, snapshot: PoolSnapshot) {
  if (!isRecord(value) || !Array.isArray(value.items) || !Array.isArray(value.invalid)
    || value.invalid.some(item => typeof item !== 'string')) throw new PoolInputError('检测报告格式无效');
  if (value.items.length !== snapshot.entries.size || value.total !== value.items.length) throw new PoolInputError('检测报告不完整，未清理');
  const seen = new Set<string>();
  const items = value.items.map((item: unknown) => {
    if (!isRecord(item) || typeof item.address !== 'string') throw new PoolInputError('检测结果缺少有效地址');
    const target = parseProxyTarget(item.address, 443);
    if (!target) throw new PoolInputError('检测结果缺少有效地址');
    const address = target.key, source = snapshot.entries.get(address);
    if (!source || seen.has(address)) throw new PoolInputError('检测报告存在重复或库外地址，未清理');
    seen.add(address);
    const response = {...item, exits:item.exits ?? []};
    if (!isProbeResponse(response)) throw new PoolInputError('检测结果格式无效，未清理');
    const result = {...response, target};
    return {address, result, entry:updatePoolEntryFromProbe(source.entry, result)};
  });
  return {items, total:items.length, unknown:items.filter(item => item.result.status === 'unknown').length,
    dead:items.filter(item => item.result.status === 'dead').length, invalid:[...snapshot.invalid, ...value.invalid]};
}
