import { POOL_STATS_BASELINE_KEY } from '../../contracts/pool';
import type { PoolCatalog } from '../../ports/pool-catalog';
import type { MaintenanceStatsRepository } from '../../ports/maintenance-stats';
import { readKvJson } from './kv-json';

/** KV 里的通知基线：只在成功通知后写入，读取失败按“没有基线”处理。 */
export class KvMaintenanceStatsRepository implements MaintenanceStatsRepository {
  constructor(
    private readonly kv: KVNamespace,
    private readonly catalog: PoolCatalog,
  ) {}

  async current() {
    return await this.catalog.list();
  }

  async loadBaseline(): Promise<Readonly<Record<string, number>> | null> {
    const result = await readKvJson(this.kv, POOL_STATS_BASELINE_KEY, 60);
    if (result.status !== 'loaded') return null;

    const record = asRecord(result.value);
    if (!record) return null;

    const counts: Record<string, number> = {};
    for (const [key, value] of Object.entries(record)) {
      if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) continue;
      counts[key] = Math.trunc(value);
    }
    return Object.keys(counts).length > 0 ? counts : null;
  }

  async saveBaseline(counts: Readonly<Record<string, number>>): Promise<void> {
    await this.kv.put(POOL_STATS_BASELINE_KEY, JSON.stringify(counts));
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}