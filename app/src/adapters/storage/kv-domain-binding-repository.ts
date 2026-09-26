import { DOMAIN_POOL_MAPPING_KEY, DOMAIN_POOL_ORDER_KEY, isUserPoolKey } from '../../contracts/pool';
import { normalizeBindingKey } from '../../domain/domain-binding';
import type { DomainBindingRepository } from '../../ports/domain-binding-repository';
import { readKvStringRecord } from './kv-json';

/** `domain_pool_mapping` / `domain_pool_order` 的唯一写入口，防止无效数据写入 KV。 */
export class KvDomainBindingRepository implements DomainBindingRepository {
  constructor(private readonly kv: KVNamespace) {}

  async read(): Promise<Readonly<Record<string, string>>> {
    return await readKvStringRecord(this.kv, DOMAIN_POOL_MAPPING_KEY);
  }

  async write(mapping: Readonly<Record<string, string>>): Promise<void> {
    const sanitized: Record<string, string> = {};
    for (const [rawKey, rawPoolKey] of Object.entries(mapping)) {
      const key = normalizeBindingKey(rawKey);
      const poolKey = rawPoolKey.trim();
      if (key && isUserPoolKey(poolKey)) sanitized[key] = poolKey;
    }
    await this.kv.put(DOMAIN_POOL_MAPPING_KEY, JSON.stringify(sanitized));
  }

  async readOrder(): Promise<readonly string[]> {
    const raw = await this.kv.get(DOMAIN_POOL_ORDER_KEY, { type: 'json' }).catch(() => null);
    return toBindingOrder(raw);
  }

  async writeOrder(order: readonly string[]): Promise<void> {
    await this.kv.put(DOMAIN_POOL_ORDER_KEY, JSON.stringify(toBindingOrder(order)));
  }
}

/** 顺序只保存合法 key 列表：坏数据按空顺序处理，读取方再按实际目标补齐。 */
function toBindingOrder(value: unknown): readonly string[] {
  if (!Array.isArray(value)) return [];
  const order: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string') continue;
    const key = normalizeBindingKey(item);
    if (key && !order.includes(key)) order.push(key);
  }
  return order;
}
