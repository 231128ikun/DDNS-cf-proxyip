import { DOMAIN_POOL_MAPPING_KEY, isUserPoolKey } from '../../contracts/pool';
import type { DomainBindingRepository } from '../../ports/domain-binding-repository';
import { readKvStringRecord } from './kv-json';

/** `domain_pool_mapping` 的唯一写入口，防止无效池 key 写入 KV。 */
export class KvDomainBindingRepository implements DomainBindingRepository {
  constructor(private readonly kv: KVNamespace) {}

  async read(): Promise<Readonly<Record<string, string>>> {
    return await readKvStringRecord(this.kv, DOMAIN_POOL_MAPPING_KEY);
  }

  async write(mapping: Readonly<Record<string, string>>): Promise<void> {
    const sanitized: Record<string, string> = {};
    for (const [key, poolKey] of Object.entries(mapping)) {
      const bindingKey = key.trim();
      const normalizedPoolKey = poolKey.trim();
      if (bindingKey && isUserPoolKey(normalizedPoolKey)) sanitized[bindingKey] = normalizedPoolKey;
    }
    await this.kv.put(DOMAIN_POOL_MAPPING_KEY, JSON.stringify(sanitized));
  }
}