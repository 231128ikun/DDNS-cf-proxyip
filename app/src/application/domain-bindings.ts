import { getPoolFixedName, isUserPoolKey } from '../contracts/pool';
import type { DomainBindingItem, DomainBindingsResponse } from '../contracts/maintenance';
import { bindingKey, normalizeBindingKey, resolvePoolKey, sortByBindingOrder } from '../domain/domain-binding';
import type { DomainBindingRepository } from '../ports/domain-binding-repository';
import type { MaintenanceSource } from '../ports/maintenance-source';

export class DomainBindingsInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DomainBindingsInputError';
  }
}

/** 域名池绑定的读取与整体保存；维护执行仍由 MaintenanceSource 解析同一份映射。 */
export class DomainBindings {
  constructor(
    private readonly source: MaintenanceSource,
    private readonly repository: DomainBindingRepository,
  ) {}

  async list(): Promise<DomainBindingsResponse> {
    const data = await this.source.load();
    const mapping = data.poolMapping;
    const items: DomainBindingItem[] = data.targets.map(({ target, enabled }) => {
      const poolKey = resolvePoolKey(mapping, target);
      return {
        key: bindingKey(target),
        domain: target.domain,
        mode: target.mode,
        poolKey,
        poolName: data.poolNames[poolKey] || getPoolFixedName(poolKey),
        enabled,
      };
    });
    // 显示顺序只影响面板排序，不影响维护执行顺序。
    return { items: sortByBindingOrder(items, await this.repository.readOrder()) };
  }

  async save(value: unknown): Promise<void> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new DomainBindingsInputError('绑定数据格式无效');
    }

    const allowed = new Set((await this.source.load()).targets.map(({ target }) => bindingKey(target)));
    // 以现有映射为基底：面板只提交当前目标，不能顺手丢掉其他历史绑定。
    const mapping: Record<string, string> = { ...(await this.repository.read()) };
    for (const [rawKey, rawPoolKey] of Object.entries(value)) {
      const key = normalizeBindingKey(rawKey);
      if (!key || !allowed.has(key)) continue;
      const poolKey = typeof rawPoolKey === 'string' ? rawPoolKey.trim() : '';
      if (!isUserPoolKey(poolKey)) throw new DomainBindingsInputError(`IP 池 key 无效：${key}`);
      mapping[key] = poolKey;
    }
    await this.repository.write(mapping);
  }

  /** 整体保存显示顺序：提交的 key 必须与实际目标集合一致，避免面板拿旧列表覆盖。 */
  async saveOrder(value: unknown): Promise<void> {
    if (!Array.isArray(value)) throw new DomainBindingsInputError('排序数据格式无效');

    const actual = (await this.source.load()).targets.map(({ target }) => bindingKey(target));
    const actualSet = new Set(actual);
    const submitted = [...new Set(value.map((item) => (typeof item === 'string' ? item.trim() : '')).filter(Boolean))];
    if (submitted.length !== actualSet.size || submitted.some((key) => !actualSet.has(key))) {
      throw new DomainBindingsInputError('管理域名列表已变化，请刷新后重试');
    }
    await this.repository.writeOrder(submitted);
  }
}
