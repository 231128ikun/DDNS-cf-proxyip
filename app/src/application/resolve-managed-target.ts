import { bindingKey, normalizeBindingKey } from '../domain/domain-binding';
import type { DnsZone } from '../ports/dns-repository';
import type { MaintenanceSource, MaintenanceTargetConfig } from '../ports/maintenance-source';
import { resolveZone } from './maintain-managed-targets';

export class TargetStatusInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TargetStatusInputError';
  }
}

/** 实况读取与人工增删共用目标定位，读写规则仍由各自用例负责。 */
export async function resolveManagedTarget(source: MaintenanceSource, targetKey: string, fallbackZone: DnsZone): Promise<{
  readonly config: MaintenanceTargetConfig;
  readonly zone: DnsZone;
}> {
  const key = normalizeBindingKey(targetKey);
  if (!key) throw new TargetStatusInputError('管理域名标识无效');
  const data = await source.load();
  const config = data.targets.find(item => bindingKey(item.target) === key);
  if (!config) throw new TargetStatusInputError('管理域名不存在或已被删除，请刷新后重试');
  return { config, zone: resolveZone(data.zones, config, fallbackZone) };
}
