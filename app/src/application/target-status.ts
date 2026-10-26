import type { TargetStatusRecord, TargetStatusResponse } from '../contracts/target-status';
import { bindingKey, normalizeBindingKey } from '../domain/domain-binding';
import type { DnsRecord, DnsRepository, DnsZone } from '../ports/dns-repository';
import type { MaintenanceSource } from '../ports/maintenance-source';
import { resolveZone } from './maintain-managed-targets';

export interface TargetStatusDependencies {
  readonly source: MaintenanceSource;
  readonly dns: DnsRepository;
  /** 目标未配置 Zone 凭据时回退的顶层凭据。 */
  readonly fallbackZone: DnsZone;
}

export class TargetStatusInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TargetStatusInputError';
  }
}

/**
 * “解析实况”的只读数据来源：按域名池绑定 key 找到维护目标，
 * 读取其当前 A/AAAA 或 TXT 记录；此用例不写 DNS。
 */
export class TargetStatus {
  constructor(private readonly dependencies: TargetStatusDependencies) {}

  async execute(targetKey: string): Promise<TargetStatusResponse> {
    const key = normalizeBindingKey(targetKey);
    if (!key) throw new TargetStatusInputError('管理域名标识无效');

    const data = await this.dependencies.source.load();
    const config = data.targets.find((item) => bindingKey(item.target) === key);
    if (!config) throw new TargetStatusInputError('管理域名不存在或已被删除，请刷新后重试');

    const zone = resolveZone(data.zones, config, this.dependencies.fallbackZone);
    const records = config.target.mode === 'TXT'
      ? await this.dependencies.dns.listTxtRecords(zone, config.target.domain)
      : await this.dependencies.dns.listAddressRecords(zone, config.target.domain);

    return {
      ok: true,
      domain: config.target.domain,
      mode: config.target.mode,
      records: records.map(toStatusRecord),
    };
  }
}

function toStatusRecord(record: DnsRecord): TargetStatusRecord {
  return {
    id: record.id,
    type: record.type,
    name: record.name,
    content: record.content,
  };
}
