import type { TargetStatusRecord, TargetStatusResponse } from '../contracts/target-status';
import type { DnsRecord, DnsRepository, DnsZone } from '../ports/dns-repository';
import type { MaintenanceSource } from '../ports/maintenance-source';
import { resolveManagedTarget } from './resolve-managed-target';

export interface TargetStatusDependencies {
  readonly source: MaintenanceSource;
  readonly dns: DnsRepository;
  /** 目标未配置 Zone 凭据时回退的顶层凭据。 */
  readonly fallbackZone: DnsZone;
}

/** 解析实况只读取当前目标的 A/AAAA 或 TXT 记录，不写 DNS。 */
export class TargetStatus {
  constructor(private readonly dependencies: TargetStatusDependencies) {}

  async execute(targetKey: string): Promise<TargetStatusResponse> {
    const { config, zone } = await resolveManagedTarget(this.dependencies.source, targetKey, this.dependencies.fallbackZone);
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
