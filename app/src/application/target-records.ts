import { bindingKey, normalizeBindingKey } from '../domain/domain-binding';
import { dnsRecordTypeForHost, parseProxyTarget } from '../domain/proxy-target';
import { parseTxtAddresses } from '../domain/txt-record';
import type { DnsRepository, DnsZone } from '../ports/dns-repository';
import type { MaintenanceSource, MaintenanceTargetConfig } from '../ports/maintenance-source';
import { resolveZone } from './maintain-managed-targets';
import { TargetStatusInputError } from './target-status';

export interface TargetRecordsDependencies {
  readonly source: MaintenanceSource;
  readonly dns: DnsRepository;
  readonly fallbackZone: DnsZone;
}

/** 解析出的维护目标与 Zone 凭据；add/remove 共用，避免重复实现 key→target→zone 的解析。 */
interface ResolvedTarget {
  readonly config: MaintenanceTargetConfig;
  readonly zone: DnsZone;
}

/**
 * 手动增删当前维护目标的 DNS 记录。
 * 这里是显式的用户写操作；与定时维护一样，所有写入都走同一个 DnsRepository。
 */
export class TargetRecords {
  constructor(private readonly dependencies: TargetRecordsDependencies) {}

  async add(targetKey: string, value: string): Promise<{ readonly ok: true }> {
    const { config, zone } = await this.resolve(targetKey);
    const input = value.trim();
    if (!input) throw new TargetStatusInputError('请输入要添加的 IP');

    if (config.target.mode === 'TXT') {
      const parsed = parseProxyTarget(input, 443);
      if (!parsed) throw new TargetStatusInputError('IP 地址格式无效');
      const records = await this.dependencies.dns.listTxtRecords(zone, config.target.domain);
      const existing = records[0] ? parseTxtAddresses(records[0].content) : [];
      const next = [...new Set([...existing, parsed.authority])];
      await this.dependencies.dns.upsertTxtRecord(
        zone,
        config.target.domain,
        records[0]?.id ?? null,
        next,
      );
      return { ok: true };
    }

    const parsed = parseProxyTarget(input, config.target.port ?? 443);
    if (!parsed || parsed.family === 'hostname') throw new TargetStatusInputError('请输入有效的 IP 地址');
    await this.dependencies.dns.addAddressRecord(
      zone,
      config.target.domain,
      parsed.host,
      dnsRecordTypeForHost(parsed.host),
    );
    return { ok: true };
  }

  async remove(targetKey: string, recordId: string, address?: string): Promise<{ readonly ok: true }> {
    const { config, zone } = await this.resolve(targetKey);
    if (!recordId) throw new TargetStatusInputError('缺少要删除的记录');

    if (config.target.mode === 'TXT') {
      const records = await this.dependencies.dns.listTxtRecords(zone, config.target.domain);
      const record = records.find((item) => item.id === recordId);
      if (!record) throw new TargetStatusInputError('记录不存在或已被删除');
      const next = parseTxtAddresses(record.content).filter((item) => item !== address?.trim());
      if (next.length === 0) {
        await this.dependencies.dns.deleteRecord(zone, recordId);
      } else {
        await this.dependencies.dns.upsertTxtRecord(zone, config.target.domain, recordId, next);
      }
      return { ok: true };
    }

    await this.dependencies.dns.deleteRecord(zone, recordId);
    return { ok: true };
  }

  private async resolve(targetKey: string): Promise<ResolvedTarget> {
    const key = normalizeBindingKey(targetKey);
    if (!key) throw new TargetStatusInputError('管理域名标识无效');

    const data = await this.dependencies.source.load();
    const config = data.targets.find((item) => bindingKey(item.target) === key);
    if (!config) throw new TargetStatusInputError('管理域名不存在或已被删除，请刷新后重试');
    return { config, zone: resolveZone(data.zones, config, this.dependencies.fallbackZone) };
  }
}
