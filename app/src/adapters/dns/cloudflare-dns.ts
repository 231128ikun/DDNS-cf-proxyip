import { dnsRecordTypeForHost, type DnsRecordType } from '../../domain/proxy-target';
import { formatTxtAddresses } from '../../domain/txt-record';
import type { DnsRecord, DnsRepository, DnsZone } from '../../ports/dns-repository';

export interface CloudflareDnsOptions {
  readonly baseUrl?: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

type JsonRecord = Record<string, unknown>;

export class CloudflareDnsRepository implements DnsRepository {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: CloudflareDnsOptions = {}) {
    this.baseUrl = (options.baseUrl ?? 'https://api.cloudflare.com/client/v4').replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async listAddressRecords(zone: DnsZone, domain: string): Promise<readonly DnsRecord[]> {
    const [a, aaaa] = await Promise.all([
      this.listRecords(zone, domain, 'A'),
      this.listRecords(zone, domain, 'AAAA'),
    ]);
    return [...a, ...aaaa];
  }

  async listTxtRecords(zone: DnsZone, domain: string): Promise<readonly DnsRecord[]> {
    return await this.listRecords(zone, domain, 'TXT');
  }

  async addAddressRecord(zone: DnsZone, domain: string, host: string, type?: DnsRecordType): Promise<DnsRecord> {
    const recordType = type ?? dnsRecordTypeForHost(host);
    const result = await this.request(zone, `/zones/${encodeURIComponent(zone.zoneId)}/dns_records`, {
      method: 'POST',
      body: JSON.stringify({ type: recordType, name: domain, content: host, ttl: 60, proxied: false }),
    });
    return parseRecord(result);
  }

  async upsertTxtRecord(zone: DnsZone, domain: string, recordId: string | null, addresses: readonly string[]): Promise<DnsRecord> {
    const body = JSON.stringify({ type: 'TXT', name: domain, content: formatTxtAddresses(addresses), ttl: 60 });
    const result = recordId
      ? await this.request(zone, `/zones/${encodeURIComponent(zone.zoneId)}/dns_records/${encodeURIComponent(recordId)}`, {
          method: 'PUT',
          body,
        })
      : await this.request(zone, `/zones/${encodeURIComponent(zone.zoneId)}/dns_records`, {
          method: 'POST',
          body,
        });
    return parseRecord(result);
  }

  async deleteRecord(zone: DnsZone, recordId: string): Promise<void> {
    await this.request(zone, `/zones/${encodeURIComponent(zone.zoneId)}/dns_records/${encodeURIComponent(recordId)}`, {
      method: 'DELETE',
    });
  }

  private async listRecords(zone: DnsZone, domain: string, type: DnsRecordType | 'TXT'): Promise<readonly DnsRecord[]> {
    const result = await this.request(
      zone,
      `/zones/${encodeURIComponent(zone.zoneId)}/dns_records?name=${encodeURIComponent(domain)}&type=${type}`,
      { method: 'GET' },
    );
    if (!Array.isArray(result)) throw new CloudflareDnsError('Cloudflare 返回的 DNS 记录格式无效');
    return result.map(parseRecord);
  }

  private async request(zone: DnsZone, path: string, init: RequestInit): Promise<unknown> {
    if (!zone.apiToken || !zone.zoneId) throw new CloudflareDnsError('Cloudflare 凭证不完整');
    const headers = new Headers(init.headers);
    headers.set('Authorization', `Bearer ${zone.apiToken}`);
    headers.set('Content-Type', 'application/json');

    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...init,
        headers,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch {
      throw new CloudflareDnsError('Cloudflare API 请求失败');
    }

    let payload: JsonRecord;
    try {
      const value = await response.json();
      if (!isRecord(value)) throw new Error('invalid response');
      payload = value;
    } catch {
      throw new CloudflareDnsError(`Cloudflare API 响应无效 (HTTP ${response.status})`);
    }

    if (!response.ok || payload.success !== true) {
      throw new CloudflareDnsError(`Cloudflare API 操作失败 (HTTP ${response.status})`);
    }
    return payload.result;
  }
}

export class CloudflareDnsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CloudflareDnsError';
  }
}

function parseRecord(value: unknown): DnsRecord {
  if (!isRecord(value)) throw new CloudflareDnsError('Cloudflare DNS 记录格式无效');
  const id = readString(value.id);
  const type = readString(value.type);
  const name = readString(value.name);
  const content = readString(value.content);
  if (!id || !type || !['A', 'AAAA', 'TXT'].includes(type) || !name || content === undefined) {
    throw new CloudflareDnsError('Cloudflare DNS 记录字段不完整');
  }
  return { id, type: type as DnsRecord['type'], name, content };
}

function readString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
