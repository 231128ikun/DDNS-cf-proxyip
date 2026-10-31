import type { DnsRecordType } from '../domain/proxy-target';

export interface DnsZone {
  readonly zoneId: string;
  readonly apiToken: string;
}

export interface DnsRecord {
  readonly id: string;
  readonly type: DnsRecordType | 'TXT';
  readonly name: string;
  readonly content: string;
}

export interface DnsRepository {
  listAddressRecords(zone: DnsZone, domain: string): Promise<readonly DnsRecord[]>;
  listTxtRecords(zone: DnsZone, domain: string): Promise<readonly DnsRecord[]>;
  addAddressRecord(zone: DnsZone, domain: string, host: string, type: DnsRecordType): Promise<DnsRecord>;
  upsertTxtRecord(zone: DnsZone, domain: string, recordId: string | null, addresses: readonly string[]): Promise<DnsRecord>;
  deleteRecord(zone: DnsZone, recordId: string): Promise<void>;
}
