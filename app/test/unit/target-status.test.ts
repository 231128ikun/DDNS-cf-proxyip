import { describe, expect, it } from 'vitest';
import { TargetStatus, TargetStatusInputError } from '../../src/application/target-status';
import type { DnsRecord, DnsRepository, DnsZone } from '../../src/ports/dns-repository';
import type { MaintenanceSource, MaintenanceSourceData } from '../../src/ports/maintenance-source';

function source(data: MaintenanceSourceData): MaintenanceSource {
  return { load: async () => data };
}

function dns(records: readonly DnsRecord[] = []): DnsRepository {
  return {
    listAddressRecords: async () => records,
    listTxtRecords: async () => records,
    addAddressRecord: async () => ({ id: 'new', type: 'A', name: 'a.example.com', content: '203.0.113.1' }),
    upsertTxtRecord: async () => ({ id: 'txt', type: 'TXT', name: 'a.example.com', content: '"203.0.113.1:443"' }),
    deleteRecord: async () => undefined,
  };
}

const fallbackZone: DnsZone = { zoneId: 'zone-fallback', apiToken: 'token-fallback' };

const data: MaintenanceSourceData = {
  zones: [{ zoneId: 'zone-a', apiToken: 'token-a' }],
  targets: [
    {
      target: { mode: 'A', domain: 'a.example.com', port: 443, minActive: 1, exitFilter: 'any', countries: [], asns: [] },
      zoneIndex: 0,
      enabled: true,
    },
  ],
  poolMapping: {},
  poolNames: {},
};

describe('TargetStatus', () => {
  it('lists address records for an A/AAAA target without leaking credentials', async () => {
    const records: DnsRecord[] = [
      { id: 'r1', type: 'A', name: 'a.example.com', content: '203.0.113.10' },
      { id: 'r2', type: 'AAAA', name: 'a.example.com', content: '2001:db8::1' },
    ];
    const service = new TargetStatus({ source: source(data), dns: dns(records), fallbackZone });

    await expect(service.execute('a.example.com|A')).resolves.toEqual({
      ok: true,
      domain: 'a.example.com',
      mode: 'A',
      records: [
        { id: 'r1', type: 'A', name: 'a.example.com', content: '203.0.113.10' },
        { id: 'r2', type: 'AAAA', name: 'a.example.com', content: '2001:db8::1' },
      ],
    });
  });

  it('lists TXT records through the TXT read path', async () => {
    const txt: DnsRecord = { id: 't1', type: 'TXT', name: 'a.example.com', content: '"203.0.113.10:443,203.0.113.11:443"' };
    const txtData: MaintenanceSourceData = {
      ...data,
      targets: [
        {
          target: { mode: 'TXT', domain: 'a.example.com', port: null, minActive: 1, exitFilter: 'any', countries: [], asns: [] },
          zoneIndex: 0,
          enabled: true,
        },
      ],
    };
    const service = new TargetStatus({ source: source(txtData), dns: dns([txt]), fallbackZone });

    await expect(service.execute('a.example.com|TXT')).resolves.toMatchObject({
      mode: 'TXT',
      records: [{ id: 't1', type: 'TXT' }],
    });
  });

  it('rejects unknown or malformed binding keys', async () => {
    const service = new TargetStatus({ source: source(data), dns: dns(), fallbackZone });

    await expect(service.execute('missing.example.com|A')).rejects.toBeInstanceOf(TargetStatusInputError);
    await expect(service.execute('')).rejects.toBeInstanceOf(TargetStatusInputError);
  });
});
