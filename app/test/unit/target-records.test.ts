import { describe, expect, it, vi } from 'vitest';
import { TargetRecords } from '../../src/application/target-records';
import { TargetStatusInputError } from '../../src/application/target-status';
import type { DnsRepository, DnsZone } from '../../src/ports/dns-repository';
import type { MaintenanceSource, MaintenanceSourceData } from '../../src/ports/maintenance-source';

const fallbackZone: DnsZone = { zoneId: 'zone-fallback', apiToken: 'token-fallback' };

function data(mode: 'A' | 'TXT'): MaintenanceSourceData {
  return {
    zones: [{ zoneId: 'zone-a', apiToken: 'token-a' }],
    targets: [
      {
        target: { mode, domain: 'a.example.com', port: mode === 'TXT' ? null : 443, minActive: 1, exitFilter: 'any', countries: [], asns: [] },
        zoneIndex: 0,
        enabled: true,
      },
    ],
    poolMapping: {},
    poolNames: {},
  };
}

function dns(mode: 'A' | 'TXT'): DnsRepository {
  const txtRecords = mode === 'TXT'
    ? [{ id: 't1', type: 'TXT' as const, name: 'a.example.com', content: '"203.0.113.10:443"' }]
    : [];
  return {
    listAddressRecords: async () => [{ id: 'r1', type: 'A', name: 'a.example.com', content: '203.0.113.10' }],
    listTxtRecords: async () => txtRecords,
    addAddressRecord: vi.fn(async () => ({ id: 'new', type: 'A' as const, name: 'a.example.com', content: '203.0.113.10' })),
    upsertTxtRecord: vi.fn(async () => ({ id: 't1', type: 'TXT' as const, name: 'a.example.com', content: '"203.0.113.10:443"' })),
    deleteRecord: vi.fn(async () => undefined),
  };
}

describe('TargetRecords', () => {
  it('adds an A/AAAA record from a bare or ported IP', async () => {
    const repository = dns('A');
    const service = new TargetRecords({
      source: { load: async () => data('A') } satisfies MaintenanceSource,
      dns: repository,
      fallbackZone,
    });

    await expect(service.add('a.example.com|A', '203.0.113.10:443')).resolves.toEqual({ ok: true });
    expect(repository.addAddressRecord).toHaveBeenCalledWith(
      expect.objectContaining({ zoneId: 'zone-a' }),
      'a.example.com',
      '203.0.113.10',
      'A',
    );
  });

  it('merges a TXT address into the existing record list', async () => {
    const repository = dns('TXT');
    const service = new TargetRecords({
      source: { load: async () => data('TXT') } satisfies MaintenanceSource,
      dns: repository,
      fallbackZone,
    });

    await service.add('a.example.com|TXT', '203.0.113.11:443');
    expect(repository.upsertTxtRecord).toHaveBeenCalledWith(
      expect.objectContaining({ zoneId: 'zone-a' }),
      'a.example.com',
      't1',
      ['203.0.113.10:443', '203.0.113.11:443'],
    );
  });

  it('deletes an A record by id and a TXT address by value', async () => {
    const aRepository = dns('A');
    const aService = new TargetRecords({
      source: { load: async () => data('A') } satisfies MaintenanceSource,
      dns: aRepository,
      fallbackZone,
    });
    await aService.remove('a.example.com|A', 'r1');
    expect(aRepository.deleteRecord).toHaveBeenCalledWith(expect.objectContaining({ zoneId: 'zone-a' }), 'r1');

    const txtRepository = dns('TXT');
    const txtService = new TargetRecords({
      source: { load: async () => data('TXT') } satisfies MaintenanceSource,
      dns: txtRepository,
      fallbackZone,
    });
    await txtService.remove('a.example.com|TXT', 't1', '203.0.113.10:443');
    expect(txtRepository.deleteRecord).toHaveBeenCalledWith(expect.objectContaining({ zoneId: 'zone-a' }), 't1');
  });

  it.each([
    { records: [] },
    { records: [{ id: 'r1', type: 'A' as const, name: 'b.example.com', content: '203.0.113.10' }] },
    { records: [{ id: 'r1', type: 'TXT' as const, name: 'a.example.com', content: '203.0.113.10:443' }] },
  ])('rejects missing, foreign and non-address record IDs: %j', async ({ records }) => {
    const repository = { ...dns('A'), listAddressRecords: async () => records };
    const service = new TargetRecords({ source: { load: async () => data('A') }, dns: repository, fallbackZone });
    await expect(service.remove('a.example.com|A', 'r1')).rejects.toBeInstanceOf(TargetStatusInputError);
    expect(repository.deleteRecord).not.toHaveBeenCalled();
  });

  it('accepts a matching AAAA record with equivalent domain spelling', async () => {
    const repository = { ...dns('A'), listAddressRecords: async () => [
      { id: 'r6', type: 'AAAA' as const, name: 'A.EXAMPLE.COM.', content: '2001:db8::1' },
    ] };
    const service = new TargetRecords({ source: { load: async () => data('A') }, dns: repository, fallbackZone });
    await expect(service.remove('a.example.com|A', 'r6')).resolves.toEqual({ ok: true });
    expect(repository.deleteRecord).toHaveBeenCalledWith(expect.anything(), 'r6');
  });

  it('does not delete records when their lookup fails', async () => {
    const repository = { ...dns('A'), listAddressRecords: async () => { throw new Error('DNS unavailable'); } };
    const service = new TargetRecords({ source: { load: async () => data('A') }, dns: repository, fallbackZone });
    await expect(service.remove('a.example.com|A', 'r1')).rejects.toThrow('DNS unavailable');
    expect(repository.deleteRecord).not.toHaveBeenCalled();
  });

  it('rejects unknown targets', async () => {
    const service = new TargetRecords({
      source: { load: async () => data('A') } satisfies MaintenanceSource,
      dns: dns('A'),
      fallbackZone,
    });
    await expect(service.add('missing.example.com|A', '203.0.113.10')).rejects.toBeInstanceOf(TargetStatusInputError);
  });
});
