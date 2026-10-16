import { describe, expect, it } from 'vitest';
import { MaintainManagedTarget } from '../../src/application/maintain-managed-target';
import { normalizeManagedTarget, type ManagedTarget } from '../../src/domain/managed-target';
import { alive, dead, unknown, type ProbeResult } from '../../src/domain/probe-result';
import { parseProxyTarget, type ProxyTarget } from '../../src/domain/proxy-target';
import type { DnsRecord, DnsRepository, DnsZone } from '../../src/ports/dns-repository';
import type { PoolRepository, TrashCandidate } from '../../src/ports/pool-repository';
import type { ProbeAdapter, ProbeContext } from '../../src/ports/probe';

const zone: DnsZone = { zoneId: 'zone-1', apiToken: 'token-1' };

function requireTarget(input: Parameters<typeof normalizeManagedTarget>[0]): ManagedTarget {
  const target = normalizeManagedTarget(input);
  if (!target) throw new Error('target fixture is invalid');
  return target;
}

function requireProxy(address: string): ProxyTarget {
  const target = parseProxyTarget(address);
  if (!target) throw new Error(`proxy target fixture is invalid: ${address}`);
  return target;
}

class MemoryPoolRepository implements PoolRepository {
  readonly trash: TrashCandidate[] = [];

  constructor(private content = '') {}

  async load(): Promise<string> {
    return this.content;
  }

  async save(_poolKey: string, content: string): Promise<void> {
    this.content = content;
  }

  async addToTrash(entries: readonly TrashCandidate[]): Promise<void> {
    this.trash.push(...entries);
  }

  value(): string {
    return this.content;
  }
}

class MemoryDnsRepository implements DnsRepository {
  private sequence = 100;
  readonly deleted: string[] = [];
  readonly added: Array<{ host: string; type: string }> = [];
  readonly upserted: Array<{ recordId: string | null; addresses: readonly string[] }> = [];

  constructor(
    private readonly addressRecords: DnsRecord[] = [],
    private txtRecords: DnsRecord[] = [],
  ) {}

  async listAddressRecords(): Promise<readonly DnsRecord[]> {
    return this.addressRecords;
  }

  async listTxtRecords(): Promise<readonly DnsRecord[]> {
    return this.txtRecords;
  }

  async addAddressRecord(_zone: DnsZone, domain: string, host: string, type: 'A' | 'AAAA'): Promise<DnsRecord> {
    const record = { id: `new-${this.sequence++}`, type, name: domain, content: host };
    this.addressRecords.push(record);
    this.added.push({ host, type });
    return record;
  }

  async upsertTxtRecord(_zone: DnsZone, domain: string, recordId: string | null, addresses: readonly string[]): Promise<DnsRecord> {
    const content = `"${addresses.join(',')}"`;
    this.upserted.push({ recordId, addresses: [...addresses] });
    if (recordId) {
      const index = this.txtRecords.findIndex((record) => record.id === recordId);
      const record = { id: recordId, type: 'TXT' as const, name: domain, content };
      if (index >= 0) this.txtRecords[index] = record;
      else this.txtRecords.push(record);
      return record;
    }
    const record = { id: `new-${this.sequence++}`, type: 'TXT' as const, name: domain, content };
    this.txtRecords.push(record);
    return record;
  }

  async deleteRecord(_zone: DnsZone, recordId: string): Promise<void> {
    this.deleted.push(recordId);
    const addressIndex = this.addressRecords.findIndex((record) => record.id === recordId);
    if (addressIndex >= 0) {
      this.addressRecords.splice(addressIndex, 1);
      return;
    }
    this.txtRecords = this.txtRecords.filter((record) => record.id !== recordId);
  }

  addressValues(): string[] {
    return this.addressRecords.map((record) => record.content);
  }

  txtValues(): string[] {
    return this.txtRecords.map((record) => record.content);
  }
}

class StubProbeAdapter implements ProbeAdapter {
  readonly name = 'stub';
  readonly calls: string[] = [];

  constructor(private readonly results: ReadonlyMap<string, ProbeResult>) {}

  async probe(target: ProxyTarget, _context?: ProbeContext): Promise<ProbeResult> {
    this.calls.push(target.authority);
    const result = this.results.get(target.authority);
    if (!result) throw new Error(`missing probe fixture: ${target.authority}`);
    return result;
  }
}

function match(address: string): ProbeResult {
  return alive(requireProxy(address), {
    exitFamily: 'ipv4',
    exits: [{ family: 'ipv4', asn: '64500', country: 'JP', ip: '198.51.100.1' }],
  });
}

/** 带延迟的可用结果：候选排序按延迟取最快，测试用它区分优先级。 */
function matchWithLatency(address: string, latencyMs: number): ProbeResult {
  return alive(requireProxy(address), {
    latencyMs,
    exitFamily: 'ipv4',
    exits: [{ family: 'ipv4', asn: '64500', country: 'JP', ip: '198.51.100.1' }],
  });
}

describe('MaintainManagedTarget', () => {
  it('maintains A records, refills with the fastest candidate and never walks the whole pool', async () => {
    const target = requireTarget({
      mode: 'A',
      domain: 'edge.example.com',
      port: 443,
      minActive: 2,
      exitFilter: 'v4',
      countries: 'JP',
      asns: '64500',
    });
    const dns = new MemoryDnsRepository([
      { id: 'a1', type: 'A', name: target.domain, content: '203.0.113.10' },
      { id: 'a2', type: 'A', name: target.domain, content: '203.0.113.11' },
      { id: 'a3', type: 'A', name: target.domain, content: '203.0.113.12' },
    ]);
    const pools = new MemoryPoolRepository([
      '203.0.113.10:443 # current',
      '203.0.113.11:443,AS64500,JP,v4 # dead',
      '203.0.113.12:443,AS64500,JP,v4 # unknown',
      '203.0.113.20:443 # candidate',
      '203.0.113.21:443 # slower-candidate',
    ].join('\n'));
    const probe = new StubProbeAdapter(new Map([
      ['203.0.113.10:443', match('203.0.113.10:443')],
      ['203.0.113.11:443', dead(requireProxy('203.0.113.11:443'))],
      ['203.0.113.12:443', unknown(requireProxy('203.0.113.12:443'), 'TIMEOUT', 'timeout')],
      ['203.0.113.20:443', matchWithLatency('203.0.113.20:443', 120)],
      ['203.0.113.21:443', matchWithLatency('203.0.113.21:443', 260)],
    ]));
    const service = new MaintainManagedTarget({ probe, pools, dns, concurrency: 2 });

    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });

    expect(dns.deleted).toEqual(['a2']);
    expect(dns.added).toEqual([{ host: '203.0.113.20', type: 'A' }]);
    expect(dns.addressValues()).toEqual(['203.0.113.10', '203.0.113.12', '203.0.113.20']);
    expect(report).toMatchObject({ deleted: 1, added: 1, dnsUpdated: true, errors: [], probeErrors: 1 });
    expect(report.plan.activeCount).toBe(2);
    expect(report.plan.exhausted).toBe(false);
    // 只补一个位置，但会多探一个候选来比较延迟：更快的 .20 入选，.21 留在池里。
    expect(probe.calls).toContain('203.0.113.21:443');
    expect(pools.value()).toContain('203.0.113.20:443,AS64500,JP,v4 # candidate');
    expect(pools.value()).not.toContain('203.0.113.11:443');
    expect(pools.value()).toContain('203.0.113.21:443 # slower-candidate');
    expect(pools.trash).toEqual([
      { entryLine: '203.0.113.11:443,AS64500,JP,v4 # dead', reason: '维护失效', poolKey: 'ip_pool_default' },
    ]);
  });

  it('preserves unknown TXT entries and upserts the retained plus refill list', async () => {
    const target = requireTarget({ mode: 'TXT', domain: 'list.example.com', minActive: 2, exitFilter: 'v4', countries: 'JP', asns: '64500' });
    const dns = new MemoryDnsRepository([], [
      {
        id: 'txt1',
        type: 'TXT',
        name: target.domain,
        content: '"203.0.113.10:443,203.0.113.11:443,203.0.113.12:443"',
      },
    ]);
    const pools = new MemoryPoolRepository([
      '203.0.113.10:443 # current',
      '203.0.113.11:443,AS64500,JP,v4 # dead',
      '203.0.113.12:443,AS64500,JP,v4 # unknown',
      '203.0.113.20:443 # candidate',
    ].join('\n'));
    const probe = new StubProbeAdapter(new Map([
      ['203.0.113.10:443', match('203.0.113.10:443')],
      ['203.0.113.11:443', dead(requireProxy('203.0.113.11:443'))],
      ['203.0.113.12:443', unknown(requireProxy('203.0.113.12:443'), 'HTTP_ERROR', '503')],
      ['203.0.113.20:443', match('203.0.113.20:443')],
    ]));
    const service = new MaintainManagedTarget({ probe, pools, dns });

    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });

    expect(dns.upserted).toEqual([{
      recordId: 'txt1',
      addresses: ['203.0.113.10:443', '203.0.113.12:443', '203.0.113.20:443'],
    }]);
    expect(dns.txtValues()).toEqual(['"203.0.113.10:443,203.0.113.12:443,203.0.113.20:443"']);
    expect(report).toMatchObject({ deleted: 0, added: 0, dnsUpdated: true, errors: [], probeErrors: 1 });
    expect(report.plan.activeCount).toBe(2);
    expect(pools.trash).toHaveLength(1);
  });

  it('deletes a TXT record only after every current address is trusted dead', async () => {
    const target = requireTarget({ mode: 'TXT', domain: 'list.example.com', minActive: 1 });
    const dns = new MemoryDnsRepository([], [
      { id: 'txt1', type: 'TXT', name: target.domain, content: '"203.0.113.11:443"' },
    ]);
    const pools = new MemoryPoolRepository('203.0.113.11:443 # dead');
    const probe = new StubProbeAdapter(new Map([
      ['203.0.113.11:443', dead(requireProxy('203.0.113.11:443'))],
    ]));
    const service = new MaintainManagedTarget({ probe, pools, dns });

    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });

    expect(dns.deleted).toEqual(['txt1']);
    expect(dns.txtValues()).toEqual([]);
    expect(report).toMatchObject({ deleted: 1, added: 0, dnsUpdated: true, errors: [] });
    expect(report.plan.exhausted).toBe(true);
    expect(report.probeErrors).toBe(0);
    expect(pools.trash).toHaveLength(1);
  });

  it('caps candidate probing instead of walking a dead pool to the end', async () => {
    const target = requireTarget({ mode: 'A', domain: 'edge.example.com', port: 443, minActive: 1 });
    const addresses = Array.from({ length: 20 }, (_, index) => `203.0.113.${100 + index}:443`);
    const pools = new MemoryPoolRepository(addresses.map((address) => `${address} # dead`).join('\n'));
    const probe = new StubProbeAdapter(new Map(addresses.map((address) => [address, dead(requireProxy(address))])));
    const service = new MaintainManagedTarget({ probe, pools, dns: new MemoryDnsRepository([]) });

    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });

    // 全失效的池不再一路探到底：窗口有上限，剩下的留给下一轮维护。
    expect(probe.calls.length).toBeLessThanOrEqual(12);
    expect(report.plan.exhausted).toBe(true);
  });

  it('prefers the fastest alive candidate when several are reachable', async () => {
    const target = requireTarget({
      mode: 'A',
      domain: 'edge.example.com',
      port: 443,
      minActive: 1,
      exitFilter: 'v4',
      countries: 'JP',
      asns: '64500',
    });
    const addresses = ['203.0.113.30:443', '203.0.113.31:443', '203.0.113.32:443'];
    const probe = new StubProbeAdapter(new Map([
      [addresses[0]!, matchWithLatency(addresses[0]!, 300)],
      [addresses[1]!, matchWithLatency(addresses[1]!, 90)],
      [addresses[2]!, matchWithLatency(addresses[2]!, 200)],
    ]));
    const pools = new MemoryPoolRepository(addresses.map((address) => `${address} # candidate`).join('\n'));
    const service = new MaintainManagedTarget({ probe, pools, dns: new MemoryDnsRepository([]) });

    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });

    expect(report.plan.additions.map((item) => item.address)).toEqual(['203.0.113.31:443']);
  });

  it('keeps a record when the probe itself throws', async () => {
    const target = requireTarget({ mode: 'A', domain: 'edge.example.com', port: 443, minActive: 1 });
    const dns = new MemoryDnsRepository([
      { id: 'a1', type: 'A', name: target.domain, content: '203.0.113.10' },
    ]);
    const pools = new MemoryPoolRepository();
    const service = new MaintainManagedTarget({
      probe: new StubProbeAdapter(new Map()),
      pools,
      dns,
    });

    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });

    expect(dns.deleted).toEqual([]);
    expect(dns.addressValues()).toEqual(['203.0.113.10']);
    expect(report.plan.current[0]?.item.result.status).toBe('unknown');
    expect(report.probeErrors).toBe(1);
    expect(report.plan.exhausted).toBe(true);
    expect(pools.trash).toEqual([]);
  });
});
