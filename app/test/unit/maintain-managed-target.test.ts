import { failingNativeProbe } from '../helpers/native-probe';
import { describe, expect, it, vi } from 'vitest';
import { ExternalApiProbeAdapter } from '../../src/adapters/probe/external-api';
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
      ['203.0.113.12:443', unknown(requireProxy('203.0.113.12:443'), 'NETWORK_ERROR', 'network error')],
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

function externalMaintenance(type: 'A' | 'AAAA' | 'TXT', payload: unknown, native?: ProbeAdapter) {
  const target = requireTarget({ mode: type === 'TXT' ? 'TXT' : 'A', domain: 'edge.example.com', port: 443, minActive: 1, exitFilter: 'dual' });
  const host = type === 'AAAA' ? '2001:db8::10' : '203.0.113.10';
  const address = type === 'AAAA' ? `[${host}]:443` : `${host}:443`;
  const record: DnsRecord = { id: 'current', type, name: target.domain, content: type === 'TXT' ? `"${address}"` : host };
  const dns = new MemoryDnsRepository(type === 'TXT' ? [] : [record], type === 'TXT' ? [record] : []);
  const initial = `${address},AS64500,JP,v4/v6 # 用户备注`;
  const pools = new MemoryPoolRepository(initial);
  const probe = native ?? new ExternalApiProbeAdapter({ endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?proxyip=' }],
    timeoutMs: 1_000, fetchImpl: (async () => new Response(JSON.stringify(payload))) as typeof fetch });
  const service = new MaintainManagedTarget({ probe, pools, dns });
  return { target, dns, pools, initial, service };
}

describe('maintenance pool write safety', () => {
  const types = ['A', 'AAAA', 'TXT'] as const;

  it.each(types)('retains the original pool when trash insertion fails for %s', async (type) => {
    const { target, pools, initial, service } = externalMaintenance(type, { success: false, message: 'node failed' });
    const save = vi.spyOn(pools, 'save');
    vi.spyOn(pools, 'addToTrash').mockRejectedValueOnce(new Error('trash write failed'));

    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });

    expect(report.errors).toEqual(['写入垃圾桶失败']);
    expect(report.plan.poolChanged).toBe(true);
    expect(pools.value()).toBe(initial);
    expect(pools.trash).toEqual([]);
    expect(save).not.toHaveBeenCalled();
  });

  it.each(types)('retains a trash copy before a failed original-pool write for %s', async (type) => {
    const { target, pools, initial, service } = externalMaintenance(type, { success: false, message: 'node failed' });
    const save = vi.spyOn(pools, 'save').mockRejectedValueOnce(new Error('pool write failed'));
    const addToTrash = vi.spyOn(pools, 'addToTrash');

    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });

    expect(report.errors).toEqual(['保存 IP 池失败']);
    expect(pools.value()).toBe(initial);
    expect(pools.trash).toEqual([{ entryLine: initial, reason: '维护失效', poolKey: 'ip_pool_default' }]);
    expect(addToTrash.mock.invocationCallOrder[0]!).toBeLessThan(save.mock.invocationCallOrder[0]!);
  });
});

describe('external probe to maintenance safety', () => {
  const types = ['A', 'AAAA', 'TXT'] as const;
  const detectorErrors = [
    { success: false, apiError: true },
    { success: true, apiError: true },
  ];

  it.each(detectorErrors.flatMap(payload => types.map(type => ({ type, payload }))))('preserves $type DNS and pool on detector error $payload', async ({ type, payload }) => {
    const { target, dns, pools, initial, service } = externalMaintenance(type, payload);
    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });
    expect(report).toMatchObject({ deleted: 0, added: 0, dnsUpdated: false, probeErrors: 1 });
    expect(report.plan.current[0]?.decision).toBe('keep-unknown');
    expect(dns.deleted).toEqual([]);
    expect(dns.upserted).toEqual([]);
    expect(pools.value()).toBe(initial);
    expect(pools.trash).toEqual([]);
  });

  const candidateFailures = [
    { success: false, message: 'Worker exceeded resource limits' },
    { success: false, message: 'too many requests, rate limit exceeded' },
    { success: false, message: 'fetch failed: internal error' },

    { success: false, detail: 'Network connection lost.' },
    { success: false, reason: 'Network connection lost.' },
    { success: false, message: 'node failed', error: 'Network connection lost.' },
    { success: false, probeResults: { ipv4: { ok: false, error: 'Network connection lost.' } } },
    { success: false, message: 'TLS handshake failed' },
    { success: false, message: 'certificate has expired' },
    { success: false, message: 'HTTP 500' },
  ];

  it.each(candidateFailures.flatMap(payload => types.map(type => ({ type, payload }))))('removes and archives a confirmed $type candidate failure $payload', async ({ type, payload }) => {
    const { target, dns, pools, service } = externalMaintenance(type, payload);
    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });
    expect(report).toMatchObject({ deleted: 1, added: 0, dnsUpdated: true, probeErrors: 0 });
    expect(report.plan.current[0]?.decision).toBe('remove-dead');
    expect(dns.deleted).toEqual(['current']);
    expect(pools.value()).toBe('');
    expect(pools.trash).toHaveLength(1);
  });

  it.each(types.flatMap(type => [false, true].map(reversed => ({ type, reversed }))))('retains dual-stack $type DNS (reversed=$reversed)', async ({ type, reversed }) => {
    const exits = [{ stack: 'ipv4', ip: '198.51.100.1', asn: 'AS64500', country: 'JP' },
      { stack: 'ipv6', ip: '2001:db8::1', asn: 'AS64500', country: 'JP' }];
    const { target, dns, pools, initial, service } = externalMaintenance(type, { success: true, exits: reversed ? exits.reverse() : exits });
    const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });
    expect(report).toMatchObject({ deleted: 0, added: 0, dnsUpdated: false, probeErrors: 0 });
    expect(report.plan.current[0]?.decision).toBe('active');
    expect(report.plan.current[0]?.item.result.exitFamily).toBe('dual');
    expect(dns.deleted).toEqual([]);
    expect(dns.upserted).toEqual([]);
    expect(pools.value()).toBe(initial);
    expect(pools.trash).toEqual([]);
  });
});

it.each(['A', 'AAAA', 'TXT'] as const)('维护 %s 时将复检后仍超时的地址入桶并移出 DNS', async kind => {
  const target = requireTarget({ mode: kind === 'TXT' ? 'TXT' : 'A', domain: 'edge.example.com', minActive: 1, port: 443 });
  const host = kind === 'A' ? '203.0.113.10' : '2001:db8::10';
  const address = kind === 'A' ? `${host}:443` : `[${host}]:${kind === 'TXT' ? 8443 : 443}`;
  const healthy = '203.0.113.20:443';
  const dns = kind === 'TXT'
    ? new MemoryDnsRepository([], [{ id: 'txt-timeout', type: 'TXT', name: target.domain, content: `"${address},${healthy}"` }])
    : new MemoryDnsRepository([
      { id: 'timeout', type: kind, name: target.domain, content: host },
      { id: 'healthy', type: 'A', name: target.domain, content: '203.0.113.20' },
    ]);
  const pools = new MemoryPoolRepository(`${address},AS64500,JP,${kind === 'A' ? 'v4' : 'v6'} # 用户备注\n${healthy}`);
  const fetchImpl = vi.fn(async (url: RequestInfo | URL) => Response.json(new URL(String(url)).searchParams.get('proxyip') === address
    ? { success: false, probe_results: { ipv6: { ok: false, error: 'tcp connect timeout' } } } : { success: true }));
  const probe = new ExternalApiProbeAdapter({ endpoints: [
    { name: 'primary', urlTemplate: 'https://primary.example/?proxyip=' },
    { name: 'backup', urlTemplate: 'https://backup.example/?proxyip=' },
  ], timeoutMs: 1000, fetchImpl: fetchImpl as typeof fetch });
  const trash = vi.spyOn(pools, 'addToTrash');
  const report = await new MaintainManagedTarget({ probe, pools, dns }).execute({ target, zone, poolKey: 'ip_pool_default' });
  expect(report).toMatchObject({ dnsUpdated: true, probeErrors: 0, errors: [] });
  expect(report.plan.current.map(item => item.decision)).toEqual(['remove-dead', 'active']);
  expect(trash).toHaveBeenCalledTimes(1);
  expect(pools.trash).toEqual([{ entryLine: `${address},AS64500,JP,${kind === 'A' ? 'v4' : 'v6'} # 用户备注`, reason: '维护失效', poolKey: 'ip_pool_default' }]);
  expect(pools.value()).not.toContain(address);
  expect(pools.value()).toContain(healthy);
  if (kind === 'TXT') expect(dns.upserted).toEqual([{ recordId: 'txt-timeout', addresses: [healthy] }]);
  else expect(dns.deleted).toEqual(['timeout']);
  expect(fetchImpl).toHaveBeenCalledTimes(3);
});

it.each(['A', 'AAAA', 'TXT'] as const)('does not delete the sole %s DNS source when archiving it fails', async type => {
  const { target, dns, pools, service } = externalMaintenance(type, { success: false });
  vi.spyOn(pools, 'addToTrash').mockRejectedValueOnce(new Error('archive failure'));
  const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });
  expect(dns.deleted).toEqual([]);
  expect(dns.upserted).toEqual([]);
  expect(report).toMatchObject({ dnsUpdated: false, deleted: 0, added: 0, errors: ['写入垃圾桶失败'] });
});

it('counts distinct active DNS addresses rather than duplicate records and probes each current address once', async () => {
  const target = requireTarget({ mode: 'A', domain: 'edge.example.com', port: 443, minActive: 3 });
  const dns = new MemoryDnsRepository([
    { id: 'one', type: 'A', name: target.domain, content: '203.0.113.10' },
    { id: 'duplicate', type: 'A', name: target.domain, content: '203.0.113.10' },
    { id: 'two', type: 'A', name: target.domain, content: '203.0.113.11' },
  ]);
  const pools = new MemoryPoolRepository('203.0.113.12:443');
  const probe = new StubProbeAdapter(new Map(['10', '11', '12'].map(last => {
    const address = '203.0.113.' + last + ':443';
    return [address, match(address)];
  })));
  const report = await new MaintainManagedTarget({ probe, pools, dns }).execute({ target, zone, poolKey: 'ip_pool_default' });
  expect(dns.added).toEqual([{ host: '203.0.113.12', type: 'A' }]);
  expect(probe.calls.filter(address => address === '203.0.113.10:443')).toHaveLength(1);
  expect(report.activeCount).toBe(3);
  expect(report.dns?.after).toEqual(['203.0.113.10', '203.0.113.11', '203.0.113.12']);
});

it('continues past the first uncertain candidate window until it finds the missing verified address', async () => {
  const target = requireTarget({ mode: 'A', domain: 'edge.example.com', port: 443, minActive: 3 });
  const dns = new MemoryDnsRepository(['10', '11'].map(last => ({ id: last, type: 'A' as const, name: target.domain, content: '203.0.113.' + last })));
  const candidates = ['20', '21', '22', '23', '24', '25'];
  const pools = new MemoryPoolRepository(candidates.map(last => '203.0.113.' + last + ':443').join('\n'));
  const results = new Map<string, ProbeResult>();
  for (const last of ['10', '11', ...candidates]) {
    const address = '203.0.113.' + last + ':443';
    results.set(address, ['20', '21', '22'].includes(last) ? unknown(requireProxy(address), 'HTTP_ERROR', 'HTTP 503') : match(address));
  }
  const report = await new MaintainManagedTarget({ probe: new StubProbeAdapter(results), pools, dns }).execute({ target, zone, poolKey: 'ip_pool_default' });
  expect(report.activeCount).toBe(3);
  expect(report.probeErrors).toBe(3);
  expect(dns.added).toEqual([{ host: '203.0.113.23', type: 'A' }]);
  expect(pools.trash).toEqual([]);
});

it('reports the actual active count when adding the planned DNS address fails', async () => {
  const target = requireTarget({ mode: 'A', domain: 'edge.example.com', port: 443, minActive: 3 });
  const dns = new MemoryDnsRepository(['10', '11'].map(last => ({ id: last, type: 'A' as const, name: target.domain, content: '203.0.113.' + last })));
  vi.spyOn(dns, 'addAddressRecord').mockRejectedValueOnce(new Error('fixture write failure'));
  const results = new Map(['10', '11', '12'].map(last => { const address = '203.0.113.' + last + ':443'; return [address, match(address)]; }));
  const report = await new MaintainManagedTarget({ probe: new StubProbeAdapter(results), pools: new MemoryPoolRepository('203.0.113.12:443'), dns })
    .execute({ target, zone, poolKey: 'ip_pool_default' });
  expect(report.plan.activeCount).toBe(3);
  expect(report.activeCount).toBe(2);
  expect(report.dns?.after).toEqual(['203.0.113.10', '203.0.113.11']);
});

it('continues with untested candidates on the next run when an uncertain scan reaches its budget', async () => {
  const target = requireTarget({ mode: 'A', domain: 'edge.example.com', port: 443, minActive: 3 });
  const dns = new MemoryDnsRepository(['10', '11'].map(last => ({ id: last, type: 'A' as const, name: target.domain, content: '203.0.113.' + last })));
  const candidates = Array.from({ length: 13 }, (_, index) => '203.0.113.' + (20 + index) + ':443');
  const pools = new MemoryPoolRepository(candidates.join('\n'));
  const values = new Map<string, ProbeResult>();
  for (const address of ['203.0.113.10:443', '203.0.113.11:443', ...candidates]) values.set(address,
    address === candidates[12] || address.endsWith('.10:443') || address.endsWith('.11:443') ? match(address) : unknown(requireProxy(address), 'HTTP_ERROR', 'HTTP 503'));
  const service = new MaintainManagedTarget({ probe: new StubProbeAdapter(values), pools, dns });
  const first = await service.execute({ target, zone, poolKey: 'ip_pool_default' });
  expect(first.activeCount).toBe(2);
  expect(first.candidates).toMatchObject({ checked: 12, remaining: 1, unknown: 12 });
  expect(pools.value().split('\n')[0]).toBe(candidates[12]);
  const next = await service.execute({ target, zone, poolKey: 'ip_pool_default' });
  expect(next.activeCount).toBe(3);
  expect(dns.added).toEqual([{ host: '203.0.113.32', type: 'A' }]);
  expect(pools.trash).toEqual([]);
});

it('does not replace an invalid DNS record verdict with a successful duplicate-family probe', async () => {
  const target = requireTarget({ mode: 'A', domain: 'edge.example.com', port: 443, minActive: 1 });
  const dns = new MemoryDnsRepository([
    { id: 'invalid', type: 'A', name: target.domain, content: '2001:db8::10' },
    { id: 'valid', type: 'AAAA', name: target.domain, content: '2001:db8::10' },
  ]);
  const address = '[2001:db8::10]:443';
  const probe = new StubProbeAdapter(new Map([[address, match(address)]]));
  const result = await new MaintainManagedTarget({ probe, pools: new MemoryPoolRepository(), dns }).execute({ target, zone, poolKey: 'ip_pool_default' });
  expect(result.plan.current.map(item => item.decision)).toEqual(['keep-unknown', 'active']);
  expect(result.plan.current[0]!.item.result.code).toBe('INVALID_DNS_VALUE');
  expect(probe.calls).toEqual([address]);
});

it('treats a detector-reported target HTTP 404 as dead and continues to a later refill candidate', async () => {
  const target = requireTarget({ mode: 'A', domain: 'edge.example.com', port: 443, minActive: 3 });
  const dns = new MemoryDnsRepository(['10', '11'].map(last => ({ id: last, type: 'A' as const, name: target.domain, content: '203.0.113.' + last })));
  const pools = new MemoryPoolRepository('203.0.113.20:443\n203.0.113.21:443');
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    const candidate = new URL(String(input)).searchParams.get('proxyip')!;
    if (candidate === '203.0.113.20:443') return Response.json({ candidate, ok: false, probe_results: [
      { probe_name: 'dbip', ok: false, status_code: 404, error: 'unexpected status: 404' },
      { probe_name: 'ipsb', ok: false, status_code: 404, error: 'unexpected status: 404' },
    ] });
    return Response.json({ success: true, exits: [{ ip: '198.51.100.42', stack: 'ipv4', asn: 'AS64500', country: 'JP' }] });
  });
  const probe = new ExternalApiProbeAdapter({ endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?proxyip=' }],
    timeoutMs: 1000, fetchImpl: fetchImpl as typeof fetch });
  const report = await new MaintainManagedTarget({ probe, pools, dns }).execute({ target, zone, poolKey: 'ip_pool_default' });
  expect(report).toMatchObject({ activeCount: 3, probeErrors: 0, added: 1 });
  expect(dns.added).toEqual([{ host: '203.0.113.21', type: 'A' }]);
  expect(pools.trash).toEqual([{ entryLine: '203.0.113.20:443', reason: '维护失效', poolKey: 'ip_pool_default' }]);
  expect(report.candidateResults?.find(item => item.address === '203.0.113.20:443')?.result)
    .toMatchObject({ status: 'dead', code: 'TARGET_HTTP_ERROR' });
});

it.each(['A', 'TXT'])('preserves %s DNS and the pool when the service reports a TCP loop', async mode => {
  const target = requireTarget({ mode, domain: 'edge.example.com', port: 443, minActive: 1 });
  const address = '203.0.113.10:443';
  const content = address + ',AS64500,JP,v4 # 原备注';
  const dns = mode === 'A'
    ? new MemoryDnsRepository([{ id: 'a1', type: 'A', name: target.domain, content: '203.0.113.10' }])
    : new MemoryDnsRepository([], [{ id: 'txt1', type: 'TXT', name: target.domain, content: '"' + address + '"' }]);
  const pools = new MemoryPoolRepository(content);
  const save = vi.spyOn(pools, 'save');
  const fetchImpl = vi.fn(async () => Response.json({ success: false, message: 'TCP Loop detected' }));
  const probe = new ExternalApiProbeAdapter({ endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?proxyip=' }],
    timeoutMs: 1000, fetchImpl: fetchImpl as typeof fetch });

  const report = await new MaintainManagedTarget({ probe, pools, dns }).execute({ target, zone, poolKey: 'ip_pool_default' });
  expect(report).toMatchObject({ probeErrors: 1, deleted: 0, added: 0, dnsUpdated: false });
  expect(report.plan.current[0]!.decision).toBe('keep-unknown');
  expect(report.plan.current[0]!.item.result).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
  expect(fetchImpl).toHaveBeenCalledTimes(2);
  expect(dns.deleted).toEqual([]);
  expect(dns.added).toEqual([]);
  expect(dns.upserted).toEqual([]);
  expect(pools.trash).toEqual([]);
  expect(save).not.toHaveBeenCalled();
  expect(pools.value()).toBe(content);
});

describe('native probe maintenance boundary', () => {
  it.each(['A', 'AAAA', 'TXT'] as const)('protects %s DNS and pool on runtime faults but cleans candidate failures', async type => {
    for (const [error, shouldClean] of [[new Error('TCP Loop detected'), false], [new TypeError('runtime failure'), false], [new Error('connection refused'), true]] as const) {
      const { target, dns, pools, initial, service } = externalMaintenance(type, null, failingNativeProbe(error));
      const report = await service.execute({ target, zone, poolKey: 'ip_pool_default' });
      expect(report.deleted).toBe(shouldClean ? 1 : 0);
      expect(pools.trash.length).toBe(shouldClean ? 1 : 0);
      expect(pools.value()).toBe(shouldClean ? '' : initial);
      if (!shouldClean) { expect(dns.deleted).toEqual([]); expect(dns.upserted).toEqual([]); }
    }
  });
});
