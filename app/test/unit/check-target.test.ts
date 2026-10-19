import { describe, expect, it } from 'vitest';
import { CheckProxy } from '../../src/application/check-proxy';
import { CheckTarget } from '../../src/application/check-target';
import { ResolveTarget } from '../../src/application/resolve-target';
import { alive, dead, unknown, type ProbeResult } from '../../src/domain/probe-result';
import type { ProxyTarget } from '../../src/domain/proxy-target';
import type { DnsLookup, DnsLookupType } from '../../src/ports/dns-lookup';
import type { ProbeAdapter } from '../../src/ports/probe';

type Verdict = 'alive' | 'dead' | 'unknown';

class RecordingProbe implements ProbeAdapter {
  readonly name = 'recording';
  readonly probed: string[] = [];

  constructor(private readonly verdict: Verdict = 'alive') {}

  async probe(target: ProxyTarget): Promise<ProbeResult> {
    this.probed.push(target.authority);
    if (this.verdict === 'dead') return dead(target);
    if (this.verdict === 'unknown') return unknown(target, 'TIMEOUT', '探测超时');
    return alive(target, { exitFamily: 'ipv4', exitIp: '198.51.100.8' });
  }
}

function lookupStub(answers: Partial<Record<DnsLookupType, readonly string[]>>): DnsLookup {
  return {
    async query(_name, type) {
      const values = answers[type];
      if (!values) return { ok: false, code: 'DNS_STATUS', message: 'no record' };
      return { ok: true, values };
    },
  };
}

function createTarget(answers: Partial<Record<DnsLookupType, readonly string[]>>, probe = new RecordingProbe()) {
  const target = new CheckTarget({
    resolver: new ResolveTarget(lookupStub(answers)),
    checkProxy: new CheckProxy(probe),
    concurrency: 2,
  });
  return { probe, target };
}

describe('CheckTarget', () => {
  it('probes a literal target directly without touching DNS', async () => {
    const { probe, target } = createTarget({});

    const outcome = await target.execute('203.0.113.10:8443');

    expect(outcome).toMatchObject({
      ok: true,
      report: { source: { kind: 'direct' }, items: [{ address: '203.0.113.10:8443' }] },
    });
    expect(probe.probed).toEqual(['203.0.113.10:8443']);
  });

  it('probes a hostname that carries an explicit port instead of resolving it', async () => {
    const { probe, target } = createTarget({ A: ['203.0.113.10'] });

    const outcome = await target.execute('edge.example.com:8443');

    expect(outcome.ok && outcome.report.source.kind).toBe('direct');
    expect(probe.probed).toEqual(['edge.example.com:8443']);
  });

  it('resolves txt@ targets into addresses and probes every one of them', async () => {
    const { probe, target } = createTarget({ TXT: ['"203.0.113.10:443,203.0.113.11:443"'] });

    const outcome = await target.execute('txt@_proxy.example.com');

    expect(outcome).toMatchObject({
      ok: true,
      report: {
        source: { kind: 'txt', host: '_proxy.example.com', addresses: ['203.0.113.10:443', '203.0.113.11:443'] },
        items: [{ address: '203.0.113.10:443' }, { address: '203.0.113.11:443' }],
        skipped: [],
      },
    });
    expect(probe.probed).toEqual(['203.0.113.10:443', '203.0.113.11:443']);
  });

  it('ignores non-address TXT values when resolving proxy targets', async () => {
    const { probe, target } = createTarget({
      TXT: ['"203.0.113.10:443,v=spf1 include:mail.example.com -all,verify-token,edge.example.com:8443"'],
    });

    const outcome = await target.execute('txt@_proxy.example.com');

    expect(outcome.ok && outcome.report.source).toMatchObject({
      kind: 'txt',
      addresses: ['203.0.113.10:443', 'edge.example.com:8443'],
    });
    expect(probe.probed).toEqual(['203.0.113.10:443', 'edge.example.com:8443']);
  });

  it('merges A and AAAA answers and defaults the port to 443', async () => {
    const { target } = createTarget({ A: ['203.0.113.10'], AAAA: ['2001:db8::1'] });

    const outcome = await target.execute('edge.example.com');

    expect(outcome.ok && outcome.report.source).toMatchObject({
      kind: 'dns',
      addresses: ['203.0.113.10', '2001:db8::1'],
    });
    expect(outcome.ok && outcome.report.items.map((item) => item.address)).toEqual([
      '203.0.113.10:443',
      '[2001:db8::1]:443',
    ]);
  });

  it('skips resolved values that are not valid targets', async () => {
    const { target } = createTarget({ A: ['not a target', '203.0.113.10'] });

    const outcome = await target.execute('edge.example.com');

    expect(outcome).toMatchObject({
      ok: true,
      report: { skipped: ['not a target'], items: [{ address: '203.0.113.10:443' }] },
    });
  });

  it('returns a failure instead of marking the node dead when resolution fails', async () => {
    const { probe, target } = createTarget({});

    const outcome = await target.execute('missing.example.com');

    expect(outcome).toMatchObject({ ok: false });
    expect(probe.probed).toEqual([]);
  });

  it('keeps probe failures as probe results, not as lookup errors', async () => {
    const { target } = createTarget({ A: ['203.0.113.10'] }, new RecordingProbe('unknown'));

    const outcome = await target.execute('edge.example.com');

    expect(outcome.ok && outcome.report.items[0]?.result.status).toBe('unknown');
  });
});
