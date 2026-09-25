import { describe, expect, it } from 'vitest';
import { normalizeManagedTarget } from '../../src/domain/managed-target';
import { buildMaintenancePlan, type CurrentMaintenanceItem } from '../../src/domain/maintenance';
import { parsePoolEntry } from '../../src/domain/pool-entry';
import { alive, dead, unknown } from '../../src/domain/probe-result';
import { parseProxyTarget } from '../../src/domain/proxy-target';

const target = normalizeManagedTarget({
  mode: 'A',
  domain: 'edge.example.com',
  port: 443,
  minActive: 2,
  exitFilter: 'v4',
  countries: 'JP',
  asns: '64500',
});
if (!target) throw new Error('target fixture is invalid');

function proxyTarget(address: string) {
  const parsed = parseProxyTarget(address);
  if (!parsed) throw new Error(`proxy target fixture is invalid: ${address}`);
  return parsed;
}

function currentItem(recordId: string, address: string, result: CurrentMaintenanceItem['result']): CurrentMaintenanceItem {
  return { recordId, address, value: address.split(':')[0] ?? address, result };
}

const matchingResult = alive(proxyTarget('203.0.113.10:443'), {
  exitFamily: 'ipv4',
  exits: [{ family: 'ipv4', asn: '64500', country: 'JP', ip: '198.51.100.1' }],
});

describe('maintenance planning', () => {
  it('keeps unknown, removes trusted failures and refills only to the target', () => {
    const candidate = parsePoolEntry('203.0.113.20:443 # candidate');
    if (!candidate) throw new Error('candidate fixture is invalid');

    const plan = buildMaintenancePlan({
      target,
      current: [
        currentItem('a1', '203.0.113.10:443', matchingResult),
        currentItem('a2', '203.0.113.11:443', dead(proxyTarget('203.0.113.11:443'))),
        currentItem('a3', '203.0.113.12:443', unknown(proxyTarget('203.0.113.12:443'), 'TIMEOUT', 'timeout')),
      ],
      candidates: [
        { entry: candidate, address: '203.0.113.20:443', value: '203.0.113.20', result: matchingResult },
        { entry: candidate, address: '203.0.113.21:443', value: '203.0.113.21', result: unknown(proxyTarget('203.0.113.21:443'), 'TIMEOUT', 'timeout') },
      ],
      poolText: [
        '203.0.113.10:443 # active',
        '203.0.113.11:443,AS64500,JP,v4 # dead',
        '203.0.113.12:443,AS64500,JP,v4 # unknown',
        '203.0.113.20:443 # candidate',
        '203.0.113.21:443 # untouched-after-limit',
      ].join('\n'),
    });

    expect(plan.current.map(({ decision }) => decision)).toEqual(['active', 'remove-dead', 'keep-unknown']);
    expect(plan.retainedValues).toEqual(['203.0.113.10', '203.0.113.12']);
    expect(plan.dnsValues).toEqual(['203.0.113.10', '203.0.113.12', '203.0.113.20']);
    expect(plan.additions.map((item) => item.address)).toEqual(['203.0.113.20:443']);
    expect(plan.activeCount).toBe(2);
    expect(plan.exhausted).toBe(false);
    expect(plan.trash).toEqual([{ entryLine: '203.0.113.11:443,AS64500,JP,v4 # dead', reason: '维护失效' }]);
    expect(plan.nextPoolText).toContain('203.0.113.10:443,AS64500,JP,v4 # active');
    expect(plan.nextPoolText).not.toContain('203.0.113.11:443');
    expect(plan.nextPoolText).toContain('203.0.113.20:443,AS64500,JP,v4 # candidate');
    expect(plan.nextPoolText).toContain('203.0.113.21:443 # untouched-after-limit');
  });

  it('keeps unknown candidates and marks the pool exhausted when no match is available', () => {
    const candidate = parsePoolEntry('203.0.113.20:443,AS64500,JP,v4');
    if (!candidate) throw new Error('candidate fixture is invalid');

    const plan = buildMaintenancePlan({
      target,
      current: [],
      candidates: [
        { entry: candidate, address: '203.0.113.20:443', value: '203.0.113.20', result: unknown(proxyTarget('203.0.113.20:443'), 'HTTP_ERROR', '503') },
      ],
      poolText: '203.0.113.20:443,AS64500,JP,v4',
    });

    expect(plan.additions).toEqual([]);
    expect(plan.trash).toEqual([]);
    expect(plan.poolChanged).toBe(false);
    expect(plan.exhausted).toBe(true);
  });
});
