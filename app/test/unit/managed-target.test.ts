import { describe, expect, it } from 'vitest';
import { decideCurrentResult } from '../../src/domain/maintenance';
import {
  normalizeManagedTarget,
  probeMatchesTarget,
  selectCandidateEntries,
  storedEntryMatchesTarget,
} from '../../src/domain/managed-target';
import { parsePoolEntry } from '../../src/domain/pool-entry';
import { alive, dead, unknown } from '../../src/domain/probe-result';
import { parseProxyTarget } from '../../src/domain/proxy-target';

const target = parseProxyTarget('203.0.113.10:443');
if (!target) throw new Error('test target is invalid');

const filteredTarget = normalizeManagedTarget({
  mode: 'A',
  domain: 'edge.example.com',
  port: 443,
  minActive: 2,
  exitFilter: 'v4',
  countries: 'jp,sg',
  asns: '64500;64501',
});
if (!filteredTarget) throw new Error('target fixture is invalid');

describe('managed target matching', () => {
  it('normalizes filters and list separators', () => {
    expect(filteredTarget).toMatchObject({
      mode: 'A',
      port: 443,
      minActive: 2,
      exitFilter: 'v4',
      countries: ['JP', 'SG'],
      asns: ['64500', '64501'],
    });
  });

  it('requires alive status and exact requested exit filter', () => {
    const ipv4 = alive(target, { exitFamily: 'ipv4', exits: [{ family: 'ipv4', asn: '64500', country: 'jp' }] });
    const dual = alive(target, { exitFamily: 'dual', exits: [{ family: 'ipv4', asn: '64500', country: 'jp' }] });
    expect(probeMatchesTarget(ipv4, filteredTarget)).toBe(true);
    expect(probeMatchesTarget(dual, filteredTarget)).toBe(false);
    expect(probeMatchesTarget(dead(target), filteredTarget)).toBe(false);
    expect(probeMatchesTarget(unknown(target, 'NO_API', 'offline'), filteredTarget)).toBe(false);
  });

  it('allows candidates with unknown stored metadata but rejects known mismatches', () => {
    const unknownMeta = parsePoolEntry('198.51.100.1:443');
    const mismatch = parsePoolEntry('198.51.100.2:443,AS64599,SG,v4');
    if (!unknownMeta || !mismatch) throw new Error('fixture is invalid');
    expect(storedEntryMatchesTarget(unknownMeta, filteredTarget)).toBe(true);
    expect(storedEntryMatchesTarget(mismatch, filteredTarget)).toBe(false);
  });

  it('filters A candidates by port and TXT candidates without a port filter', () => {
    const entries = [
      parsePoolEntry('198.51.100.1:443'),
      parsePoolEntry('198.51.100.2:8443'),
      parsePoolEntry('198.51.100.3:8443'),
    ].filter((entry): entry is NonNullable<typeof entry> => Boolean(entry));
    const txtTarget = normalizeManagedTarget({ mode: 'TXT', domain: 'list.example.com' });
    if (!txtTarget) throw new Error('target fixture is invalid');

    expect(selectCandidateEntries(entries, filteredTarget, new Set()).map((entry) => entry.address)).toEqual(['198.51.100.1:443']);
    expect(selectCandidateEntries(entries, txtTarget, new Set()).map((entry) => entry.address)).toEqual([
      '198.51.100.1:443',
      '198.51.100.2:8443',
      '198.51.100.3:8443',
    ]);
  });

  it('never treats unknown as dead', () => {
    expect(decideCurrentResult(unknown(target, 'NO_API', 'offline'), filteredTarget)).toBe('keep-unknown');
    expect(decideCurrentResult(dead(target), filteredTarget)).toBe('remove-dead');
    expect(decideCurrentResult(alive(target, { exitFamily: 'ipv6' }), filteredTarget)).toBe('remove-mismatch');
  });
});
