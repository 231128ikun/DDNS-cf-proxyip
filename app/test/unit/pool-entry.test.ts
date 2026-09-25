import { describe, expect, it } from 'vitest';
import { alive, unknown } from '../../src/domain/probe-result';
import { parseProxyTarget } from '../../src/domain/proxy-target';
import {
  formatPoolEntry,
  mergePoolMetadata,
  parsePoolEntry,
  parsePoolText,
  poolMetadataFromProbe,
  serializePoolText,
} from '../../src/domain/pool-entry';

const target = parseProxyTarget('203.0.113.10:443');
if (!target) throw new Error('test target is invalid');

describe('pool entries', () => {
  it('parses existing and current formats with attached comments', () => {
    expect(parsePoolEntry('203.0.113.10:8443')).toEqual({
      address: '203.0.113.10:8443',
      asn: null,
      country: null,
      stack: null,
      comment: '',
    });
    expect(parsePoolEntry('203.0.113.10:8443,64500,JP,v4 # primary')).toEqual({
      address: '203.0.113.10:8443',
      asn: '64500',
      country: 'JP',
      stack: 'v4',
      comment: '# primary',
    });
    expect(parsePoolEntry('# comment only')).toBeNull();
  });

  it('formats IPv6 and normalizes metadata without dropping comments', () => {
    expect(formatPoolEntry({
      address: '2001:db8::1',
      asn: '64500/64501',
      country: 'jp',
      stack: 'v4',
      comment: '# edge',
    })).toBe('[2001:db8::1]:443,AS64500/AS64501,JP,v4 # edge');
  });

  it('round-trips non-entry comment lines while preserving their order', () => {
    const lines = parsePoolText('203.0.113.10:443,64500,JP,v4 # a\n# section\n198.51.100.2:443');
    expect(lines.map((line) => line.entry?.address ?? line.raw)).toEqual([
      '203.0.113.10:443',
      '# section',
      '198.51.100.2:443',
    ]);
    expect(serializePoolText(lines)).toBe('203.0.113.10:443,64500,JP,v4 # a\n# section\n198.51.100.2:443');
  });

  it('keeps known metadata when a later probe omits it', () => {
    const previous = parsePoolEntry('203.0.113.10:443,AS64500,JP,v4 # edge');
    if (!previous) throw new Error('fixture is invalid');
    const merged = mergePoolMetadata(previous, {});
    expect(merged).toMatchObject({ asn: 'AS64500', country: 'JP', stack: 'v4' });
  });

  it('extracts aggregate metadata from successful exits', () => {
    const result = alive(target, {
      exitFamily: 'dual',
      exits: [
        { family: 'ipv4', asn: '64500', country: 'jp', ip: '198.51.100.1' },
        { family: 'ipv6', asn: '64501', country: 'sg', ip: '2001:db8::2' },
      ],
    });
    expect(poolMetadataFromProbe(result)).toEqual({ asn: '64500/64501', country: 'JP/SG', stack: 'v4/v6' });
    expect(poolMetadataFromProbe(unknown(target, 'NO_API', 'offline'))).toEqual({});
  });
});
