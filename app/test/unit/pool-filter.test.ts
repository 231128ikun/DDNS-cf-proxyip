import { describe, expect, it } from 'vitest';
import {
  matchesPoolFilter,
  parsePoolFilter,
} from '../../src/domain/pool-filter';
import { cleanPoolText } from '../../src/domain/pool-text';
import { parsePoolText } from '../../src/domain/pool-entry';

function filter(query: string) {
  const parsed = parsePoolFilter(query);
  expect(parsed).not.toBeNull();
  return parsed!;
}

describe('pool filter', () => {
  it('uses spaces as AND and commas as OR within one condition', () => {
    expect(matchesPoolFilter('203.0.113.10:443,AS64500,US,v4', filter('port:443 country:US'))).toBe(true);
    expect(matchesPoolFilter('203.0.113.11:8443,AS64500,US,v4', filter('port:443 country:US'))).toBe(false);
    expect(matchesPoolFilter('203.0.113.12:8443,AS64500,KR,v4', filter('port:443,8443 country:KR'))).toBe(true);
  });

  it('matches single ports and inclusive ranges', () => {
    expect(matchesPoolFilter('203.0.113.10:9000', filter('port:9000-9100'))).toBe(true);
    expect(matchesPoolFilter('203.0.113.10:9100', filter('port:9000-9100'))).toBe(true);
    expect(matchesPoolFilter('203.0.113.10:9101', filter('port:9000-9100'))).toBe(false);
  });

  it('returns null for an invalid port condition', () => {
    for (const query of ['port:0', 'port:65536', 'port:9000-8999', 'port:abc', 'port:80-90-100']) {
      expect(parsePoolFilter(query), query).toBeNull();
    }
  });

  it('matches country, ASN, exit stack and plain text', () => {
    const line = '203.0.113.10:443,AS64500,US,v6 # hk premium';
    expect(matchesPoolFilter(line, filter('country:US,KR asn:64500'))).toBe(true);
    expect(matchesPoolFilter(line, filter('as:AS64500 stack:v6'))).toBe(true);
    expect(matchesPoolFilter(line, filter('premium'))).toBe(true);
    expect(matchesPoolFilter(line, filter('AS64500'))).toBe(true);
    expect(matchesPoolFilter(line, filter('JP'))).toBe(false);
  });

  it('does not treat an unknown stack as confirmed dual-stack', () => {
    expect(matchesPoolFilter('203.0.113.10:443,AS64500,US', filter('stack:v4/v6'))).toBe(false);
    expect(matchesPoolFilter('203.0.113.10:443,AS64500,US', filter('exit:dual'))).toBe(false);
  });

  it('uses pipe as OR between groups', () => {
    const expression = filter('country:KR asn:64500 | country:US');
    expect(matchesPoolFilter('203.0.113.10:443,AS64500,US,v4', expression)).toBe(true);
    expect(matchesPoolFilter('203.0.113.11:443,AS64500,KR,v4', expression)).toBe(true);
    expect(matchesPoolFilter('203.0.113.12:443,AS64501,KR,v4', expression)).toBe(false);
  });

  it('matches parsed entries by port and country without modifying their metadata', () => {
    const text = '203.0.113.10:443,AS64500,US,v4\n203.0.113.11:8443,AS64501,KR,v4\n\n';
    const lines = parsePoolText(text).map(line => line.raw);
    expect(lines.filter(line => matchesPoolFilter(line, filter('port:443')))).toEqual(['203.0.113.10:443,AS64500,US,v4']);
    expect(lines.filter(line => !matchesPoolFilter(line, filter('port:443')))).toEqual(['203.0.113.11:8443,AS64501,KR,v4']);
    expect(lines.map(line => matchesPoolFilter(line, filter('country:US,KR')))).toEqual([true, true]);
  });

  it('deduplicates by canonical address and keeps the later line', () => {
    const text = [
      '203.0.113.10,AS64500,US,v4 # first',
      '203.0.113.10:443,AS64501,KR,v6 # later',
      '2001:db8::1 # ipv6',
      '[2001:db8::1]:443 # same ipv6',
      'not a target',
    ].join('\n');

    expect(cleanPoolText(text)).toBe([
      '203.0.113.10:443,AS64501,KR,v6 # later',
      '[2001:db8::1]:443,null,null,null # same ipv6',
    ].join('\n'));
  });

  it('filters and deduplicates mixed-separator input as individual entries', () => {
    const text = '203.0.113.10:443,AS64500,US,v4|203.0.113.11:8443,AS64501,KR,v4\t203.0.113.10:443,AS64500,US,v4';
    const matching = parsePoolText(text).map(line => line.raw).filter(line => matchesPoolFilter(line, filter('port:443')));
    expect(matching).toEqual(['203.0.113.10:443,AS64500,US,v4', '203.0.113.10:443,AS64500,US,v4']);
    expect(cleanPoolText(text)).toBe([
      '203.0.113.10:443,AS64500,US,v4',
      '203.0.113.11:8443,AS64501,KR,v4',
    ].join('\n'));
  });
});

it('rejects an invalid OR group, an empty condition, or an empty OR branch as a whole', () => {
  for (const query of ['port:abc | country:US', 'country:US | port:0', 'port:', 'country:US |', '| country:US']) {
    expect(parsePoolFilter(query), query).toBeNull();
  }
});

it('retains earlier valid metadata when deduplicating a later incomplete entry', () => {
  expect(cleanPoolText('203.0.113.10:443,AS64500,JP,v4 # old\n203.0.113.10:443,null,null,null # new'))
    .toBe('203.0.113.10:443,AS64500,JP,v4 # new');
});
