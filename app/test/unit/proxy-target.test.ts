import { describe, expect, it } from 'vitest';
import { parseProxyTarget } from '../../src/domain/proxy-target';

describe('parseProxyTarget', () => {
  it('parses IPv4 with port', () => {
    const target = parseProxyTarget('203.0.113.10:8443');
    expect(target).toMatchObject({
      host: '203.0.113.10',
      port: 8443,
      family: 'ipv4',
      authority: '203.0.113.10:8443',
    });
  });

  it('parses bracketed IPv6 with port', () => {
    const target = parseProxyTarget('[2001:db8::1]:443');
    expect(target).toMatchObject({
      host: '2001:db8::1',
      port: 443,
      family: 'ipv6',
      authority: '[2001:db8::1]:443',
    });
  });

  it.each([
    '[2001:0DB8:0:0:0:0:0:1]:443',
    '2001:db8:0:0::1',
    'https://[2001:0db8:0:0:0:0:0:1]/',
  ])('uses the same key for equivalent IPv6 input: %s', (input) => {
    expect(parseProxyTarget(input)).toMatchObject({
      host: '2001:db8::1', key: '[2001:db8::1]:443', family: 'ipv6',
    });
    expect(parseProxyTarget(input)?.key).not.toBe(parseProxyTarget('[2001:db8::1]:8443')?.key);
  });

  it('uses the default port for a bare IPv6 address', () => {
    const target = parseProxyTarget('2001:db8::1');
    expect(target).toMatchObject({ port: 443, family: 'ipv6' });
  });

  it('parses a hostname and ignores an HTTP scheme', () => {
    const target = parseProxyTarget('https://Proxy.Example.com:2053/path');
    expect(target).toMatchObject({ host: 'proxy.example.com', port: 2053, family: 'hostname' });
  });

  it.each(['', '300.1.1.1:443', '[2001:db8::1', 'example.com:0', 'example.com:70000',
    '2001:db8::1]/unexpected', '2001:db8::1]:8443/path', '2001:db8::1]#fragment',
    '2001:db8::1]?query', '2001: db8::1'])(
    'rejects invalid input: %s',
    (input) => {
      expect(parseProxyTarget(input)).toBeNull();
    },
  );
});