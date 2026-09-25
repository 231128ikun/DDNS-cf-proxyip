import { describe, expect, it } from 'vitest';
import { isPrivateHost, validateRemoteUrl } from '../../src/domain/remote-url';

describe('validateRemoteUrl', () => {
  it('accepts public http and https URLs', () => {
    for (const value of ['https://raw.githubusercontent.com/a/b.txt', 'http://example.com/pool.txt']) {
      const result = validateRemoteUrl(value);
      expect(result.ok, value).toBe(true);
    }
  });

  it('rejects non-http protocols, credentials and empty values', () => {
    for (const value of ['ftp://example.com/a.txt', 'file:///etc/passwd', 'data:text/plain,1', 'https://user:pass@example.com/a.txt', '', '   ']) {
      expect(validateRemoteUrl(value)).toEqual({ ok: false, reason: 'invalid-url' });
    }
  });

  it('rejects loopback names and internal suffixes', () => {
    for (const value of [
      'http://localhost/a.txt',
      'http://panel.internal/a.txt',
      'http://printer.local/a.txt',
      'http://a.home.arpa/a.txt',
      'http://metadata.google.internal/computeMetadata/v1/',
    ]) {
      expect(validateRemoteUrl(value), value).toEqual({ ok: false, reason: 'blocked-host' });
    }
  });

  it('rejects obfuscated IPv4 literal forms', () => {
    // WHATWG URL 会先把十进制/八进制/十六进制写法规范化成点分十进制。
    for (const value of ['http://2130706433/a.txt', 'http://0177.0.0.1/a.txt', 'http://0x7f.0.0.1/a.txt']) {
      expect(validateRemoteUrl(value), value).toEqual({ ok: false, reason: 'blocked-host' });
    }
  });

  it('rejects IPv4-mapped IPv6 addresses that URL rewrites to hex', () => {
    for (const value of [
      'http://[::ffff:127.0.0.1]/a.txt',
      'http://[0:0:0:0:0:ffff:169.254.169.254]/a.txt',
      'http://[::ffff:7f00:1]/a.txt',
    ]) {
      expect(validateRemoteUrl(value), value).toEqual({ ok: false, reason: 'blocked-host' });
    }
  });
});

describe('isPrivateHost', () => {
  it('blocks private, loopback, link-local, CGNAT and reserved IPv4 ranges', () => {
    for (const host of [
      '0.0.0.0',
      '10.1.2.3',
      '127.0.0.1',
      '169.254.169.254',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '100.64.0.1',
      '100.127.255.255',
      '198.18.0.1',
      '239.0.0.1',
    ]) {
      expect(isPrivateHost(host), host).toBe(true);
    }
  });

  it('keeps public IPv4 addresses next to those ranges reachable', () => {
    for (const host of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '172.15.0.1', '100.128.0.1', '100.63.255.255', '198.20.0.1']) {
      expect(isPrivateHost(host), host).toBe(false);
    }
  });

  it('blocks IPv6 loopback, mapped, unique-local, link-local and multicast ranges', () => {
    for (const host of ['[::1]', '::', '::ffff:192.168.0.1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1']) {
      expect(isPrivateHost(host), host).toBe(true);
    }
  });

  it('allows public IPv6 addresses and public hostnames', () => {
    for (const host of ['2001:4860:4860::8888', '2606:4700:4700::1111', 'example.com', 'raw.githubusercontent.com']) {
      expect(isPrivateHost(host), host).toBe(false);
    }
  });

  it('treats unparsable colon hosts as blocked', () => {
    expect(isPrivateHost('not:an:address')).toBe(true);
  });
});