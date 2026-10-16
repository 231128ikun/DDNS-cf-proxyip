import { describe, expect, it, vi } from 'vitest';
import { DohLookup, parseDohPayload } from '../../src/adapters/dns/doh-lookup';

describe('DoH lookup adapter', () => {
  it('queries the JSON endpoint by record type and dedupes answers', async () => {
    const calls: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return Response.json({
        Status: 0,
        Answer: [
          { name: 'example.com', type: 1, data: '203.0.113.10' },
          { name: 'example.com', type: 1, data: '203.0.113.10' },
          { name: 'example.com', type: 28, data: '2001:db8::1' },
        ],
      });
    });
    const lookup = new DohLookup({ endpoint: 'https://doh.example/dns-query', fetchImpl: fetchMock as typeof fetch });

    await expect(lookup.query('example.com', 'A')).resolves.toEqual({ ok: true, values: ['203.0.113.10'] });
    expect(calls[0]).toContain('name=example.com');
    expect(calls[0]).toContain('type=A');
  });

  it('keeps TXT answers verbatim so the caller reuses pool parsing', async () => {
    const fetchMock = vi.fn(async () => Response.json({
      Status: 0,
      Answer: [{ type: 16, data: '"203.0.113.10:443,203.0.113.11:443"' }],
    }));
    const lookup = new DohLookup({ endpoint: 'https://doh.example/dns-query', fetchImpl: fetchMock as typeof fetch });

    await expect(lookup.query('_proxy.example.com', 'TXT')).resolves.toEqual({
      ok: true,
      values: ['"203.0.113.10:443,203.0.113.11:443"'],
    });
  });

  it('turns DNS status, HTTP failures and network errors into failures', async () => {
    const nxdomain = new DohLookup({
      endpoint: 'https://doh.example/dns-query',
      fetchImpl: (async () => Response.json({ Status: 3 })) as typeof fetch,
    });
    await expect(nxdomain.query('missing.example.com', 'A')).resolves.toMatchObject({ ok: false, code: 'DNS_STATUS' });

    const broken = new DohLookup({
      endpoint: 'https://doh.example/dns-query',
      fetchImpl: (async () => new Response('nope', { status: 502 })) as typeof fetch,
    });
    await expect(broken.query('example.com', 'A')).resolves.toMatchObject({ ok: false, code: 'HTTP_ERROR' });

    const offline = new DohLookup({
      endpoint: 'https://doh.example/dns-query',
      fetchImpl: (async () => {
        throw new Error('boom');
      }) as typeof fetch,
    });
    await expect(offline.query('example.com', 'A')).resolves.toMatchObject({ ok: false, code: 'NETWORK_ERROR' });
  });

  it('rejects malformed payloads and ignores other record types', () => {
    expect(parseDohPayload(null, 'A')).toMatchObject({ ok: false, code: 'BAD_RESPONSE' });
    expect(parseDohPayload({ Answer: [] }, 'A')).toMatchObject({ ok: false, code: 'BAD_RESPONSE' });
    expect(parseDohPayload({ Status: 0, Answer: [{ type: 1, data: '203.0.113.10' }] }, 'AAAA')).toEqual({
      ok: true,
      values: [],
    });
  });
});
