import { describe, expect, it, vi } from 'vitest';
import {
  CloudflareDnsError,
  CloudflareDnsRepository,
} from '../../src/adapters/dns/cloudflare-dns';

const zone = { zoneId: 'zone-123', apiToken: 'token-456' };

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
  });
}

describe('CloudflareDnsRepository', () => {
  it('lists A and AAAA records with encoded zone and domain filters', async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      expect(init?.method).toBe('GET');
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token-456');
      if (url.endsWith('type=A')) {
        return jsonResponse({ success: true, result: [{ id: 'a1', type: 'A', name: 'edge.example.com', content: '203.0.113.10' }] });
      }
      return jsonResponse({ success: true, result: [{ id: 'a2', type: 'AAAA', name: 'edge.example.com', content: '2001:db8::1' }] });
    }) as typeof fetch;
    const repository = new CloudflareDnsRepository({ fetchImpl });

    await expect(repository.listAddressRecords(zone, 'edge.example.com')).resolves.toEqual([
      { id: 'a1', type: 'A', name: 'edge.example.com', content: '203.0.113.10' },
      { id: 'a2', type: 'AAAA', name: 'edge.example.com', content: '2001:db8::1' },
    ]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('creates address records with the correct type and proxy disabled', async () => {
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.method).toBe('POST');
      expect(JSON.parse(String(init?.body))).toEqual({
        type: 'AAAA',
        name: 'edge.example.com',
        content: '2001:db8::1',
        ttl: 60,
        proxied: false,
      });
      return jsonResponse({ success: true, result: { id: 'a2', type: 'AAAA', name: 'edge.example.com', content: '2001:db8::1' } });
    }) as typeof fetch;
    const repository = new CloudflareDnsRepository({ fetchImpl });

    await expect(repository.addAddressRecord(zone, 'edge.example.com', '2001:db8::1')).resolves.toMatchObject({
      id: 'a2',
      type: 'AAAA',
    });
  });

  it('creates or updates the single TXT record with fixed formatting', async () => {
    const calls: Array<{ method: string; path: string; body: unknown }> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ method: String(init?.method), path: new URL(String(input)).pathname, body: JSON.parse(String(init?.body)) });
      const body = JSON.parse(String(init?.body)) as { name: string; content: string };
      return jsonResponse({ success: true, result: { id: 'txt1', type: 'TXT', name: body.name, content: body.content } });
    }) as typeof fetch;
    const repository = new CloudflareDnsRepository({ fetchImpl });

    await repository.upsertTxtRecord(zone, 'list.example.com', null, ['203.0.113.10:443']);
    await repository.upsertTxtRecord(zone, 'list.example.com', 'txt1', ['203.0.113.10:443', '2001:db8::1:8443']);

    expect(calls).toEqual([
      {
        method: 'POST',
        path: '/client/v4/zones/zone-123/dns_records',
        body: { type: 'TXT', name: 'list.example.com', content: '"203.0.113.10:443"', ttl: 60 },
      },
      {
        method: 'PUT',
        path: '/client/v4/zones/zone-123/dns_records/txt1',
        body: { type: 'TXT', name: 'list.example.com', content: '"203.0.113.10:443,2001:db8::1:8443"', ttl: 60 },
      },
    ]);
  });

  it('deletes records through the expected endpoint', async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.method).toBe('DELETE');
      expect(String(input)).toBe('https://api.cloudflare.com/client/v4/zones/zone-123/dns_records/a1');
      return jsonResponse({ success: true, result: { id: 'a1' } });
    }) as typeof fetch;
    const repository = new CloudflareDnsRepository({ fetchImpl });

    await expect(repository.deleteRecord(zone, 'a1')).resolves.toBeUndefined();
  });

  it('rejects HTTP, API and malformed JSON failures', async () => {
    const httpFailure = new CloudflareDnsRepository({
      fetchImpl: vi.fn(async () => jsonResponse({ success: false }, { status: 403 })) as typeof fetch,
    });
    const apiFailure = new CloudflareDnsRepository({
      fetchImpl: vi.fn(async () => jsonResponse({ success: false, result: null })) as typeof fetch,
    });
    const invalidJson = new CloudflareDnsRepository({
      fetchImpl: vi.fn(async () => new Response('not-json', { status: 200 })) as typeof fetch,
    });

    await expect(httpFailure.listTxtRecords(zone, 'list.example.com')).rejects.toBeInstanceOf(CloudflareDnsError);
    await expect(apiFailure.listTxtRecords(zone, 'list.example.com')).rejects.toThrow('HTTP 200');
    await expect(invalidJson.listTxtRecords(zone, 'list.example.com')).rejects.toThrow('响应无效');
  });
});
