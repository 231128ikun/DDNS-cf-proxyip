import { describe, expect, it } from 'vitest';
import { ApiClient } from '../../web/src/api/client';
import { PoolWorkspace } from '../../web/src/state/pool-workspace';

function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
function setup(handler: (path: string, init: RequestInit) => unknown | Promise<unknown>) {
  const calls: { path: string; method: string; body: unknown }[] = [];
  const client = new ApiClient({ fetchImpl: async (url, init = {}) => {
    calls.push({ path: String(url), method: init.method!, body: init.body ? JSON.parse(String(init.body)) : undefined });
    const result = await handler(String(url), init); return result instanceof Response ? result : Response.json(result);
  } });
  return { model: new PoolWorkspace(client), calls };
}
const receipt = (mode = 'append', written = true, content = '203.0.113.10:443,AS64500,JP,v4') => ({ ok: true, mode, count: 1, added: 1, removed: 0, replaced: 0,
  receipt: { poolKey: 'ip_pool_default', content, written } });

describe('pool input workspace', () => {
  it('sends one explicit append and one precise removal without previews or follow-up reads', async () => {
    const { model, calls } = setup((_path, init) => receipt(JSON.parse(String(init.body)).mode));
    expect(await model.save('203.0.113.10:443', 'append')).toBe(true);
    expect(await model.save('203.0.113.10:443', 'remove')).toBe(true);
    expect(calls.map(call => call.method)).toEqual(['PUT', 'PUT']);
    expect(calls[1]?.body).toEqual({ content: '203.0.113.10:443', mode: 'remove', returnReceipt: true });
  });
  it('preserves session contents across pool switches and clears deleted identities', async () => {
    const { model, calls } = setup(() => ({ key: 'ip_pool_default', content: '203.0.113.10:443' }));
    await model.read(); model.select('ip_pool_001'); model.select('ip_pool_default');
    expect(model.content).toContain('203.0.113.10'); expect(calls).toHaveLength(1);
    model.forgetPool('ip_pool_default'); expect(model.content).toBeUndefined();
  });
  it('does not submit invalid input, duplicate clicks, or automatic retries', async () => {
    const pending = deferred<unknown>(); const { model, calls } = setup(() => pending.promise);
    expect(await model.save('???', 'remove')).toBe(false); expect(calls).toHaveLength(0);
    const writing = model.save('203.0.113.10:443', 'append');
    expect(await model.save('203.0.113.10:443', 'append')).toBe(false);
    pending.resolve(Response.json({ error: 'failed' }, { status: 500 }));
    expect(await writing).toBe(false); expect(calls).toHaveLength(1); expect(model.content).toBeUndefined();
  });
  it('ignores delayed reads after writing or selecting a different pool', async () => {
    const pending = deferred<unknown>(); const { model } = setup((_path, init) => init.method === 'GET' ? pending.promise : receipt());
    const reading = model.read(); await model.save('203.0.113.10:443', 'append');
    pending.resolve({ key: 'ip_pool_default', content: 'old' }); await reading;
    expect(model.content).toContain('203.0.113.10');
    model.select('ip_pool_001'); expect(model.content).toBeUndefined();
    model.select('ip_pool_default'); expect(model.content).toContain('203.0.113.10');
  });
  it('does not replace a confirmed write with a no-write stale receipt', async () => {
    let result = receipt(); const { model } = setup(() => result);
    await model.save('203.0.113.10:443', 'append'); result = receipt('append', false, 'stale');
    await model.save('203.0.113.10:443', 'append'); expect(model.content).not.toBe('stale');
  });
  it('rejects a receipt for another pool and leaves prior contents intact', async () => {
    const { model } = setup(() => ({ ...receipt(), receipt: { poolKey: 'ip_pool_001', content: 'wrong', written: true } }));
    expect(await model.save('203.0.113.10:443', 'append')).toBe(false); expect(model.content).toBeUndefined();
  });
});
