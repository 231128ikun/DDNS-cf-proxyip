import { describe, expect, it } from 'vitest';
import { ApiClient } from '../../web/src/api/client';
import { PoolWorkspace } from '../../web/src/state/pool-workspace';

const preview = { ok: true, poolKey: 'ip_pool_default', mode: 'append', currentCount: 1, count: 2,
  added: 1, updated: 0, removed: 0, changed: true, unrecognized: { before: 0, after: 0 },
  standaloneComments: { before: 0, after: 0 }, changes: [{ address: '1.1.1.1:443', kind: 'add', after: '1.1.1.1:443' }] };
function setup(handler: (path: string, init: RequestInit) => unknown | Promise<unknown>) {
  const calls: { path: string; method: string; body: unknown; signal: AbortSignal | null | undefined }[] = [];
  const client = new ApiClient({ fetchImpl: (async (url, init = {}) => {
    calls.push({ path: String(url), method: init.method!, body: init.body ? JSON.parse(String(init.body)) : undefined, signal: init.signal });
    const data = await handler(String(url), init);
    return data instanceof Response ? data : Response.json(data);
  }) as typeof fetch });
  return { model: new PoolWorkspace(client), calls };
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
const success = (written: boolean | undefined, content = '1.1.1.1:443\n2.2.2.2:443') => ({ ok: true, mode: 'append', count: 2, added: 1, removed: 0, replaced: 0,
  ...(written === undefined ? {} : { receipt: { poolKey: 'ip_pool_default', content, written } }) });

describe('pool workspace command/query boundary', () => {
  it('forgets only the confirmed container identity that was deleted or recreated, so empty reused keys read empty', async () => {
    const { model } = setup((path, init) => {
      const key = path.split('/')[3]!;
      if (path.endsWith('/preview')) return { ...preview, poolKey: key };
      if (init.method === 'PUT') return { ...success(true), receipt: { poolKey: key, content: '1.1.1.1:443', written: true } };
      return { key, content: '' };
    });
    await model.prepare('1.1.1.1', 'append'); await model.save();
    model.select('ip_pool_002'); await model.prepare('1.1.1.1', 'append'); await model.save();
    model.forgetPool('ip_pool_002'); model.select('ip_pool_default'); model.select('ip_pool_002'); await model.read();
    expect(model.content).toBe(''); expect(model.divergent).toBeUndefined();
    expect(model.confirmed.has('ip_pool_002')).toBe(false);
    expect(model.confirmed.get('ip_pool_default')?.content).toBe('1.1.1.1:443');
  });
  it('binds preview and write to identical explicit content/mode and requests a receipt without a GET', async () => {
    const { model, calls } = setup((path, init) => path.endsWith('/preview') ? preview : init.method === 'PUT' ? success(true) : {});
    await model.prepare('1.1.1.1:443', 'append');
    expect(model.preview?.content).toBe('1.1.1.1:443');
    expect(await model.save()).toBe(true);
    expect(calls.map(c => [c.method, c.body])).toEqual([
      ['POST', { content: '1.1.1.1:443', mode: 'append' }],
      ['PUT', { content: '1.1.1.1:443', mode: 'append', returnReceipt: true }],
    ]);
    expect(model.content).toBe('1.1.1.1:443\n2.2.2.2:443');
    expect(model.confirmed.get(model.key)?.count).toBe(2);
  });
  it('rejects invalid candidates without silently stripping them or issuing requests', async () => {
    const { model, calls } = setup(() => preview);
    await model.prepare('1.1.1.1:443\n???', 'replace');
    expect(model.message).toContain('无法识别');
    expect(model.preview).toBeUndefined();
    expect(calls).toHaveLength(0);
  });
  it('invalidates delayed previews and aborts their signal when input changes', async () => {
    const response = deferred<unknown>();
    const { model, calls } = setup(() => response.promise);
    const pending = model.prepare('1.1.1.1', 'append');
    model.invalidate(); response.resolve(preview); await pending;
    expect(calls[0]?.signal?.aborted).toBe(true);
    expect(model.preview).toBeUndefined();
    expect(await model.save()).toBe(false);
    expect(calls).toHaveLength(1);
  });
  it('ignores old pool reads even if the server ignores cancellation', async () => {
    const response = deferred<unknown>();
    const { model, calls } = setup(path => path.endsWith('default') ? response.promise : { key: 'ip_pool_001', content: '2.2.2.2' });
    const pending = model.read(); model.select('ip_pool_001'); await model.read();
    response.resolve({ key: 'ip_pool_default', content: '1.1.1.1' }); await pending;
    expect(calls[0]?.signal?.aborted).toBe(true);
    expect(model.content).toBe('2.2.2.2');
  });
  it('protects receipts from reads started before writing and offers explicit adoption of divergent reads', async () => {
    const old = deferred<unknown>(); let reads = 0;
    const { model } = setup((path, init) => path.endsWith('/preview') ? preview : init.method === 'PUT' ? success(true)
      : ++reads === 1 ? old.promise : { key: 'ip_pool_default', content: '3.3.3.3' });
    const pending = model.read(); await model.prepare('1.1.1.1', 'append'); await model.save();
    old.resolve({ key: 'ip_pool_default', content: 'old' }); await pending;
    expect(model.content).toContain('2.2.2.2');
    await model.read(); expect(model.divergent).toBe('3.3.3.3');
    expect(model.content).toContain('2.2.2.2');
    model.adoptRead(); expect(model.content).toBe('3.3.3.3'); expect(model.confirmed.has(model.key)).toBe(false);
  });
  it.each([false, undefined])('does not turn written=%s into a new confirmed write', async written => {
    let result = success(true);
    const { model } = setup(path => path.endsWith('/preview') ? preview : result);
    await model.prepare('1.1.1.1', 'append'); await model.save();
    result = success(written, 'stale');
    await model.prepare('2.2.2.2', 'append'); await model.save();
    expect(model.content).toContain('2.2.2.2');
    expect(model.confirmed.get(model.key)?.content).not.toBe('stale');
    expect(model.message).toContain(written === false ? '未执行新写入' : '未提供回执');
  });
  it('shows a no-put receipt as a read only when there is no prior confirmation', async () => {
    const { model } = setup(path => path.endsWith('/preview') ? preview : success(false, 'read snapshot'));
    await model.prepare('1.1.1.1', 'append'); await model.save();
    expect(model.content).toBe('read snapshot'); expect(model.confirmed.size).toBe(0);
  });
  it('retains the exact preview for one explicit retry after an unconfirmed failure and guards double clicks', async () => {
    const response = deferred<unknown>(); let puts = 0;
    const { model, calls } = setup(path => path.endsWith('/preview') ? preview : ++puts === 1 ? response.promise : success(true));
    await model.prepare('1.1.1.1', 'append'); const pending = model.save();
    expect(await model.save()).toBe(false);
    response.resolve(Response.json({ error: 'failed' }, { status: 500 })); await pending;
    expect(model.preview?.content).toBe('1.1.1.1'); expect(model.message).toContain('未取得成功确认');
    expect(await model.save()).toBe(true);
    expect(calls.filter(c => c.method === 'PUT')).toHaveLength(2);
  });
  it('never applies an operation receipt to a different pool', async () => {
    const response = deferred<unknown>();
    const { model } = setup(path => path.endsWith('/preview') ? preview : response.promise);
    await model.prepare('1.1.1.1', 'append'); const pending = model.save(); model.select('ip_pool_001');
    response.resolve(success(true)); await pending;
    expect(model.content).toBeUndefined(); expect(model.confirmed.get('ip_pool_default')?.count).toBe(2);
  });
  it('rejects mismatched receipt identities and no-change previews do not write', async () => {
    let data: unknown = preview;
    const { model, calls } = setup(path => path.endsWith('/preview') ? data : { ...success(true), receipt: { poolKey: 'ip_pool_001', written: true, content: 'wrong' } });
    await model.prepare('1.1.1.1', 'append'); await model.save();
    expect(model.confirmed.size).toBe(0); expect(model.message).toContain('回执');
    data = { ...preview, changed: false }; await model.prepare('1.1.1.1', 'append');
    expect(await model.save()).toBe(false); expect(calls.filter(c => c.method === 'PUT')).toHaveLength(1);
  });
});
