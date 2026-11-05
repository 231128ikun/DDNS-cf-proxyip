import { expect, it, vi } from 'vitest';
import { ApiClient } from '../../web/src/api/client';
import { readCleanPoolStream } from '../../web/src/api/clean-pool';
import { CheckProxy } from '../../src/application/check-proxy';
import { CheckPoolText } from '../../src/application/check-pool';
import { CleanPool } from '../../src/application/clean-pool';
import { PoolService } from '../../src/application/pool-service';
import { CheckTarget } from '../../src/application/check-target';
import { ResolveTarget } from '../../src/application/resolve-target';
import { createHttpApp } from '../../src/transport/http';
import { alive, dead } from '../../src/domain/probe-result';
import type { ProbeAdapter } from '../../src/ports/probe';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';

function fixture(probe: ProbeAdapter, text = 'dead.example:443\nalive.example:443') {
  const catalog = new MemoryPoolCatalog({ ip_pool_default: text });
  const write = vi.spyOn(catalog, 'write');
  const trash = { load: async () => '', save: async () => {}, addToTrash: vi.fn(async () => {}) };
  const checkProxy = new CheckProxy(probe);
  const cleanPool = new CleanPool({ pools: new PoolService(catalog), catalog, trash, checkPool: new CheckPoolText(checkProxy, 1) });
  const app = createHttpApp({ cleanPool, version: 'test', checkTarget: new CheckTarget({checkProxy, resolver: new ResolveTarget({query: async () => ({ok:true, values:[]})})}) });
  const client = new ApiClient({fetchImpl: async (url, init) => app.request(String(url), init)});
  return { app, client, catalog, write, trash };
}

it('delivers real progress before completion and writes only after the entire pool is checked', async () => {
  let release!: () => void, arrived!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const progress = new Promise<void>(resolve => { arrived = resolve; });
  const {client, catalog, write, trash} = fixture({name:'fake', probe: async target => {
    if (target.host === 'dead.example') return dead(target, {code:'TARGET_CONNECT_ERROR'});
    await gate; return alive(target);
  }});
  const result = client.cleanPool('ip_pool_default', undefined, event => { if (event.completed === 1) arrived(); });
  await progress;
  expect(write).not.toHaveBeenCalled(); expect(trash.addToTrash).not.toHaveBeenCalled();
  release();
  expect(await result).toMatchObject({checked:2, kept:1, trashed:1, skipped:false});
  expect(catalog.data.get('ip_pool_default')).not.toContain('dead.example');
  expect(trash.addToTrash).toHaveBeenCalledTimes(1); expect(write).toHaveBeenCalledTimes(1);
});

it('cancels in-flight work and does not start queued probes or cleanup writes', async () => {
  const probe = vi.fn<ProbeAdapter['probe']>(async (target, context = {}) => {
    if (target.host === 'dead.example') return dead(target);
    await new Promise<void>(resolve => {
      if (context.signal?.aborted) resolve();
      else context.signal?.addEventListener('abort', () => resolve(), {once:true});
    });
    context.signal?.throwIfAborted(); return alive(target);
  });
  const {client, write, trash} = fixture({name:'fake', probe}, 'dead.example:443\nalive.example:443\nqueued.example:443');
  const controller = new AbortController();
  await expect(client.cleanPool('ip_pool_default', controller.signal, () => controller.abort())).rejects.toThrow();
  expect(probe).toHaveBeenCalledTimes(2); expect(write).not.toHaveBeenCalled(); expect(trash.addToTrash).not.toHaveBeenCalled();
});

it('rejects changed inventory before any cleanup writes', async () => {
  const {client, catalog, write, trash} = fixture({name:'fake', probe:async target => dead(target)});
  await expect(client.cleanPool('ip_pool_default', undefined, () => catalog.data.set('ip_pool_default', 'new.example:443'))).rejects.toThrow('库存已变化');
  expect(catalog.data.get('ip_pool_default')).toBe('new.example:443');
  expect(write).not.toHaveBeenCalled(); expect(trash.addToTrash).not.toHaveBeenCalled();
});

it.each([
  '{"type":"start"}\n',
  '{"type":"complete","result":{"ok":true,"skipped":false}}\n',
  '{"type":"complete","result":null}\n',
  'broken\n',
])('never reports success for truncated or malformed streams: %s', async text => {
  await expect(readCleanPoolStream(new Response(text, {headers:{'content-type':'application/x-ndjson'}}))).rejects.toThrow();
});

it('decodes UTF-8 frames split across arbitrary network chunks', async () => {
  const encoder = new TextEncoder(), text = JSON.stringify({type:'error',error:'池为空，无需洗库'}) + '\n';
  const stream = new ReadableStream<Uint8Array>({start(controller) { for (const byte of encoder.encode(text)) controller.enqueue(Uint8Array.of(byte)); controller.close(); }});
  await expect(readCleanPoolStream(new Response(stream, {headers:{'content-type':'application/x-ndjson'}}))).rejects.toThrow('池为空，无需洗库');
});
