import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { launchBrowser } from './ui-browser.mjs';

/** Inject a stop at an emitted-item boundary, keeping the real hook, client and scheduler. */
export async function auditBatchLifecycle(cdp, sessionId) {
  const { outputFiles } = await build({ bundle: true, write: false, format: 'esm', platform: 'browser', target: 'es2022',
    stdin: { resolveDir: fileURLToPath(new URL('../', import.meta.url)), contents: `
      import { h, render } from 'preact';
      import { useBatchCheck } from './web/src/state/use-batch-check';
      import { ApiClient } from './web/src/api/client';
      let hook, interrupt = true, rateScenario = false;
      const requests = [];
      class Client extends ApiClient {
        checkBatch(text, signal, progress, concurrency) {
          return super.checkBatch(text, signal, event => {
            progress(event);
            if (interrupt && (rateScenario ? event.sourceComplete : !event.sourceComplete)) { interrupt = false; hook.handleStopBatch(); }
          }, concurrency);
        }
      }
      const client = new Client({ fetchImpl: async (_url, init) => {
        const address = JSON.parse(init.body).proxyip; requests.push(address);
        const addresses = address === 'multi.example.com' ? ['2.2.2.2:443', '3.3.3.3:443']
          : address === 'three.example.com' ? ['5.5.5.5:443', '6.6.6.6:443', '7.7.7.7:443'] : [address];
        return Response.json({ ok: true, input: address, source: { kind: 'direct' }, skipped: [],
          items: addresses.map(address => ({ address, result: { status: 'alive', exitFamily: 'ipv4', exits: [] } })) });
      } });
      function Harness() {
        hook = useBatchCheck({ client, config: { status: 'ready', data: {} }, webCheckConcurrency: 1,
          notify() {}, appendConsoleLog() {}, onInterrupt() {} });
        window.batchHook = hook; window.batchRequests = requests;
        return h('p', {}, 'batch lifecycle ready');
      }
      render(h(Harness), document.body);
      window.startRateScenario = () => { rateScenario = true; interrupt = true; hook.replaceIpText('three.example.com\\n4.4.4.4:443'); };
    ` } });
  const server = createServer((request, response) => {
    response.setHeader('content-type', request.url === '/test.js' ? 'text/javascript' : 'text/html');
    response.end(request.url === '/test.js' ? outputFiles[0].contents : '<!doctype html><html><body><script type="module" src="/test.js"></script></body></html>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await cdp.send('Page.navigate', { url: `http://127.0.0.1:${server.address().port}` }, sessionId);
    const read = expression => cdp.evaluate(sessionId, expression);
    await cdp.until(sessionId, 'Boolean(window.batchHook)');
    await read('window.batchHook.replaceIpText("1.1.1.1:443\\nmulti.example.com")');
    await cdp.until(sessionId, 'window.batchHook.ipText.includes("multi.example.com")');
    await read('window.batchHook.handleCheckBatch()');
    await cdp.until(sessionId, 'Boolean(window.batchHook.batchInterrupt)');
    assert.equal(await read('window.batchHook.batchInterrupt.valid'), 2, '中断时有效结果数量错误');
    await read('window.batchHook.handleResumeBatch()');
    await cdp.until(sessionId, 'window.batchHook.batch.status === "ready"');
    const actual = await read(`({ requests: window.batchRequests, source: window.batchHook.ipText,
      addresses: window.batchHook.batchReport.items.map(item => item.address), alive: window.batchHook.batch.data.alive,
      progress: window.batchHook.batchProgressState, incomplete: window.batchHook.batchReport.incomplete })`);
    assert.deepEqual(actual, { requests: ['1.1.1.1:443', 'multi.example.com', 'multi.example.com'],
      source: '1.1.1.1:443\nmulti.example.com', addresses: ['1.1.1.1:443', '2.2.2.2:443', '3.3.3.3:443'],
      alive: 3, progress: { completed: 3, total: 3 }, incomplete: [] },
    '续检未完成的多结果源时重复保留部分结果，或重复检测已完成源/虚增计数');
    await read('window.startRateScenario()');
    await cdp.until(sessionId, 'window.batchHook.ipText.startsWith("three.example.com")');
    await read('window.batchHook.handleCheckBatch()');
    await cdp.until(sessionId, 'Boolean(window.batchHook.batchInterrupt)');
    const stats = await read('window.batchHook.batchInterrupt');
    assert.equal(stats.checked, 1, '完成源数量错误');
    assert.equal(stats.total, 2, '总源数量错误');
    assert.equal(stats.valid, 3, '可用地址结果数量错误');
    assert.equal(stats.rate, '100.0', '已检测地址结果全可用时有效率不应以源行数为分母');
  } finally { await new Promise(resolve => server.close(resolve)); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const browser = await launchBrowser();
  try {
    const { targetId } = await browser.cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await browser.cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await browser.cdp.send('Page.enable', {}, sessionId);
    await auditBatchLifecycle(browser.cdp, sessionId);
    console.log('Multi-result stop/resume: real hook + ApiClient + scheduler PASS');
  } finally { await browser.close(); }
}
