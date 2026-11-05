import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { build } from 'esbuild';
import { launchBrowser } from './ui-browser.mjs';
import { createUiFixture, serveUiFixture, waitForUiRequest } from './ui-fixture.mjs';

// Only external request timing is controlled; the panel, hook, API client and pool routes stay real.
const requestGates = `(() => {
  const original = window.fetch;
  window.__blocks = new Set(); window.__waiting = new Map();
  window.__confirms = []; window.__confirmAnswer = true;
  window.confirm = message => { window.__confirms.push(message); return window.__confirmAnswer; };
  window.__release = key => window.__waiting.get(key)?.();
  window.fetch = async (input, init) => {
    const path = new URL(input instanceof Request ? input.url : input, location.href).pathname;
    const key = path === '/api/check' ? JSON.parse(init.body).proxyip : path;
    if (window.__blocks.has(key)) await new Promise((resolve, reject) => {
      const release = () => { window.__waiting.delete(key); init?.signal?.removeEventListener('abort', abort); resolve(); };
      const abort = () => { window.__waiting.delete(key); reject(new DOMException('cancelled', 'AbortError')); };
      window.__waiting.set(key, release);
      if (init?.signal?.aborted) abort(); else init?.signal?.addEventListener('abort', abort, { once: true });
    });
    return original(input, init);
  };
})();`;

// A real mounted hook with a controllable checkBatch port can interrupt a multi-result source
// between progress events, a boundary the HTTP client's synchronous result loop cannot expose.
const hookBundle = await build({
  absWorkingDir: resolve(import.meta.dirname, '..'), bundle: true, write: false, format: 'iife', platform: 'browser',
  stdin: { resolveDir: resolve(import.meta.dirname, '..'), contents: `
    import { h, render } from 'preact';
    import { useBatchCheck } from './web/src/state/use-batch-check';
    window.__mountHook = config => {
      window.__runs = []; window.__hookLogs = [];
      const client = { checkBatch(text, signal, progress, concurrency) {
        return new Promise(resolve => window.__runs.push({ text, signal, progress, concurrency, resolve }));
      } };
      function Harness() {
        window.__hook = useBatchCheck({ client, config: { status: 'ready', data: { config } },
          webCheckConcurrency: 2, notify() {}, onInterrupt() {},
          appendConsoleLog: message => window.__hookLogs.push(message) });
        return h('output', null, window.__hook.batchReport?.items.length ?? 0);
      }
      render(h(Harness), document.getElementById('hook-root'));
    };`, loader: 'ts' },
});

const outArg = process.argv.indexOf('--out');
const out = resolve(outArg >= 0 ? process.argv[outArg + 1] : join(import.meta.dirname, '../.wrangler/tmp/ui-pool-review-fixes'));
mkdirSync(out, { recursive: true });
const server = await serveUiFixture();
let browser;
const results = [];
try {
  browser = await launchBrowser();
  const { cdp } = browser;
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: requestGates }, sessionId);
  const read = expression => cdp.evaluate(sessionId, expression);
  const until = expression => cdp.until(sessionId, expression);
  const click = selector => cdp.click(sessionId, selector);
  const settle = () => read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
  const setValue = async (selector, text) => {
    await read(`(() => { const input = document.querySelector(${JSON.stringify(selector)});
      input.value = ${JSON.stringify(text)}; input.dispatchEvent(new Event('input', { bubbles: true })); })()`);
    await settle();
  };
  const open = async (configure = () => {}) => {
    Object.assign(server.fixture, createUiFixture()); configure(server.fixture);
    await cdp.send('Page.navigate', { url: server.base }, sessionId);
    await until('document.querySelectorAll("#status-table .status-badge.ok").length === 2 && Boolean(document.querySelector("[data-action=check-stored]"))');
    await click('[data-pool-mode=import]');
  };
  const capture = async (name, width, panel = true) => {
    await settle();
    if (panel) await read('document.querySelector(".dashboard-pool-card").scrollIntoView({ block: "start", behavior: "instant" })');
    const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
    const path = join(out, `${name}-${width}.png`);
    writeFileSync(path, Buffer.from(data, 'base64'));
    return path;
  };
  const run = async (name, width, test) => {
    try {
      await test();
      results.push({ name, width, passed: true });
      console.log(`PASS ${width}px ${name}`);
    } catch (error) {
      const screenshot = await capture(`failed-${name}`, width, false);
      results.push({ name, width, passed: false, error: error.message, screenshot });
      console.error(`FAIL ${width}px ${name}: ${error.message}`);
      process.exitCode = 1;
    }
  };
  const category = label => `[...document.querySelectorAll('[aria-label="检测结果分类"] button')].find(button => button.textContent.startsWith('${label} '))`;
  const checkCompleted = async (start, address) => {
    const deadline = Date.now() + 10_000;
    while (!server.requests.slice(start).some(request => request.path === '/api/check' && request.input.proxyip === address && request.completed)) {
      if (Date.now() >= deadline) throw new Error(`check did not finish: ${address}`);
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    await settle();
  };

  for (const width of [375, 1440]) {
    await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 1000, mobile: width < 768, deviceScaleFactor: 1 }, sessionId);
    await run('stored-selection-check', width, async () => {
      await open(); await click('[data-pool-mode=manage]');
      await until('document.querySelectorAll(".pool-table tbody strong").length === 2');
      await capture('pool-management', width);
      await click('.pool-table tbody input');
      const start = server.requests.length;
      await click('[data-action=check-stored]');
      await until('document.querySelector(".pool-report")?.textContent.includes("可用 1") && !document.querySelector("[aria-label=停止批量检测]")');
      assert.equal(await read('document.querySelector("#ip-input").value'), '203.0.113.10:443');
      assert.deepEqual(server.requests.slice(start).filter(item => item.path === '/api/check').map(item => item.input.proxyip), ['203.0.113.10:443']);
      assert.equal(server.requests.slice(start).filter(item => item.method === 'PUT').length, 0, 'ordinary stored detection writes the pool');
      assert.equal(await read('document.documentElement.scrollWidth <= innerWidth'), true);
      await capture('stored-check-result', width);
    });
    await run('remote-retry-lock', width, async () => {
      await open(fixture => { fixture.probeErrors['203.0.113.40:443'] = { code: 'NETWORK_ERROR', message: 'interface unavailable' }; });
      await setValue('#ip-input', '203.0.113.40:443'); await click('#main-actions button:first-child');
      await until('document.querySelector(".pool-report")?.textContent.includes("检测异常 1") && !document.querySelector("[aria-label=停止批量检测]")');
      await read(`window.__blocks.add('/api/remote-load')`);
      await click('.pool-remote-help > summary');
      await setValue('#remote-url', 'https://pool.example.test/nodes.txt');
      await click('[aria-label="从远程 URL 加载"]');
      await until(`window.__waiting.has('/api/remote-load')`);
      const start = server.requests.length;
      const retry = `[...document.querySelectorAll('.pool-report button')].find(button => button.textContent === '重新检测')`;
      assert.equal(await read(`${retry}.disabled`), true, 'remote loading leaves the old-draft retry enabled');
      await read(`${retry}.click()`); await settle();
      assert.equal(server.requests.slice(start).filter(request => request.path === '/api/check').length, 0, 'disabled retry starts another check');
      await capture('remote-retry-locked', width);
      await read(`window.__release('/api/remote-load')`);
      await until('document.querySelector("#ip-input").value === "203.0.113.99:443" && !document.querySelector("#pool-selector").disabled');
      assert.equal(await read('document.querySelector(".pool-report") === null'), true, 'remote draft retains the old report');
    });

    await run('live-report-and-view', width, async () => {
      await open(fixture => { fixture.probeErrors['203.0.113.50:443'] = { code: 'NETWORK_ERROR', message: 'interface unavailable' }; });
      const source = '203.0.113.50:443\n203.0.113.51:443\n203.0.113.52:443';
      await read(`window.__blocks.add('203.0.113.51:443'); window.__blocks.add('203.0.113.52:443')`);
      await setValue('#ip-input', source);
      assert.equal(await read('document.querySelector("[data-action=view-draft]").getAttribute("aria-pressed")'), 'true');
      const start = server.requests.length;
      await click('#main-actions button:first-child');
      await until('window.__waiting.size === 2'); await checkCompleted(start, '203.0.113.50:443');
      assert.equal(await read('document.querySelector("[data-action=view-results]").getAttribute("aria-pressed")'), 'true', 'a new batch does not open its results');
      assert.equal(await read(`${category('检测异常')}.textContent`), '检测异常 1', 'completed unknown result stays absent during the active batch');
      assert.equal(await read(`${category('未完成')}.textContent`), '未完成 2', 'completed source remains in the incomplete count');
      await read(`${category('检测异常')}.click()`); await settle();
      await capture('live-report', width);
      await click('[data-action=view-draft]');
      await read(`window.__release('203.0.113.51:443')`); await checkCompleted(start, '203.0.113.51:443');
      assert.equal(await read('document.querySelector("[data-action=view-draft]").getAttribute("aria-pressed")'), 'true', 'progress overrides the chosen draft view');
      assert.equal(await read(`${category('检测异常')}.getAttribute('aria-pressed')`), 'true', 'progress resets the selected category');
      await click('[data-action=view-results]');
      assert.equal(await read('document.querySelectorAll(".pool-result-list li").length'), 1);
      assert.ok(await read('document.querySelector(".pool-result-list").textContent.includes("203.0.113.50:443")'));
      await click('[data-action=view-draft]');
      await read(`window.__release('203.0.113.52:443')`);
      await until('!document.querySelector("[aria-label=停止批量检测]")'); await settle();
      assert.equal(await read('document.querySelector("[data-action=view-draft]").getAttribute("aria-pressed")'), 'true', 'batch completion overrides the chosen draft view');
      assert.equal(await read(`${category('检测异常')}.getAttribute('aria-pressed')`), 'true');
      assert.equal(await read(`${category('可用')}.textContent`), '可用 2');
      assert.equal(await read(`${category('未完成')}.textContent`), '未完成 0');
      assert.equal(await read('document.querySelector("#ip-input").value'), source);
      assert.equal(server.requests.slice(start).filter(request => request.path === '/api/check').length, 3);
      await capture('draft-preserved', width);
      // Starting again with the same source must reset the view even though a report already exists.
      await click('#main-actions button:first-child');
      await until('window.__waiting.size === 2 && Boolean(document.querySelector("[aria-label=停止批量检测]"))');
      assert.equal(await read('document.querySelector("[data-action=view-results]").getAttribute("aria-pressed")'), 'true', 'a repeated batch stays in the previously chosen draft view');
      assert.equal(await read(`${category('可用')}.getAttribute('aria-pressed')`), 'true', 'a repeated batch retains the previous category');
      await capture('new-run-results', width);
      await click('[aria-label=停止批量检测]'); await until('Boolean(document.querySelector("#batch-interrupt-title"))');
      await click('.btn-abandon'); await until('!document.querySelector("#batch-interrupt-title")');
    });

    await run('comment-only-clear-confirm', width, async () => {
      await open(); await click('[data-pool-mode=manage]');
      await until('document.querySelectorAll(".pool-table tbody tr").length === 2');
      await read(`[...document.querySelectorAll('.dashboard-pool-card button')].find(button => button.textContent === '编辑文本').click()`);
      await setValue('#pool-editor', '# retained note'); await click('[data-action=replace-pool]');
      await until('Boolean(document.querySelector("#pool-preview-title"))');
      const start = server.requests.length;
      await read('window.__confirms = []; window.__confirmAnswer = false');
      await click('[data-action=confirm-pool]'); await settle();
      assert.equal(await read('window.__confirms.length'), 1, 'comment-only replacement bypasses the destructive confirmation');
      assert.equal(server.requests.slice(start).filter(request => request.method === 'PUT').length, 0, 'cancelled destructive confirmation writes the pool');
      assert.equal(await read('Boolean(document.querySelector("#pool-preview-title"))'), true, 'cancelled confirmation discards the preview');
      await capture('comment-only-preview', width, false);
      server.fixture.poolWriteFailures = 1;
      await read('window.__confirmAnswer = true'); await click('[data-action=confirm-pool]');
      await until('document.querySelector(".pool-preview-modal")?.textContent.includes("未取得成功确认")');
      assert.equal(server.requests.slice(start).filter(request => request.method === 'PUT').length, 1);
      await click('[data-action=confirm-pool]');
      await until('!document.querySelector("#pool-preview-title")');
      await waitForUiRequest(server.requests, start + 1, '/api/pools/ip_pool_default', 'PUT', 200);
      assert.equal(server.fixture.poolContents.ip_pool_default, '# retained note');
      assert.equal(await read('document.querySelector("#pool-count").textContent'), '0');
      assert.equal(await read('window.__confirms.length'), 3, 'failure retry skips the destructive confirmation');
      const puts = server.requests.slice(start).filter(request => request.method === 'PUT');
      assert.equal(puts.length, 2); assert.deepEqual(puts[0].input, puts[1].input, 'retry changes the confirmed replacement');
    });
  }

  await run('partial-source-stop-resume', 1440, async () => {
    await cdp.send('Page.navigate', { url: server.base }, sessionId);
    await until('document.querySelector(".dashboard-pool-card")');
    await read('document.body.innerHTML = \'<main id="hook-root"></main>\'');
    await read(hookBundle.outputFiles[0].text);
    await read(`window.__mountHook(${JSON.stringify(server.fixture.config)})`);
    await read(`window.__hook.replaceIpText(${JSON.stringify('203.0.113.60:443\nexample.test\n203.0.113.62:443')})`); await settle();
    await read('window.__hook.handleCheckBatch()'); await settle();
    const event = async (runIndex, sourceIndex, address, sourceComplete, completed, total) => {
      await read(`window.__runs[${runIndex}].progress(${JSON.stringify({ type: 'progress', sourceIndex, sourceComplete, completed, total,
        item: { address, status: 'alive', exitFamily: 'ipv4', line: `${address},AS64500,US,v4` } })})`); await settle();
    };
    await event(0, 0, '203.0.113.60:443', true, 1, 4);
    await event(0, 1, '203.0.113.70:443', false, 2, 4);
    await read('window.__hook.handleStopBatch()'); await settle();
    assert.deepEqual(await read('window.__hook.batchReport.incomplete'), ['example.test', '203.0.113.62:443']);
    assert.equal(await read('window.__hook.batchInterrupt.checked'), 1);
    assert.equal(await read('window.__runs[0].signal.aborted'), true);
    await read('window.__hook.handleResumeBatch()'); await settle();
    assert.equal(await read('window.__runs[1].text'), 'example.test\n203.0.113.62:443');
    assert.equal(await read('window.__runs[1].concurrency'), 2);
    assert.deepEqual(await read('window.__hook.batchReport.items.map(item => item.address)'), ['203.0.113.60:443']);
    await event(0, 1, '203.0.113.71:443', true, 3, 4);
    assert.deepEqual(await read('window.__hook.batchReport.items.map(item => item.address)'), ['203.0.113.60:443'], 'late events from the aborted run enter the new report');
    await event(1, 0, '203.0.113.72:443', false, 1, 3);
    assert.deepEqual(await read('window.__hook.batchReport.items.map(item => item.address)'), ['203.0.113.60:443', '203.0.113.72:443'], 'partial-source progress is not published');
    assert.deepEqual(await read('window.__hook.batchReport.incomplete'), ['example.test', '203.0.113.62:443'], 'one result prematurely completes a multi-result source');
    await event(1, 0, '203.0.113.73:443', true, 2, 3);
    await event(1, 1, '203.0.113.62:443', true, 3, 3);
    await read(`window.__runs[1].resolve(${JSON.stringify({ total: 3, alive: 3, dead: 0, unknown: 0, invalid: [],
      items: ['203.0.113.72:443', '203.0.113.73:443', '203.0.113.62:443'].map(address => ({
        address, status: 'alive', exitFamily: 'ipv4', line: `${address},AS64500,US,v4`,
      })) })})`); await settle();
    assert.deepEqual(await read('window.__hook.batchReport.items.map(item => item.address)'), ['203.0.113.60:443', '203.0.113.72:443', '203.0.113.73:443', '203.0.113.62:443']);
    assert.deepEqual(await read('window.__hook.batchReport.incomplete'), []);
    assert.equal(await read('window.__hook.batch.data.alive'), 4);
    assert.deepEqual(await read('window.__hook.batchProgressState'), { completed: 4, total: 4 });
    assert.equal(await read('window.__hook.ipText'), '203.0.113.60:443\nexample.test\n203.0.113.62:443');
  });
} finally {
  writeFileSync(join(out, 'results.json'), JSON.stringify(results, null, 2) + '\n');
  await browser?.close(); await server.close();
}
