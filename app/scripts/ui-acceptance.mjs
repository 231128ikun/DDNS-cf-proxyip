import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { launchBrowser } from './ui-browser.mjs';
import { createUiFixture, serveUiFixture, waitForUiRequest } from './ui-fixture.mjs';

const out = resolve(import.meta.dirname, '../.wrangler/tmp/ui-acceptance');
mkdirSync(out, { recursive: true });
const server = await serveUiFixture();
let browser;
const results = [];
try {
  browser = await launchBrowser();
  const { cdp } = browser;
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId); await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('Emulation.setFocusEmulationEnabled', { enabled: true }, sessionId);
  const read = expression => cdp.evaluate(sessionId, expression);
  const until = expression => cdp.until(sessionId, expression);
  const click = selector => cdp.click(sessionId, selector);
  const set = (selector, text) => read(`(() => { const input = document.querySelector(${JSON.stringify(selector)}); input.value = ${JSON.stringify(text)}; input.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  const capture = async name => {
    await read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
    const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
    writeFileSync(join(out, name + '.png'), Buffer.from(data, 'base64'));
  };
  for (const width of [375, 1440]) {
    Object.assign(server.fixture, createUiFixture());
    server.fixture.poolContents.ip_pool_default = '203.0.113.10:443,AS64500,JP,v4 # 保留备注';
    await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 1000, mobile: width < 768, deviceScaleFactor: 1 }, sessionId);
    await cdp.send('Page.navigate', { url: server.base }, sessionId);
    await until('document.querySelector("#pool-editor") && !document.querySelector("[data-action=read-pool]").disabled && document.querySelector("#log-window").textContent.includes("已加载")');
    await read('window.__confirmCalls = []; window.__confirmAnswer = true; window.confirm = message => { window.__confirmCalls.push(message); return window.__confirmAnswer; }');
    assert.equal(await read('Boolean(document.querySelector(".pool-table"))'), false, '普通库仍以表格展示');
    const logs = await read('document.querySelector("#log-window").textContent');
    assert.ok(logs.includes('正在加载配置'));
    assert.ok(!logs.includes('[解析]') && !logs.includes('203.0.113.10'), '解析实况重复写入日志');
    const mutationStart = server.requests.length;
    await set('#pool-editor', '203.0.113.10:443,AS64500,JP,v4 # 保留备注\n203.0.113.20:443');
    await click('[data-action=replace-pool]');
    await until('Boolean(document.querySelector("#pool-preview-title"))');
    await click('[data-action=confirm-pool]');
    await waitForUiRequest(server.requests, mutationStart, '/api/pools/ip_pool_default', 'PUT', 200);
    await until('!document.querySelector("#pool-preview-title")');
    assert.ok(server.fixture.poolContents.ip_pool_default.includes('203.0.113.20:443'));
    const clearStart = server.requests.length;
    await set('#pool-editor', '# 仅保留备注');
    await click('[data-action=replace-pool]');
    await until('Boolean(document.querySelector("#pool-preview-title"))');
    await read('window.__confirmAnswer = false');
    await click('[data-action=confirm-pool]');
    assert.equal(server.requests.slice(clearStart).filter(item => item.method === 'PUT').length, 0, '取消清空后仍写库');
    assert.ok(await read('window.__confirmCalls.some(message => message.includes("清空"))'));
    await read('window.__confirmAnswer = true');
    await click('.pool-preview-modal .custom-modal-buttons .btn-outline-secondary');
    await until('!document.querySelector("#pool-preview-title")');
    await click('[data-action=read-pool]');
    await until('!document.querySelector("[data-action=read-pool]").disabled');
    await read('document.querySelector(".dashboard-pool-card").scrollIntoView({ block: "start", behavior: "instant" })');
    await capture('pool-' + width);

    await click('[data-pool-mode=import]');
    await set('#ip-input', '203.0.113.99:443');
    const addStart = server.requests.length;
    await click('[data-action=append-pool]');
    await waitForUiRequest(server.requests, addStart, '/api/pools/ip_pool_default', 'PUT', 200);
    await until('!document.querySelector("[data-action=append-pool]").disabled');
    assert.equal(await read('Boolean(document.querySelector("#pool-preview-title"))'), false, '普通追加多余确认');
    assert.ok(server.fixture.poolContents.ip_pool_default.includes('203.0.113.99:443'));
    assert.ok(server.fixture.poolContents.ip_pool_default.includes('保留备注'));
    await click('#main-actions .btn-primary');
    await until('document.querySelector("[data-action=view-results]") && document.querySelector("#main-actions .btn-primary")?.disabled === false');
    assert.equal(await read('document.querySelector("#ip-input").value'), '203.0.113.99:443');
    assert.ok(await read('document.querySelector(".pool-report").textContent.includes("可用 1")'));
    assert.equal(await read('document.documentElement.scrollWidth > innerWidth'), false);
    await capture('results-' + width);

    await click('[data-page=config]');
    await until('Boolean(document.querySelector("#cfg-probe-ipv4"))');
    assert.equal(await read('document.querySelector("#cfg-probe-ipv4").closest("details").open'), false);
    assert.equal(await read('document.querySelector("#cfg-probe-ipv4").value'), '');
    assert.equal(await read('document.querySelector("#cfg-probe-ipv6").value'), '');
    await read('document.querySelector("#cfg-probe-ipv4").closest("details").open = true; document.querySelector("#cfg-probe-ipv4").closest("details").parentElement.closest("details").open = true');
    await set('#cfg-probe-ipv4', 'https://custom.example.test/json');
    const configStart = server.requests.length;
    await click('#btn-save-config');
    await waitForUiRequest(server.requests, configStart, '/api/config', 'PUT', 200);
    assert.equal(server.fixture.config.probeIpv4Url, 'https://custom.example.test/json');
    await read('document.querySelector("#cfg-probe-ipv4").scrollIntoView({ block: "center", behavior: "instant" })');
    await capture('config-' + width);
    await click('[aria-label="版本更新历史"]');
    await until('!document.querySelector("#version-notes").hidden');
    assert.ok(await read('document.querySelector("#version-notes").textContent.includes("修复原生检测")'));
    assert.equal(await read('document.querySelector("#version-notes").getBoundingClientRect().left < 0 || document.querySelector("#version-notes").getBoundingClientRect().right > innerWidth'), false);
    await capture('version-' + width);
    await click('[aria-label="关闭更新历史"]');
    results.push({ width, passed: true });
    console.log(`PASS ${width}px: text edit, destructive cancellation, one-click append, check, quiet logs, probe override and version history`);
  }
} catch (error) {
  process.exitCode = 1; results.push({ passed: false, error: error.stack }); console.error(error);
} finally {
  writeFileSync(join(out, 'results.json'), JSON.stringify(results, null, 2));
  await browser?.close(); await server.close();
}
