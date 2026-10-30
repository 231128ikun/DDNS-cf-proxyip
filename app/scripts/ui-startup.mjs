import assert from 'node:assert/strict';
import { launchBrowser } from './ui-browser.mjs';
import { createUiFixture, serveUiFixture, waitForUiRequest } from './ui-fixture.mjs';

const server = await serveUiFixture();
const { fixture, requests, base } = server;
let browser;
try {
  browser = await launchBrowser();
  const { cdp } = browser;
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);
  const read = expression => cdp.evaluate(sessionId, expression);
  const navigate = () => cdp.send('Page.navigate', { url: base }, sessionId);
  const complete = () => cdp.until(sessionId, "document.querySelectorAll('#status-table .status-badge.ok').length === 2");
  const selectTarget = key => read(`(() => {
    const select = document.querySelector('.target-select-overlay');
    select.value = ${JSON.stringify(key)};
    select.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);

  fixture.configDelay = 400;
  fixture.bindingListDelay = 1400;
  fixture.poolListDelay = 1400;
  fixture.probeDelay = 1200;
  fixture.probeDelays['203.0.113.10:443'] = 200;
  const start = requests.length;
  await navigate();
  await cdp.until(sessionId, "document.querySelector('#status-table')?.textContent.includes('203.0.113.10:443')");
  const early = await read(`({
    placeholder: Boolean(document.querySelector('#startup-loading')),
    at: performance.now(),
    ready: document.querySelectorAll('#status-table .status-badge.ok').length,
    app: performance.getEntriesByType('resource').find(entry => new URL(entry.name).pathname.includes('/app-') && entry.name.endsWith('.js'))?.startTime,
    config: performance.getEntriesByType('resource').find(entry => new URL(entry.name).pathname === '/api/config')?.responseEnd,
  })`);
  assert.equal(early.ready, 0, 'DNS records must appear before slow probe results');
  assert.equal(early.placeholder, false, 'static loading placeholder must be removed once the app renders');
  assert.ok(early.app < early.config, 'panel code must download concurrently with the authenticated configuration request');
  for (const path of ['/api/pools', '/api/domain-bindings']) {
    assert.ok(requests.slice(start).some(entry => entry.path === path && !entry.completed), `DNS must not wait for ${path}`);
  }
  await cdp.until(sessionId, "document.querySelectorAll('#status-table .status-badge.ok').length === 1");
  const firstProbeAt = await read('performance.now()');
  await complete();
  const completedAt = await read('performance.now()');
  assert.equal(requests.slice(start).filter(entry => entry.path === '/api/config').length, 1, 'startup must not read config twice');
  assert.equal(requests.slice(start).filter(entry => entry.path === '/api/auth/status').length, 0, 'normal startup must not add a separate auth roundtrip');
  console.log(`DNS visible at ${Math.round(early.at)}ms, first probe at ${Math.round(firstProbeAt)}ms, all probes at ${Math.round(completedAt)}ms; no wait for pool bindings.`);
  await waitForUiRequest(requests, start, '/api/domain-bindings', 'GET', 200);
  await waitForUiRequest(requests, start, '/api/pools', 'GET', 200);

  Object.assign(fixture, createUiFixture());
  fixture.bindings.items.reverse();
  fixture.bindingListDelay = 600;
  fixture.probeDelay = 900;
  await navigate();
  await cdp.until(sessionId, "document.querySelector('#status-table')?.textContent.includes('203.0.113.10:443')");
  await cdp.until(sessionId, "document.querySelector('.target-summary-domain')?.textContent === 'proxy.example.com'");
  await complete();
  assert.ok(await read("document.querySelector('#status-table').textContent.includes('[2001:db8::10]:8443')"), 'late binding order must select the saved first target, not restore stale A results');

  Object.assign(fixture, createUiFixture());
  fixture.bindingListDelay = 1200;
  const choiceStart = requests.length;
  await navigate();
  await cdp.until(sessionId, "document.querySelector('.target-summary-domain')?.textContent === 'edge.example.com'");
  await selectTarget('proxy.example.com|TXT');
  await cdp.until(sessionId, "document.querySelector('#status-table')?.textContent.includes('[2001:db8::10]:8443')");
  await waitForUiRequest(requests, choiceStart, '/api/domain-bindings', 'GET', 200);
  await read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
  assert.equal(await read("document.querySelector('.target-summary-domain').textContent"), 'proxy.example.com', 'late bindings must not overwrite a user selection');

  Object.assign(fixture, createUiFixture());
  fixture.config.authKey = 'fixture-panel-key';
  const authStart = requests.length;
  await navigate();
  await cdp.until(sessionId, "Boolean(document.querySelector('#auth-key')?.offsetWidth)");
  assert.ok(await read("!document.querySelector('#page-dashboard')"), 'unauthenticated users must not see the panel');
  assert.deepEqual(requests.slice(authStart).map(entry => entry.path), ['/api/config'], '401 must show login without a reload loop or downstream data requests');
  console.log('Saved order, early user selection, and unauthorized startup checks passed.');
} finally {
  await browser?.close();
  await server.close();
}
