import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { launchBrowser } from './ui-browser.mjs';
import { createUiFixture, serveUiFixture, waitForUiRequest } from './ui-fixture.mjs';

const args = process.argv.slice(2);
const flag = (name, fallback) => args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const out = resolve(flag('--out', join(import.meta.dirname, '..', '.wrangler/tmp/ui-startup')));
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
  await cdp.send('Network.enable', {}, sessionId);
  await cdp.send('Network.setCacheDisabled', { cacheDisabled: true }, sessionId);
  mkdirSync(out, { recursive: true });
  const read = expression => cdp.evaluate(sessionId, expression);
  const navigate = () => cdp.send('Page.navigate', { url: base }, sessionId);
  const complete = () => cdp.until(sessionId, "document.querySelectorAll('#status-table .status-badge.ok').length === 2");
  const capture = async name => {
    const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
    writeFileSync(join(out, `${name}.png`), Buffer.from(data, 'base64'));
  };
  const selectTarget = key => read(`(() => {
    const select = document.querySelector('.target-select-overlay');
    select.value = ${JSON.stringify(key)};
    select.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);

  if (args.includes('--benchmark')) {
    const runs = Number(flag('--runs', '5'));
    assert.ok(Number.isInteger(runs) && runs >= 3 && runs <= 20, '--runs must be between 3 and 20');
    await cdp.send('Network.emulateNetworkConditions', { offline: false, latency: 80,
      downloadThroughput: 500_000, uploadThroughput: 500_000 }, sessionId);
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: `{
      const timings = window.startupTimings = {};
      new MutationObserver(() => {
        const table = document.querySelector('#status-table');
        if (table?.textContent.includes('203.0.113.10:443') && timings.dns === undefined) timings.dns = performance.now();
        const ready = table?.querySelectorAll('.status-badge.ok').length ?? 0;
        if (ready && timings.firstProbe === undefined) timings.firstProbe = performance.now();
        if (ready === 2 && timings.complete === undefined) timings.complete = performance.now();
      }).observe(document, { childList: true, subtree: true, characterData: true });
    }` }, sessionId);
    Object.assign(fixture, createUiFixture());
    fixture.configDelay = Number(flag('--config-delay', '400'));
    assert.ok(Number.isFinite(fixture.configDelay) && fixture.configDelay >= 0 && fixture.configDelay <= 60_000, 'invalid config delay');
    fixture.currentStatusDelay = 250;
    fixture.bindingListDelay = 1400;
    fixture.poolListDelay = 1400;
    fixture.probeDelay = 400;
    fixture.probeDelays['203.0.113.10:443'] = 100;
    const samples = [];
    for (let run = 0; run < runs; run++) {
      const start = requests.length;
      await navigate();
      await complete();
      samples.push(await read(`(() => {
        const entries = performance.getEntriesByType('resource');
        const resource = path => entries.find(entry => new URL(entry.name).pathname === path);
        const config = resource('/api/config');
        const dns = resource('/api/current-status');
        const probe = resource('/api/check');
        const batch = entries.find(entry => new URL(entry.name).pathname.includes('/batch-check-'));
        return { ...window.startupTimings,
          configToDns: dns.startTime - config.responseEnd,
          dnsToProbe: probe.startTime - dns.responseEnd,
          batchBeforeDns: batch.startTime < dns.responseEnd };
      })()`));
      await waitForUiRequest(requests, start, '/api/domain-bindings', 'GET', 200);
      await waitForUiRequest(requests, start, '/api/pools', 'GET', 200);
    }
    const percentile = (key, fraction) => {
      const values = samples.map(sample => sample[key]).sort((a, b) => a - b);
      return Math.round(values[Math.ceil(values.length * fraction) - 1]);
    };
    const report = { runs, network: { latencyMs: 80, bytesPerSecond: 500_000 }, configDelayMs: fixture.configDelay, samples,
      medianMs: Object.fromEntries(['dns', 'firstProbe', 'complete', 'configToDns', 'dnsToProbe'].map(key => [key, percentile(key, 0.5)])),
      p95Ms: Object.fromEntries(['dns', 'firstProbe', 'complete'].map(key => [key, percentile(key, 0.95)])) };
    writeFileSync(join(out, 'benchmark.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
  } else {
    // 同一加载组件贯穿静态启动、鉴权与代码加载；就绪后立即移除，不延迟可操作界面。
    for (const width of [375, 1440]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width === 375 }, sessionId);
      Object.assign(fixture, createUiFixture());
      fixture.entryChunkDelay = 800;
      fixture.appChunkDelay = 1600;
      fixture.configDelay = 500;
      const start = requests.length;
      await navigate();
      await cdp.until(sessionId, "Boolean(document.querySelector('#startup-loading .loading-indicator'))");
      await capture(`static-${width}`);
      await cdp.until(sessionId, "document.querySelector('#auth-loading')?.dataset.phase === 'checking'");
      assert.equal(await read("getComputedStyle(document.querySelector('.loading-indicator')).animationName"), 'loading-spin');
      assert.ok(await read("document.querySelector('#auth-loading').getAttribute('role') === 'status' && document.querySelector('.loading-indicator').getAttribute('aria-hidden') === 'true'"));
      assert.ok(await read('document.documentElement.scrollWidth <= innerWidth'), 'loading screen must fit the viewport');
      await capture(`checking-${width}`);
      await cdp.until(sessionId, "document.querySelector('#auth-loading')?.dataset.phase === 'loading-app'");
      assert.ok(!requests.slice(start).some(entry => !['/api/config', '/api/auth/login', '/api/auth/status'].includes(entry.path)), 'loading the App module must not start protected data requests');
      await capture(`loading-app-${width}`);
      await complete();
      assert.ok(await read("!document.querySelector('#startup-loading, #auth-loading')"), 'ready page must not retain the loader');
      await capture(`ready-${width}`);
    }
    await cdp.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] }, sessionId);
    Object.assign(fixture, createUiFixture());
    fixture.configDelay = 800;
    await navigate();
    await cdp.until(sessionId, "document.querySelector('#auth-loading')?.dataset.phase === 'checking'");
    assert.equal(await read("getComputedStyle(document.querySelector('.loading-indicator')).animationName"), 'none', 'reduced motion must stop the loader animation');
    await capture('reduced-motion');
    await complete();
    assert.equal(await read("getComputedStyle(document.querySelector('.app-entrance')).animationName"), 'none', 'reduced motion must stop the page entrance');
    await cdp.send('Emulation.setEmulatedMedia', { features: [] }, sessionId);

    Object.assign(fixture, createUiFixture());
    fixture.configDelay = 400;
    fixture.bindingListDelay = 1400;
    fixture.poolListDelay = 1400;
    fixture.currentStatusDelay = 650;
    fixture.batchChunkDelay = 350;
    fixture.probeDelay = 1200;
    fixture.probeDelays['203.0.113.10:443'] = 200;
    const start = requests.length;
    await navigate();
    await cdp.until(sessionId, "document.querySelector('#status-table')?.textContent.includes('203.0.113.10:443')");
    const early = await read(`({
      placeholder: Boolean(document.querySelector('#startup-loading, #auth-loading')),
      at: performance.now(),
      ready: document.querySelectorAll('#status-table .status-badge.ok').length,
      app: performance.getEntriesByType('resource').find(entry => new URL(entry.name).pathname.includes('/app-') && entry.name.endsWith('.js'))?.startTime,
      config: performance.getEntriesByType('resource').find(entry => new URL(entry.name).pathname === '/api/config')?.responseEnd,
      batch: performance.getEntriesByType('resource').find(entry => new URL(entry.name).pathname.includes('/batch-check-'))?.responseEnd,
      dns: performance.getEntriesByType('resource').find(entry => new URL(entry.name).pathname === '/api/current-status')?.responseEnd,
    })`);
    assert.equal(early.ready, 0, 'DNS records must appear before slow probe results');
    assert.equal(early.placeholder, false, 'loading screen must be removed once the app renders');
    assert.ok(early.app < early.config, 'panel code must download concurrently with the authenticated configuration request');
    assert.ok(early.batch < early.dns, 'batch code must prewarm while DNS loads');
    for (const path of ['/api/pools', '/api/domain-bindings']) {
      assert.ok(requests.slice(start).some(entry => entry.path === path && !entry.completed), `DNS must not wait for ${path}`);
    }
    const dnsRequest = requests.slice(start).find(entry => entry.path === '/api/current-status');
    assert.ok(requests.slice(start).filter(entry => entry.path === '/api/check').every(entry => entry.startedAt >= dnsRequest.completedAt), 'module prewarming must not start probes before DNS returns');
    await cdp.until(sessionId, "document.querySelectorAll('#status-table .status-badge.ok').length === 1");
    const firstProbeAt = await read('performance.now()');
    await complete();
    const completedAt = await read('performance.now()');
    assert.equal(requests.slice(start).filter(entry => entry.path === '/api/config').length, 1, 'startup must not read config twice');
    assert.equal(requests.slice(start).filter(entry => entry.path === '/api/auth/status').length, 0, 'normal startup must not add a separate auth roundtrip');
    console.log(`DNS visible at ${Math.round(early.at)}ms, first probe at ${Math.round(firstProbeAt)}ms, all probes at ${Math.round(completedAt)}ms; batch code overlaps DNS.`);
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
    console.log('Loading motion, saved order, early user selection, and unauthorized startup checks passed.');
    console.log(`Startup screenshots: ${out}`);
  }
} finally {
  await browser?.close();
  await server.close();
}
