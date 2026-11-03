/** Configuration-page toggles and contextual target selection, using only the in-memory Worker fixture. */
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { launchBrowser } from './ui-browser.mjs';
import { createUiFixture, serveUiFixture, waitForUiRequest } from './ui-fixture.mjs';

const out = resolve('.wrangler/tmp/ui-header-settings');
mkdirSync(out, { recursive: true });
const server = await serveUiFixture();
let browser;
try {
  browser = await launchBrowser();
  const { cdp } = browser;
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);
  const read = expression => cdp.evaluate(sessionId, expression);
  const click = selector => cdp.click(sessionId, selector);
  const flush = () => read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
  const setValue = async (selector, value) => {
    await read(`(() => { const input = document.querySelector(${JSON.stringify(selector)}); input.value = ${JSON.stringify(value)};
      input.dispatchEvent(new Event('input', { bubbles: true })); input.dispatchEvent(new Event('change', { bubbles: true })); })()`);
    await flush();
  };
  const toggle = id => click(`#page-config label:has(#${id})`);
  const writes = () => server.requests.filter(request => request.path === '/api/config' && request.method === 'PUT');
  const probes = () => server.requests.filter(request => ['/api/current-status', '/api/check'].includes(request.path)).length;
  for (const width of [375, 1440]) {
    Object.assign(server.fixture, createUiFixture());
    await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 1000, mobile: width < 768, deviceScaleFactor: 1 }, sessionId);
    await cdp.send('Page.navigate', { url: server.base }, sessionId);
    await cdp.until(sessionId, 'Boolean(document.querySelector("#status-table")?.offsetWidth)');
    assert(await read('!document.querySelector(".hero input[role=switch]") && ![...document.querySelectorAll("input[role=switch]")].some(input => input.checkVisibility())'), 'Configuration switches leaked onto the dashboard');
    assert(await read('document.querySelectorAll(".target-select-overlay").length === 1 && Boolean(document.querySelector(".probe-overview-card .target-select-overlay")) && !document.querySelector(".hero .target-select-overlay")'), 'Target selector is not scoped to live DNS');
    await setValue('.target-select-overlay', 'proxy.example.com|TXT');
    await cdp.until(sessionId, 'document.querySelector("#status-table").textContent.includes("8443") && document.querySelectorAll("#status-table .status-badge.ok").length === 2');
    await setValue('.target-select-overlay', 'edge.example.com|A');
    await cdp.until(sessionId, 'document.querySelectorAll("#status-table .status-badge.ok").length === 2 && !document.querySelector("#status-table").textContent.includes("8443")');
    const compact = await read(`(() => { const chip=document.querySelector('.target-summary').getBoundingClientRect(); const domain=document.querySelector('.target-summary-domain').getBoundingClientRect(); const meta=document.querySelector('.target-summary-meta').getBoundingClientRect(); const title=document.querySelector('#status-overview-title').getBoundingClientRect(); return { height:chip.height, inline:Math.abs((domain.top+domain.bottom)/2-(meta.top+meta.bottom)/2)<2, aligned:innerWidth<992 || Math.abs((title.top+title.bottom)/2-(chip.top+chip.bottom)/2)<2 }; })()`);
    assert(compact.height >= 32 && compact.height <= 40 && compact.inline && compact.aligned, 'Domain chip is too tall, stacked, or misaligned with the section title');
    await click('#tab-config');
    await cdp.until(sessionId, 'Boolean(document.querySelector(".config-details-summary")?.offsetWidth)');
    await click('.config-details-summary > :first-child');
    assert(await read('document.querySelectorAll(".config-details-body input[role=switch]").length === 2 && [...document.querySelectorAll("#page-config input[role=switch]")].every(input => input.checkVisibility()) && document.querySelector(".config-task-settings").getBoundingClientRect().bottom <= document.querySelector("#cfg-check-api").getBoundingClientRect().top'), 'Task switches are not inside the expanded configuration above its parameters');
    await setValue('#cfg-concurrent-checks', '7');
    await click('#page-config > :has(> #zone-edit-panel) .config-mini-card .actions button:first-child');
    await setValue('#zone-name-0', '未提交编辑草稿');
    const assertDraft = async () => {
      assert(await read('document.querySelector("#cfg-concurrent-checks").value === "7" && document.querySelector("#zone-name-0")?.value === "未提交编辑草稿" && Boolean(document.querySelector("#btn-save-config")?.offsetWidth)'), 'Toggle write replaced unsaved settings or editor draft');
    };
    server.fixture.configSaveDelay = 400;
    server.fixture.failConfigSave = true;
    let start = server.requests.length;
    const before = writes().length;
    const probeCount = probes();
    await toggle('cfg-scheduled-enabled');
    assert(await read('[...document.querySelectorAll("#page-config input[role=switch]")].every(input => input.matches(":disabled"))'), 'Toggle permits overlapping config writes');
    await toggle('cfg-tg-enabled');
    await waitForUiRequest(server.requests, start, '/api/config', 'PUT', 500);
    await cdp.until(sessionId, '!document.querySelector("#cfg-scheduled-enabled").matches(":disabled")');
    assert.equal(writes().length, before + 1, 'A disabled switch queued another write');
    assert(await read('document.querySelector("#cfg-scheduled-enabled").checked'), 'Failed write did not keep the confirmed flag');
    assert.equal(server.fixture.config.scheduledEnabled, true);
    await assertDraft();
    start = server.requests.length;
    await toggle('cfg-scheduled-enabled');
    const saved = await waitForUiRequest(server.requests, start, '/api/config', 'PUT', 200);
    await cdp.until(sessionId, '!document.querySelector("#cfg-scheduled-enabled").matches(":disabled")');
    assert.deepEqual(saved.input, { scheduledEnabled: false }, 'Flag write overwrote unrelated config');
    assert.equal(server.fixture.config.settings.CONCURRENT_CHECKS, 32, 'Toggle persisted a local settings draft');
    assert(await read('!document.querySelector("#cfg-scheduled-enabled").checked'));
    await assertDraft();
    start = server.requests.length;
    await toggle('cfg-tg-enabled');
    const notified = await waitForUiRequest(server.requests, start, '/api/config', 'PUT', 200);
    await cdp.until(sessionId, '!document.querySelector("#cfg-tg-enabled").matches(":disabled")');
    assert.deepEqual(notified.input, { tgEnabled: true });
    await assertDraft();
    assert.equal(probes(), probeCount, 'Changing global flags reloaded DNS/probes');
    await click('#zone-edit-panel .config-edit-actions button:last-child');
    start = server.requests.length;
    const beforeFormSave = writes().length;
    await click('#btn-save-config');
    assert(await read('[...document.querySelectorAll("#page-config input[role=switch]")].every(input => input.matches(":disabled"))'), 'Form saving does not share the shared configuration write lock');
    await toggle('cfg-scheduled-enabled');
    const formSave = await waitForUiRequest(server.requests, start, '/api/config', 'PUT', 200);
    await cdp.until(sessionId, '!document.querySelector("#btn-save-config")?.offsetWidth');
    assert.equal(writes().length, beforeFormSave + 1);
    assert(!('scheduledEnabled' in formSave.input) && !('tgEnabled' in formSave.input), 'Form save can overwrite newer global flags');
    assert.equal(server.fixture.config.settings.CONCURRENT_CHECKS, 7);
    assert.equal(server.fixture.config.zones[0].label, '未提交编辑草稿');
    assert.equal(server.fixture.config.scheduledEnabled, false);
    assert.equal(server.fixture.config.tgEnabled, true);
    assert(await read('!document.querySelector("#cfg-scheduled-enabled").checked && document.querySelector("#cfg-tg-enabled").checked'));
    await click('#tab-dashboard');
    await flush();
    assert(await read('![...document.querySelectorAll("input[role=switch]")].some(input => input.checkVisibility())'), 'Switches remain visible on the dashboard');
    assert(await read('document.documentElement.scrollWidth <= innerWidth'), 'Configuration switches or live DNS toolbar overflows');
    await read('window.scrollTo({ top: 0, behavior: "instant" })');
    const { cssContentSize: size } = await cdp.send('Page.getLayoutMetrics', {}, sessionId);
    const screenshot = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true,
      clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } }, sessionId);
    writeFileSync(join(out, `dashboard-${width}.png`), Buffer.from(screenshot.data, 'base64'));
    await click('#tab-config');
    await flush();
    const configShot=await cdp.send('Page.captureScreenshot', {format:'png'}, sessionId);
    writeFileSync(join(out, `config-${width}.png`), Buffer.from(configShot.data,'base64'));
    console.log(`${width}px configuration switches: partial saves, failure recovery, shared lock, draft preservation and target context PASS`);
    Object.assign(server.fixture, createUiFixture());
    const original = server.fixture.config.targets[width === 375 ? 1 : 0];
    const prefix = `${'long-domain.'.repeat(8)}node`;
    const domain = `${prefix}.example.com`;
    server.fixture.config.targets = [{ ...original, prefix, domain }];
    server.fixture.records[`${domain}|${original.mode}`] = server.fixture.records[`${original.domain}|${original.mode}`];
    const binding = server.fixture.bindings.items.find(item => item.mode === original.mode);
    server.fixture.bindings.items = [{ ...binding, key: `${domain}|${original.mode}`, domain }];
    await cdp.send('Page.navigate', { url: server.base }, sessionId);
    await cdp.until(sessionId, `document.querySelector('.target-summary-domain')?.textContent === ${JSON.stringify(domain)}`);
    await cdp.until(sessionId, 'document.getAnimations().every(animation => animation.playState !== "running")');
    const longTarget = await read(`(() => {
      const name = document.querySelector('.target-summary-domain');
      const chip = document.querySelector('.target-summary').getBoundingClientRect();
      const badge = document.querySelector('.target-summary .record-badge').getBoundingClientRect();
      const meta = document.querySelector('.target-summary-meta').getBoundingClientRect();
      const select = document.querySelector('.target-select-overlay');
      return { height: chip.height, clipped: name.scrollWidth > name.clientWidth, nameWidth: name.clientWidth,
        fullName: name.title === ${JSON.stringify(domain)} && select.selectedOptions[0].textContent.includes(name.title),
        badge: badge.width, metadata: meta.width, arrowSpace: chip.right - meta.right,
        overflow: document.documentElement.scrollWidth > innerWidth };
    })()`);
    const longShot = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
    writeFileSync(join(out, `long-domain-${width}.png`), Buffer.from(longShot.data, 'base64'));
    assert(longTarget.height <= 40 && longTarget.clipped && longTarget.nameWidth >= 80 && longTarget.fullName
      && longTarget.badge >= 16 && longTarget.metadata >= 30 && longTarget.arrowSpace >= 20 && !longTarget.overflow,
    `Long target hides the record type, metadata, dropdown or full domain: ${JSON.stringify(longTarget)}`);
    console.log(`${width}px long ${original.mode} target: ellipsis, full name and inline metadata PASS`);
  }
} finally {
  await browser?.close();
  await server.close();
}
