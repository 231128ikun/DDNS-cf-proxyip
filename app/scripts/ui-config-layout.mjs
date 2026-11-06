/** Compact settings and credential actions; all requests use the in-memory fixture. */
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { launchBrowser } from './ui-browser.mjs';
import { createUiFixture, serveUiFixture } from './ui-fixture.mjs';

const args = process.argv.slice(2);
const out = resolve(args.includes('--out') ? args[args.indexOf('--out') + 1] : '.wrangler/tmp/ui-config-layout');
mkdirSync(out, { recursive: true });
const server = await serveUiFixture();
const failures = [];
let browser;
try {
  browser = await launchBrowser();
  const { cdp } = browser;
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);
  const read = expression => cdp.evaluate(sessionId, expression);
  for (const width of [375, 768, 992, 1440]) {
    for (const configured of [false, true]) {
      Object.assign(server.fixture, createUiFixture());
      if (configured) {
        server.fixture.config.authKey = 'fixture-panel-key';
        server.fixture.config.tgToken = 'fixture-telegram-token';
        await cdp.send('Network.setCookie', { name: 'ddns_auth', value: 'fixture-panel-key', url: server.base }, sessionId);
      }
      await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 1000, mobile: width < 768, deviceScaleFactor: 1 }, sessionId);
      const loaded = cdp.wait(sessionId, 'Page.loadEventFired');
      await cdp.send('Page.navigate', { url: server.base }, sessionId);
      await loaded;
      await cdp.until(sessionId, 'Boolean(document.querySelector("#tab-config")?.offsetWidth)');
      await cdp.until(sessionId, 'Boolean(document.querySelector(".target-summary-domain")?.offsetWidth)');
      const prominentTarget = await read('document.querySelector(".target-summary").getBoundingClientRect().height <= 40 && parseFloat(getComputedStyle(document.querySelector(".target-summary-domain")).fontSize) >= 14');
      assert(prominentTarget, `Target chooser is not compact and readable at ${width}px`);
      await cdp.click(sessionId, '#tab-config');
      await cdp.until(sessionId, 'Boolean(document.querySelector(".config-details-summary")?.offsetWidth)');
      await cdp.click(sessionId, '.config-details-summary > :first-child');
      await cdp.until(sessionId, 'Boolean(document.querySelector("#cfg-tg-token")?.offsetWidth)');
      await cdp.until(sessionId, '[...document.querySelectorAll(".ui-icon")].filter(icon => icon.checkVisibility()).every(icon => { const box = icon.getBBox(); return box.width > 0 && box.height > 0; })');
      const state = `${configured ? 'configured' : 'empty'}-${width}`;
      const issues = await read(`(() => {
        const issues = [];
        const basics = document.querySelector('.config-details').getBoundingClientRect();
        if (innerWidth >= 992 && basics.height > 800) issues.push('basic settings exceed a compact desktop panel');
        if (innerWidth >= 992 && basics.top > 200) issues.push('header pushes settings below the first screen');
        const reference = document.querySelector('#cfg-doh').getBoundingClientRect();
        if (document.querySelector('#zone-config-title').textContent.trim() !== '域名权限配置') issues.push('permissions heading does not match the domain task');
        if (document.querySelector('#target-config-title').textContent.trim() !== '维护域名管理') issues.push('maintained domain heading does not match the domain task');
        if (document.querySelectorAll('#page-config input[role="switch"]').length !== 2 || document.querySelector('.hero input[role="switch"], .config-options')) issues.push('task settings are duplicated or outside configuration');
        if (document.querySelectorAll('#target-config-title').length !== 1 || document.querySelectorAll('#target-edit-panel').length !== 1) issues.push('domain settings entry is duplicated');
        if (document.querySelectorAll('#page-config .config-mini-card .domain-binding-select').length !== 2) issues.push('pool binding is not integrated with maintained domains');
        if (document.querySelector('#page-dashboard .domain-binding-card')) issues.push('dashboard still has a second binding panel');
        const columns = getComputedStyle(document.querySelector('#maintained-domains .config-card-grid')).gridTemplateColumns.split(' ').length;
        if (innerWidth >= 992 && columns < 2) issues.push('desktop domains are not grouped in cards');
        if (innerWidth < 600 && columns !== 1) issues.push('phone domain cards do not use a single column');
        if (document.querySelector('.field button, .secret-state')) issues.push('routine fields contain auxiliary actions or badges');
        if (document.querySelector('.config-details .switch-slider')) issues.push('routine settings contain decorative switches');
        for (const id of ['cfg-auth-key', 'cfg-tg-token']) {
          const input = document.getElementById(id);
          const field = input.closest('.field');
          const box = input.getBoundingClientRect();
          const area = field.getBoundingClientRect();
          if (Math.abs(box.height - reference.height) > 1) issues.push(id + ': control height differs');
          if (!input.labels.length) issues.push(id + ': missing associated label');
          if (innerWidth > 768 && id === 'cfg-auth-key' && Math.abs(box.top - document.getElementById("cfg-tg-token").getBoundingClientRect().top) > 1) issues.push(id + ': paired inputs are not aligned');
          if (box.width < 140 || box.left < area.left - 1 || box.right > area.right + 1) issues.push(id + ': input does not fit field');
        }
        if (document.documentElement.scrollWidth > innerWidth) issues.push('page overflows viewport');
        return issues;
      })()`);
      failures.push(...issues.map(issue => `${state}: ${issue}`));
      await read('window.scrollTo({ top: 0, behavior: "instant" })');
      const { cssContentSize: size } = await cdp.send('Page.getLayoutMetrics', {}, sessionId);
      const shot = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true,
        clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } }, sessionId);
      writeFileSync(join(out, `${state}.png`), Buffer.from(shot.data, 'base64'));
      if (configured && [375, 1440].includes(width)) {
        const draftStart = server.requests.length;
        await cdp.click(sessionId, '#maintained-domains .domain-binding-actions button:first-child');
        await cdp.until(sessionId, 'Boolean(document.querySelector("#target-edit-panel.active")?.offsetWidth)');
        assert(await read('!document.querySelector("#target-edit-panel .domain-binding-select").disabled'), 'New target cannot preselect a pool');
        await read('const select = document.querySelector("#target-edit-panel .domain-binding-select"); select.value = "ip_pool_002"; select.dispatchEvent(new Event("change", {bubbles:true})); select.scrollIntoView({block:"center",behavior:"instant"})');
        const draftShot = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
        writeFileSync(join(out, `new-target-pool-${width}.png`), Buffer.from(draftShot.data, 'base64'));
        await cdp.click(sessionId, '#target-edit-panel .config-edit-actions button:last-child');
        await cdp.until(sessionId, 'document.querySelectorAll("#maintained-domains .config-mini-card").length === 3');
        assert(await read('[...document.querySelectorAll("#maintained-domains .config-mini-card .domain-binding-select")].at(-1).value === "ip_pool_002"'), 'Pool selection did not survive target confirmation');
        assert(!server.requests.slice(draftStart).some(request => request.method === 'PUT'), 'Selecting a draft pool wrote to storage');
        assert.equal(server.fixture.config.targets.length, 2, 'Confirming a card wrote configuration before Save');
        await cdp.click(sessionId, '#btn-save-config');
        await cdp.until(sessionId, '!document.querySelector("#btn-save-config")?.offsetWidth');
        assert.equal(server.fixture.config.targets.length, 3);
        const created = server.fixture.config.targets[2];
        assert.equal(server.fixture.bindingMapping[created.domain + '|' + created.mode], 'ip_pool_002');
        await cdp.until(sessionId, '[...document.querySelectorAll("#maintained-domains .config-mini-card .domain-binding-select")].at(-1)?.value === "ip_pool_002"');
        assert(!server.requests.slice(draftStart).some(request => request.method === 'GET' && request.path === '/api/domain-bindings'), 'Saving a target depends on rereading all bindings');
        server.fixture.bindingListFailures = 1;
        await cdp.click(sessionId, '[aria-label="刷新域名池绑定"]');
        await cdp.until(sessionId, 'document.querySelector("#maintained-domains").textContent.includes("模拟读取失败")');
        assert(await read('[...document.querySelectorAll("#maintained-domains .config-mini-card .domain-binding-select")].at(-1).value === "ip_pool_002"'), 'Failed reread lost the confirmed pool binding');
        assert(await read('![...document.querySelectorAll("#maintained-domains .config-mini-card .domain-binding-select")].at(-1).disabled'), 'Failed reread disabled a confirmed binding');
        await read('document.querySelector("#maintained-domains .config-mini-card:last-child").scrollIntoView({block:"center",behavior:"instant"})');
        const savedShot = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
        writeFileSync(join(out, `saved-target-pool-${width}.png`), Buffer.from(savedShot.data, 'base64'));
        await cdp.click(sessionId, '#maintained-domains .config-mini-card:last-child .actions button:last-child');
        await cdp.click(sessionId, '#btn-save-config');
        await cdp.until(sessionId, '!document.querySelector("#btn-save-config")?.offsetWidth');
        await cdp.click(sessionId, '#page-config > :has(> #zone-edit-panel) .config-mini-card .actions button:first-child');
        await read('document.querySelector("#zone-domain-0").value = "example.net"; document.querySelector("#zone-domain-0").dispatchEvent(new Event("input", { bubbles: true }))');
        await cdp.click(sessionId, '#zone-edit-panel .config-edit-actions button:last-child');
        await read('new Promise(resolve => requestAnimationFrame(resolve))');
        assert(await read('[...document.querySelectorAll("#maintained-domains .domain-binding-select")].every(select => !select.disabled)'), 'Renamed target cannot stage a pool binding');
        assert(await read('document.querySelector("#maintained-domains .domain-binding-name").textContent === "edge.example.net"'), 'Cards do not show the effective domain after a permission edit');
        await cdp.click(sessionId, '#btn-cancel-config');
        await cdp.until(sessionId, '!document.querySelector("#btn-cancel-config")?.offsetWidth');
        await read('document.querySelector("#cfg-check-timeout").value = "16000"; document.querySelector("#cfg-check-timeout").dispatchEvent(new Event("input", { bubbles: true }))');
        await cdp.click(sessionId, '#btn-save-config');
        await cdp.until(sessionId, '!document.querySelector("#btn-save-config")?.offsetWidth');
        assert.equal(server.fixture.config.tgToken, 'fixture-telegram-token', 'Saving blank Telegram input changed its stored credential');
        assert.equal(server.fixture.config.authKey, 'fixture-panel-key', 'Saving blank panel input changed its stored credential');
      }
      console.log(`${state}: ${issues.length ? issues.join('; ') : 'PASS'}`);
    }
  }
  for (const width of [375, 1440]) {
    Object.assign(server.fixture, createUiFixture());
    const zone = server.fixture.config.zones[0];
    server.fixture.config.zones.push(...Array.from({ length: 18 }, (_, index) => ({ ...zone,
      name: `权限 ${index + 2}`, label: `权限 ${index + 2}`, baseDomain: `zone${index}.example.test`, zoneId: `fixture-zone-${index + 2}` })));
    const baseTarget = server.fixture.config.targets[0];
    server.fixture.config.targets = Array.from({ length: 18 }, (_, index) => {
      const prefix = index === 17 ? `${'long-'.repeat(12)}last` : `node-${index}`;
      return { ...baseTarget, prefix, domain: `${prefix}.example.com` };
    });
    server.fixture.bindings.items = server.fixture.config.targets.map(target => ({ key: `${target.domain}|A`,
      domain: target.domain, mode: 'A', poolKey: 'ip_pool_default', poolName: '默认池', enabled: true }));
    await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 1000, mobile: width < 768, deviceScaleFactor: 1 }, sessionId);
    await cdp.send('Page.navigate', { url: server.base }, sessionId);
    await cdp.until(sessionId, 'Boolean(document.querySelector("#tab-config")?.offsetWidth)');
    await cdp.click(sessionId, '#tab-config');
    await cdp.until(sessionId, 'document.querySelectorAll("#maintained-domains .config-mini-card").length === 18');
    const metrics = await read(`(() => {
      const grids = [...document.querySelectorAll('.config-card-grid')];
      return { overflow: document.documentElement.scrollWidth > innerWidth,
        grids: grids.map(grid => ({ height: grid.clientHeight, content: grid.scrollHeight })) };
    })()`);
    assert.equal(metrics.overflow, false, `Long domain overflow at ${width}px`);
    for (const grid of metrics.grids) {
      if (width >= 992) assert(grid.content > grid.height && grid.height <= 520, 'Desktop domain lists do not cap and scroll');
      else assert(grid.content <= grid.height + 1, 'Phone domain lists create a nested scrolling window');
    }
    await cdp.click(sessionId, '[data-target-index="17"] .actions button:first-of-type');
    await cdp.until(sessionId, 'Boolean(document.querySelector("#target-prefix-17")?.offsetWidth)');
    assert.equal(await read('document.querySelector("#target-prefix-17").value'), server.fixture.config.targets[17].prefix, 'Scrolled card edited a different domain');
    console.log(`many-domains-${width}: PASS (19 permissions, 18 targets, long names and scrolled editing)`);
  }
  assert.deepEqual(failures, [], 'Credential layout regression');
} finally {
  await browser?.close();
  await server.close();
}
