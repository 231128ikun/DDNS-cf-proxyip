/** Credential layout and clear/cancel regression; all requests use the in-memory fixture. */
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
      await cdp.send('Page.navigate', { url: server.base }, sessionId);
      await cdp.until(sessionId, 'Boolean(document.querySelector("#tab-config")?.offsetWidth)');
      await cdp.click(sessionId, '#tab-config');
      await cdp.until(sessionId, 'Boolean(document.querySelector(".config-details-summary")?.offsetWidth)');
      await cdp.click(sessionId, '.config-details-summary > :first-child');
      await cdp.until(sessionId, 'Boolean(document.querySelector("#cfg-tg-token")?.offsetWidth)');
      const state = `${configured ? 'configured' : 'empty'}-${width}`;
      const issues = await read(`(() => {
        const issues = [];
        const reference = document.querySelector('#cfg-doh').getBoundingClientRect();
        for (const id of ['cfg-auth-key', 'cfg-tg-token']) {
          const input = document.getElementById(id);
          const field = input.closest('.field');
          const action = field.querySelector('button');
          const box = input.getBoundingClientRect();
          const area = field.getBoundingClientRect();
          if (Math.abs(box.height - reference.height) > 1) issues.push(id + ': control height differs');
          if (!input.labels.length) issues.push(id + ': missing associated label');
          if (box.width < 140 || box.left < area.left - 1 || box.right > area.right + 1) issues.push(id + ': input does not fit field');
          if (!action) continue;
          if (action.closest('label')) issues.push(id + ': action nested inside input label');
          const range = document.createRange();
          range.selectNodeContents(action);
          if (range.getBoundingClientRect().height > parseFloat(getComputedStyle(action).lineHeight) + 1) issues.push(id + ': action label wraps');
          const button = action.getBoundingClientRect();
          if (button.left < box.right || button.right > area.right + 1) issues.push(id + ': action overlaps field');
        }
        if (document.documentElement.scrollWidth > innerWidth) issues.push('page overflows viewport');
        return issues;
      })()`);
      failures.push(...issues.map(issue => `${state}: ${issue}`));
      if (configured) {
        const action = '#cfg-tg-token';
        const clickAction = async () => {
          await read(`document.querySelector(${JSON.stringify(action)}).closest('.field').querySelector('button').click()`);
          await read('new Promise(resolve => requestAnimationFrame(resolve))');
        };
        const writes = () => server.requests.filter(item => item.path === '/api/config' && item.method === 'PUT').length;
        const before = writes();
        await clickAction();
        assert(await read('document.querySelector("#cfg-tg-token").disabled'), `${state}: clear did not disable input`);
        await clickAction();
        assert(await read('!document.querySelector("#cfg-tg-token").disabled'), `${state}: cancel did not restore input`);
        assert.equal(writes(), before, `${state}: clear/cancel wrote configuration before save`);
      }
      await read('window.scrollTo({ top: 0, behavior: "instant" })');
      const { cssContentSize: size } = await cdp.send('Page.getLayoutMetrics', {}, sessionId);
      const shot = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true,
        clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } }, sessionId);
      writeFileSync(join(out, `${state}.png`), Buffer.from(shot.data, 'base64'));
      console.log(`${state}: ${issues.length ? issues.join('; ') : 'PASS'}`);
    }
  }
  assert.deepEqual(failures, [], 'Credential layout regression');
} finally {
  await browser?.close();
  await server.close();
}
