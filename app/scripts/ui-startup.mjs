import assert from 'node:assert/strict';
import { launchBrowser } from './ui-browser.mjs';
import { serveUiFixture } from './ui-fixture.mjs';

const fixture = await serveUiFixture();
fixture.fixture.probeDelay = 1200;
let browser;
try {
  browser = await launchBrowser();
  const { cdp } = browser;
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: `{
    const original = window.fetch.bind(window);
    window.fetch = async (...args) => {
      const response = await original(...args);
      if (String(args[0]).endsWith('/api/auth/status')) {
        await new Promise(resolve => setTimeout(resolve, 400));
        performance.mark('auth-ready');
      }
      return response;
    };
  }` }, sessionId);
  await cdp.send('Page.navigate', { url: fixture.base }, sessionId);
  await cdp.until(sessionId, "document.querySelector('#status-table')?.textContent.includes('203.0.113.10:443')");
  const early = await cdp.evaluate(sessionId, `({
    placeholder: Boolean(document.querySelector('#startup-loading')),
    at: performance.now(),
    ready: document.querySelectorAll('#status-table .status-badge.ok').length,
    app: performance.getEntriesByType('resource').find(entry => new URL(entry.name).pathname.includes('/app-') && entry.name.endsWith('.js'))?.startTime,
    auth: performance.getEntriesByName('auth-ready')[0]?.startTime,
  })`);
  assert.equal(early.ready, 0, 'DNS records must appear before slow probe results');
  assert.equal(early.placeholder, false, 'static loading placeholder must be removed once the app renders');
  assert.ok(early.app < early.auth, 'panel code must download concurrently with authentication');
  await cdp.until(sessionId, "document.querySelectorAll('#status-table .status-badge.ok').length === 2");
  const completedAt = await cdp.evaluate(sessionId, 'performance.now()');
  console.log(`DNS visible ${Math.round(completedAt - early.at)}ms before slow probe completion; panel download overlaps authentication.`);
} finally {
  await browser?.close();
  await fixture.close();
}
