import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { launchBrowser } from './ui-browser.mjs';
import { createUiFixture, serveUiFixture, UI_REFERENCE_REF } from './ui-fixture.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const widths = option('--widths', '375,768,992,1440').split(',').map(Number);
if (widths.some(width => !Number.isInteger(width) || width < 280 || width > 3840)) throw new Error('Invalid widths');
const out = resolve(option('--out', '.wrangler/tmp/ui-visual'));
mkdirSync(out, { recursive: true });
const results = [];
const server = await serveUiFixture({ reference: true, ref: UI_REFERENCE_REF });
let browser;
try {
  browser = await launchBrowser();
  const { cdp } = browser;
  for (const width of widths) {
    const viewport = { width, sessions: [] };
    results.push(viewport);
    for (const [name, path] of [['main', '/reference'], ['current', '/']]) {
      Object.assign(server.fixture, createUiFixture());
      const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
      const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
      const session = { name, images: {}, styles: {} };
      viewport.sessions.push(session);
      await cdp.send('Page.enable', {}, sessionId);
      await cdp.send('Runtime.enable', {}, sessionId);
      await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 1000, mobile: width < 768, deviceScaleFactor: 1 }, sessionId);
      await cdp.send('Emulation.setTimezoneOverride', { timezoneId: 'UTC' }, sessionId);
      await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: `{
        const NativeDate = Date;
        globalThis.Date = class extends NativeDate {
          constructor(...args) { super(...(args.length ? args : ['2026-10-28T12:00:00.000Z'])); }
          static now() { return 1793188800000; }
        };
        const scrollIntoView = Element.prototype.scrollIntoView;
        Element.prototype.scrollIntoView = function(options) {
          return scrollIntoView.call(this, typeof options === 'object' ? { ...options, behavior: 'instant' } : options);
        };
      }` }, sessionId);
      await cdp.send('Page.navigate', { url: server.base + path }, sessionId);
      await cdp.until(sessionId, "document.querySelectorAll('#status-table .address-pill').length === 2 && [...document.querySelectorAll('#status-table .status-badge')].every(el => el.textContent === '可用')");
      await cdp.until(sessionId, "document.querySelector('#log-window').textContent.includes('已加载池配置')");
      await cdp.evaluate(sessionId, `(() => {
        const style = document.createElement('style');
        style.textContent = 'html{scroll-behavior:auto!important}*,*::before,*::after{animation:none!important;transition:none!important;caret-color:transparent!important}';
        document.head.append(style);
      })()`);
      const capture = async state => {
        await cdp.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: 0, y: 0 }, sessionId);
        await cdp.evaluate(sessionId, `(async () => {
          await document.fonts.ready;
          document.activeElement?.blur();
          window.scrollTo({ top: 0, behavior: 'instant' });
          // Only the build identifier is normalized; log content and all visual styles stay intact.
          const footer = document.querySelector('footer');
          if (footer) footer.textContent = 'DDNS Pro · visual-fixture';
          await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        })()`);
        session.styles[state] = await cdp.evaluate(sessionId, `(() => {
          const selectors = ['.hero h1','.hero-actions','.guide-toggle','.target-summary','.nav-tab',
            '.probe-overview-card','.card-title','.table th','.table td','.address-pill','.exit-detail','.exit-ip',
            '.latency-badge','.colo-badge','.status-badge','.exit-stack','.exit-tag','.btn-primary','.btn-success',
            '.toolbar-row','.console','.domain-binding-header','.config-mini-card','.config-details-summary',
            '.config-grid','.field','.field > span','.field > small','.field input','.config-edit-panel.active',
            '.config-section-heading','.config-card-open','.config-mini-card .meta','.config-mini-card .actions',
            '.record-badge','.switch-row','.switch','.hero','.top-nav','footer',
            '#lookup-domain','#remote-url','#manual-add-ip','#ip-input','#universal-filter','#pool-selector',
            '.config-info','.target-summary-meta','.filter-line','.filter-preview','.action-menu-trigger','.console-event',
            '.domain-binding-table-wrap','.domain-binding-select','.domain-binding-domain'];
          return Object.fromEntries(selectors.map(selector => [selector, [...document.querySelectorAll(selector)].slice(0, 4).map(element => {
            const css = getComputedStyle(element), box = element.getBoundingClientRect();
            return { text: element.textContent.trim().slice(0,80), x: box.x, y: box.y, width: box.width, height: box.height,
              ...Object.fromEntries(['fontFamily','fontSize','fontWeight','lineHeight','color','backgroundColor','padding','margin','border','borderRadius','boxShadow','gap'].map(key => [key, css[key]])) };
          })]));
        })()`);
        const { cssContentSize: size } = await cdp.send('Page.getLayoutMetrics', {}, sessionId);
        let screenshot, previous;
        for (let attempt = 0; attempt < 8; attempt++) {
          screenshot = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true,
            clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } }, sessionId);
          if (screenshot.data === previous) break;
          if (attempt === 7) throw new Error(`${width}px ${name} ${state}: screenshot did not settle`);
          previous = screenshot.data;
          await new Promise(resolve => setTimeout(resolve, 100));
        }
        const filename = `${name}-${state}-${width}.png`;
        writeFileSync(join(out, filename), Buffer.from(screenshot.data, 'base64'));
        session.images[state] = filename;
      };
      await capture('dashboard');
      await cdp.click(sessionId, '.domain-binding-header');
      await capture('bindings');
      await cdp.click(sessionId, '.domain-binding-header');
      await cdp.click(sessionId, '.nav-tab[data-page="config"]');
      await cdp.until(sessionId, "document.querySelectorAll('#page-config .config-mini-card').length === 3");
      await capture('config');
      await cdp.click(sessionId, '.config-details-summary > :first-child');
      await capture('basics');
      await cdp.click(sessionId, '.config-details-summary > :first-child');
      for (const type of ['zone', 'target']) {
        await cdp.click(sessionId, `#page-config > :has(> #${type}-edit-panel) .config-mini-card .actions button:first-of-type`);
        await cdp.until(sessionId, `Boolean(document.querySelector('#${type}-edit-panel.active input')?.offsetWidth)`);
        await capture(`${type}-editor`);
        await cdp.click(sessionId, `#${type}-edit-panel .config-edit-actions button:first-child`);
      }
      await cdp.click(sessionId, '.nav-tab[data-page="dashboard"]');
      for (const [state, selector] of [['usage-guide', '.guide-toggle'], ['filter-help', '.filter-help-btn']]) {
        await cdp.click(sessionId, selector);
        await capture(state);
        await cdp.click(sessionId, selector);
      }
      await cdp.click(sessionId, '.action-menu-trigger');
      await capture('pool-menu');
      await cdp.click(sessionId, '.action-menu-item:nth-child(3)');
      await cdp.until(sessionId, "Boolean(document.querySelector('#pool-order-list')?.offsetWidth)");
      await capture('pool-order');
      await cdp.click(sessionId, '#pool-order-cancel');
      await cdp.click(sessionId, name === 'main' ? '[onclick*="openDomainPoolOrderDialog()"]' : '#domain-order-trigger');
      await cdp.until(sessionId, "Boolean(document.querySelector('#domain-pool-order-list')?.offsetWidth)");
      await capture('binding-order');
      await cdp.click(sessionId, '#domain-pool-order-cancel');
      const select = async (selector, value) => cdp.evaluate(sessionId, `(() => {
        const select = document.querySelector(${JSON.stringify(selector)});
        select.value = ${JSON.stringify(value)};
        select.dispatchEvent(new Event('change', { bubbles: true }));
      })()`);
      await select('.target-select-overlay', name === 'main' ? '1' : 'proxy.example.com|TXT');
      await cdp.until(sessionId, "document.querySelectorAll('#status-table .status-badge.ok').length === 2 && document.querySelector('#status-table').textContent.includes('8443')");
      await capture('txt-status');
      await select('#pool-selector', 'ip_pool_trash');
      await cdp.until(sessionId, "Boolean(document.querySelector('#trash-actions button')?.offsetWidth) && document.querySelector('#pool-count').textContent === '0'");
      await capture('trash');
      server.fixture.config.authKey = 'fixture-panel-key';
      await cdp.send('Network.deleteCookies', { name: 'ddns_auth', url: server.base }, sessionId);
      await cdp.send('Page.navigate', { url: server.base + (name === 'main' ? '/reference-login' : '/') }, sessionId);
      await cdp.until(sessionId, "Boolean(document.querySelector('input[name=key]')?.offsetWidth)");
      await capture('login');
      await cdp.send('Target.closeTarget', { targetId });
      console.log(`${width}px ${name}: ${Object.keys(session.images).length} fixed states captured`);
    }
  }
  writeFileSync(join(out, 'report.json'), JSON.stringify({ reference: UI_REFERENCE_REF, generatedAt: new Date().toISOString(),
    captureConditions: { time: '2026-10-28T12:00:00.000Z', timezone: 'UTC', scale: 1, animations: 'disabled',
      footer: 'build identifier normalized', logs: 'unaltered', flows: 'no preceding mutation flows' }, results }, null, 2));
} finally {
  await browser?.close();
  await server.close();
}
