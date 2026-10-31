import assert from 'node:assert/strict';
import { launchBrowser } from './ui-browser.mjs';
import { serveUiFixture } from './ui-fixture.mjs';

// 小行高复现 Linux 字体下的问题；两侧覆盖相同属性，不依赖本机字体安装。
const fixture = await serveUiFixture({ reference: true });
let browser;
try {
  browser = await launchBrowser();
  const { cdp } = browser;
  const heights = [];
  for (const path of ['/reference', '/']) {
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('Page.navigate', { url: fixture.base + path }, sessionId);
    await cdp.until(sessionId, "Boolean(document.querySelector('.nav-tab'))");
    heights.push(await cdp.evaluate(sessionId, `(() => {
      for (const button of document.querySelectorAll('.nav-tab')) button.style.lineHeight = '16px';
      return document.querySelector('.top-nav').getBoundingClientRect().height;
    })()`));
    await cdp.send('Target.closeTarget', { targetId });
  }
  assert.equal(heights[1], heights[0], `navigation natural height: current ${heights[1]}, main ${heights[0]}`);
  console.log('Navigation follows main natural line height.');
} finally {
  await browser?.close();
  await fixture.close();
}
