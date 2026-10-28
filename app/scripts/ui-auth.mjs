import { createUiFixture } from './ui-fixture.mjs';

/** 静态面板先显示登录卡片，认证成功后 API 才可访问。 */
export async function auditAuthGate(cdp, sessionId, base, fixture, capture) {
  const original = structuredClone(fixture);
  const failures = [];
  const read = expression => cdp.evaluate(sessionId, expression);
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const setValue = async value => {
    await read(`(() => {
      const input = document.querySelector('#auth-key');
      input.value = ${JSON.stringify(value)};
      input.dispatchEvent(new Event('input', { bubbles: true }));
    })()`);
  };

  try {
    Object.assign(fixture, createUiFixture());
    fixture.config.authKey = 'fixture-panel-key';
    await cdp.send('Network.deleteCookies', { name: 'ddns_auth', url: base }, sessionId);
    await cdp.send('Page.navigate', { url: base }, sessionId);
    await cdp.until(sessionId, 'Boolean(document.querySelector("#auth-key")?.offsetWidth)');
    assert(await read('!document.querySelector("#page-dashboard")'), '未认证时已经渲染了管理面板');

    await setValue('wrong-key');
    await cdp.click(sessionId, 'form button[type="submit"]');
    await cdp.until(sessionId, 'document.querySelector("[role=alert]")?.textContent.includes("未授权")');
    assert(await read('Boolean(document.querySelector("#auth-key")?.offsetWidth)'), '错误密钥没有停留在登录卡片');

    await setValue('fixture-panel-key');
    await cdp.click(sessionId, 'form button[type="submit"]');
    await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.10:443")');
    await capture?.('auth-login');

    await cdp.send('Page.navigate', { url: `${base}/?key=fixture-panel-key` }, sessionId);
    await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.10:443")');
    assert(await read('!new URL(location.href).searchParams.has("key")'), '认证成功后没有从地址栏移除 AUTH_KEY');
    await capture?.('auth-query-login');
  } catch (error) {
    failures.push(`auth-gate: ${error.message}`);
    await capture?.('auth-gate-failure');
  } finally {
    Object.assign(fixture, original);
  }
  return failures;
}
