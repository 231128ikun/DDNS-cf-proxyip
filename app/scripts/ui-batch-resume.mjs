import { createUiFixture } from './ui-fixture.mjs';

/** 中断后的继续检测只重跑未完成项，并保留已完成的清洗结果。 */
export async function auditBatchResume(cdp, sessionId, base, requests, fixture, capture) {
  const original = structuredClone(fixture);
  const failures = [];
  const read = expression => cdp.evaluate(sessionId, expression);
  const assert = (condition, message) => { if (!condition) throw new Error(message); };

  try {
    Object.assign(fixture, createUiFixture());
    fixture.config.settings.CONCURRENT_CHECKS = 2;
    fixture.probeDelay = 180;
    await cdp.send('Page.navigate', { url: base }, sessionId);
    await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.10:443")');
    const addresses = Array.from({ length: 12 }, (_, index) => `203.0.113.${index + 20}:443`);
    await read(`(() => {
      const input = document.querySelector('#ip-input');
      input.value = ${JSON.stringify(addresses.join('\n'))};
      input.dispatchEvent(new Event('input', { bubbles: true }));
    })()`);
    const start = requests.length;
    await cdp.click(sessionId, '#main-actions button:first-child');
    await cdp.until(sessionId, 'document.querySelector("#log-window")?.textContent.includes("[批量 2/")');

    assert(await read('document.querySelector("#ip-input").readOnly'), '批量检测期间仍可编辑源输入，会破坏续检状态');
    assert(await read('document.querySelector("#pool-selector").disabled'), '批量检测期间仍可切换目标 IP 池');
    assert(await read('[...document.querySelectorAll("#page-dashboard textarea, #page-dashboard .toolbar-row button")].every(element => element.readOnly || element.disabled)'),
      '批量检测期间仍有会改写输入框的控件可用');

    const completedBefore = new Set(requests.slice(start)
      .filter(request => request.path === '/api/check' && request.completed && !request.aborted)
      .map(request => request.input.proxyip));
    assert(completedBefore.size >= 2, '中断前没有记录已完成地址');

    await cdp.click(sessionId, '#main-actions button:first-child');
    await cdp.until(sessionId, 'Boolean(document.querySelector(".custom-modal-overlay .btn-continue"))');
    assert(await read('document.querySelector("#ip-input").value.trim().split("\\n").length === 12'),
      '检测中断时没有把已完成结果合并回输入框');
    await cdp.click(sessionId, '.custom-modal-overlay .btn-continue');
    await cdp.until(sessionId, 'document.querySelector("#log-window")?.textContent.includes("[批量] 完成")');

    const resumed = requests.slice(start).filter(request => request.path === '/api/check');
    for (const address of completedBefore) {
      assert(resumed.filter(request => request.input.proxyip === address && request.completed && !request.aborted).length === 1,
        `继续检测重复请求了已完成地址：${address}`);
    }
    assert(await read('document.querySelector("#ip-input").value.trim().split("\\n").length === 12'),
      '继续检测完成后没有保留完整输入数量');
    assert(await read(`document.querySelector("#ip-input").value.trim() === ${JSON.stringify(addresses.map(address => `${address},AS64500,US,v4`).join('\n'))}`),
      '继续检测完成后已完成和未完成项没有统一规范');
    await capture?.('batch-resume');
  } catch (error) {
    failures.push(`batch-resume: ${error.message}`);
    await capture?.('batch-resume-failure');
  } finally {
    Object.assign(fixture, original);
  }
  return failures;
}
