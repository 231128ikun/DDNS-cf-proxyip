import { createUiFixture, waitForUiRequest } from './ui-fixture.mjs';

/** 延迟分块与 PUT 成功、GET 失败的恢复边界。 */
export async function auditOrderRecovery(cdp, sessionId, base, requests, fixture, capture) {
  const original = structuredClone(fixture);
  const failures = [];
  const read = expression => cdp.evaluate(sessionId, expression);
  const click = selector => cdp.click(sessionId, selector);
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const navigate = async () => {
    await cdp.send('Page.navigate', { url: base }, sessionId);
    await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.10:443")');
  };
  const open = async kind => {
    if (kind === 'pools') {
      await click('#pool-action-trigger');
      const index = await read('[...document.querySelectorAll(".action-menu-item")].findIndex(item => item.textContent.includes("自定义池排序"))');
      await click(`.action-menu-item:nth-child(${index + 1})`);
    } else await click('#domain-order-trigger');
  };
  const run = async (name, task) => {
    Object.assign(fixture, createUiFixture());
    try { await task(); await capture?.(name); }
    catch (error) { failures.push(`${name}: ${error.message}`); await capture?.(`${name}-failure`); }
  };
  try {
    await cdp.send('Network.enable', {}, sessionId);
    await cdp.send('Network.setCacheDisabled', { cacheDisabled: true }, sessionId);
    await run('order-delayed-load', async () => {
      await navigate();
      fixture.orderChunkDelay = 800;
      fixture.probeDelay = 1500;
      await read(`(() => {
        const input = document.querySelector('#ip-input');
        input.value = ${JSON.stringify(Array.from({ length: 40 }, (_, index) => `203.0.113.${index + 1}:443`).join('\n'))};
        input.dispatchEvent(new Event('input', { bubbles: true }));
      })()`);
      await click('#main-actions button:first-child');
      await open('bindings');
      await click('#main-actions button:first-child');
      await cdp.until(sessionId, "document.querySelector('[aria-labelledby=\"batch-interrupt-title\"]')");
      await cdp.until(sessionId, 'performance.getEntriesByType("resource").some(entry => entry.name.includes("/order-dialog-") && entry.responseEnd > 0)');
      await read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
      assert(await read('document.querySelectorAll("[role=dialog]").length === 1 && !document.querySelector(".pool-order-modal")'),
        '分块加载完成后排序与中断弹窗同时显示');
      await click('[aria-labelledby="batch-interrupt-title"] .btn-abandon');
      await cdp.until(sessionId, '!document.querySelector(".custom-modal-overlay")');
      assert(await read('document.body.style.overflow !== "hidden"'), '关闭弹窗后遗留滚动锁');
      if (await read('document.documentElement.scrollHeight > innerHeight')) {
        await read('scrollTo(0, 0)');
        await cdp.send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: 180, y: 180, deltaX: 0, deltaY: 600 }, sessionId);
        await cdp.until(sessionId, 'scrollY > 0');
      }
    });
    for (const kind of ['pools', 'bindings']) await run(`${kind}-read-retry`, async () => {
      await navigate();
      const prefix = kind === 'pools' ? 'pool-order' : 'domain-pool-order';
      const route = kind === 'pools' ? '/api/pools/order' : '/api/domain-bindings/order';
      const readRoute = kind === 'pools' ? '/api/pools' : '/api/domain-bindings';
      const failureKey = kind === 'pools' ? 'poolListFailures' : 'bindingListFailures';
      const delayKey = kind === 'pools' ? 'poolListDelay' : 'bindingListDelay';
      const before = requests.filter(request => request.path === route && request.method === 'PUT').length;
      await open(kind);
      await cdp.until(sessionId, `Boolean(document.querySelector('#${prefix}-list')?.offsetWidth)`);
      await click(`#${prefix}-list [data-action="down"][data-index="0"]`);
      fixture[failureKey] = 2;
      const saveStart = requests.length;
      await click(`#${prefix}-save`);
      await waitForUiRequest(requests, saveStart, route, 'PUT', 200);
      await waitForUiRequest(requests, saveStart, readRoute, 'GET', 500);
      await cdp.until(sessionId, '!document.querySelector(".pool-order-modal")');
      const expected = kind === 'pools' ? ['ip_pool_default', 'ip_pool_002', 'ip_pool_001', 'ip_pool_trash'] : ['proxy.example.com', 'edge.example.com'];
      const keys = kind === 'pools' ? '[...document.querySelector("#pool-selector").options].map(item => item.value)'
        : '[...document.querySelectorAll(".domain-binding-name")].map(item => item.textContent.trim())';
      assert(await read(`JSON.stringify(${keys}) === ${JSON.stringify(JSON.stringify(expected))}`), `${kind} 回读失败丢失了已保存列表或顺序`);
      await cdp.until(sessionId, `Boolean(document.querySelector('#retry-${kind}')?.offsetWidth)`);
      assert(await read('document.body.innerText.includes("刷新失败")'), '回读失败没有给出明确提示');
      for (const status of [500, 200]) {
        fixture[delayKey] = 500;
        const retryStart = requests.length;
        await click(`#retry-${kind}`);
        await waitForUiRequest(requests, retryStart, readRoute, 'GET', status);
        await cdp.until(sessionId, status === 500
          ? `Boolean(document.querySelector('#retry-${kind}')?.offsetWidth)`
          : `!document.querySelector('#retry-${kind}')`);
        assert(await read(`JSON.stringify(${keys}) === ${JSON.stringify(JSON.stringify(expected))}`),
          `${kind} 延迟回读返回 ${status} 后丢失保存列表或顺序`);
        if (status === 500) assert(await read('document.body.innerText.includes("刷新失败")'), '再次回读失败后丢失错误提示');
      }
      assert(await read(`JSON.stringify(${keys}) === ${JSON.stringify(JSON.stringify(expected))}`), `${kind} 只读重试没有恢复保存顺序`);
      assert(requests.filter(request => request.path === route && request.method === 'PUT').length === before + 1,
        '回读重试重复提交排序');
    });
  } finally {
    await cdp.send('Network.setCacheDisabled', { cacheDisabled: false }, sessionId);
    Object.assign(fixture, original);
  }
  return failures;
}
