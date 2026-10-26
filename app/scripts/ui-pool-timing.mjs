import { createUiFixture, waitForUiRequest } from './ui-fixture.mjs';

/** 绑定写入与创建池使用真实 Worker 和内存 KV，检查确认缓存及刷新等待。 */
export async function auditPoolTiming(cdp, sessionId, base, requests, fixture, capture) {
  const original = structuredClone(fixture);
  const failures = [];
  const read = expression => cdp.evaluate(sessionId, expression);
  const click = selector => cdp.click(sessionId, selector);
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const settled = () => read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
  const setValue = async (selector, value) => {
    await read(`(() => {
      const input = document.querySelector(${JSON.stringify(selector)});
      if (!input?.offsetWidth) throw new Error('Missing or hidden input: ' + ${JSON.stringify(selector)});
      input.value = ${JSON.stringify(value)};
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);
    await settled();
  };
  const setPool = value => setValue('.domain-binding-select', value);
  const navigate = async () => {
    await cdp.send('Page.navigate', { url: base }, sessionId);
    await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.10:443")');
    await cdp.until(sessionId, 'document.querySelector("#pool-selector")?.options.length === 4');
  };
  const bindings = async () => {
    await click('.domain-binding-header');
    await cdp.until(sessionId, 'Boolean(document.querySelector(".domain-binding-select")?.offsetWidth)');
  };
  const configPage = async () => {
    await click('.nav-tab[data-page="config"]');
    await cdp.until(sessionId, 'Boolean(document.querySelector("#page-config .config-mini-card")?.offsetWidth)');
  };
  const saveWithFailedBindings = async () => {
    fixture.bindingListFailures = 1;
    const start = requests.length;
    await click('#btn-save-config');
    await waitForUiRequest(requests, start, '/api/config', 'PUT', 200);
    await waitForUiRequest(requests, start, '/api/domain-bindings', 'GET', 500);
    await click('.nav-tab[data-page="dashboard"]');
    await cdp.until(sessionId, 'Boolean(document.querySelector("#retry-bindings")?.offsetWidth)');
    await bindings();
    return start;
  };
  const run = async (name, task) => {
    Object.assign(fixture, createUiFixture());
    try { await task(); await capture?.(name); }
    catch (error) { failures.push(`${name}: ${error.message}`); await capture?.(`${name}-failure`); }
  };
  try {
    await run('binding-overlap-failure', async () => {
      await navigate();
      await bindings();
      fixture.bindingSaveDelay = 600;
      fixture.bindingSaveFailures = 2;
      fixture.bindingListFailures = 2;
      fixture.bindingListDelay = 200;
      const start = requests.length;
      await setPool('ip_pool_001');
      const locked = await read('[...document.querySelectorAll(".domain-binding-select")].every(select => select.matches(":disabled"))');
      if (!locked) await setPool('ip_pool_002');
      await waitForUiRequest(requests, start, '/api/domain-bindings', 'PUT', 500);
      await waitForUiRequest(requests, start, '/api/domain-bindings', 'GET', 500);
      await settled();
      await Promise.all(requests.slice(start).filter(request => !request.completed).map(request =>
        waitForUiRequest(requests, requests.indexOf(request), request.path, request.method)));
      await cdp.until(sessionId, 'Boolean(document.querySelector("#retry-bindings")?.offsetWidth)');
      assert(fixture.bindings.items[0].poolKey === 'ip_pool_default', '失败写入修改了实际保存的绑定');
      assert(await read('document.querySelector(".domain-binding-select").value === "ip_pool_default"'),
        '连续写入与回读失败后，界面仍显示未落库的乐观绑定');
      assert(locked, '绑定保存等待期间没有阻止重叠写入');
      const writes = requests.slice(start).filter(request => request.path === '/api/domain-bindings' && request.method === 'PUT');
      assert(writes.length === 1 && Object.keys(writes[0].input.mapping).join() === 'edge.example.com|A',
        '单行绑定提交了其他目标的旧映射或发生重叠保存');
      assert(await read('!document.querySelector(".domain-binding-select").matches(":disabled")'), '失败后绑定控件没有恢复');
    });
    await run('binding-confirmed-read-retry', async () => {
      await navigate();
      await bindings();
      const start = requests.length;
      await setPool('ip_pool_002');
      await waitForUiRequest(requests, start, '/api/domain-bindings', 'PUT', 200);
      await cdp.until(sessionId, '!document.querySelector(".domain-binding-select").matches(":disabled")');
      assert(fixture.bindings.items[0].poolKey === 'ip_pool_002' && fixture.bindings.items[1].poolKey === 'ip_pool_001',
        '保存单行绑定覆盖了其他目标');
      fixture.bindingListFailures = 1;
      const refreshStart = requests.length;
      await click('.domain-binding-refresh');
      await waitForUiRequest(requests, refreshStart, '/api/domain-bindings', 'GET', 500);
      await cdp.until(sessionId, 'Boolean(document.querySelector("#retry-bindings")?.offsetWidth)');
      assert(await read('document.querySelector(".domain-binding-select").value === "ip_pool_002"'), '回读失败丢失了确认保存的绑定');
      const retryStart = requests.length;
      await click('#retry-bindings');
      await waitForUiRequest(requests, retryStart, '/api/domain-bindings', 'GET', 200);
      await cdp.until(sessionId, '!document.querySelector("#retry-bindings")');
      assert(await read('document.querySelector(".domain-binding-select").value === "ip_pool_002"'), '成功回读后绑定值不一致');
      assert(Object.keys(requests.slice(start).find(request => request.method === 'PUT').input.mapping).join() === 'edge.example.com|A',
        '绑定保存仍提交整张旧映射');
    });
    await run('binding-renamed-target-read-failure', async () => {
      await navigate();
      await setValue('.target-select-overlay', 'proxy.example.com|TXT');
      await configPage();
      await click('#page-config > :has(> #target-edit-panel) .config-mini-card:nth-child(2) .actions button:first-of-type');
      await setValue('#target-prefix-1', 'renamed');
      await click('#target-edit-panel .config-edit-actions button:last-child');
      fixture.records['renamed.example.com|TXT'] = fixture.records['proxy.example.com|TXT'];
      const start = await saveWithFailedBindings();
      await cdp.until(sessionId, 'document.querySelector(".target-summary-domain")?.textContent === "renamed.example.com"');
      const writeStart = requests.length;
      await setPool('ip_pool_002');
      await waitForUiRequest(requests, writeStart, '/api/domain-bindings', 'PUT', 200);
      await cdp.until(sessionId, '!document.querySelector(".domain-binding-select").matches(":disabled")');
      await settled();
      assert(await read('document.querySelector(".target-summary-domain")?.textContent === "renamed.example.com"'),
        '绑定回读失败后更新另一行，把改名后的选中目标切换到了其他目标');
      assert(await read('document.querySelector(".target-select-overlay").value === "renamed.example.com|TXT"'),
        '改名后的目标没有出现在维护域名选择中');
      assert(await read('Boolean(document.querySelector("#retry-bindings")?.offsetWidth)'),
        '局部绑定写入清除了旧目标列表的读取失败提示');
      assert(requests.slice(start).filter(request => request.path === '/api/current-status')
        .every(request => request.query.target === 'renamed.example.com|TXT'), '局部绑定写入向另一个目标发起当前记录查询');
      const retryStart = requests.length;
      await click('#retry-bindings');
      await waitForUiRequest(requests, retryStart, '/api/domain-bindings', 'GET', 200);
      await cdp.until(sessionId, '!document.querySelector("#retry-bindings")');
      assert(await read('document.querySelector(".target-select-overlay").value === "renamed.example.com|TXT"'),
        '绑定列表恢复后没有保持改名后的选中目标');
    });
    await run('binding-deleted-target-read-failure', async () => {
      await navigate();
      await configPage();
      await click('#page-config > :has(> #target-edit-panel) .config-mini-card:nth-child(2) .actions button:last-child');
      await saveWithFailedBindings();
      const stale = '.domain-binding-select[aria-label="proxy.example.com 绑定的 IP 池"]';
      assert(await read(`document.querySelector(${JSON.stringify(stale)})?.matches(':disabled')`),
        '删除目标后的旧绑定行仍可操作，Worker 会忽略失效 key 而页面误报保存成功');
      const start = requests.length;
      await click('#retry-bindings');
      await waitForUiRequest(requests, start, '/api/domain-bindings', 'GET', 200);
      await cdp.until(sessionId, `!document.querySelector(${JSON.stringify(stale)})`);
      await cdp.until(sessionId, '!document.querySelector("#retry-bindings")');
      assert(await read(`!document.querySelector(${JSON.stringify(stale)})`), '成功回读后仍展示已删除目标的绑定控件');
      assert(requests.slice(start).every(request => request.method !== 'PUT'), '恢复旧目标列表时重复提交了绑定写入');
    });
    await run('pool-create-read-retry', async () => {
      await navigate();
      fixture.poolListDelay = 600;
      fixture.poolListFailures = 1;
      await read('window.prompt = () => "新建池回归"');
      const start = requests.length;
      await click('#pool-action-trigger');
      await click('.action-menu-item:first-child');
      await waitForUiRequest(requests, start, '/api/pools', 'POST', 200);
      await settled();
      const selectedWhileRefreshing = await read('document.querySelector("#pool-selector").value === "ip_pool_003"');
      await waitForUiRequest(requests, start, '/api/pools', 'GET', 500);
      await cdp.until(sessionId, 'Boolean(document.querySelector("#retry-pools")?.offsetWidth)');
      assert(fixture.pools.some(pool => pool.key === 'ip_pool_003' && pool.name === '新建池回归'), '真实 Worker 未创建池');
      assert(selectedWhileRefreshing, '创建成功后的旧列表刷新状态把选择退回默认池');
      assert(await read('document.querySelector("#pool-selector").value === "ip_pool_003"'), '回读失败丢失了新建池选择');
      const retryStart = requests.length;
      await click('#retry-pools');
      await waitForUiRequest(requests, retryStart, '/api/pools', 'GET', 200);
      await cdp.until(sessionId, '!document.querySelector("#retry-pools")');
      assert(await read('document.querySelector("#pool-selector").value === "ip_pool_003"'), '成功刷新后选错了池');
      assert(requests.slice(start).filter(request => request.path === '/api/pools' && request.method === 'POST').length === 1,
        '只读重试重复创建池');
    });
  } finally { Object.assign(fixture, original); }
  return failures;
}
