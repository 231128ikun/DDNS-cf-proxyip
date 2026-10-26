import { createUiFixture, waitForUiRequest } from './ui-fixture.mjs';

/** 配置恢复、保存后继续编辑和首次检测的异步边界。 */
export async function auditConfigTiming(cdp, sessionId, base, requests, fixture, capture) {
  const original = structuredClone(fixture);
  const failures = [];
  const read = expression => cdp.evaluate(sessionId, expression);
  const click = selector => cdp.click(sessionId, selector);
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const setValue = async (selector, value) => {
    await read(`(() => {
      const input = document.querySelector(${JSON.stringify(selector)});
      if (!input?.offsetWidth) throw new Error('Missing or hidden input: ' + ${JSON.stringify(selector)});
      input.value = ${JSON.stringify(value)};
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);
    await read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
  };
  const navigate = async () => {
    await cdp.send('Page.navigate', { url: base }, sessionId);
    await cdp.until(sessionId, 'document.querySelector(".target-summary-domain")?.textContent === "edge.example.com"');
  };
  const ready = () => cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.10:2053")');
  const configPage = async () => {
    await click('.nav-tab[data-page="config"]');
    await cdp.until(sessionId, 'Boolean(document.querySelector("#page-config .config-mini-card")?.offsetWidth)');
  };
  const reset = () => {
    Object.assign(fixture, createUiFixture());
    fixture.config.targets[0].port = 2053;
    fixture.config.settings.CONCURRENT_CHECKS = 4;
  };
  const run = async (name, task) => {
    reset();
    try {
      await task();
      await capture?.(name);
    } catch (error) {
      failures.push(`${name}: ${error.message}`);
      await capture?.(`${name}-failure`);
    }
  };
  try {
    await run('config-startup', async () => {
      fixture.configDelay = 800;
      await navigate();
      await setValue('#ip-input', Array.from({ length: 40 }, (_, index) => `203.0.113.${index + 1}:443`).join('\n'));
      assert(await read('document.querySelector("#main-actions button:first-child").disabled'), '首次配置未就绪仍可启动批量检测');
      await ready();
      fixture.probeDelay = 100;
      fixture.probeMetrics.peak = 0;
      const start = requests.length;
      await click('#main-actions button:first-child');
      await cdp.until(sessionId, 'document.querySelector("#log-window")?.textContent.includes("[批量] 完成")');
      assert(fixture.probeMetrics.peak === 4, `保存的并发 4 未生效，峰值 ${fixture.probeMetrics.peak}`);
      assert(requests.slice(start).filter(request => request.path === '/api/check').length === 40, '批量检测没有逐地址执行完整输入');
    });
    await run('config-retry', async () => {
      fixture.configFailures = 1;
      await navigate();
      await configPage();
      await click('.nav-tab[data-page="dashboard"]');
      await ready();
      assert(await read('document.querySelectorAll("#status-table .status-badge.ok").length === 2'),
        '重试后没有恢复当前记录探测');
    });
    await run('config-new-draft', async () => {
      await navigate();
      await ready();
      await configPage();
      await click('#page-config > :has(> #zone-edit-panel) .config-mini-card .actions button:first-child');
      await setValue('#zone-name-0', '已保存基线');
      await click('#zone-edit-panel .config-edit-actions button:last-child');
      fixture.configDelay = 800;
      await click('#btn-save-config');
      await cdp.until(sessionId, '!document.querySelector("#btn-save-config")?.offsetWidth');
      await click('#page-config > :has(> #zone-edit-panel) .config-mini-card .actions button:first-child');
      await setValue('#zone-name-0', '保存后新的草稿');
      await read('new Promise(resolve => setTimeout(resolve, 1000))');
      assert(await read('document.querySelector("#zone-edit-panel.active #zone-name-0")?.value === "保存后新的草稿"'), '保存后回读覆盖了新草稿或关闭编辑器');
    });
    await run('config-saving-lock', async () => {
      await navigate();
      await ready();
      await configPage();
      await click('#page-config > :has(> #zone-edit-panel) .config-mini-card .actions button:first-child');
      await setValue('#zone-name-0', '本次提交');
      await click('#zone-edit-panel .config-edit-actions button:last-child');
      await click('#page-config > :has(> #zone-edit-panel) .config-mini-card .actions button:first-child');
      fixture.configSaveDelay = 1200;
      const start = requests.length;
      await click('#btn-save-config');
      await cdp.until(sessionId, 'document.querySelector("#btn-save-config")?.textContent.includes("保存中")');
      const locked = await read('[...document.querySelectorAll("#page-config input, #page-config select, #page-config textarea, #page-config button")].every(input => input.matches(":disabled"))');
      await waitForUiRequest(requests, start, '/api/config', 'PUT', 200);
      assert(locked, 'PUT 等待期间仍可修改配置，成功响应会覆盖这些编辑');
      await cdp.until(sessionId, '!document.querySelector("#btn-save-config")?.offsetWidth');
      assert(fixture.config.zones[0].label === '本次提交', '本次配置未落库');
      await click('#page-config > :has(> #zone-edit-panel) .config-mini-card .actions button:first-child');
      await setValue('#zone-name-0', '下一份草稿');
      assert(await read('document.querySelector("#zone-name-0").value === "下一份草稿"'), '保存完成后控件没有恢复编辑');
    });
    await run('config-target-row-identity', async () => {
      const third = { ...fixture.config.targets[0], prefix: 'spare', domain: 'spare.example.com' };
      fixture.config.targets.push(third);
      fixture.records['spare.example.com|A'] = fixture.records['edge.example.com|A'];
      fixture.records['renamed.example.com|TXT'] = fixture.records['proxy.example.com|TXT'];
      await navigate();
      await ready();
      await setValue('.target-select-overlay', 'proxy.example.com|TXT');
      await cdp.until(sessionId, 'document.querySelector(".target-summary-domain")?.textContent === "proxy.example.com"');
      await configPage();
      await click('#page-config > :has(> #target-edit-panel) .config-mini-card:first-child .actions button:last-child');
      await click('#page-config > :has(> #target-edit-panel) .config-mini-card:first-child .actions button:nth-of-type(1)');
      await setValue('#target-prefix-0', 'renamed');
      await click('#target-edit-panel .config-edit-actions button:last-child');
      const start = requests.length;
      await click('#btn-save-config');
      await waitForUiRequest(requests, start, '/api/config', 'PUT', 200);
      await waitForUiRequest(requests, start, '/api/domain-bindings', 'GET', 200);
      await read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
      assert(await read('document.querySelector(".target-summary-domain")?.textContent === "renamed.example.com"'),
        '删除前项并改名后没有保留原选中的目标行');
      await click('.nav-tab[data-page="dashboard"]');
      await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.10:443")');
      const lookups = requests.slice(start).filter(request => request.path === '/api/current-status');
      assert(lookups.length > 0 && lookups.every(request => request.query.target === 'renamed.example.com|TXT'),
        '改名后的当前记录查询转向了另一个目标');
      assert(requests.slice(start).find(request => request.path === '/api/config' && request.method === 'PUT').input.targets
        .every(target => !('sourceKey' in target)), '前端行身份进入了持久化配置请求');
    });
    await run('config-target-cache', async () => {
      await navigate();
      await ready();
      await configPage();
      await click('#page-config > :has(> #target-edit-panel) .config-mini-card .actions button:nth-of-type(1)');
      await setValue('#target-prefix-0', 'changed');
      await click('#target-edit-panel .config-edit-actions button:last-child');
      fixture.records['changed.example.com|A'] = fixture.records['edge.example.com|A'];
      await click('#btn-save-config');
      await cdp.until(sessionId, '!document.querySelector("#btn-save-config")?.offsetWidth');
      await click('.nav-tab[data-page="dashboard"]');
      await cdp.until(sessionId, 'document.querySelector(".target-summary-domain")?.textContent === "changed.example.com"');
      await ready();
      assert(await read('document.querySelector(".target-summary-meta").textContent.includes("2053")'), '保存目标后丢失了共享配置端口');
    });
    await run('config-legacy-target', async () => {
      delete fixture.config.targets[0].prefix;
      delete fixture.config.targets[0].baseDomain;
      fixture.records['example.com|A'] = fixture.records['edge.example.com|A'];
      await navigate();
      await ready();
      await configPage();
      await click('#page-config > :has(> #zone-edit-panel) .config-mini-card .actions button:first-child');
      await setValue('#zone-name-0', '只修改权限备注');
      await click('#zone-edit-panel .config-edit-actions button:last-child');
      const start = requests.length;
      await click('#btn-save-config');
      await waitForUiRequest(requests, start, '/api/config', 'PUT', 200);
      await waitForUiRequest(requests, start, '/api/domain-bindings', 'GET', 200);
      await read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
      assert(fixture.config.targets[0].domain === 'edge.example.com', '修改其他配置时把旧格式的完整目标域名改写成了根域名');
      assert(await read('document.querySelector(".target-summary-domain")?.textContent === "edge.example.com"'), '保存旧格式配置后选中了另一个域名');
    });
  } finally {
    Object.assign(fixture, original);
  }
  return failures;
}
