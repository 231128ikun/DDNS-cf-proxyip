/** 解析实况与任意探測共用表格；只操作本地模拟数据。 */
export async function auditDashboardFlow(cdp, sessionId, surface, fixture) {
  const failures = [];
  const check = (condition, message) => { if (!condition) failures.push(message); };
  const read = (expression) => cdp.evaluate(sessionId, expression);
  const click = (selector) => cdp.click(sessionId, selector);
  const flush = () => read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
  const setValue = async (selector, value) => {
    await read(`(() => { const input = document.querySelector(${JSON.stringify(selector)});
      input.value = ${JSON.stringify(value)};
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true })); })()`);
    await flush();
  };
  const lookupButton = surface === 'baseline' ? '[onclick="lookupDomain()"]' : '.ddns-lookup-form button:first-of-type';
  const refreshButton = surface === 'baseline' ? '[onclick="refreshStatus()"]' : '.ddns-lookup-form button:last-of-type';
  const select = '.target-select-overlay';
  if (surface === 'current') {
    fixture.maintenanceResponse = { ok: true, changed: true, insufficient: true, errors: ['模拟维护错误'], probeErrors: 2,
      results: [{ domain: 'edge.example.com', mode: 'A', poolKey: 'ip_pool_default', poolName: '默认池',
        dnsUpdated: true, added: 2, deleted: 1, probeErrors: 2, error: '模拟目标错误' }] };
    try {
      await click('.dashboard-console-card > button');
      await cdp.until(sessionId, 'document.querySelector("#log-window").textContent.includes("[维护] 完成")');
      const log = await read('document.querySelector("#log-window").textContent');
      for (const text of ['edge.example.com (A)', '+2 / -1', '模拟目标错误', '模拟维护错误', '可用 IP 不足']) {
        check(log.includes(text), '维护信息没有写入工作台日志：' + text);
      }
      check(await read('document.querySelector(".dashboard-console-card h2").textContent.trim().endsWith("工作台")'), '日志区域应明确命名为工作台');
      check(await read('!document.querySelector(".maintenance-summary, .maintenance-result")'), '工作台外仍保留另一套维护日志');
      check(await read('Math.abs(document.querySelector("#log-window").scrollHeight - document.querySelector("#log-window").clientHeight - document.querySelector("#log-window").scrollTop) < 2'), '工作台日志没有自动滚动到最新结果');
    } finally { fixture.maintenanceResponse = null; }
    const remove = '#main-actions button:last-child';
    const canRemove = await read(`!document.querySelector('${remove}').disabled`);
    check(canRemove, '空输入应允许点击移除，并在本地提示');
    if (canRemove) {
      await click(remove);
      await flush();
      check(await read('document.querySelector("#log-window").textContent.includes("❌ 内容为空")'), '空输入没有给出原版提示');
      check(await read('!performance.getEntriesByType("resource").some(entry => new URL(entry.name).pathname === "/api/pools/ip_pool_default")'), '空输入不应发起池写请求');
      await setValue('#ip-input', '203.0.113.10:443');
      await Promise.all([
        (async () => {
          await cdp.wait(sessionId, 'Page.javascriptDialogOpening');
          await cdp.send('Page.handleJavaScriptDialog', { accept: false }, sessionId);
        })(), click(remove),
      ]);
      check(await read('document.querySelector("#ip-input").value === "203.0.113.10:443"'), '取消移除不应改变输入');
      check(await read('!performance.getEntriesByType("resource").some(entry => new URL(entry.name).pathname === "/api/pools/ip_pool_default")'), '取消移除不应发起池写请求');
      await setValue('#ip-input', '');
    }
    await click('.action-menu-trigger');
    check(await read('document.querySelector(".action-menu-item:last-child").disabled'), '默认池的删除菜单应禁用');
    await click('.action-menu-trigger');
  }
  check(await read('document.querySelector("#status-table").textContent.includes("AS64500")'), '当前 DNS 地址没有显示探测出口信息');
  check(await read('document.querySelector("#status-table").textContent.includes("SJC")'), '可信探针返回的 Colo 没有显示');
  await setValue(select, surface === 'baseline' ? '1' : 'proxy.example.com|TXT');
  await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("8443")');
  check(await read('document.querySelectorAll("#status-table tr").length === 2'), 'TXT 列表没有逐地址显示');
  await setValue(select, surface === 'baseline' ? '0' : 'edge.example.com|A');
  await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.10:443")');
  await click('#status-table .address-pill');
  await flush();
  check(await read('document.querySelector("#ip-input").value === ""'), '复制维护地址不应修改池输入框');

  await setValue('#lookup-domain', '203.0.113.99:443');
  await click(lookupButton);
  await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.99:443")');
  check(await read('document.querySelectorAll("#status-table tr").length === 1'), '任意探测没有替换统一表格中的当前记录');
  await click('#status-table td:last-child button');
  await flush();
  check(await read('document.querySelector("#ip-input").value.includes("203.0.113.99:443,AS64500,US,v4")'), '探测结果添加到输入框时丢失 ASN、国家和出口栈');
  await click(refreshButton);
  await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.10:443")');
  check(await read('document.querySelectorAll("#status-table tr").length === 2'), '刷新后没有恢复当前 DNS 记录');

  fixture.failRecordSave = true;
  await setValue('#manual-add-ip', '203.0.113.42:443');
  await click(surface === 'baseline' ? '[onclick="manualAddIP()"]' : '#manual-add-section button');
  await cdp.until(sessionId, 'performance.getEntriesByType("resource").some(entry => /\\/api\\/add-(a-)?record$/.test(new URL(entry.name).pathname) && entry.responseEnd > 0)');
  await flush();
  check(await read('document.querySelector("#manual-add-ip").value === "203.0.113.42:443"'), 'DNS 添加失败后丢失了待重试的输入');

  await setValue('#lookup-domain', '203.0.113.55:443');
  await click(lookupButton);
  await cdp.until(sessionId, 'document.querySelector("#status-table").textContent.includes("203.0.113.55:443")');
  await click(surface === 'baseline' ? '[onclick="manualAddIP()"]' : '#manual-add-section button');
  await cdp.until(sessionId, 'document.querySelector("#status-table").textContent.includes("203.0.113.42:443")');
  check(await read('document.querySelectorAll("#status-table tr").length === 3 && document.querySelector("#manual-add-ip").value === ""'), '添加成功后没有清空已提交输入并恢复当前 DNS 记录');
  await Promise.all([
    (async () => {
      await cdp.wait(sessionId, 'Page.javascriptDialogOpening');
      await cdp.send('Page.handleJavaScriptDialog', { accept: true }, sessionId);
    })(),
    click(`#status-table tr:last-child td:last-child ${surface === 'baseline' ? 'a' : 'button'}`),
  ]);
  await cdp.until(sessionId, 'document.querySelectorAll("#status-table tr").length === 2 && !document.querySelector("#status-table").textContent.includes("203.0.113.42:443")');

  if (surface === 'current') {
    fixture.probeDelay = 250;
    await setValue('#lookup-domain', '203.0.113.88:443');
    await click(lookupButton);
    await click(refreshButton);
    await new Promise((resolve) => setTimeout(resolve, 350));
    check(await read('document.querySelector("#status-table").textContent.includes("203.0.113.10:443")'), '旧探测响应覆盖了刷新后的当前记录');
    fixture.probeDelay = 0;
    fixture.probeErrors['203.0.113.89:443'] = { code: 'TIMEOUT', message: '检测接口超时，节点状态未知' };
    try {
      await setValue('#lookup-domain', '203.0.113.89:443');
      await click(lookupButton);
      await cdp.until(sessionId, 'document.querySelector("#status-table .status-reason")?.textContent.includes("检测接口超时")');
      check(await read('document.querySelector("#status-table .status-badge.warn")?.textContent === "未知（超时）"'), '真实接口异常未显示为未知');
      check(await read('document.querySelector("#status-table .status-reason")?.checkVisibility()'), '未知原因只藏在提示中，没有直接展示');
    } finally {
      delete fixture.probeErrors['203.0.113.89:443'];
    }
    await click(refreshButton);
    await cdp.until(sessionId, 'document.querySelectorAll("#status-table .status-badge.ok").length === 2');
  }
  return failures;
}

/** 绑定先返回、配置后返回时，首次检测必须使用保存的 A/AAAA 端口。 */
export async function auditTargetStartup(cdp, sessionId, base, requests, fixture) {
  const failures = [];
  const previousPort = fixture.config.targets[0].port;
  const previousDelay = fixture.configDelay;
  const previousStatusDelay = fixture.currentStatusDelay;
  const start = requests.length;
  fixture.config.targets[0].port = 2053;
  fixture.configDelay = 600;
  fixture.currentStatusDelay = 120;
  try {
    await cdp.send('Page.navigate', { url: `${base}/` }, sessionId);
    await cdp.until(sessionId, 'document.querySelector("#status-table")?.textContent.includes("203.0.113.10:2053")');
    await cdp.until(sessionId, 'document.querySelectorAll("#status-table .status-badge.ok").length === 2');
    const checked = requests.slice(start).filter((request) => request.path === '/api/check' && request.input.proxyip.endsWith(':2053')).map((request) => request.input.proxyip).sort();
    const dns = requests.slice(start).filter(request => request.path === '/api/current-status');
    if (dns.length !== fixture.config.targets.length || dns.some(request => request.startedAt >= Math.min(...dns.map(item => item.completedAt)))) {
      failures.push('首次加载没有同时发起全部域名的解析实况请求');
    }
    if (JSON.stringify(checked) !== JSON.stringify(['203.0.113.10:2053', '[2001:db8::10]:2053'])) {
      failures.push(`配置延迟返回时首次探测的端口错误：${checked.join('、') || '没有探测请求'}`);
    }
    if (!(await cdp.evaluate(sessionId, 'document.querySelectorAll("#status-table .status-badge.ok").length === 2'))) {
      failures.push('配置延迟返回后，非 443 端口的当前记录没有显示探测结果');
    }
  } finally {
    fixture.config.targets[0].port = previousPort;
    fixture.configDelay = previousDelay;
    fixture.currentStatusDelay = previousStatusDelay;
  }
  return failures;
}
