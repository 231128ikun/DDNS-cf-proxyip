/** main 与重构页面的配置编辑流程，所有写请求只到 ui-fixture 的内存替身。 */
export async function auditConfigFlow(cdp, sessionId, surface, requests, fixture) {
  const failures = [];
  const referenceDefects = [];
  const check = (condition, message) => { if (!condition) failures.push(message); };
  const read = (expression) => cdp.evaluate(sessionId, expression);
  const click = (selector) => cdp.click(sessionId, selector);
  const flush = () => read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
  const setValue = async (selector, value) => {
    await read(`(() => {
      const input = document.querySelector(${JSON.stringify(selector)});
      if (!input || !input.offsetWidth) throw new Error('Missing or hidden input: ' + ${JSON.stringify(selector)});
      input.value = ${JSON.stringify(value)};
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);
    await flush();
  };
  const zoneInput = surface === 'main' ? '#edit-zone-label' : '#zone-name-0';
  const portInput = surface === 'main' ? '#edit-target-port' : '#target-port-0';
  const modeSelect = surface === 'main' ? '#edit-target-mode' : '#target-mode-0';
  const section = (type) => `#page-config > :has(> #${type}-edit-panel)`;
  const card = (type) => `${section(type)} .config-mini-card`;
  let zoneOpenAttempts = 0;
  const openZone = async () => {
    zoneOpenAttempts++;
    await click(`${card('zone')} .actions button:first-of-type`);
    try {
      await cdp.until(sessionId, `Boolean(document.querySelector(${JSON.stringify(zoneInput)})?.offsetWidth)`);
    } catch (error) {
      throw new Error(`第 ${zoneOpenAttempts} 次打开权限编辑器失败：${error.message}`);
    }
  };
  const writes = () => requests.filter((request) => request.surface === surface && ['POST', 'PUT'].includes(request.method)
    && ['/api/config', '/api/save-config'].includes(request.path));
  const initialWrites = writes().length;

  await openZone();
  await setValue(zoneInput, '未提交备注');
  check(!(await read(`document.querySelector(${JSON.stringify(card('zone'))}).textContent.includes('未提交备注')`)), '编辑输入不应直接改动配置卡片');
  await click('#zone-edit-panel .config-edit-actions button:first-child');
  await openZone();
  check(await read(`document.querySelector(${JSON.stringify(zoneInput)}).value === '测试权限'`), '取消编辑没有丢弃未提交的修改');
  await setValue(zoneInput, '已保存到页面');
  await click('#zone-edit-panel .config-edit-actions button:last-child');
  await flush();
  check(writes().length === initialWrites, '保存到页面提前写入了 KV');
  check(await read(`document.querySelector(${JSON.stringify(card('zone'))}).textContent.includes('已保存到页面')`), '保存到页面没有更新卡片');
  check(await read('Boolean(document.querySelector("#btn-save-config")?.offsetWidth)'), '折叠基础配置时必须可以保存到 KV');

  await openZone();
  await setValue(zoneInput, '切页中的编辑草稿');
  await click('.nav-tab[data-page="dashboard"]');
  await click('.nav-tab[data-page="config"]');
  await flush();
  check(await read(`document.querySelector(${JSON.stringify(zoneInput)})?.value === '切页中的编辑草稿'`), '切换页面丢失了编辑区草稿');
  if (await read('Boolean(document.querySelector("#zone-edit-panel.active"))')) await click('#zone-edit-panel .config-edit-actions button:first-child');
  check(await read(`document.querySelector(${JSON.stringify(card('zone'))}).textContent.includes('已保存到页面')`), '切换页面丢失了已提交到页面的草稿');

  const zoneCount = await read(`document.querySelectorAll(${JSON.stringify(card('zone'))}).length`);
  await click(`${section('zone')} > :first-child button`);
  await flush();
  check(await read(`document.querySelectorAll(${JSON.stringify(card('zone'))}).length === ${zoneCount}`), '添加权限配置在保存前就创建了卡片');
  await click('#zone-edit-panel .config-edit-actions button:first-child');
  check(await read(`document.querySelectorAll(${JSON.stringify(card('zone'))}).length === ${zoneCount}`), '取消添加权限配置留下了空卡片');

  await click(`${card('target')} .actions button:first-of-type`);
  await setValue(portInput, '2053');
  await setValue(modeSelect, 'TXT');
  check(await read(`document.querySelector(${JSON.stringify(portInput)}).disabled`), 'TXT 模式的端口输入没有禁用');
  await setValue(modeSelect, 'A');
  check(await read(`document.querySelector(${JSON.stringify(portInput)}).value === '2053'`), '切回 A/AAAA 模式丢失了原端口');
  check(await read(`document.querySelector(${JSON.stringify(`${card('target')} .actions input[type="checkbox"]`)}).checked`), '维护开关的测试初始状态应为开启');
  await click(`${card('target')} .actions .switch`);
  await flush();
  const maintenanceToggleApplied = await read(`!document.querySelector(${JSON.stringify(`${card('target')} .actions input[type="checkbox"]`)}).checked`);
  check(maintenanceToggleApplied, '卡片维护开关没有响应点击');
  await click('#target-edit-panel .config-edit-actions button:last-child');
  await flush();
  check(writes().length === initialWrites, '管理域名的保存到页面提前写入了 KV');
  const enabledAfterCommit = await read(`document.querySelector(${JSON.stringify(`${card('target')} .actions input[type="checkbox"]`)}).checked`);
  if (surface === 'main' && maintenanceToggleApplied && enabledAfterCommit) {
    referenceDefects.push('main 的管理域名编辑器保留了旧的维护开关值：编辑时关闭卡片维护开关，再保存到页面，会重新开启维护。重构版必须保留用户刚切换的值。');
  } else check(!enabledAfterCommit, '提交编辑草稿覆盖了刚切换的维护开关');

  await click('.config-details-summary > :first-child');
  await cdp.until(sessionId, 'Boolean(document.querySelector("#cfg-concurrent-checks")?.offsetWidth)');
  check(await read('Boolean(document.querySelector("#cfg-auth-key")?.offsetWidth)'), '配置中心没有恢复 main 的面板密钥字段');
  await setValue('#cfg-concurrent-checks', '7');
  await setValue('#cfg-doh-timeout', '9000');
  await click('.config-details-summary > :first-child');
  check(writes().length === initialWrites, '运行参数编辑提前写入了 KV');

  const save = await read('Boolean(document.querySelector("#btn-save-config")?.offsetWidth)');
  if (save) {
    fixture.failConfigSave = true;
    await click('#btn-save-config');
    try {
      await cdp.until(sessionId, 'document.body.innerText.includes("配置保存失败") && !document.querySelector("#btn-save-config").disabled');
    } catch (error) {
      throw new Error(`${surface} 保存失败状态：${await read('JSON.stringify({ text: document.body.innerText.slice(-900), toast: document.querySelector(".toast")?.outerHTML, button: document.querySelector("#btn-save-config")?.outerHTML })')}; writes=${writes().length - initialWrites}; pending=${fixture.failConfigSave}; ${error.message}`);
    }
    check(await read(`document.querySelector(${JSON.stringify(card('zone'))}).textContent.includes('已保存到页面')`), '保存到 KV 失败后丢失了页面草稿');
    check(await read('document.querySelector("#cfg-concurrent-checks").value === "7" && document.querySelector("#cfg-doh-timeout").value === "9000"'), '保存失败后丢失了运行参数草稿');
    await click('#btn-save-config');
    await cdp.until(sessionId, '!document.querySelector("#btn-save-config")?.offsetWidth');
    const saved = writes().at(-1)?.input;
    const update = saved?.config ?? saved;
    check(writes().length === initialWrites + 2, '失败重试应只有两次明确的配置写请求');
    check(update?.zones?.[0]?.label === '已保存到页面' && Number(update?.targets?.[0]?.port) === 2053, '保存到 KV 没有合并权限配置和管理域名的页面草稿');
    check(update?.targets?.[0]?.enabled === (surface === 'main' ? enabledAfterCommit : false), '保存到 KV 丢失了维护开关改动');
    check(Number(update?.settings?.CONCURRENT_CHECKS) === 7 && Number(update?.settings?.DOH_TIMEOUT) === 9000, '统一保存没有保留浏览器并发与 DoH 超时');
    if (surface === 'current') check(update?.zones?.[0]?.apiKey === '', '编辑备注不应回传已保存的 Token');
  } else failures.push('无法完成统一保存到 KV 的流程');

  await openZone();
  await setValue(zoneInput, '等待还原的改动');
  await click('#zone-edit-panel .config-edit-actions button:last-child');
  await click('.config-details-summary > :first-child');
  await setValue('#cfg-concurrent-checks', '9');
  await setValue('#cfg-doh-timeout', '12000');
  await click('.config-details-summary > :first-child');
  await cdp.until(sessionId, 'Boolean(document.querySelector("#btn-cancel-config")?.offsetWidth)');
  await click('#btn-cancel-config');
  await cdp.until(sessionId, '!document.querySelector("#btn-cancel-config")?.offsetWidth');
  await flush();
  check(await read(`document.querySelector(${JSON.stringify(card('zone'))}).textContent.includes('已保存到页面')`), '还原改动没有回到最近一次 KV 保存的基线');
  check(await read('document.querySelector("#cfg-concurrent-checks").value === "7" && document.querySelector("#cfg-doh-timeout").value === "9000"'), '还原改动没有恢复最近保存的运行参数');
  check(writes().length === initialWrites + 2, '还原改动不应写入 KV');

  await click(`${section('zone')} > :first-child button`);
  const newZoneDomain = surface === 'main' ? '#edit-zone-base' : '#zone-domain-1';
  await cdp.until(sessionId, `Boolean(document.querySelector(${JSON.stringify(newZoneDomain)})?.offsetWidth)`);
  await setValue(newZoneDomain, 'example.com');
  await click('#zone-edit-panel .config-edit-actions button:last-child');
  await flush();
  check(await read(`document.querySelectorAll(${JSON.stringify(card('zone'))}).length === 1 && Boolean(document.querySelector('#zone-edit-panel.active'))`), '重复权限配置没有在保存到页面前被拦截');
  await click('#zone-edit-panel .config-edit-actions button:first-child');

  if (surface === 'current') {
    await click(`${section('zone')} > :first-child button`);
    await cdp.until(sessionId, 'Boolean(document.querySelector("#zone-domain-1")?.offsetWidth)');
    await setValue('#zone-domain-1', 'example.net');
    await setValue('#zone-id-1', 'fixture-second-zone');
    await click('#zone-edit-panel .config-edit-actions button:last-child');
    await flush();
    await click(`${card('target')}:nth-child(2) .actions button:first-of-type`);
    await cdp.until(sessionId, 'Boolean(document.querySelector("#target-prefix-1")?.offsetWidth)');
    await setValue('#target-edit-panel select:first-of-type', '1');
    await setValue('#target-prefix-1', 'edited');
    await click(`${card('zone')} .actions button:last-of-type`);
    await flush();
    check(await read('Boolean(document.querySelector("#target-prefix-1")?.offsetWidth)'), '删除权限配置改变了正在编辑的管理域名身份');
    await click('#target-edit-panel .config-edit-actions button:last-child');
    await flush();
    check(await read(`document.querySelectorAll(${JSON.stringify(card('target'))})[1].textContent.includes('edited.example.net')`), '删除 Zone 后的保存修改了错误的管理域名');
    check(await read(`document.querySelectorAll(${JSON.stringify(card('target'))})[0].textContent.includes('edge.example.com')`), '编辑第二个管理域名时覆盖了第一个域名');
    await click('#btn-cancel-config');
    await flush();
    check(writes().length === initialWrites + 2, '本地编辑验证产生了额外的 KV 写请求');
  }
  return { failures, referenceDefects };
}
