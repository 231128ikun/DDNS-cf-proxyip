import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { launchBrowser } from './ui-browser.mjs';
import { createUiFixture, serveUiFixture } from './ui-fixture.mjs';

export async function auditPoolFlow(cdp, sessionId, base, requests, fixture, capture) {
  const original = structuredClone(fixture);
  const failures = [];
  const read = expression => cdp.evaluate(sessionId, expression);
  const click = selector => cdp.click(sessionId, selector);
  const setValue = async (selector, value) => {
    await read(`(() => { const input = document.querySelector(${JSON.stringify(selector)}); input.value = ${JSON.stringify(value)};
      input.dispatchEvent(new Event('input', { bubbles: true })); input.dispatchEvent(new Event('change', { bubbles: true })); })()`);
    await read('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
  };
  const button = text => read(`[...document.querySelectorAll('.dashboard-pool-card button')].find(b => b.textContent.trim() === ${JSON.stringify(text)})?.click()`);
  const dialog = async (selector, accept) => Promise.all([
    (async () => { await cdp.wait(sessionId, 'Page.javascriptDialogOpening'); await cdp.send('Page.handleJavaScriptDialog', { accept }, sessionId); })(),
    click(selector),
  ]);
  try {
    Object.assign(fixture, createUiFixture());
    await cdp.send('Page.navigate', { url: base }, sessionId);
    await cdp.until(sessionId, 'document.querySelectorAll("#status-table .status-badge.ok").length === 2');
    assert.ok(await read('Boolean(document.querySelector("[data-pool-mode=manage]"))'), '管理当前池入口缺失');
    const start = requests.length;
    const source = '203.0.113.40:443 # note\n203.0.113.41:443\n203.0.113.42:443\n???';
    fixture.probeErrors['203.0.113.41:443'] = { code: 'NETWORK_ERROR', message: 'interface unavailable' };
    fixture.probeErrors['203.0.113.42:443'] = { code: 'TIMEOUT', message: 'candidate timeout' };
    await setValue('#ip-input', source); await click('#main-actions button:first-child');
    await cdp.until(sessionId, 'document.querySelector(".pool-report")?.textContent.includes("可用 1") && document.querySelector("#log-window").textContent.includes("[批量] 完成")');
    assert.equal(await read('document.querySelector("#ip-input").value'), source, '检测改写原始草稿');
    assert.ok(await read('document.querySelector(".pool-report").textContent.includes("未知 1") && document.querySelector(".pool-report").textContent.includes("失效 1") && document.querySelector(".pool-report").textContent.includes("格式无效 1")'), '报告分类缺项');
    assert.ok(await read('document.querySelector("[data-action=append-input]").disabled'), '无效输入仍可直接写入');
    assert.equal(requests.slice(start).filter(item => item.method !== 'GET' && item.path !== '/api/check').length, 0, '普通检测或筛选触发写入');
    await click('[data-action=append-alive]');
    await cdp.until(sessionId, 'Boolean(document.querySelector("#pool-preview-title"))');
    assert.ok(await read('document.querySelector(".pool-preview-modal").textContent.includes("新增 1")'), '预览没有真实地址差异');
    await capture?.('append-preview');
    fixture.poolWriteFailures = 1;
    await click('[data-action=confirm-pool]');
    await cdp.until(sessionId, 'document.querySelector(".pool-preview-modal")?.textContent.includes("未取得成功确认")');
    assert.ok(await read('Boolean(document.querySelector("#pool-preview-title"))'), '失败丢失可重试的同源预览');
    fixture.poolWriteDelay = 180;
    fixture.poolListCounts.ip_pool_default = 0;
    const writeStart = requests.length;
    await read('document.querySelector("[data-action=confirm-pool]").click(); document.querySelector("[data-action=confirm-pool]").click()');
    await cdp.until(sessionId, '!document.querySelector("#pool-preview-title")');
    assert.equal(requests.slice(writeStart).filter(item => item.method === 'PUT').length, 1, '重复点击发出两个写入');
    assert.equal(requests.slice(writeStart).filter(item => item.method === 'GET' && item.path.endsWith('ip_pool_default')).length, 0, '回执后立即 GET');
    assert.ok(fixture.poolContents.ip_pool_default.includes('203.0.113.10:443') && fixture.poolContents.ip_pool_default.includes('203.0.113.40:443,AS64500,US,v4 # note'), '追加覆盖旧条目或丢元数据备注');
    assert.equal(await read('document.querySelector("#pool-count").textContent'), '3', '回执确认数量未保留');
    fixture.poolListCounts = {};
    const writes = requests.slice(start).filter(item => item.method === 'PUT' && item.path.endsWith('ip_pool_default'));
    assert.ok(writes.every(item => item.input.mode === 'append' && item.input.returnReceipt === true), '未显式请求同 mode 回执');

    fixture.poolReadOverride = '203.0.113.88:443';
    await click('[data-pool-mode=manage]');
    await click('[data-action=read-pool]');
    await cdp.until(sessionId, 'document.querySelector(".dashboard-pool-card").textContent.includes("可能尚未同步或已被其他操作修改")');
    assert.ok(await read('document.querySelector(".pool-table").textContent.includes("203.0.113.40:443")'), '差异读取覆盖确认内容');
    await button('采用读取快照');
    await cdp.until(sessionId, 'document.querySelector(".pool-table").textContent.includes("203.0.113.88:443")');
    fixture.poolReadOverride = null;
    await click('[data-action=read-pool]');
    await cdp.until(sessionId, 'document.querySelectorAll(".pool-table tbody tr").length === 3');
    await click('.pool-table input');
    await setValue('#universal-filter', 'country:US');
    assert.equal(await read('document.querySelectorAll(".pool-table input:checked").length'), 0, '筛选保留隐藏旧选择');
    assert.ok(await read('document.querySelector("[data-action=remove-selected]").disabled'), '空选择可以删除');
    await setValue('#universal-filter', 'port:0 |');
    assert.ok(await read('document.querySelector(".dashboard-pool-card").textContent.includes("筛选条件无效")'), '非法 OR 被忽略');
    await setValue('#universal-filter', ''); await click('.pool-table input');
    await click('[data-action=remove-selected]');
    await cdp.until(sessionId, 'Boolean(document.querySelector("#pool-preview-title"))');
    assert.ok(await read('document.querySelector(".pool-preview-modal").textContent.includes("仅删除明确选择")'), '删除预览仍使用追加说明');
    await click('[data-action=confirm-pool]');
    await cdp.until(sessionId, '!document.querySelector("#pool-preview-title")');
    assert.ok(!fixture.poolContents.ip_pool_default.includes('203.0.113.10:443') && fixture.poolContents.ip_pool_default.includes('203.0.113.11:443'), '删除范围不等于规范化选择');
    assert.ok(!fixture.poolContents.ip_pool_trash, '人工删除写入垃圾桶');

    await button('完整编辑'); await setValue('#pool-editor', '# standalone\n203.0.113.55:443');
    // A selector change, rather than a click, invokes the dirty-leave guard.
    await read('window.__poolConfirm = window.confirm; window.confirm = () => false');
    await setValue('#pool-selector', 'ip_pool_001');
    assert.equal(await read('document.querySelector("#pool-selector").value'), 'ip_pool_default', '取消离开仍然切池');
    await read('window.confirm = window.__poolConfirm');
    await click('[data-action=replace-pool]'); await cdp.until(sessionId, 'Boolean(document.querySelector("#pool-preview-title"))');
    assert.ok(await read('document.querySelector(".pool-preview-modal").textContent.includes("独立备注 0 → 1")'), '覆盖遗漏独立备注影响');
    await click('[data-action=confirm-pool]'); await cdp.until(sessionId, '!document.querySelector("#pool-preview-title")');
    assert.ok(fixture.poolContents.ip_pool_default.includes('# standalone'), '完整覆盖未保存备注');
    await button('完整编辑'); await setValue('#pool-editor', ''); await click('[data-action=replace-pool]');
    await cdp.until(sessionId, 'Boolean(document.querySelector("#pool-preview-title"))');
    await dialog('[data-action=confirm-pool]', false);
    assert.notEqual(fixture.poolContents.ip_pool_default, '', '空 replace 缺少独立危险确认');
    await dialog('[data-action=confirm-pool]', true);
    await cdp.until(sessionId, '!document.querySelector("#pool-preview-title")');
    assert.equal(fixture.poolContents.ip_pool_default, '', '危险确认后未清空内容');

    fixture.poolContents.ip_pool_001 = Array.from({ length: 201 }, (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250 + 1}:443`).join('\n');
    await setValue('#pool-selector', 'ip_pool_001');
    await cdp.until(sessionId, 'document.querySelector("#filter-preview")?.textContent.includes("201")');
    const cleanStart = requests.length;
    await button('洗库（写库与入桶）');
    assert.ok(await read('document.querySelector(".pool-feedback")?.textContent.includes("最多 200")'), '洗库超限未提示');
    assert.equal(requests.slice(cleanStart).filter(item => item.path.endsWith('/clean')).length, 0, '超限洗库仍发请求');
    const geometry = await read(`(() => {
      const table = document.querySelector('.pool-table'), row = table.querySelector('tbody tr');
      const check = row.querySelector('input').getBoundingClientRect(), address = row.querySelector('strong').getBoundingClientRect();
      const oneLine = element => { const range = document.createRange(); range.selectNodeContents(element); return range.getClientRects().length === 1; };
      return { overlap: check.right > address.left, checkboxSize: Math.min(check.width, check.height),
        selectionHeading: oneLine(table.querySelector('th:first-child')), statusHeading: oneLine(table.querySelector('th:last-child')),
        status: oneLine(row.querySelector('td:last-child')) };
    })()`);
    assert.deepEqual(geometry, { overlap: false, checkboxSize: 32, selectionHeading: true, statusHeading: true, status: true }, '管理表选择/状态换行或复选框遮挡地址');
    await capture?.('manage-long');
    await button('完整编辑'); await setValue('#pool-editor', '203.0.113.200:443');
    await click('[data-action=replace-pool]'); await cdp.until(sessionId, 'Boolean(document.querySelector("#pool-preview-title"))');
    assert.ok(await read('document.querySelectorAll(".pool-change-list li").length === 202'), '长预览静默截断差异');
    await read('Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {})))');
    await read('document.querySelector("[data-action=confirm-pool]").focus()');
    assert.ok(await read('(() => { const button = document.querySelector("[data-action=confirm-pool]"), box = button.getBoundingClientRect(), modal = document.querySelector(".pool-preview-modal").getBoundingClientRect(); return document.activeElement === button && box.top >= modal.top && box.bottom <= Math.min(modal.bottom, innerHeight); })()'), '长预览确认动作被弹窗裁切，无法完整聚焦可见');
    await capture?.('long-preview');
    await click('.pool-preview-modal .custom-modal-buttons button:first-child');
    await read('window.__poolConfirm = window.confirm; window.confirm = () => true');
    await button('取消完整编辑'); await read('window.confirm = window.__poolConfirm');

    fixture.poolContents.ip_pool_trash = '203.0.113.77:443,AS77,JP,v4 # dead 来自 ip_pool_001';
    await setValue('#pool-selector', 'ip_pool_trash');
    await cdp.until(sessionId, 'document.querySelector(".pool-table")?.textContent.includes("203.0.113.77")');
    assert.equal(await read('document.querySelectorAll("[data-pool-mode]").length'), 0, '垃圾桶有重复入口');
    assert.ok(await read('document.querySelector(".pool-table").textContent.includes("香港节点")'), '未显示来源池');
    await click('.pool-table input'); fixture.restoreFailures = 1;
    await click('[data-action=restore-trash]');
    await cdp.until(sessionId, 'document.querySelector(".pool-feedback")?.textContent.includes("未取得成功确认")');
    assert.equal(await read('document.querySelectorAll(".pool-table input:checked").length'), 1, '恢复失败丢选择');
    await click('[data-action=restore-trash]');
    await cdp.until(sessionId, 'document.querySelector(".pool-feedback")?.textContent.includes("已恢复 1")');
    assert.ok(fixture.poolContents.ip_pool_001.includes('203.0.113.77:443,AS77,JP,v4'), '真实 Worker 未恢复到来源池');
    assert.ok(!fixture.poolContents.ip_pool_trash.includes('203.0.113.77'), '恢复后未清理来源');
    await capture?.('trash');
    fixture.poolContents.ip_pool_trash = Array.from({ length: 1001 }, (_, i) => `10.1.${Math.floor(i / 250)}.${i % 250 + 1}:443`).join('\n');
    await click('[data-action=read-pool]');
    await cdp.until(sessionId, 'document.querySelector("#filter-preview")?.textContent.includes("1001")');
    await button('选择当前筛选结果'); const restoreStart = requests.length;
    await click('[data-action=restore-trash]');
    assert.ok(await read('document.querySelector(".pool-feedback")?.textContent.includes("最多恢复 1000")'), '恢复超限未报错');
    assert.equal(requests.slice(restoreStart).filter(item => item.path.endsWith('/restore')).length, 0, '恢复静默截断或超限发请求');

    fixture.poolContents.ip_pool_002 = '203.0.113.15:443\n???';
    await setValue('#pool-selector', 'ip_pool_002');
    await cdp.until(sessionId, 'document.querySelector(".pool-table")?.textContent.includes("203.0.113.15")');
    fixture.cleanResponse = { ok: true, poolKey: 'ip_pool_002', checked: 1, kept: 1, trashed: 0, unknown: 1, skipped: true };
    await read('window.__poolConfirm = window.confirm; window.confirm = () => true');
    await button('洗库（写库与入桶）');
    await cdp.until(sessionId, 'document.querySelector(".pool-feedback")?.textContent.includes("洗库跳过")');
    assert.ok(await read('document.querySelector(".pool-table").textContent.includes("203.0.113.15")'), '跳过洗库丢失快照');
    await click('[data-pool-mode=import]');
    assert.ok(await read('document.querySelector(".pool-import").textContent.includes("服务端规范化") && document.querySelector(".pool-import").textContent.includes("无效原始行无法恢复")'), '远程导入缺少已有规范化限制说明');
    await setValue('#remote-url', 'https://example.test/pool.txt'); fixture.remoteFailures = 1;
    await click('[aria-label="从远程 URL 加载"]');
    await cdp.until(sessionId, 'document.querySelector(".pool-feedback")?.textContent.includes("模拟远程加载失败")');
    assert.equal(await read('document.querySelector("#ip-input").value'), source, '远程失败丢原草稿');
    await click('[aria-label="从远程 URL 加载"]');
    await cdp.until(sessionId, 'document.querySelector("#ip-input").value === "203.0.113.99:443"');
    fixture.poolPreviewDelay = 240;
    await click('[data-action=append-input]');
    await setValue('#ip-input', '203.0.113.100:443');
    await read('new Promise(resolve => setTimeout(resolve, 350))');
    assert.ok(await read('!document.querySelector("#pool-preview-title")'), '草稿变化后旧预览仍可提交');
    fixture.poolPreviewDelay = 0;
    const clearStart = requests.length; await button('清空输入');
    assert.equal(requests.slice(clearStart).filter(item => item.method !== 'GET').length, 0, '清空输入发起写入');
    fixture.probeErrors['203.0.113.101:443'] = { status: 'alive', exitFamily: 'ipv4', code: 'PARTIAL_EXIT', message: 'IPv6 target HTTP 502' };
    await setValue('#ip-input', '203.0.113.101:443'); await click('#main-actions button:first-child');
    await cdp.until(sessionId, 'document.querySelector(".pool-report")?.textContent.includes("可用 1") && !document.querySelector("[aria-label=停止批量检测]")');
    assert.ok(await read('document.querySelector(".pool-report").textContent.includes("PARTIAL_EXIT") && document.querySelector(".pool-report").textContent.includes("IPv6 target HTTP 502")'), '部分出口异常没有在可用分类直接警示');
    await read('window.confirm = window.__poolConfirm');
    fixture.poolContents.ip_pool_002 = '';
    await click('[data-action=append-alive]'); await cdp.until(sessionId, 'Boolean(document.querySelector("#pool-preview-title"))');
    await click('[data-action=confirm-pool]'); await cdp.until(sessionId, '!document.querySelector("#pool-preview-title")');
    assert.equal(await read('document.querySelector("#pool-count").textContent'), '1', '复用测试未建立原容器的确认值');
    await read('window.confirm = () => true; window.prompt = () => "复用编号的新池"');
    await click('#pool-action-trigger'); await click('.action-menu-item:last-child');
    await cdp.until(sessionId, 'document.querySelector("#pool-selector").value === "ip_pool_default" && !document.querySelector("#pool-selector").disabled');
    await click('#pool-action-trigger'); await click('.action-menu-item:first-child');
    await cdp.until(sessionId, 'document.querySelector("#pool-selector").value === "ip_pool_002" && !document.querySelector("#pool-selector").disabled');
    await click('[data-pool-mode=manage]'); await click('[data-action=read-pool]');
    await cdp.until(sessionId, '!document.querySelector("[data-action=read-pool]").disabled');
    assert.equal(await read('document.querySelector("#pool-count").textContent'), '0', '删除后复用相同 key 恢复了旧确认数量');
    assert.equal(await read('document.querySelectorAll(".pool-table tbody tr").length'), 0, '新建空池仍显示已删除容器地址');
    assert.ok(await read('document.documentElement.scrollWidth <= innerWidth'), 'IP 库操作造成页面溢出');
  } catch (error) { failures.push('pool-flow: ' + error.message); }
  finally { Object.assign(fixture, original); }
  return failures;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = await serveUiFixture(); let browser;
  try {
    browser = await launchBrowser(); const { cdp } = browser;
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Page.enable', {}, sessionId); await cdp.send('Runtime.enable', {}, sessionId);
    for (const width of [375, 1440]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 1000, mobile: width < 768, deviceScaleFactor: 1 }, sessionId);
      const capture = async name => {
        await cdp.evaluate(sessionId, 'Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))).then(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))');
        const out = join(import.meta.dirname, '../.wrangler/tmp/ui-pool'); mkdirSync(out, { recursive: true });
        // Capture the real viewport before a full-page capture can temporarily resize it.
        if (name.includes('preview')) {
          const { data: viewport } = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
          writeFileSync(join(out, `${name}-viewport-${width}.png`), Buffer.from(viewport, 'base64'));
        }
        const { cssContentSize: size } = await cdp.send('Page.getLayoutMetrics', {}, sessionId);
        const { data } = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true,
          clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } }, sessionId);
        writeFileSync(join(out, `${name}-${width}.png`), Buffer.from(data, 'base64'));
      };
      const failures = await auditPoolFlow(cdp, sessionId, server.base, server.requests, server.fixture, capture);
      console.log(`${width}px pool: ${failures.join('; ') || 'passed'}`);
      if (failures.length) process.exitCode = 1;
    }
  } finally { await browser?.close(); await server.close(); }
}
