#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { launchBrowser } from './ui-browser.mjs';
import { createUiFixture, serveUiFixture, UI_REFERENCE_REF } from './ui-fixture.mjs';
import { auditConfigFlow } from './ui-config-flow.mjs';
import { auditDashboardFlow, auditTargetStartup } from './ui-dashboard-flow.mjs';
import { auditOrderFlow, auditOrderEdges } from './ui-order-flow.mjs';
import { auditConfigTiming } from './ui-config-timing.mjs';
import { auditOrderRecovery } from './ui-order-recovery.mjs';
import { auditPoolTiming } from './ui-pool-timing.mjs';

const args = process.argv.slice(2);
const flag = (key, fallback) => args.includes(`--${key}`) ? args[args.indexOf(`--${key}`) + 1] : fallback;
const out = resolve(flag('out', '.wrangler/tmp/ui-parity'));
const widths = flag('widths', '375,768,992,1440').split(',').map(Number);
if (widths.some((width) => !Number.isInteger(width) || width < 280 || width > 3840)) throw new Error('--widths 必须是 280–3840 之间的整数');
const referenceRef = flag('ref', UI_REFERENCE_REF);
const selectors = {
  hero: '.hero', target: '.target-summary', nav: '.top-nav',
  overview: '#page-dashboard > .card', workbench: '#page-dashboard .col-lg-7 > .card',
  bindings: '.domain-binding-card', consoleCard: '#page-dashboard .col-lg-5 > .card', console: '#log-window',
};

const measure = (selectors) => {
  const boxes = Object.fromEntries(Object.entries(selectors).map(([name, selector]) => {
    const element = document.querySelector(selector);
    if (!element) return [name, null];
    const box = element.getBoundingClientRect();
    const css = getComputedStyle(element);
    return [name, { x: box.x + scrollX, y: box.y + scrollY, width: box.width, height: box.height,
      radius: css.borderRadius, background: css.backgroundColor }];
  }));
  return { boxes, overflow: document.documentElement.scrollWidth > innerWidth,
    poolOrder: [...(document.querySelector('#pool-selector')?.options || [])].map((option) => option.value),
    basicsOpen: Boolean(document.querySelector('.config-details[open]')),
    statusCellDisplay: document.querySelector('#status-table td') ? getComputedStyle(document.querySelector('#status-table td')).display : null,
    statusHeadingWidth: document.querySelector('.status-table thead')?.getBoundingClientRect().width ?? 0,
    configCards: document.querySelectorAll('#page-config .config-mini-card').length,
    settingsIds: [...document.querySelectorAll('.config-details-body input[type="number"]')].map((input) => input.id),
    editorLabels: [...document.querySelectorAll('.config-edit-panel.active .field > span:first-child')].map((element) => element.textContent.trim()),
    toolbarCenters: [...document.querySelectorAll('.toolbar-row > *')].map((element) => {
      const box = element.getBoundingClientRect();
      return box.y + box.height / 2;
    }),
    statusTables: document.querySelectorAll('#page-dashboard table:not(.domain-binding-table-wrap table)').length };
};

function differences(reference, current, width) {
  const failures = [];
  if (current.overflow) failures.push('页面横向溢出');
  if (JSON.stringify(reference.poolOrder) !== JSON.stringify(current.poolOrder)) failures.push('池选择器没有保留服务端保存的顺序');
  if (current.statusTables !== reference.statusTables) failures.push(`解析实况有 ${current.statusTables} 个展示表，应共用 main 的 ${reference.statusTables} 个表`);
  if (current.statusCellDisplay !== reference.statusCellDisplay || current.statusHeadingWidth < 100) failures.push('解析实况未保留 main 的行列表格与可见表头');
  if (Math.abs(reference.boxes.overview.height - current.boxes.overview.height) > 40) failures.push(`解析实况卡片高度偏差 ${Math.round(current.boxes.overview.height - reference.boxes.overview.height)}px`);
  if (current.toolbarCenters.length !== 4 || Math.max(...current.toolbarCenters) - Math.min(...current.toolbarCenters) > 2) failures.push('远程加载输入框与操作按钮没有保留在同一行');
  for (const key of ['workbench', 'bindings', 'consoleCard']) {
    const expected = reference.boxes[key];
    const actual = current.boxes[key];
    if (!expected || !actual) { failures.push(`${key} 缺失`); continue; }
    if (Math.abs(expected.width - actual.width) > 2) failures.push(`${key} 宽度偏差 ${Math.round(actual.width - expected.width)}px`);
  }
  const r = reference.boxes;
  const c = current.boxes;
  if (c.target.radius !== r.target.radius) failures.push('维护目标卡片圆角与 main 不同');
  if (width > 768 && Math.abs(c.target.width - r.target.width) > 4) failures.push(`维护目标摘要宽度偏差 ${Math.round(c.target.width - r.target.width)}px`);
  if (c.nav.radius !== r.nav.radius || c.nav.background !== r.nav.background) failures.push('导航容器没有保留 main 的独立按钮布局');
  if (Math.abs(c.console.height - r.console.height) > 2) failures.push(`控制台高度 ${c.console.height}px，main 为 ${r.console.height}px`);
  if (width >= 992 && c.bindings && c.workbench) {
    if (Math.abs(c.bindings.x - c.workbench.x) > 2) failures.push('域名绑定没有留在 IP 管理左栏');
    if (c.bindings.y < c.workbench.y + c.workbench.height) failures.push('域名绑定没有位于 IP 管理下方');
    if (Math.abs(c.consoleCard.y - c.workbench.y) > 2) failures.push('控制台与 IP 管理没有顶端对齐');
  }
  return failures;
}

async function capture(cdp, session, width, state, failures) {
  await cdp.evaluate(session.sessionId, "window.scrollTo({top: 0, behavior: 'instant'}); new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))");
  const metrics = await cdp.send('Page.getLayoutMetrics', {}, session.sessionId);
  const size = metrics.cssContentSize;
  const screenshot = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true,
    clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } }, session.sessionId);
  const filename = `${session.name}-${state}-${width}.png`;
  writeFileSync(join(out, filename), Buffer.from(screenshot.data, 'base64'));
  const data = await cdp.evaluate(session.sessionId, `(${measure})({})`);
  if (data.overflow) failures.push(`${session.name} ${state} 页面横向溢出`);
  session.images ??= {};
  session.images[state] = filename;
  return data;
}

async function captureConfigStates(cdp, session, width, failures) {
  await cdp.click(session.sessionId, '.config-details-summary > :first-child');
  await cdp.until(session.sessionId, "document.querySelector('.config-details[open]')");
  await capture(cdp, session, width, 'basics', failures);
  await cdp.click(session.sessionId, '.config-details-summary > :first-child');
  const section = (type) => `#page-config > :has(> #${type}-edit-panel)`;
  for (const type of ['zone', 'target']) {
    await cdp.click(session.sessionId, `${section(type)} .config-mini-card .actions button:first-of-type`);
    await cdp.until(session.sessionId, `Boolean(document.querySelector('#${type}-edit-panel.active input')?.offsetWidth)`);
    session.editors ??= {};
    session.editors[type] = await capture(cdp, session, width, `${type}-editor`, failures);
    await cdp.click(session.sessionId, `#${type}-edit-panel .config-edit-actions button:first-child`);
    await cdp.until(session.sessionId, `!document.querySelector('#${type}-edit-panel.active')`);
  }
}

async function captureBindings(cdp, session, width, failures) {
  await cdp.click(session.sessionId, '.domain-binding-header');
  await cdp.until(session.sessionId, 'document.querySelectorAll(".domain-binding-card[open] tbody select").length === 2');
  session.bindings = await cdp.evaluate(session.sessionId, `
    [...document.querySelectorAll('.domain-binding-card tbody tr')].map(row => ({
      domain: row.querySelector('.domain-binding-name')?.textContent.trim(),
      pool: row.querySelector('select')?.value,
      options: [...row.querySelectorAll('option')].map(option => option.value),
    }))`);
  await capture(cdp, session, width, 'bindings', failures);
  await cdp.click(session.sessionId, '.domain-binding-header');
}

function writeReport(results, fatal) {
  const report = { reference: referenceRef, generatedAt: new Date().toISOString(), flows: args.includes('--flows'),
    referenceDefects: [...new Set(results.flatMap((result) => result.sessions.flatMap((session) => session.referenceDefects ?? [])))],
    coverage: ['运行面板', '域名池绑定展开与当前选择', '配置卡片', '基础配置展开与运行参数顺序', '权限编辑器', '管理域名编辑器',
      ...(args.includes('--flows') ? ['已列出的解析与配置保存流程', '浏览器并发与 DoH 超时的编辑、保存失败重试与还原',
        '两种排序的本地草稿、取消、背景关闭、保存失败重试与完整顺序', '重构版排序的 Escape、焦点约束与归还、固定系统池',
        '重构版 24 个长名称自定义池、20 个长域名的滚动与取消，以及零或单条目的提示', '重构版配置延迟返回时首次检测非 443 端口',
        '重构版共享配置失败恢复、保存期间完整锁定、保存后新草稿与目标缓存更新', '重构版删除前项并改名后保持目标行选择与记录查询',
        '重构版首次配置就绪前检测禁用与配置并发执行', '重构版绑定串行保存、部分映射更新与连续失败时保留确认缓存',
        '重构版真实 Worker 新建池后保持选择、回读失败保留新池与只读重试',
        '重构版延迟排序分块与中断弹窗互斥', '重构版排序写入成功、连续回读失败仍保留列表与只读重试；等待 HTTP 请求实际完成及成功'] : [])],
    limits: ['布局断言和人工截图对照不等于整站像素等价', '配置、绑定与池创建读取使用真实 Worker 和内存 KV，探测、DNS 与排序保存使用本地替身；未验证真实部署和 Cloudflare 写入',
      '保留更高的文字对比度、至少 32px 的点击目标以及 unknown 的安全语义', '测试阶段未启用鉴权，旧鉴权不在等价覆盖范围', '排序弹窗补充 Escape 和焦点约束，未复制 main 缺少键盘约束的行为'],
    ...(fatal ? { fatal } : {}), results };
  writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 2));
  const escape = (value) => String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  const names = { dashboard: '运行面板', bindings: '域名池绑定展开', 'bindings-order': '自定义绑定池排序', 'pools-order': '自定义池排序',
    'bindings-order-long': '长域名排序边界', 'pools-order-long': '长池名称排序边界', config: '配置中心', basics: '基础配置展开', 'zone-editor': '权限编辑器', 'target-editor': '管理域名编辑器' };
  const content = results.map((result) => `<section><h2>${result.width}px · ${result.failures.length ? '存在差异' : '已覆盖检查通过'}</h2>
    ${result.failures.length ? `<ul>${result.failures.map((failure) => `<li>${escape(failure)}</li>`).join('')}</ul>` : ''}
    ${Object.entries(names).map(([state, title]) => `<details ${state === 'dashboard' ? 'open' : ''}><summary>${title}</summary><div class="pair">
      ${result.sessions.map((session) => `<figure><figcaption>${session.name === 'main' ? 'main 基准' : '重构实现'}</figcaption>
        ${session.images?.[state] ? `<a href="${escape(session.images[state])}"><img src="${escape(session.images[state])}" alt="${escape(title)} ${session.name} ${result.width}px" loading="lazy"></a>`
          : state.endsWith('-long') && session.name === 'main' ? '<p>此边界只验证重构实现。</p>' : '<p>未生成；见执行范围或失败原因。</p>'}</figure>`).join('')}</div></details>`).join('')}</section>`).join('');
  writeFileSync(join(out, 'index.html'), `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>DDNS Pro main 对照验收</title><style>body{margin:24px;font:15px/1.6 system-ui;color:#1d1d1f;background:#f5f5f7}h1{font-size:24px}section{margin:24px 0}details{background:white;margin:12px 0;padding:16px;border-radius:12px}summary{cursor:pointer;font-weight:600}.pair{display:grid;grid-template-columns:1fr 1fr;gap:16px}figure{margin:12px 0;min-width:0}figcaption{font-weight:600}img{display:block;width:100%;height:auto;border:1px solid #ddd;box-sizing:border-box}code{overflow-wrap:anywhere}@media(max-width:640px){body{margin:12px}.pair{grid-template-columns:1fr}}</style>
    <h1>DDNS Pro main 对照验收</h1><p>基准提交：<code>${escape(referenceRef)}</code>。同一浏览器、同一视口、同一组虚构数据。点击图片可查看原尺寸。</p>
    <p>自动检查覆盖关键布局${report.flows ? '和解析、配置保存流程' : ''}；图片保留整页供人工审阅。</p><ul>${report.limits.map((limit) => `<li>${escape(limit)}</li>`).join('')}</ul>
    ${report.referenceDefects.length ? `<h2>已确认的 main 缺陷</h2><ul>${report.referenceDefects.map((defect) => `<li>${escape(defect)}</li>`).join('')}</ul>` : ''}
    ${fatal ? `<p>${escape(fatal)}</p>` : ''}${content}</html>`);
}

async function run() {
  mkdirSync(out, { recursive: true });
  const server = await serveUiFixture({ reference: true, ref: referenceRef });
  let browser;
  const results = [];
  let fatal;
  try {
    browser = await launchBrowser(flag('chrome', undefined));
    const { cdp } = browser;
    for (const width of widths) {
      Object.assign(server.fixture, createUiFixture());
      const sessions = [];
      const failures = [];
      results.push({ width, failures, sessions });
      for (const [name, path] of [['main', '/reference'], ['current', '/']]) {
        const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
        const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
        await cdp.send('Page.enable', {}, sessionId);
        await cdp.send('Runtime.enable', {}, sessionId);
        let reportedError = false;
        cdp.listeners.set(`${sessionId}:Runtime.exceptionThrown`, [(event) => {
          if (!reportedError) {
            const message = `${name} JavaScript: ${event.exceptionDetails.exception?.description || event.exceptionDetails.text}`;
            console.error(message);
            failures.push(message);
          }
          reportedError = true;
        }]);
        await cdp.send('Target.activateTarget', { targetId });
        await cdp.send('Emulation.setFocusEmulationEnabled', { enabled: true }, sessionId);
        await cdp.send('Page.bringToFront', {}, sessionId);
        await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 1000, mobile: width < 768, deviceScaleFactor: 1 }, sessionId);
        await cdp.send('Page.navigate', { url: server.base + path }, sessionId);
        await cdp.until(sessionId, "document.querySelector('#pool-selector') && document.querySelector('.target-summary-domain')?.textContent === 'edge.example.com'");
        await cdp.until(sessionId, "document.querySelector('#manual-add-ip, .current-status-add input')");
        await cdp.until(sessionId, "document.querySelectorAll('#status-table .address-pill').length === 2");
        const data = await cdp.evaluate(sessionId, `(${measure})(${JSON.stringify(selectors)})`);
        const session = { name, sessionId, targetId, data };
        sessions.push(session);
        await capture(cdp, session, width, 'dashboard', failures);
      }
      failures.push(...differences(sessions[0].data, sessions[1].data, width));
      console.log(`${width}px dashboard: ${failures.join('；') || '通过'}`);
      for (const session of sessions) {
        await cdp.send('Target.activateTarget', { targetId: session.targetId });
        await captureBindings(cdp, session, width, failures);
        if (args.includes('--flows')) {
          try {
            const flowFailures = await auditDashboardFlow(cdp, session.sessionId, session.name, server.fixture);
            failures.push(...flowFailures.map((message) => `${session.name} 解析流程：${message}`));
          } catch (error) {
            failures.push(`${session.name} 解析流程：${error.message}`);
            await capture(cdp, session, width, 'dashboard-failure', failures);
          }
          try {
            const orderFailures = await auditOrderFlow(cdp, session.sessionId, session.name, server.requests, server.fixture,
              state => capture(cdp, session, width, state, failures));
            failures.push(...orderFailures.map(message => `${session.name} 排序流程：${message}`));
          } catch (error) {
            failures.push(`${session.name} 排序流程：${error.message}`);
            await capture(cdp, session, width, 'order-failure', failures);
          }
        }
        await cdp.until(session.sessionId, '!document.querySelector(".toast.show")');
        await cdp.click(session.sessionId, '.nav-tab[data-page="config"]');
        try {
          await cdp.until(session.sessionId, "document.querySelector('#page-config .config-mini-card')");
        } catch (error) {
          const screenshot = await cdp.send('Page.captureScreenshot', { format: 'png' }, session.sessionId);
          writeFileSync(join(out, `${session.name}-config-failure-${width}.png`), Buffer.from(screenshot.data, 'base64'));
          throw new Error(`${session.name}: ${error.message}; ${await cdp.evaluate(session.sessionId, 'document.body.innerText.slice(0, 600)')}`);
        }
        session.config = await cdp.evaluate(session.sessionId, `(${measure})({})`);
        await capture(cdp, session, width, 'config', failures);
        await captureConfigStates(cdp, session, width, failures);
        if (args.includes('--flows')) {
          try {
            const flow = await auditConfigFlow(cdp, session.sessionId, session.name, server.requests, server.fixture);
            session.referenceDefects = flow.referenceDefects;
            failures.push(...flow.failures.map((message) => `${session.name} 配置流程：${message}`));
          } catch (error) {
            await capture(cdp, session, width, 'config-flow-failure', failures);
            const state = await cdp.evaluate(session.sessionId, `JSON.stringify({ scrollY, panel: document.querySelector('#zone-edit-panel')?.className,
              inputs: [...document.querySelectorAll('#zone-edit-panel input')].map(input => input.id) })`);
            failures.push(`${session.name} 配置流程：${error.message}; ${state}`);
          }
          if (session.name === 'current') {
            try {
              const timingFailures = await auditConfigTiming(cdp, session.sessionId, server.base, server.requests, server.fixture,
                state => capture(cdp, session, width, state, failures));
              failures.push(...timingFailures.map(message => `current 配置时序：${message}`));
            } catch (error) { failures.push(`current 配置时序：${error.message}`); }
            try {
              const poolFailures = await auditPoolTiming(cdp, session.sessionId, server.base, server.requests, server.fixture,
                state => capture(cdp, session, width, state, failures));
              failures.push(...poolFailures.map(message => `current 池与绑定时序：${message}`));
            } catch (error) { failures.push(`current 池与绑定时序：${error.message}`); }
            try {
              const recoveryFailures = await auditOrderRecovery(cdp, session.sessionId, server.base, server.requests, server.fixture,
                state => capture(cdp, session, width, state, failures));
              failures.push(...recoveryFailures.map(message => `current 排序恢复：${message}`));
            } catch (error) { failures.push(`current 排序恢复：${error.message}`); }
            try {
              const startupFailures = await auditTargetStartup(cdp, session.sessionId, server.base, server.requests, server.fixture);
              failures.push(...startupFailures.map((message) => `current 首屏流程：${message}`));
            } catch (error) { failures.push(`current 首屏流程：${error.message}`); }
            try {
              const edgeFailures = await auditOrderEdges(cdp, session.sessionId, server.base, server.requests, server.fixture,
                state => capture(cdp, session, width, state, failures));
              failures.push(...edgeFailures.map(message => `current 排序边界：${message}`));
            } catch (error) {
              failures.push(`current 排序边界：${error.message}`);
              await capture(cdp, session, width, 'order-edge-failure', failures);
            }
          }
        }
        await cdp.send('Target.closeTarget', { targetId: session.targetId });
      }
      if (JSON.stringify(sessions[0].bindings) !== JSON.stringify(sessions[1].bindings)) failures.push('域名池绑定列表、当前选择或可选池与 main 不同');
      if (sessions[0].config.basicsOpen !== sessions[1].config.basicsOpen) failures.push('基础配置默认展开状态与 main 不同');
      if (sessions[0].config.configCards !== sessions[1].config.configCards) failures.push('配置卡片数与 main 不同');
      if (JSON.stringify(sessions[0].config.settingsIds) !== JSON.stringify(sessions[1].config.settingsIds)) failures.push('运行参数字段和顺序与 main 不同');
      for (const type of ['zone', 'target']) {
        if (JSON.stringify(sessions[0].editors[type].editorLabels) !== JSON.stringify(sessions[1].editors[type].editorLabels)) failures.push(`${type} 编辑器字段和顺序与 main 不同`);
      }
      console.log(`${width}px: ${failures.length ? failures.join('；') : '已覆盖的布局与流程通过'}`);
    }
  } catch (error) {
    fatal = error.message;
  } finally {
    await browser?.close();
    await server.close();
    writeReport(results, fatal);
  }
  console.log(`对照截图和报告：${out}`);
  if (fatal) console.error(fatal);
  if (fatal || results.some((result) => result.failures.length)) process.exitCode = 1;
}

run().catch((error) => { console.error(error.message); process.exitCode = 1; });
