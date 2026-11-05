#!/usr/bin/env node
/**
 * 运行：npm run build && npm run audit:ui（Node >= 22）。
 * 默认使用本地模拟数据；--base 可检查已启动的本地页面。
 * 参数：--base / --out / --chrome / --compare-baseline。
 * 基准对照仅容许同一内容、同等或更轻的问题；Chrome 数据目录位于系统临时目录。
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { launchBrowser } from "./ui-browser.mjs";
import { serveUiFixture, UI_BASELINE_REF } from "./ui-fixture.mjs";
import { compareAudit } from "./ui-audit-diff.mjs";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
};
let BASE = flag("base", "");
const compareBaseline = args.includes("--compare-baseline");
if (compareBaseline && BASE) throw new Error('--compare-baseline 必须使用本地同数据 fixture，不能配合 --base');
const OUT = resolve(flag("out", ".wrangler/tmp/ui-audit"));
const MIN_TARGET = 32;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const VIEWPORTS = [
  { name: "375", width: 375, height: 900, mobile: true },
  { name: "768", width: 768, height: 1000, mobile: false },
  { name: "992", width: 992, height: 1000, mobile: false },
  { name: "1265", width: 1265, height: 1000, mobile: false },
  { name: "1440", width: 1440, height: 1050, mobile: false },
  { name: "1920", width: 1920, height: 1080, mobile: false },
];
const PAGES = [
  { key: "dashboard", path: "/" },
  { key: "config", path: "/", tab: '.nav-tab[data-page="config"]', expect: "#page-config" },
];

/** 在页面上下文中执行，返回单个视口的审计结果。 */
const auditProbe = () => {
  const parseColor = (value) => {
    const m = value.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const parts = m[1].split(/[,\/]/).map((p) => parseFloat(p.trim()));
    if (parts.length < 3 || parts.slice(0, 3).some((n) => Number.isNaN(n))) return null;
    const alpha = parts.length > 3 ? parts[3] : 1;
    return { r: parts[0], g: parts[1], b: parts[2], a: Number.isNaN(alpha) ? 1 : alpha };
  };
  const srgb = (c) => {
    const v = c / 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  };
  const lum = (c) => 0.2126 * srgb(c.r) + 0.7152 * srgb(c.g) + 0.0722 * srgb(c.b);
  const blend = (fg, bg) => ({
    r: fg.r * fg.a + bg.r * (1 - fg.a),
    g: fg.g * fg.a + bg.g * (1 - fg.a),
    b: fg.b * fg.a + bg.b * (1 - fg.a),
    a: 1,
  });
  const ratio = (a, b) => {
    const l1 = lum(a);
    const l2 = lum(b);
    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
  };
  const effectiveBg = (el) => {
    let node = el;
    const stack = [];
    while (node && node.nodeType === 1) {
      const style = getComputedStyle(node);
      if (style.backgroundImage && style.backgroundImage !== "none") return { kind: "image" };
      const c = parseColor(style.backgroundColor);
      if (c && c.a > 0) {
        stack.push(c);
        if (c.a >= 1) break;
      }
      node = node.parentElement;
    }
    let base = stack.length && stack[stack.length - 1].a >= 1 ? stack.pop() : { r: 255, g: 255, b: 255, a: 1 };
    while (stack.length) base = blend(stack.pop(), base);
    return { kind: "color", color: base };
  };
  const visible = (el) => {
    if (!el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) return false;
    const style = getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none" || style.opacity === "0") return false;
    return true;
  };
  const describe = (el) => {
    const id = el.id ? `#${el.id}` : "";
    const cls = el.classList.length ? `.${[...el.classList].slice(0, 3).join(".")}` : "";
    return `${el.tagName.toLowerCase()}${id}${cls}`;
  };
  const ownText = (el) =>
    [...el.childNodes]
      .filter((n) => n.nodeType === 3)
      .map((n) => n.textContent.trim())
      .filter(Boolean)
      .join(" ")
      .trim();
  // 基准的文本 emoji 与当前图标 span 忽略表示差异；彩色 emoji 不按 CSS color 计算对比度。
  const textKey = (text) => text.normalize('NFKC').replace(/[\p{Extended_Pictographic}\uFE0F\u200D]/gu, '').replace(/\s+/g, '');
  const issueKey = (el, text) => {
    const region = el.closest('#page-dashboard, #page-config, .hero, .top-nav, footer');
    const area = region?.id || (region?.matches('footer') ? 'footer' : region?.matches('.hero') ? 'hero' : region?.matches('.top-nav') ? 'top-nav' : 'document');
    const anchors = ['#manual-add-section', ':has(> #lookup-domain)', '#status-display', '.domain-binding-card',
      '.pool-remote', '.pool-buttons', '.hero-actions', '.domain-selector', '.config-details', '.config-card-grid', '#log-window'];
    const feature = el.closest(anchors.join(','));
    const anchor = anchors.find(selector => feature?.matches(selector)) || 'content';
    return `${area}:${anchor}:${area === 'footer' ? 'footer' : textKey(text) || text.trim()}`;
  };

  const all = [...document.querySelectorAll("*")];
  const contrastFailures = [];
  const imageText = [];
  const fontSizes = {};
  for (const el of all) {
    if (!visible(el)) continue;
    const text = ownText(el);
    if (!text) continue;
    const style = getComputedStyle(el);
    const size = style.fontSize;
    const bucket = (fontSizes[size] ||= { count: 0, samples: [] });
    bucket.count += 1;
    if (bucket.samples.length < 4) bucket.samples.push({ el: describe(el), text: text.slice(0, 30) });
    if (!textKey(text)) continue;

    const fg = parseColor(style.color);
    if (!fg) continue;
    const bg = effectiveBg(el);
    if (bg.kind === "image") {
      imageText.push({ el: describe(el), text: text.slice(0, 40) });
      continue;
    }
    const fgFinal = fg.a < 1 ? blend(fg, bg.color) : fg;
    const r = ratio(fgFinal, bg.color);
    const px = parseFloat(size);
    const weight = parseInt(style.fontWeight, 10) || 400;
    const large = px >= 24 || (px >= 18.66 && weight >= 700);
    const required = large ? 3 : 4.5;
    if (r < required) {
      contrastFailures.push({
        key: issueKey(el, text),
        el: describe(el),
        text: text.slice(0, 40),
        ratio: r,
        required,
        color: style.color,
        bg: `rgb(${Math.round(bg.color.r)}, ${Math.round(bg.color.g)}, ${Math.round(bg.color.b)})`,
        size: px,
        weight,
      });
    }
  }

  const smallTargets = [];
  for (const el of document.querySelectorAll("a[href], button, input, select, textarea, summary, [onclick], [role='button'], [tabindex]:not([tabindex='-1'])")) {
    if (!visible(el)) continue;
    if (el.tagName === "INPUT" && el.type === "hidden") continue;
    // 复选框的关联 label 也是实际点击目标；只量 13px 的 input 会误报。
    const target = el.tagName === "INPUT" && ["checkbox", "radio"].includes(el.type) && el.labels?.length
      ? [...el.labels].find((label) => visible(label)) ?? el
      : el;
    const rect = target.getBoundingClientRect();
    if (rect.height < 32) {
      smallTargets.push({
        key: issueKey(el, target.textContent?.trim() || el.getAttribute('placeholder') || el.getAttribute('title') || el.id || el.tagName),
        el: describe(el),
        w: rect.width,
        h: rect.height,
        text: (target.textContent || el.value || "").trim().slice(0, 24),
      });
    }
  }

  const controlMetrics = [...document.querySelectorAll(".ddns-lookup-form .btn")].map((el) => {
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return {
      text: (el.textContent || "").trim(),
      w: Math.round(rect.width * 10) / 10,
      h: Math.round(rect.height * 10) / 10,
      fontSize: style.fontSize,
      fontWeight: style.fontWeight,
      padding: style.padding,
      borderRadius: style.borderRadius,
    };
  });

  const icons = [];
  for (const el of document.querySelectorAll(".ui-icon")) {
    if (!visible(el)) continue;
    const rect = el.getBoundingClientRect();
    const label = el.getAttribute("aria-label") || el.closest("button,a")?.textContent?.trim().slice(0, 20) || "";
    icons.push({ w: Math.round(rect.width * 10) / 10, h: Math.round(rect.height * 10) / 10, label });
  }

  const accName = (el) => {
    const aria = el.getAttribute("aria-label");
    if (aria && aria.trim()) return aria.trim();
    const labelledby = el.getAttribute("aria-labelledby");
    if (labelledby) {
      const t = labelledby
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim() || "")
        .join(" ")
        .trim();
      if (t) return t;
    }
    const text = el.textContent?.trim();
    if (text) return text;
    const title = el.getAttribute("title");
    if (title) return title;
    const labelled = el.labels?.length ? [...el.labels].map((l) => l.textContent.trim()).join(" ").trim() : "";
    if (labelled) return labelled;
    const ph = el.getAttribute("placeholder");
    if (ph) return ph;
    if (typeof el.value === "string" && el.value) return el.value;
    return "";
  };
  const unnamedControls = [];
  for (const el of document.querySelectorAll("a[href], button, input, select, textarea, [role='button']")) {
    if (!visible(el) || el.getAttribute("aria-hidden") === "true") continue;
    if (el.tagName === "INPUT" && el.type === "hidden") continue;
    if (!accName(el)) unnamedControls.push(describe(el));
  }
  const idCounts = new Map();
  for (const el of document.querySelectorAll("[id]")) idCounts.set(el.id, (idCounts.get(el.id) || 0) + 1);

  return {
    innerWidth: window.innerWidth,
    docWidth: document.documentElement.scrollWidth,
    overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
    contrastFailures,
    imageText,
    smallTargets,
    controlMetrics,
    fontSizes,
    icons,
    iconCount: icons.length,
    headings: [...document.querySelectorAll("h1, h2, h3, h4, h5, h6")]
      .filter(visible)
      .map((el) => ({ level: el.tagName.toLowerCase(), text: el.textContent.trim().slice(0, 40) })),
    a11y: {
      lang: document.documentElement.getAttribute("lang"),
      title: document.title,
      unnamedControls,
      duplicateIds: [...idCounts.entries()].filter(([, n]) => n > 1).map(([id, n]) => `${id} x${n}`),
      imagesMissingAlt: document.querySelectorAll("img:not([alt])").length,
    },
  };
};

const checkPage = async (cdp, sessionId) => {
  const result = await cdp.send("Runtime.evaluate", { expression: `(${auditProbe.toString()})()`, returnByValue: true }, sessionId);
  if (result.exceptionDetails) throw new Error(`evaluate failed: ${JSON.stringify(result.exceptionDetails)}`);
  return result.result?.value;
};

/**
 * 用确定性的浏览器内响应跑一次真实检测流程。
 * 测试不依赖外部探针，只验证页面能否消费逐地址检测结果并把结论呈现出来。
 */
async function runBatchFlowCheck(cdp, sessionId, viewport, expectEmpty) {
  const source = `(() => {
    const nativeFetch = window.fetch.bind(window);
    window.__batchDelayMs = 0;
    window.fetch = (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.endsWith("/api/check")) {
        const proxyip = JSON.parse(init?.body).proxyip;
        const payload = proxyip === "203.0.113.11:443"
          ? { ok: true, input: proxyip, source: { kind: "direct" }, items: [{ address: proxyip, result: { status: "unknown", exitFamily: "unknown", exits: [], code: "TIMEOUT", message: "检测超时" } }], skipped: [] }
          : { ok: true, input: proxyip, source: { kind: "direct" }, items: [{ address: proxyip, result: { status: "alive", exitFamily: "ipv4", exits: [] } }], skipped: [] };
        const response = () => Response.json(payload);
        if (!window.__batchDelayMs) return Promise.resolve(response());
        return new Promise((resolve, reject) => {
          const signal = init?.signal;
          if (signal?.aborted) {
            reject(new DOMException("Aborted", "AbortError"));
            return;
          }
          const timer = setTimeout(() => resolve(response()), window.__batchDelayMs);
          signal?.addEventListener("abort", () => {
            clearTimeout(timer);
            reject(new DOMException("Aborted", "AbortError"));
          }, { once: true });
        });
      }
      return nativeFetch(input, init);
    };
  })();`;

  await cdp.send(
    "Emulation.setDeviceMetricsOverride",
    { width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: viewport.mobile },
    sessionId,
  );
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source }, sessionId);
  const loaded = cdp.wait(sessionId, "Page.loadEventFired");
  await cdp.send("Page.navigate", { url: `${BASE}/` }, sessionId);
  await loaded.catch(() => {});
  await sleep(1000);

  const interact = await cdp.send(
    "Runtime.evaluate",
    {
      expression: `(async () => {
        const waitFor = async (read, timeout = 6000) => {
          const deadline = Date.now() + timeout;
          while (Date.now() < deadline) {
            const value = read();
            if (value) return value;
            await new Promise((resolve) => setTimeout(resolve, 100));
          }
          return null;
        };
        const input = await waitFor(() => document.querySelector("#ip-input"));
        const button = await waitFor(() => document.querySelector('button[aria-label="批量检测导入草稿"]'));
        if (!input || !button) return { failures: ["检测控件未渲染"] };

        const failures = [];
        if (${expectEmpty}) {
        if (document.querySelector('#manual-add-section')?.checkVisibility()) failures.push('未配置目标时不应显示 DNS 添加控件');
        if (document.querySelector('.domain-selector > button')) failures.push('未配置目标时多出独立跳转按钮');
        if (document.querySelector('.target-summary-meta')?.textContent !== '请先到配置中心添加') failures.push('空目标摘要与基准页面不同');
        if (!document.querySelector('#log-window')?.textContent.includes('未设置维护域名，请在配置中心添加')) failures.push('空配置缺少启动引导日志');
        if (document.querySelector('#page-dashboard .domain-binding-card')) failures.push('运行面板不应保留重复绑定入口');
        }
        const original = "203.0.113.10:443\\n203.0.113.11:443";
        input.value = original;
        input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: original }));
        await new Promise((resolve) => setTimeout(resolve, 50));
        button.click();

        const report = await waitFor(() => {
          return !document.querySelector('button[aria-label="停止批量检测"]') && document.querySelector('.pool-report')?.textContent.includes('异常 1') ? document.querySelector('.pool-report').textContent : null;
        });
        if (!report || !report.includes('可用 1') || input.value !== original) failures.push('检测报告没有独立保留可用/未知数量与原始草稿');
        const resultCategory = document.querySelector('[aria-label="检测结果分类"]');
        if (resultCategory) { resultCategory.value = 'unknown'; resultCategory.dispatchEvent(new Event('change', { bubbles: true })); }
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        if (!document.querySelector('.pool-result-list')?.textContent.includes('检测超时')) failures.push('未知检测结果缺少具体原因');

        window.__batchDelayMs = 250;
        document.querySelector('[data-action=view-draft]')?.click();
        input.value = original;
        input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: original }));
        await new Promise((resolve) => setTimeout(resolve, 50));
        document.querySelector('button[aria-label="批量检测导入草稿"]')?.click();
        await new Promise((resolve) => setTimeout(resolve, 80));
        const stopButton = document.querySelector('button[aria-label="停止批量检测"]');
        if (!stopButton) failures.push("检测运行中缺少停止按钮");
        if (!input.readOnly) failures.push("检测期间源输入没有锁定");
        stopButton?.click();
        const abandon = await waitFor(() => document.querySelector('.custom-modal-overlay .btn-abandon'));
        if (!abandon) failures.push("停止后缺少放弃操作");
        abandon?.click();
        await new Promise((resolve) => setTimeout(resolve, 400));
        window.__batchDelayMs = 0;
        document.querySelector('[data-action=view-draft]')?.click();
        if (!(await waitFor(() => document.querySelector('button[aria-label="批量检测导入草稿"]')))) {
          failures.push("中止检测后没有回到清洗按钮");
        }
        if (input.value !== original) failures.push("放弃后未完成输入被旧请求覆盖");

        const clear = document.querySelector('[data-action=clear-input]');
        if (!clear) failures.push('找不到清空输入动作');
        else {
          clear.click(); await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
          if (input.value !== '' || document.querySelector('.pool-report')) failures.push('清空输入没有同时使派生报告失效');
        }
        return { failures };
      })()`,
      awaitPromise: true,
      returnByValue: true,
    },
    sessionId,
  );
  if (interact.exceptionDetails) throw new Error(`检测流程执行失败：${JSON.stringify(interact.exceptionDetails)}`);
  return interact.result?.value?.failures ?? ["检测流程没有返回结果"];
}

/**
 * 在空的配置中心里实际新增 Zone 和管理域名，验证卡片尺寸不是只对静态空状态成立。
 */
async function runConfigCardCheck(cdp, sessionId, viewport) {
  await cdp.send(
    "Emulation.setDeviceMetricsOverride",
    { width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: viewport.mobile },
    sessionId,
  );
  const loaded = cdp.wait(sessionId, "Page.loadEventFired");
  await cdp.send("Page.navigate", { url: `${BASE}/` }, sessionId);
  await loaded.catch(() => {});
  await sleep(800);

  const result = await cdp.send(
    "Runtime.evaluate",
    {
      expression: `(async () => {
        const waitFor = async (read, timeout = 4000) => {
          const deadline = Date.now() + timeout;
          while (Date.now() < deadline) {
            const value = read();
            if (value) return value;
            await new Promise((resolve) => setTimeout(resolve, 50));
          }
          return null;
        };
        const buttonByText = (text) =>
          [...document.querySelectorAll("button")].find((button) => button.textContent?.trim().endsWith(text));

        document.querySelector("#tab-config")?.click();
        const page = await waitFor(() => document.querySelector("#page-config"));
        if (!page) return { failures: ["配置中心未渲染"] };
        const emptyFailures = [...page.querySelectorAll('.config-empty-state')].flatMap(element => {
          const box = element.getBoundingClientRect();
          const grid = element.parentElement;
          const column = parseFloat(getComputedStyle(grid).gridTemplateColumns);
          return box.height > 80 || Math.abs(box.width - column) > 1
            ? ['空配置占位卡没有保持基准页面的单列宽度和内容高度'] : [];
        });

        for (let index = 0; index < 2; index += 1) {
          const addZone = await waitFor(() => buttonByText("添加权限配置"));
          if (!addZone) return { failures: ["找不到添加权限配置按钮"] };
          addZone.click();
          await new Promise((resolve) => setTimeout(resolve, 80));
          for (const [id, value] of [
            ["zone-name-" + index, "测试权限 " + (index + 1)],
            ["zone-domain-" + index, "example" + index + ".com"],
            ["zone-id-" + index, "fixture-zone-" + index],
          ]) {
            const input = document.getElementById(id);
            input.value = value;
            input.dispatchEvent(new Event("input", { bubbles: true }));
          }
          await new Promise((resolve) => setTimeout(resolve, 50));
          document.querySelector("#zone-edit-panel .config-edit-actions button:last-child").click();
          await new Promise((resolve) => setTimeout(resolve, 80));
        }

        const addTarget = await waitFor(() => buttonByText("添加维护域名"));
        if (!addTarget) return { failures: ["新增 Zone 后找不到添加管理域名按钮"] };
        addTarget.click();
        await new Promise((resolve) => setTimeout(resolve, 100));
        document.querySelector("#target-edit-panel .config-edit-actions button:last-child").click();
        await new Promise((resolve) => setTimeout(resolve, 80));
        document.querySelector(".config-details-summary").click();
        await new Promise((resolve) => setTimeout(resolve, 80));

        const failures = [...emptyFailures];
        const grids = [...document.querySelectorAll(".config-card-grid")];
        const zoneCards = [...(grids[0]?.querySelectorAll(".config-mini-card") ?? [])];
        const targetCards = [...(grids[1]?.querySelectorAll(".config-mini-card") ?? [])];
        const cards = [...zoneCards, ...targetCards];
        if (zoneCards.length !== 2) failures.push(\`新增 Zone 卡片数量为 \${zoneCards.length}/2\`);
        if (targetCards.length !== 1) failures.push(\`新增管理域名卡片数量为 \${targetCards.length}/1\`);

        const metrics = cards.map((card) => {
          const box = card.getBoundingClientRect();
          const cardStyle = getComputedStyle(card);
          const heading = card.querySelector("h3");
          return {
            width: Math.round(box.width * 10) / 10,
            height: Math.round(box.height * 10) / 10,
            minHeight: cardStyle.minHeight,
            padding: cardStyle.padding,
            radius: cardStyle.borderRadius,
            background: cardStyle.backgroundColor,
            headingSize: heading ? getComputedStyle(heading).fontSize : null,
            title: heading?.textContent?.trim() ?? "",
          };
        });
        const formGrid = document.querySelector("#page-config .config-grid");
        if (formGrid && getComputedStyle(formGrid).columnGap !== getComputedStyle(formGrid).getPropertyValue('--space-7').trim()) failures.push("配置表单网格间距未使用统一间距变量");
        const formControl = formGrid?.querySelector(".form-control-sm, .form-select-sm");
        if (formControl && formControl.getBoundingClientRect().height < 32) failures.push("配置表单控件高度不足 32px");
        for (const metric of metrics) {
          if (metric.height < 64) failures.push(\`配置列表行高度不足 64px：\${metric.title}\`);
          if (metric.width > page.clientWidth) failures.push(\`配置列表行超出容器：\${metric.title}\`);
        }
        if (zoneCards.length > 1 && metrics[0] && metrics[1]) {
          if (Math.abs(metrics[0].width - metrics[1].width) > 1) failures.push("同一行配置卡片宽度不一致");
          if (Math.abs(metrics[0].height - metrics[1].height) > 1) failures.push("同一行配置卡片高度不一致");
        }
        return { failures, metrics };
      })()`,
      awaitPromise: true,
      returnByValue: true,
    },
    sessionId,
  );
  if (result.exceptionDetails) throw new Error(`配置卡片检查失败：${JSON.stringify(result.exceptionDetails)}`);
  const layout = await cdp.send("Page.getLayoutMetrics", {}, sessionId);
  const size = layout.cssContentSize;
  const screenshot = await cdp.send(
    "Page.captureScreenshot",
    { format: "png", captureBeyondViewport: true, clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } },
    sessionId,
  );
  writeFileSync(join(OUT, `config-cards-${viewport.name}.png`), Buffer.from(screenshot.data, "base64"));
  return result.result?.value?.failures ?? ["配置卡片检查没有返回结果"];
}

async function main() {
  const fixture = BASE ? null : await serveUiFixture({ empty: true, reference: compareBaseline });
  BASE ||= fixture.base;
  mkdirSync(OUT, { recursive: true });
  let browser;
  let exitCode = 0;
  try {
    browser = await launchBrowser(flag("chrome", undefined));
    const { cdp } = browser;
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Page.enable", {}, sessionId);
    await cdp.send("Runtime.enable", {}, sessionId);

    const results = [];
    const referenceResults = [];
    for (const viewport of VIEWPORTS) {
      for (const page of PAGES) {
        for (const surface of compareBaseline ? ['baseline', 'current'] : ['current']) {
        await cdp.send(
          "Emulation.setDeviceMetricsOverride",
          { width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: viewport.mobile },
          sessionId,
        );
        const loaded = cdp.wait(sessionId, "Page.loadEventFired");
        await cdp.send("Page.navigate", { url: `${BASE}${surface === 'baseline' ? '/reference' : page.path}` }, sessionId);
        await loaded.catch(() => {});
        if (fixture) await cdp.until(sessionId, "parseInt(document.querySelector('#pool-count')?.textContent) === 2");
        else await sleep(1200);
        await cdp.evaluate(sessionId, 'document.fonts.ready.then(() => true)');
        if (page.tab) {
          await cdp.send("Runtime.evaluate", { expression: `document.querySelector(${JSON.stringify(page.tab)})?.click()`, returnByValue: true }, sessionId);
          await sleep(700);
          if (page.expect) {
            const target = JSON.stringify(page.expect);
            const switched = await cdp.send(
              "Runtime.evaluate",
              { expression: `Boolean(document.querySelector(${target}))`, returnByValue: true },
              sessionId,
            );
            if (switched.result?.value !== true) throw new Error(`${page.key} 页面未切换：缺少 ${page.expect}`);
            await cdp.until(sessionId, `Boolean(document.querySelector(${target})?.checkVisibility())`);
          }
        }
        const data = await checkPage(cdp, sessionId);
        (surface === 'baseline' ? referenceResults : results).push({ page: page.key, viewport: viewport.name, ...data });

        const metrics = await cdp.send("Page.getLayoutMetrics", {}, sessionId);
        const size = metrics.cssContentSize;
        const shot = await cdp.send(
          "Page.captureScreenshot",
          { format: "png", captureBeyondViewport: true, clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } },
          sessionId,
        );
        writeFileSync(join(OUT, `${surface === 'baseline' ? 'baseline-' : ''}${page.key}-${viewport.name}.png`), Buffer.from(shot.data, "base64"));
        }
      }
    }
    const interactionFailures = [];
    for (const viewport of [VIEWPORTS[0], VIEWPORTS[4]]) {
      const flowTarget = await cdp.send("Target.createTarget", { url: "about:blank" });
      const flowSession = await cdp.send("Target.attachToTarget", { targetId: flowTarget.targetId, flatten: true });
      await cdp.send("Page.enable", {}, flowSession.sessionId);
      await cdp.send("Runtime.enable", {}, flowSession.sessionId);
      const failures = await runBatchFlowCheck(cdp, flowSession.sessionId, viewport, Boolean(fixture));
      interactionFailures.push(...failures.map((failure) => `${viewport.name}: ${failure}`));
      const cardFailures = await runConfigCardCheck(cdp, flowSession.sessionId, viewport);
      interactionFailures.push(...cardFailures.map((failure) => `${viewport.name}: ${failure}`));
      await cdp.send("Target.closeTarget", { targetId: flowTarget.targetId });
    }

    await cdp.send("Target.closeTarget", { targetId });

    const comparisons = compareBaseline ? results.map(current => ({ page: current.page, viewport: current.viewport,
      ...compareAudit(referenceResults.find(reference => reference.page === current.page && reference.viewport === current.viewport), current),
    })) : [];

    writeFileSync(
      join(OUT, "report.json"),
      JSON.stringify({ generatedAt: new Date().toISOString(), base: BASE, mode: compareBaseline ? 'baseline-regression' : 'strict',
        reference: compareBaseline ? UI_BASELINE_REF : null, results, referenceResults, comparisons, interactionFailures }, null, 2),
    );

    for (const r of results) {
      console.log(
        `${r.page}@${r.viewport}`.padEnd(18) +
          `overflow=${r.overflow}(doc ${r.docWidth}/${r.innerWidth})`.padEnd(26) +
          `contrast=${r.contrastFailures.length}`.padEnd(14) +
          `targets<${MIN_TARGET}px=${r.smallTargets.length}`.padEnd(22) +
          `icons=${r.iconCount}`,
      );
    }
    const failures = results.flatMap((r) =>
      r.contrastFailures.map((f) => `${f.page ?? r.page}@${r.viewport} ${f.el} "${f.text}" ${f.ratio}:1 (need ${f.required}) ${f.color} on ${f.bg}`),
    );
    for (const f of failures) console.log(`  CONTRAST ${f}`);
    for (const r of results) for (const s of r.smallTargets) console.log(`  TARGET ${r.page}@${r.viewport} ${s.el} ${s.w}x${s.h} "${s.text}"`);
    for (const r of results) for (const el of r.a11y.unnamedControls) console.log(`  A11Y ${r.page}@${r.viewport} 无可访问名称 ${el}`);
    for (const r of results) for (const id of r.a11y.duplicateIds) console.log(`  A11Y ${r.page}@${r.viewport} 重复 id ${id}`);

    const headingSkips = results.filter((r) => {
      const levels = r.headings.map((h) => Number(h.level.slice(1)));
      return levels.some((level, i) => i > 0 && level - levels[i - 1] > 1);
    });
    for (const r of headingSkips) console.log(`  A11Y ${r.page}@${r.viewport} 标题层级跳级：${r.headings.map((h) => h.level).join(" > ")}`);
    for (const failure of interactionFailures) console.log(`  FLOW ${failure}`);
    for (const comparison of comparisons) for (const failure of comparison.regressions) {
      console.log(`  REGRESSION ${comparison.page}@${comparison.viewport} ${failure}`);
    }

    const problems =
      results.filter((r) => r.overflow || (!compareBaseline && (r.contrastFailures.length || r.smallTargets.length))
        || r.a11y.unnamedControls.length || r.a11y.duplicateIds.length || r.a11y.imagesMissingAlt).length +
      headingSkips.length +
      interactionFailures.length + comparisons.reduce((count, comparison) => count + comparison.regressions.length, 0);
    if (problems > 0) exitCode = 1;
    console.log(`\n报告与截图输出目录：${OUT}`);
    console.log(problems === 0 ? (compareBaseline
      ? "结论：相对基准页面无新增对比度或点击目标退步；基准已有问题仍在报告中，不代表严格无障碍通过"
      : "结论：全部视口通过（无横向溢出、无对比度失败、无小于 32px 目标、无 a11y 问题）") : `结论：存在 ${problems} 类问题，见上方明细`);
  } finally {
    await browser?.close();
    await fixture?.close();
  }
  process.exitCode = exitCode;
}

main().catch((error) => {
  console.error(`审计失败：${error.message}`);
  process.exitCode = 1;
});
