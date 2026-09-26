#!/usr/bin/env node
/**
 * UI 验收审计：响应式布局 + 对比度 + 点击目标 + 语义/可访问性 + 截图。
 *
 * 用法：
 *   1) 另开一个终端启动本地服务：npm run dev（默认 http://127.0.0.1:8788）
 *   2) node scripts/ui-audit.mjs
 *
 * 可选参数：--base / --out / --port / --chrome / --keep-open
 * 脚本会自行启动 headless Chrome，用户数据目录放在系统临时目录，绝不写进仓库。
 * 只依赖 Node 内置能力（Node >= 22 提供全局 WebSocket），不引入任何依赖。
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
};
const BASE = flag("base", "http://127.0.0.1:8788");
const OUT = resolve(flag("out", ".wrangler/tmp/ui-audit"));
const PORT = Number(flag("port", "9222"));
const KEEP_OPEN = args.includes("--keep-open");
const MIN_TARGET = 32;
const CDP = `http://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const VIEWPORTS = [
  { name: "375", width: 375, height: 900, mobile: true },
  { name: "768", width: 768, height: 1000, mobile: false },
  { name: "992", width: 992, height: 1000, mobile: false },
  { name: "1265", width: 1265, height: 1000, mobile: false },
];
const PAGES = [
  { key: "dashboard", path: "/" },
  { key: "config", path: "/", tab: "#tab-config", expect: "#page-config" },
];

function findChrome() {
  const explicit = flag("chrome", "");
  const candidates = [
    explicit,
    process.env.CHROME_PATH,
    `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
    `${process.env.ProgramFiles}\\Google\\Chrome\\Application\\chrome.exe`,
    `${process.env["ProgramFiles(x86)"]}\\Google\\Chrome\\Application\\chrome.exe`,
    `${process.env.ProgramFiles}\\Microsoft\\Edge\\Application\\msedge.exe`,
    `${process.env["ProgramFiles(x86)"]}\\Microsoft\\Edge\\Application\\msedge.exe`,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
  ].filter(Boolean);
  return candidates.find((path) => existsSync(path));
}

class Cdp {
  constructor(url) {
    this.url = url;
    this.id = 0;
    this.pending = new Map();
    this.listeners = new Map();
  }
  async connect() {
    this.ws = new WebSocket(this.url);
    await new Promise((resolve, reject) => {
      this.ws.addEventListener("open", resolve, { once: true });
      this.ws.addEventListener("error", reject, { once: true });
    });
    this.ws.addEventListener("message", (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id !== undefined) {
        const entry = this.pending.get(msg.id);
        if (!entry) return;
        this.pending.delete(msg.id);
        if (msg.error) entry.reject(new Error(JSON.stringify(msg.error)));
        else entry.resolve(msg.result);
        return;
      }
      const subs = this.listeners.get(`${msg.sessionId || ""}:${msg.method}`) || [];
      for (const fn of subs) fn(msg.params);
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(payload));
    });
  }
  wait(sessionId, method, timeout = 15000) {
    return new Promise((resolve, reject) => {
      const key = `${sessionId || ""}:${method}`;
      const timer = setTimeout(() => reject(new Error(`timeout waiting ${method}`)), timeout);
      const fn = (params) => {
        clearTimeout(timer);
        const subs = this.listeners.get(key) || [];
        this.listeners.set(key, subs.filter((s) => s !== fn));
        resolve(params);
      };
      this.listeners.set(key, [...(this.listeners.get(key) || []), fn]);
    });
  }
}

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
        el: describe(el),
        text: text.slice(0, 40),
        ratio: Math.round(r * 100) / 100,
        required,
        color: style.color,
        bg: `rgb(${Math.round(bg.color.r)}, ${Math.round(bg.color.g)}, ${Math.round(bg.color.b)})`,
        size: px,
        weight,
      });
    }
  }

  const smallTargets = [];
  for (const el of document.querySelectorAll("a[href], button, input, select, textarea, summary, [role='button'], [tabindex]:not([tabindex='-1'])")) {
    if (!visible(el)) continue;
    if (el.tagName === "INPUT" && el.type === "hidden") continue;
    // 复选框的关联 label 也是实际点击目标；只量 13px 的 input 会误报。
    const target = el.tagName === "INPUT" && el.labels?.length
      ? [...el.labels].find((label) => visible(label)) ?? el
      : el;
    const rect = target.getBoundingClientRect();
    if (rect.height < 32) {
      smallTargets.push({
        el: describe(el),
        w: Math.round(rect.width),
        h: Math.round(rect.height),
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
  for (const el of document.querySelectorAll("svg.ui-icon")) {
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

async function waitForCdp(timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${CDP}/json/version`);
      if (res.ok) return res.json();
    } catch {
      /* 还没起来 */
    }
    await sleep(300);
  }
  throw new Error(`CDP 未在 ${timeoutMs}ms 内就绪：${CDP}`);
}

async function main() {
  const chrome = findChrome();
  if (!chrome) throw new Error("未找到 Chrome/Edge，可用 --chrome <path> 或 CHROME_PATH 指定");
  try {
    const res = await fetch(`${BASE}/`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
  } catch (error) {
    throw new Error(`本地服务不可用（${BASE}）：${error.message}，请先执行 npm run dev`);
  }

  mkdirSync(OUT, { recursive: true });
  const profile = join(tmpdir(), `ddns-ui-audit-${process.pid}`);
  const browser = spawn(
    chrome,
    [
      "--headless=new",
      `--remote-debugging-port=${PORT}`,
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--disable-gpu",
      "--hide-scrollbars",
      "--force-device-scale-factor=1",
      "about:blank",
    ],
    { stdio: "ignore", detached: false },
  );

  let exitCode = 0;
  try {
    const version = await waitForCdp();
    const cdp = new Cdp(version.webSocketDebuggerUrl);
    await cdp.connect();
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Page.enable", {}, sessionId);
    await cdp.send("Runtime.enable", {}, sessionId);

    const results = [];
    for (const viewport of VIEWPORTS) {
      for (const page of PAGES) {
        await cdp.send(
          "Emulation.setDeviceMetricsOverride",
          { width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: viewport.mobile },
          sessionId,
        );
        const loaded = cdp.wait(sessionId, "Page.loadEventFired");
        await cdp.send("Page.navigate", { url: `${BASE}${page.path}` }, sessionId);
        await loaded.catch(() => {});
        await sleep(1200);
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
          }
        }
        const data = await checkPage(cdp, sessionId);
        results.push({ page: page.key, viewport: viewport.name, ...data });

        const metrics = await cdp.send("Page.getLayoutMetrics", {}, sessionId);
        const size = metrics.cssContentSize;
        const shot = await cdp.send(
          "Page.captureScreenshot",
          { format: "png", captureBeyondViewport: true, clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } },
          sessionId,
        );
        writeFileSync(join(OUT, `${page.key}-${viewport.name}.png`), Buffer.from(shot.data, "base64"));
      }
    }
    await cdp.send("Target.closeTarget", { targetId });

    writeFileSync(join(OUT, "report.json"), JSON.stringify({ generatedAt: new Date().toISOString(), base: BASE, results }, null, 2));

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

    const problems =
      results.filter((r) => r.overflow || r.contrastFailures.length || r.smallTargets.length || r.a11y.unnamedControls.length || r.a11y.duplicateIds.length).length + headingSkips.length;
    console.log(`\n报告与截图输出目录：${OUT}`);
    console.log(problems === 0 ? "结论：全部视口通过（无横向溢出、无对比度失败、无小于 32px 目标、无 a11y 问题）" : `结论：存在 ${problems} 类问题，见上方明细`);
  } finally {
    if (!KEEP_OPEN) {
      browser.kill();
      await sleep(500);
      rmSync(profile, { recursive: true, force: true });
    } else {
      console.log(`--keep-open：Chrome 仍在运行（pid ${browser.pid}），用户目录 ${profile}`);
    }
  }
  process.exit(exitCode);
}

main().catch((error) => {
  console.error(`审计失败：${error.message}`);
  process.exit(1);
});
