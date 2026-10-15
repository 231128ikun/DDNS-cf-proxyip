#!/usr/bin/env node
/**
 * 部署形态冒烟检查：启动本地 Worker，验证「静态资源 + /api/*」的分工没有被改坏。
 *
 *   1) `/` 由 Cloudflare 静态资源返回 HTML；
 *   2) `/api/health` 由 Worker 返回 JSON 与版本号；
 *   3) 缺失的静态资源必须 404，不能被兜底成 200 HTML；
 *   4) 未知 API 路由返回 JSON 404。
 *
 * 用法：node scripts/smoke.mjs [--port 8799]
 * 需要先 `npm run build`（要读 app/dist/web 与 app/src）。
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
};

const port = Number(flag('port', '8799'));
const base = `http://127.0.0.1:${port}`;
const appRoot = join(import.meta.dirname, '..');
const wrangler = join(appRoot, 'node_modules', 'wrangler', 'bin', 'wrangler.js');
const indexHtml = join(appRoot, 'dist', 'web', 'index.html');

if (!existsSync(wrangler)) throw new Error('未安装 wrangler：先执行 npm ci');
if (!existsSync(indexHtml)) throw new Error('app/dist/web/index.html 缺失：先执行 npm run build');

const child = spawn(process.execPath, [wrangler, 'dev', '--config', '../wrangler.toml', '--port', String(port), '--local'], {
  cwd: appRoot,
  stdio: 'ignore',
  env: { ...process.env, CI: '1', NO_COLOR: '1', WRANGLER_SEND_METRICS: 'false' },
});

let failed = false;

try {
  await waitForReady();
  await check('静态资源返回面板', '/', 200, (response) => response.headers.get('content-type')?.includes('text/html') ?? false);
  await check('Worker 返回健康信息', '/api/health', 200, async (response) => {
    const body = await response.json();
    return body?.ok === true && typeof body.version === 'string' && body.version.length > 0;
  });
  await check('缺失的静态资源必须 404', '/assets/definitely-missing.js', 404);
  await check('未知 API 路由返回 404', '/api/definitely-missing', 404);
} finally {
  await stopServer();
}

if (failed) {
  console.error('\n冒烟检查失败：部署形态与预期不符。');
  process.exitCode = 1;
} else {
  console.log('\n冒烟检查通过。');
}

async function check(label, path, expectedStatus, verify) {
  try {
    const response = await fetch(base + path, { redirect: 'manual' });
    const detail = verify ? await verify(response) : true;
    const ok = response.status === expectedStatus && detail !== false;
    if (!ok) failed = true;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${path.padEnd(30)} ${response.status} ${response.headers.get('content-type') ?? ''}`);
  } catch (error) {
    failed = true;
    console.log(`  FAIL ${path.padEnd(30)} ${error.message}`);
  }
}

/** 轮询到 Worker 就绪：只看端口是否已经能响应，不看具体状态码。 */
async function waitForReady() {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    try {
      await fetch(`${base}/api/health`, { redirect: 'manual' });
      return;
    } catch {
      await sleep(500);
    }
  }
  throw new Error(`本地 Worker 在 45 秒内没有就绪（${base}）`);
}

/** Windows 上 wrangler 会派生 workerd，必须整棵进程树收掉，否则端口会一直被占用。 */
async function stopServer() {
  if (child.exitCode !== null) return;
  const tree = process.platform === 'win32';
  await new Promise((resolve) => {
    const killer = tree
      ? spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' })
      : spawn('kill', ['-TERM', String(child.pid)], { stdio: 'ignore' });
    killer.on('exit', resolve);
    killer.on('error', resolve);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}