import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

/**
 * 体积门禁分两条，都只拦数量级回归，不锁死精确值：
 *
 *   - Worker 打包体积：冷启动与部署大小。面板不再打包进 Worker，
 *     因此这里只含 `app/src/` 的逻辑，预算是它自己的量级。
 *   - 首屏页面重量：浏览器端 JS 与 CSS 的 gzip 合计。面板由 Cloudflare
 *     静态资源分发，和 Worker 体积互不影响，所以分开计量。
 *
 * 重新引入 Zod/Hono 等重型运行时依赖，或把大块逻辑塞进首屏，都应让 `npm run check` 失败。
 */
const BUDGETS = {
  worker: { rawKb: 230, gzipKb: 60 },
  script: { rawKb: 60, gzipKb: 22 },
  scriptTotal: { rawKb: 90, gzipKb: 32 },
  style: { rawKb: 40, gzipKb: 10 },
  pageTotal: { rawKb: 130, gzipKb: 42 },
};

const appRoot = new URL('../', import.meta.url);
const repoRoot = new URL('../../', import.meta.url);
const assetsDir = fileURLToPath(new URL('dist/web/assets', appRoot));
const targets = [
  { label: 'worker  app/dist/release/worker.js', path: fileURLToPath(new URL('app/dist/release/worker.js', repoRoot)), budget: BUDGETS.worker },
];

let scriptRaw = 0;
let scriptGzip = 0;
let styleRaw = 0;
let styleGzip = 0;

for (const file of readdirSync(assetsDir)) {
  const path = join(assetsDir, file);
  if (file.endsWith('.js')) targets.push({ label: `web js  ${file}`, path, budget: BUDGETS.script });
  if (file.endsWith('.css')) targets.push({ label: `web css ${file}`, path, budget: BUDGETS.style });
}

let failed = false;

const report = (label, rawKb, gzipKb, budget) => {
  const over = rawKb > budget.rawKb || gzipKb > budget.gzipKb;
  failed ||= over;
  const mark = over ? 'FAIL' : 'ok';
  console.log(
    `  ${mark.padEnd(4)} ${label.padEnd(34)} raw ${rawKb.toFixed(2)} KB (<= ${budget.rawKb})  gzip ${gzipKb.toFixed(2)} KB (<= ${budget.gzipKb})`,
  );
};

console.log('产物体积:');
for (const { label, path, budget } of targets) {
  const bytes = readFileSync(path);
  const rawKb = bytes.length / 1024;
  const gzipKb = gzipSync(bytes).length / 1024;
  if (label.startsWith('web js')) {
    scriptRaw += rawKb;
    scriptGzip += gzipKb;
  }
  if (label.startsWith('web css')) {
    styleRaw += rawKb;
    styleGzip += gzipKb;
  }
  report(label, rawKb, gzipKb, budget);
}

report('首屏 js 合计', scriptRaw, scriptGzip, BUDGETS.scriptTotal);
report('首屏 css 合计', styleRaw, styleGzip, BUDGETS.style);
report('首屏 js + css 合计', scriptRaw + styleRaw, scriptGzip + styleGzip, BUDGETS.pageTotal);

if (failed) {
  console.error('\n体积超出预算：请先确认新增依赖或静态资源是否必要；不要直接调高预算。');
  process.exitCode = 1;
}