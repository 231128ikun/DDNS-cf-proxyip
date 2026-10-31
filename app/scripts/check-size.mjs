import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

/**
 * 体积门禁分两条，都只拦数量级回归，不锁死精确值：
 *
 *   - Worker 打包体积：冷启动与部署大小。面板不再打包进 Worker，
 *     因此这里只含 `app/src/` 的逻辑，预算是它自己的量级。
 *   - 页面重量：入口静态依赖单列，全量 JS 与 CSS 预算覆盖动态块。面板由 Cloudflare
 *     静态资源分发，和 Worker 体积互不影响，所以分开计量。
 *
 * 重新引入 Zod/Hono 等重型运行时依赖，或把大块逻辑塞进首屏，都应让 `npm run check` 失败。
 */
const BUDGETS = {
  worker: { rawKb: 230, gzipKb: 60 },
  // 单文件预算保留约 15% 余量：正常小改动可通过，单次数百 KB 的依赖膨胀仍会失败。
  script: { rawKb: 70, gzipKb: 24 },
  // 经用户授权增加源码体积余量；压缩后传输预算不变。
  scriptTotal: { rawKb: 115, gzipKb: 38 },
  style: { rawKb: 40, gzipKb: 10 },
  pageTotal: { rawKb: 155, gzipKb: 50 },
};

// 调整预算时最多只能相对上一轮生效值放宽 20%，避免连续追涨掩盖体积膨胀。
const BUDGET_BASELINE = {
  worker: { rawKb: 230, gzipKb: 60 },
  script: { rawKb: 60, gzipKb: 22 },
  scriptTotal: { rawKb: 100, gzipKb: 38 },
  style: { rawKb: 40, gzipKb: 10 },
  pageTotal: { rawKb: 140, gzipKb: 50 },
};
const MAX_BUDGET_GROWTH = 0.2;

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

for (const [name, budget] of Object.entries(BUDGETS)) {
  const baseline = BUDGET_BASELINE[name];
  const maxRaw = baseline.rawKb * (1 + MAX_BUDGET_GROWTH);
  const maxGzip = baseline.gzipKb * (1 + MAX_BUDGET_GROWTH);
  if (budget.rawKb > maxRaw || budget.gzipKb > maxGzip) {
    throw new Error(
      `预算 ${name} 单次放宽超过 ${MAX_BUDGET_GROWTH * 100}%：` +
      `raw ${baseline.rawKb}->${budget.rawKb} KB，gzip ${baseline.gzipKb}->${budget.gzipKb} KB`,
    );
  }
}

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

if (!scriptRaw || !styleRaw) throw new Error('构建不完整：缺少 JS 或 CSS 产物');
report('全量前端 js 合计', scriptRaw, scriptGzip, BUDGETS.scriptTotal);
report('全量前端 css 合计', styleRaw, styleGzip, BUDGETS.style);
report('全量前端 js + css 合计', scriptRaw + styleRaw, scriptGzip + styleGzip, BUDGETS.pageTotal);

const manifest = JSON.parse(readFileSync(new URL('dist/release/web-manifest.json', appRoot), 'utf8'));
const entry = Object.keys(manifest).find(key => manifest[key].isEntry);
if (!entry) throw new Error('构建不完整：缺少 HTML 入口清单');
const visited = new Set();
const initialFiles = new Set();
function visit(key) {
  if (visited.has(key)) return;
  visited.add(key);
  const chunk = manifest[key];
  if (!chunk) throw new Error(`构建清单引用缺失：${key}`);
  initialFiles.add(chunk.file);
  for (const file of chunk.css ?? []) initialFiles.add(file);
  for (const imported of chunk.imports ?? []) visit(imported);
}
visit(entry);
let initialRaw = 0, initialGzip = 0;
for (const file of initialFiles) {
  if (!/^assets\/[\w.-]+\.(js|css)$/.test(file)) throw new Error(`非法入口资源路径：${file}`);
  const bytes = readFileSync(new URL(`dist/web/${file}`, appRoot));
  initialRaw += bytes.length / 1024;
  initialGzip += gzipSync(bytes).length / 1024;
}
report('HTML 静态入口依赖 js + css', initialRaw, initialGzip, BUDGETS.pageTotal);
console.log('  入口统计不含登录后动态导入和预取；全量预算仍覆盖所有懒加载块。单位为 KiB。');

if (failed) {
  console.error('\n体积超出预算：请先确认新增依赖或静态资源是否必要；不要直接调高预算。');
  process.exitCode = 1;
}
