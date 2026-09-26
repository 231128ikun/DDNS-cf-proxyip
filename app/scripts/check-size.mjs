import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

/**
 * 体积预算只拦住数量级回归，不锁死精确值。
 * 重新引入 Zod/Hono 等重型运行时依赖应让 `npm run check` 失败。
 *
 * 动态 import 只改变加载时机，不减少总量，因此 JS 同时检查单文件和合计。
 */
const BUDGETS = {
  worker: { rawKb: 230, gzipKb: 80 },
  script: { rawKb: 60, gzipKb: 25 },
  scriptTotal: { rawKb: 72, gzipKb: 25 },
  style: { rawKb: 35, gzipKb: 12 },
};

const appRoot = new URL('../', import.meta.url);
const repoRoot = new URL('../../', import.meta.url);
const assetsDir = fileURLToPath(new URL('dist/web/assets', appRoot));
const targets = [
  { label: 'app/dist/release/worker.js', path: fileURLToPath(new URL('app/dist/release/worker.js', repoRoot)), budget: BUDGETS.worker },
];

for (const file of readdirSync(assetsDir)) {
  const path = join(assetsDir, file);
  if (file.endsWith('.js')) targets.push({ label: `web js  ${file}`, path, budget: BUDGETS.script });
  if (file.endsWith('.css')) targets.push({ label: `web css ${file}`, path, budget: BUDGETS.style });
}

let failed = false;
let scriptRaw = 0;
let scriptGzip = 0;

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
  report(label, rawKb, gzipKb, budget);
}

report('web js 合计', scriptRaw, scriptGzip, BUDGETS.scriptTotal);

if (failed) {
  console.error('\n体积超出预算：请先确认新增依赖或静态资源是否必要；不要直接调高预算。');
  process.exitCode = 1;
}
