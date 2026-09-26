import { execFileSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { extname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

/**
 * 把 `app/` 中的重构源码构建成独立检查产物 `worker.js`。
 *
 * 构建顺序：
 *   1. 用 Vite 构建 `app/web/`；
 *   2. 把前端产物 gzip 后编码为 Worker 内置资源表；
 *   3. 用 Wrangler 打包唯一的 `createWorker()` 入口。
 *
 * 根目录当前仍以手工可读的 `_worker.js` 为部署入口，完成行为对齐前不覆盖它。
 * 构建产物不手工编辑；重构源码始终以 `app/` 为准。
 */

const root = fileURLToPath(new URL('../../', import.meta.url));
const appRoot = join(root, 'app');
const webDir = join(appRoot, 'dist', 'web');
const outDir = join(appRoot, 'dist', 'release');
const buildDir = join(appRoot, 'dist', 'bundle-build');
const generatedDir = join(buildDir, 'generated');
const bundleDir = join(buildDir, 'bundle');
const releaseWorkerPath = join(outDir, 'worker.js');

/** 前端产物只支持明确列出的类型；出现新类型时先显式登记 MIME。 */
const CONTENT_TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.mjs', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.webp', 'image/webp'],
  ['.gif', 'image/gif'],
  ['.ico', 'image/x-icon'],
  ['.woff', 'font/woff'],
  ['.woff2', 'font/woff2'],
  ['.txt', 'text/plain; charset=utf-8'],
]);

console.log('构建 worker.js:');
runNpm('build:web');

rmSync(outDir, { recursive: true, force: true });
rmSync(buildDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });
mkdirSync(generatedDir, { recursive: true });

const assets = collectAssets(webDir);
if (!assets.some((asset) => asset.path === '/index.html')) {
  throw new Error('app/dist/web/index.html 缺失：前端构建结果不完整');
}

writeFileSync(join(generatedDir, 'assets.ts'), renderAssetsModule(assets), 'utf8');
writeFileSync(join(generatedDir, 'index.ts'), renderEntryModule(generatedDir), 'utf8');

runWrangler([
  toPosix(relative(root, join(generatedDir, 'index.ts'))),
  '--dry-run',
  '--config',
  'wrangler.toml',
  '--outdir',
  toPosix(relative(root, bundleDir)),
]);

const bundle = createBundle();
writeFileSync(releaseWorkerPath, bundle, 'utf8');
rmSync(buildDir, { recursive: true, force: true });

console.log(`  资源 ${assets.length} 个，打包 ${formatKb(assets.reduce((sum, asset) => sum + asset.bytes.length, 0))}`);
console.log(`  worker.js  raw ${formatKb(Buffer.byteLength(bundle))}  gzip ${formatKb(gzipSync(bundle).length)}`);
console.log('  构建产物：app/dist/release/worker.js');

/** npm 在 Windows 上是 .cmd 包装器，用字符串形式交给 shell 启动，避免 spawn EINVAL。 */
function runNpm(script) {
  execSync(`npm run ${script}`, { cwd: appRoot, stdio: 'inherit' });
}

/**
 * Wrangler 的 dry-run 在 Windows 上偶发写出 bundle 后不主动退出。
 * 只要 bundle 已完整写出，就按成功处理；没有产物时才保留真实错误。
 */
function runWrangler(args) {
  try {
    execFileSync(process.execPath, [join(appRoot, 'node_modules', 'wrangler', 'bin', 'wrangler.js'), 'deploy', ...args], {
      cwd: root,
      stdio: 'inherit',
      timeout: 90_000,
      env: { ...process.env, CI: '1', NO_COLOR: '1', WRANGLER_SEND_METRICS: 'false' },
    });
  } catch (error) {
    if (existsSync(bundleDir) && readdirSync(bundleDir).some((name) => name.endsWith('.js'))) {
      console.warn('  Wrangler 已写出 bundle，但未正常退出；构建继续。');
      return;
    }
    throw error;
  }
}

function createBundle() {
  const source = readFileSync(pickBundleFile(bundleDir), 'utf8');
  return stripSourceMapReference(source);
}

/** Wrangler 产物末尾指向 sourcemap，但发布目录不保留 map 文件，去掉悬空引用。 */
function stripSourceMapReference(source) {
  return source.replace(/^\/\/# sourceMappingURL=.*$/gm, '');
}

/** 递归收集前端产物，生成以请求路径为 key 的资源表。 */
function collectAssets(directory) {
  const collected = [];

  for (const entry of readdirSync(directory, { withFileTypes: true }).sort(byName)) {
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) {
      collected.push(...collectAssets(absolute));
      continue;
    }
    if (extname(entry.name) === '.map') continue;

    const path = `/${toPosix(relative(webDir, absolute))}`;
    const contentType = CONTENT_TYPES.get(extname(entry.name));
    if (!contentType) throw new Error(`app/dist/web 出现未登记 MIME 的资源：${path}`);

    const bytes = readFileSync(absolute);
    const gzip = gzipSync(bytes, { level: 9 });
    const useGzip = gzip.length < bytes.length;
    collected.push({
      path,
      contentType,
      bytes,
      base64: (useGzip ? gzip : bytes).toString('base64'),
      gzip: useGzip,
    });
  }

  return collected;
}

function pickBundleFile(directory) {
  const candidates = readdirSync(directory).filter((name) => name.endsWith('.js'));
  if (candidates.length !== 1) {
    throw new Error(`期望 ${directory} 只有一个打包产物，实际为：${candidates.join(', ') || '空'}`);
  }
  return join(directory, candidates[0]);
}

function byName(left, right) {
  return left.name.localeCompare(right.name);
}

function renderAssetsModule(collected) {
  const rows = collected
    .map((asset) => `  ${quote(asset.path)}: { contentType: ${quote(asset.contentType)}, base64: ${quote(asset.base64)}, gzip: ${asset.gzip} },`)
    .join('\n');
  return [
    '// 由 scripts/build-worker.mjs 生成，请勿手改。',
    `import type { BundledAssetMap } from ${quote(importPath(generatedDir, 'app/src/adapters/assets/bundled-assets'))};`,
    '',
    'export const BUNDLED_WEB_ASSETS: BundledAssetMap = {',
    rows,
    '};',
    '',
  ].join('\n');
}

function renderEntryModule(fromDirectory) {
  return [
    '// 由 scripts/build-worker.mjs 生成，请勿手改。',
    "import { connect } from 'cloudflare:sockets';",
    `import { createBundledAssets } from ${quote(importPath(fromDirectory, 'app/src/adapters/assets/bundled-assets'))};`,
    `import { createWorker } from ${quote(importPath(fromDirectory, 'app/src/worker'))};`,
    "import { BUNDLED_WEB_ASSETS } from './assets';",
    '',
    'export default createWorker({ connect, assets: createBundledAssets(BUNDLED_WEB_ASSETS) });',
    '',
  ].join('\n');
}

function importPath(fromDirectory, target) {
  const specifier = toPosix(relative(fromDirectory, join(root, target)));
  return specifier.startsWith('.') ? specifier : `./${specifier}`;
}

function toPosix(value) {
  return value.split(sep).join('/');
}

function quote(value) {
  return JSON.stringify(value);
}

function formatKb(bytes) {
  return `${(bytes / 1024).toFixed(2)} KB`;
}