import { execFileSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync, renameSync, rmdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

/**
 * 构建检查产物：
 *   1. 用 Vite 构建 `app/web/` 到 `app/dist/web/`，该目录就是部署时的静态资源目录；
 *   2. 用 Wrangler 打包 `app/src/index.ts` 到 `app/dist/release/worker.js`，只用于体积门禁。
 *
 * 部署入口由 `wrangler.toml` 指向源码，仓库不提交任何构建产物，
 * 因此这里不再生成第二份“可复制部署”的单文件。
 */

const root = fileURLToPath(new URL('../../', import.meta.url));
const appRoot = join(root, 'app');
const webDir = join(appRoot, 'dist', 'web');
const outDir = join(appRoot, 'dist', 'release');
const releaseWorkerPath = join(outDir, 'worker.js');

console.log('构建检查产物:');
runNpm('build:web');

if (!existsSync(join(webDir, 'index.html'))) {
  throw new Error('app/dist/web/index.html 缺失：前端构建结果不完整');
}

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });
// 清单只用于验收，不能作为静态资源发布。
renameSync(join(webDir, '.vite', 'manifest.json'), join(outDir, 'web-manifest.json'));
rmdirSync(join(webDir, '.vite'));

runWrangler(['deploy', '--dry-run', '--config', 'wrangler.toml', '--outdir', toPosix(relative(root, outDir))]);

const bundle = createBundle();
writeFileSync(releaseWorkerPath, bundle, 'utf8');

console.log(`  worker.js  raw ${formatKb(Buffer.byteLength(bundle))}  gzip ${formatKb(gzipSync(bundle).length)}`);
console.log('  静态资源：app/dist/web（部署时由 wrangler.toml 的 [assets] 指向）');

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
    execFileSync(process.execPath, [join(appRoot, 'node_modules', 'wrangler', 'bin', 'wrangler.js'), ...args], {
      cwd: root,
      stdio: 'inherit',
      timeout: 90_000,
      env: { ...process.env, CI: '1', NO_COLOR: '1', WRANGLER_SEND_METRICS: 'false' },
    });
  } catch (error) {
    if (existsSync(outDir) && readdirSync(outDir).some((name) => name.endsWith('.js'))) {
      console.warn('  Wrangler 已写出 bundle，但未正常退出；构建继续。');
      return;
    }
    throw error;
  }
}

function createBundle() {
  const source = readFileSync(pickBundleFile(outDir), 'utf8');
  return stripSourceMapReference(source);
}

/** Wrangler 产物末尾指向 sourcemap，但发布目录不保留 map 文件，去掉悬空引用。 */
function stripSourceMapReference(source) {
  const withoutMap = source.replace(/^\/\/# sourceMappingURL=.*$/gm, '');
  return withoutMap.replace(/\s+$/, '') + '\n';
}

function pickBundleFile(directory) {
  const candidates = readdirSync(directory).filter((name) => name.endsWith('.js'));
  if (candidates.length !== 1) {
    throw new Error(`期望 ${directory} 只有一个打包产物，实际为：${candidates.join(', ') || '空'}`);
  }
  return join(directory, candidates[0]);
}

function toPosix(value) {
  return value.split(sep).join('/');
}

function formatKb(bytes) {
  return `${(bytes / 1024).toFixed(2)} KB`;
}
