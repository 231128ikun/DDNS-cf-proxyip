import { execFileSync, execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, renameSync, rmdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const appRoot = fileURLToPath(new URL('../', import.meta.url));
const webDir = join(appRoot, 'dist', 'web');
const outDir = join(appRoot, 'dist', 'release');
const releaseWorkerPath = join(outDir, 'worker.js');
const skipCustomBuild = 'DDNS_SKIP_CUSTOM_BUILD';

export function fingerprintInputs(root = appRoot) {
  const paths = ['src', 'web'].flatMap(directory => filesIn(join(root, directory)));
  const changelog = resolve(root, '../CHANGELOG.md');
  if (existsSync(changelog)) paths.push(changelog);
  paths.push(...['package.json', 'package-lock.json', 'wrangler.toml', 'tsconfig.json', '.node-version',
    'scripts/build-worker.mjs', 'scripts/check-size.mjs', 'scripts/clean.mjs'].map(path => join(root, path)));
  return fingerprint(root, paths);
}

export function fingerprintOutputs(root = appRoot) {
  return fingerprint(root, [...filesIn(join(root, 'dist', 'web')),
    join(root, 'dist', 'release', 'worker.js'), join(root, 'dist', 'release', 'web-manifest.json')]);
}

export function canReuseBuild(root = appRoot) {
  try {
    const state = JSON.parse(readFileSync(statePath(root), 'utf8'));
    return state.inputs === fingerprintInputs(root) && state.outputs === fingerprintOutputs(root);
  } catch {
    return false;
  }
}

export function saveBuildState(root, inputs) {
  if (inputs !== fingerprintInputs(root)) throw new Error('构建期间源码发生变化，请重新构建');
  const path = statePath(root);
  mkdirSync(join(root, '.wrangler', 'tmp'), { recursive: true });
  writeFileSync(path, JSON.stringify({ inputs, outputs: fingerprintOutputs(root) }), 'utf8');
}

function build() {
  // 内层 Wrangler 只打包 Worker，不能再次触发当前构建命令。
  if (process.env[skipCustomBuild] === '1') {
    console.log('  内层打包：跳过重复自定义构建。');
    return;
  }
  const customBuild = Boolean(process.env.WRANGLER_COMMAND);
  if (customBuild && canReuseBuild()) {
    console.log('  源码与产物未变化，复用已完成构建。');
    runNpm('check:size');
    return;
  }

  const inputs = fingerprintInputs();
  console.log('构建静态面板与 Worker 检查产物:');
  runNpm('clean');
  runNpm('build:web');

  if (!existsSync(join(webDir, 'index.html'))) throw new Error('dist/web/index.html 缺失：前端构建结果不完整');
  mkdirSync(outDir, { recursive: true });
  // 清单只用于验收，不能作为静态资源发布。
  renameSync(join(webDir, '.vite', 'manifest.json'), join(outDir, 'web-manifest.json'));
  rmdirSync(join(webDir, '.vite'));

  runWrangler(['deploy', '--dry-run', '--config', 'wrangler.toml', '--outdir', toPosix(relative(appRoot, outDir))]);
  const bundle = readFileSync(pickBundleFile(outDir), 'utf8').replace(/^\/\/# sourceMappingURL=.*$/gm, '').trimEnd() + '\n';
  writeFileSync(releaseWorkerPath, bundle, 'utf8');
  saveBuildState(appRoot, inputs);
  console.log(`  worker.js  raw ${formatKb(Buffer.byteLength(bundle))}  gzip ${formatKb(gzipSync(bundle).length)}`);
  console.log('  静态资源：dist/web');
  if (customBuild) runNpm('check:size');
}

/** npm 在 Windows 上是 .cmd 包装器，用 shell 启动以避免 spawn EINVAL。 */
function runNpm(script) {
  execSync(`npm run ${script}`, { cwd: appRoot, stdio: 'inherit' });
}

function runWrangler(args) {
  try {
    execFileSync(process.execPath, [join(appRoot, 'node_modules', 'wrangler', 'bin', 'wrangler.js'), ...args], {
      cwd: appRoot,
      stdio: 'inherit',
      timeout: 90_000,
      env: { ...process.env, [skipCustomBuild]: '1', CI: '1', NO_COLOR: '1', WRANGLER_SEND_METRICS: 'false' },
    });
  } catch (error) {
    // Windows 偶发在完整写出 bundle 后不退出；其他错误必须阻止发布。
    if (error.code === 'ETIMEDOUT' && existsSync(outDir) && readdirSync(outDir).some(name => name.endsWith('.js'))) {
      console.warn('  Wrangler 已写出 bundle，但未及时退出；继续校验产物。');
      return;
    }
    throw error;
  }
}

function filesIn(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    if (['node_modules', 'dist', '.wrangler', '.git'].includes(entry.name)) return [];
    const path = join(directory, entry.name);
    return entry.isDirectory() ? filesIn(path) : entry.isFile() ? [path] : [];
  });
}

function fingerprint(root, paths) {
  const hash = createHash('sha256').update(process.version);
  for (const path of paths.sort()) {
    const data = readFileSync(path);
    hash.update(`${toPosix(relative(root, path))}\0${data.length}\0`).update(data);
  }
  return hash.digest('hex');
}

function statePath(root) {
  return join(root, '.wrangler', 'tmp', 'build-state.json');
}

function pickBundleFile(directory) {
  const candidates = readdirSync(directory).filter(name => name.endsWith('.js'));
  if (candidates.length !== 1) throw new Error(`期望 ${directory} 只有一个打包产物，实际为：${candidates.join(', ') || '空'}`);
  return join(directory, candidates[0]);
}

function toPosix(value) {
  return value.split(sep).join('/');
}

function formatKb(bytes) {
  return `${(bytes / 1024).toFixed(2)} KB`;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) build();
