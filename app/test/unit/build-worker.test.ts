import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, utimesSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const scriptUrl = new URL('../../scripts/build-worker.mjs', import.meta.url);
const { fingerprintInputs, fingerprintOutputs, canReuseBuild, saveBuildState } = await import(scriptUrl.href);
let root: string;

function put(path: string, content: string) {
  const full = join(root, path);
  mkdirSync(join(full, '..'), { recursive: true });
  writeFileSync(full, content);
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'ddns-build-state-'));
  for (const [path, content] of Object.entries({
    'src/index.ts': 'export default {};',
    'web/index.html': '<div id="app"></div>',
    'web/src/styles.css': 'body { margin: 0; }',
    'web/public/icon.svg': '<svg></svg>',
    'package.json': '{}', 'package-lock.json': '{}', 'tsconfig.json': '{}', '.node-version': '22',
    'wrangler.toml': 'main = "src/index.ts"',
    'scripts/check-size.mjs': 'console.log("size");', 'scripts/clean.mjs': 'console.log("clean");',
    'dist/web/index.html': '<script src="assets/app.js"></script>',
    'dist/web/assets/app.js': 'console.log("app");',
    'dist/web/assets/app.css': 'body { margin: 0; }',
    'dist/release/worker.js': 'export default {};',
    'dist/release/web-manifest.json': '{}',
  })) put(path, content);
  put('scripts/build-worker.mjs', readFileSync(fileURLToPath(scriptUrl), 'utf8'));
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

describe('Wrangler automatic build state', () => {
  it('reuses only matching complete source and output fingerprints', () => {
    expect(canReuseBuild(root)).toBe(false);
    saveBuildState(root, fingerprintInputs(root));
    expect(canReuseBuild(root)).toBe(true);
    const before = fingerprintInputs(root);
    utimesSync(join(root, 'src/index.ts'), new Date(), new Date());
    expect(fingerprintInputs(root)).toBe(before);
    expect(canReuseBuild(root)).toBe(true);
  });

  it.each(['src/index.ts', 'web/src/styles.css', 'web/public/icon.svg', 'package.json', 'package-lock.json',
    'wrangler.toml', 'scripts/check-size.mjs'])('rebuilds after input changes: %s', path => {
    saveBuildState(root, fingerprintInputs(root));
    put(path, 'changed');
    expect(canReuseBuild(root)).toBe(false);
  });

  it.each(['dist/web/index.html', 'dist/web/assets/app.js', 'dist/release/worker.js',
    'dist/release/web-manifest.json'])('rejects modified or missing output: %s', path => {
    saveBuildState(root, fingerprintInputs(root));
    put(path, 'changed');
    expect(canReuseBuild(root)).toBe(false);
    rmSync(join(root, path));
    expect(canReuseBuild(root)).toBe(false);
  });

  it('detects added and removed source files without a Git checkout', () => {
    saveBuildState(root, fingerprintInputs(root));
    put('web/src/new.ts', 'export const added = true;');
    expect(canReuseBuild(root)).toBe(false);
    rmSync(join(root, 'web/src/new.ts'));
    expect(canReuseBuild(root)).toBe(true);
    rmSync(join(root, 'web/public/icon.svg'));
    expect(canReuseBuild(root)).toBe(false);
  });

  it('does not treat its cache record or output files as source changes', () => {
    const before = fingerprintInputs(root);
    saveBuildState(root, before);
    put('.wrangler/tmp/another.json', '{}');
    expect(fingerprintInputs(root)).toBe(before);
    expect(canReuseBuild(root)).toBe(true);
  });

  it('rebuilds when the state record is malformed', () => {
    put('.wrangler/tmp/build-state.json', '{broken');
    expect(canReuseBuild(root)).toBe(false);
  });

  it('rejects a source change that occurred during the build', () => {
    const before = fingerprintInputs(root);
    put('src/index.ts', 'export default { changed: true };');
    expect(() => saveBuildState(root, before)).toThrow('构建期间源码发生变化');
    expect(existsSync(join(root, '.wrangler/tmp/build-state.json'))).toBe(false);
  });

  it('explicitly skips the nested hook without modifying artifacts', () => {
    const inputs = fingerprintInputs(root);
    const outputs = fingerprintOutputs(root);
    const log = execFileSync(process.execPath, [join(root, 'scripts/build-worker.mjs')], {
      cwd: root, encoding: 'utf8', env: { ...process.env, DDNS_SKIP_CUSTOM_BUILD: '1', WRANGLER_COMMAND: 'deploy' },
    });
    expect(log).toContain('跳过重复自定义构建');
    expect(fingerprintInputs(root)).toBe(inputs);
    expect(fingerprintOutputs(root)).toBe(outputs);
    expect(existsSync(join(root, '.wrangler/tmp/build-state.json'))).toBe(false);
  });
});
