import { mkdtempSync, readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const script = new URL('../../scripts/deploy.mjs', import.meta.url);
const { deployWithKvRecovery, materializeConfig, parseKvConflict, sanitizeLog, createWranglerRunner } = await import(script.href);
const account = 'a'.repeat(32);
const namespace = '1'.repeat(32);
const title = 'ddns-cf-proxyip-ip-data';
const conflictLog = `Provisioning IP_DATA (KV Namespace)...\nCreating new KV Namespace "${title}"...\nA request to the Cloudflare API (/accounts/${account}/storage/kv/namespaces) failed.\na namespace with this account ID and title already exists [code: 10014]`;
const failed = { exitCode: 1, stdout: conflictLog, stderr: '' };
const succeeded = { exitCode: 0, stdout: 'Deployment completed', stderr: '' };
const inventory = (items: unknown) => ({ exitCode: 0, stdout: JSON.stringify(items), stderr: '' });
let root: string;

function config() {
  return { name: 'ddns-cf-proxyip', main: 'src/index.ts', tsconfig: 'tsconfig.json',
    build: { command: 'node scripts/build-worker.mjs', watch_dir: ['src', 'web', 'scripts'] },
    assets: { directory: 'dist/web', binding: 'ASSETS' }, kv_namespaces: [{ binding: 'IP_DATA' }],
    triggers: { crons: ['0 */3 * * *'] } };
}

function runner(results: { exitCode: number; stdout: string; stderr: string; interrupted?: boolean }[]) {
  const snapshots: { args: string[]; config: ReturnType<typeof config> & { account_id?: string } }[] = [];
  const run = vi.fn(async (args: string[]) => {
    const path = args[args.indexOf('--config') + 1]!;
    snapshots.push({ args: [...args], config: JSON.parse(readFileSync(path, 'utf8')) });
    return results.shift() ?? succeeded;
  });
  return { run, snapshots };
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'ddns-kv-deploy-'));
  writeFileSync(join(root, 'wrangler.toml'), 'original source config');
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function expectClean() {
  expect(readFileSync(join(root, 'wrangler.toml'), 'utf8')).toBe('original source config');
  expect(readdirSync(join(root, '.wrangler', 'tmp'))).toEqual([]);
}

describe('create-first KV deployment recovery', () => {
  it('keeps local aliases resolvable after relocating root and environment configuration', () => {
    const raw = { ...config(), alias: { crypto: './src/adapters/probe/web-crypto.ts', package: 'some-package',
      absolute: resolve(root, 'absolute.ts'), parent: '../shared/adapter.ts' },
      env: { beta: { alias: { crypto: './src/adapters/probe/web-crypto.ts', builtin: 'node:crypto' } } } };
    const original = structuredClone(raw);
    const normalized = materializeConfig(raw, root);
    expect(normalized.alias).toEqual({ crypto: resolve(root, 'src/adapters/probe/web-crypto.ts'),
      package: 'some-package', absolute: resolve(root, 'absolute.ts'), parent: resolve(root, '../shared/adapter.ts') });
    expect(normalized.env.beta.alias).toEqual({ crypto: resolve(root, 'src/adapters/probe/web-crypto.ts'), builtin: 'node:crypto' });
    expect(raw).toEqual(original);
  });
  it('uses the native first deployment for creation or inheritance without extra lookups', async () => {
    const raw = config();
    const { run, snapshots } = runner([succeeded]);
    expect(await deployWithKvRecovery(raw, { sourceDir: root, run, log: vi.fn(), env: {} })).toBe(0);
    expect(run).toHaveBeenCalledTimes(1);
    expect(snapshots[0]!.args[0]).toBe('deploy');
    expect(snapshots[0]!.config.main).toBe(join(root, 'src', 'index.ts'));
    expect(snapshots[0]!.config.assets.directory).toBe(join(root, 'dist', 'web'));
    expect(snapshots[0]!.config.kv_namespaces).toEqual([{ binding: 'IP_DATA' }]);
    expect(raw).toEqual(config());
    expectClean();
  });

  it('only after code 10014 finds the unique same-title namespace in the failed account and retries', async () => {
    const raw = config();
    const { run, snapshots } = runner([failed, inventory([
      { title: title + '-other', id: '2'.repeat(32) }, { title, id: namespace },
    ]), succeeded]);
    const log = vi.fn();
    expect(await deployWithKvRecovery(raw, { sourceDir: root, run, log, env: {} })).toBe(0);
    expect(snapshots.map(item => item.args.slice(0, 3))).toEqual([
      ['deploy', '--config', expect.any(String)], ['kv', 'namespace', 'list'], ['deploy', '--config', expect.any(String)],
    ]);
    expect(snapshots[1]!.config.account_id).toBe(account);
    expect(snapshots[2]!.config.kv_namespaces).toEqual([{ binding: 'IP_DATA', id: namespace }]);
    expect(raw).toEqual(config());
    expect(log.mock.calls.flat().join('\n')).not.toContain(account);
    expect(log.mock.calls.flat().join('\n')).not.toContain(namespace);
    expectClean();
  });

  it('recovers using real child processes and the normal Wrangler log level without remote requests', async () => {
    const mock = join(root, 'mock-wrangler.mjs');
    writeFileSync(mock, `import { readFileSync } from 'node:fs';
const args = process.argv.slice(2);
const cfg = JSON.parse(readFileSync(args[args.indexOf('--config') + 1], 'utf8'));
if (args[0] === 'kv') {
  if (cfg.account_id !== '${account}') process.exitCode = 2;
  else console.log(JSON.stringify([{title: '${title}', id: '${namespace}'}]));
} else if (cfg.kv_namespaces[0].id === '${namespace}') {
  console.log('Deployment completed');
} else {
  if (process.env.WRANGLER_LOG === 'log') console.log('Provisioning IP_DATA (KV Namespace)...\\nCreating new KV Namespace "${title}"...');
  console.error('A request to the Cloudflare API (/accounts/${account}/storage/kv/namespaces) failed. [code: 10014]');
  process.exitCode = 1;
}`);
    const run = createWranglerRunner({ cwd: root, script: mock, env: { ...process.env, WRANGLER_LOG: 'info' } });
    const log = vi.fn();
    expect(await deployWithKvRecovery(config(), { sourceDir: root, run, log, env: {} })).toBe(0);
    expect(log.mock.calls.flat().join('\n')).toContain('重试一次');
    expectClean();
  });

  it('never replaces an explicitly configured namespace', async () => {
    const raw = { ...config(), kv_namespaces: [{ binding: 'IP_DATA', id: namespace }] };
    const { run, snapshots } = runner([failed]);
    expect(await deployWithKvRecovery(raw, { sourceDir: root, run, log: vi.fn(), env: {} })).toBe(1);
    expect(run).toHaveBeenCalledTimes(1);
    expect(snapshots[0]!.config.kv_namespaces).toEqual(raw.kv_namespaces);
    expectClean();
  });

  it.each([
    'HTTP 500', 'Network connection lost', 'Missing entry-point',
    conflictLog.replace('storage/kv/namespaces', 'd1/database'),
    conflictLog.replace('Provisioning IP_DATA', 'Provisioning OTHER'),
    '[custom build] ' + conflictLog.replaceAll('\n', '\n[custom build] '),
  ])('does not retry unrelated or uncertain errors: %s', async output => {
    const { run } = runner([{ exitCode: 1, stdout: output, stderr: '' }]);
    expect(await deployWithKvRecovery(config(), { sourceDir: root, run, log: vi.fn(), env: {} })).toBe(1);
    expect(run).toHaveBeenCalledTimes(1);
    expectClean();
  });

  it('cleans private deployment configuration after a command throws', async () => {
    const run = vi.fn(async () => { throw new Error('command startup failed'); });
    await expect(deployWithKvRecovery(config(), { sourceDir: root, run, log: vi.fn(), env: {} })).rejects.toThrow('command startup failed');
    expectClean();
  });

  it('does not retry an interrupted command even if the buffered log contains the conflict', async () => {
    const { run } = runner([{ ...failed, interrupted: true }]);
    expect(await deployWithKvRecovery(config(), { sourceDir: root, run, log: vi.fn(), env: {} })).toBe(1);
    expect(run).toHaveBeenCalledTimes(1);
    expectClean();
  });

  it.each([
    { items: [] }, { items: [{ title: title + '-other', id: namespace }] }, { items: [{ title, id: 'invalid' }] },
    { items: [{ title, id: namespace }, { title, id: '2'.repeat(32) }] }, { items: { result: [{ title, id: namespace }] } },
  ])('rejects missing, ambiguous or malformed matches: $items', async ({ items }) => {
    const { run } = runner([failed, inventory(items)]);
    expect(await deployWithKvRecovery(config(), { sourceDir: root, run, log: vi.fn(), env: {} })).toBe(1);
    expect(run).toHaveBeenCalledTimes(2);
    expectClean();
  });

  it.each([
    { exitCode: 1, stdout: '', stderr: 'Permission denied' },
    { exitCode: 0, stdout: 'not JSON', stderr: '' },
  ])('does not publish after an unsuccessful inventory read: %j', async result => {
    const { run } = runner([failed, result]);
    expect(await deployWithKvRecovery(config(), { sourceDir: root, run, log: vi.fn(), env: {} })).toBe(1);
    expect(run).toHaveBeenCalledTimes(2);
    expectClean();
  });

  it('retries at most once and preserves source configuration after retry failure', async () => {
    const { run } = runner([failed, inventory([{ title, id: namespace }]), failed]);
    expect(await deployWithKvRecovery(config(), { sourceDir: root, run, log: vi.fn(), env: {} })).toBe(1);
    expect(run).toHaveBeenCalledTimes(3);
    expectClean();
  });

  it.each([{ args: ['--dry-run'] }, { args: ['--dry-run=true'] }])('does not recover or look up remote resources during dry-run: $args', async ({ args }) => {
    const { run } = runner([failed]);
    expect(await deployWithKvRecovery(config(), { args, sourceDir: root, run, log: vi.fn(), env: {} })).toBe(1);
    expect(run).toHaveBeenCalledTimes(1);
    expectClean();
  });

  it('stops if the conflict account differs from explicitly configured scope', async () => {
    const { run } = runner([failed]);
    expect(await deployWithKvRecovery({ ...config(), account_id: 'b'.repeat(32) }, { sourceDir: root, run, log: vi.fn(), env: {} })).toBe(1);
    expect(run).toHaveBeenCalledTimes(1);
    expectClean();
  });

  it('keeps environment and authentication arguments while only updating the target environment binding', async () => {
    const raw = { ...config(), kv_namespaces: [{ binding: 'IP_DATA', id: '2'.repeat(32) }],
      env: { production: { name: 'ddns-production', kv_namespaces: [{ binding: 'IP_DATA' }], assets: { directory: 'dist/web' } } } };
    const environmentTitle = 'ddns-production-ip-data';
    const { run, snapshots } = runner([{ ...failed, stdout: conflictLog.replace(title, environmentTitle) }, inventory([{ title: environmentTitle, id: namespace }]), succeeded]);
    writeFileSync(join(root, '.env.private'), 'FIXTURE=value');
    expect(await deployWithKvRecovery(raw, { args: ['--env=production', '--profile', 'selected', '--env-file', '.env.private'],
      sourceDir: root, run, log: vi.fn(), env: {} })).toBe(0);
    const retry = snapshots[2]!;
    expect(retry.args).toContain('--env');
    expect(retry.args).toContain('production');
    expect(snapshots[1]!.args).toContain('--profile');
    expect(snapshots[1]!.args).toContain(join(root, '.env.private'));
    const normalized = retry.config as typeof raw;
    expect(normalized.kv_namespaces).toEqual(raw.kv_namespaces);
    expect(normalized.env.production.kv_namespaces).toEqual([{ binding: 'IP_DATA', id: namespace }]);
    expect(normalized.env.production.assets.directory).toBe(join(root, 'dist/web'));
    expect(raw.env.production.kv_namespaces).toEqual([{ binding: 'IP_DATA' }]);
    expectClean();
  });

  it('loads default source-directory dotenv files consistently for both attempts and the inventory', async () => {
    writeFileSync(join(root, '.env'), 'FIXTURE=value');
    const { run, snapshots } = runner([failed, inventory([{ title, id: namespace }]), succeeded]);
    expect(await deployWithKvRecovery(config(), { sourceDir: root, run, log: vi.fn(), env: {} })).toBe(0);
    expect(snapshots.every(item => item.args.includes(join(root, '.env')))).toBe(true);
    expectClean();
  });

  it('normalizes boolean deployment flags without forwarding stray positional values', async () => {
    const { run, snapshots } = runner([succeeded]);
    expect(await deployWithKvRecovery(config(), { args: ['--dry-run', 'false', '--autoconfig', 'false'], sourceDir: root, run, log: vi.fn(), env: {} })).toBe(0);
    expect(snapshots[0]!.args.filter(value => value === '--autoconfig=false')).toHaveLength(1);
    expect(snapshots[0]!.args).toContain('--dry-run=false');
    expect(snapshots[0]!.args).not.toContain('false');
    expectClean();
  });

  it('redacts configured and environment secrets from command output', async () => {
    const raw = { ...config(), vars: { AUTH_KEY: 'fixture-password' } };
    const { run } = runner([{ exitCode: 0, stdout: `fixture-password fixture-token ${account} ${namespace}`, stderr: '' }]);
    const log = vi.fn();
    expect(await deployWithKvRecovery(raw, { sourceDir: root, run, log, env: { CLOUDFLARE_API_TOKEN: 'fixture-token' } })).toBe(0);
    const text = log.mock.calls.flat().join('\n');
    expect(text).not.toContain('fixture-password');
    expect(text).not.toContain('fixture-token');
    expect(text).not.toContain(account);
    expect(text).not.toContain(namespace);
    expectClean();
  });
});

describe('deployment configuration and conflict boundaries', () => {
  it('makes source, asset and build paths absolute without changing the source object', () => {
    const raw = config();
    const normalized = materializeConfig(raw, root);
    expect(normalized.main).toBe(resolve(root, 'src/index.ts'));
    expect(normalized.build.cwd).toBe(root);
    expect(normalized.build.watch_dir).toEqual(['src', 'web', 'scripts'].map(path => resolve(root, path)));
    expect(normalized.assets.directory).toBe(resolve(root, 'dist/web'));
    expect(raw).toEqual(config());
  });

  it('does not carry a previous IP_DATA provisioning context into a later resource failure', () => {
    expect(parseKvConflict(conflictLog.replace('A request to', 'Provisioning OTHER (KV Namespace)...\nA request to'))).toBeNull();
  });

  it('redacts secrets loaded from an explicit dotenv file', async () => {
    writeFileSync(join(root, '.env.private'), 'AUTH_KEY="dotenv-password"\n');
    const { run } = runner([{ exitCode: 0, stdout: 'dotenv-password', stderr: '' }]);
    const log = vi.fn();
    expect(await deployWithKvRecovery(config(), { args: ['--env-file', '.env.private'], sourceDir: root, run, log, env: {} })).toBe(0);
    expect(log.mock.calls.flat().join('\n')).not.toContain('dotenv-password');
    expectClean();
  });

  it('redacts literal and JSON-escaped secret representations', () => {
    const secret = 'fixture"password';
    expect(sanitizeLog(`${secret} ${JSON.stringify(secret)} ${namespace}`, [secret])).not.toContain('password');
    expect(sanitizeLog(namespace)).toBe('[resource-id]');
  });

  it.each([{ args: ['--config', 'other.toml'] }, { args: ['--cwd', '..'] }, { args: ['--env'] }, { args: ['--autoconfig=true'] }, { args: ['--dry-run=maybe'] }])('rejects unsafe or incomplete entry overrides: $args', async ({ args }) => {
    const { run } = runner([]);
    await expect(deployWithKvRecovery(config(), { args, sourceDir: root, run, log: vi.fn(), env: {} })).rejects.toThrow();
    expect(run).not.toHaveBeenCalled();
  });
});
