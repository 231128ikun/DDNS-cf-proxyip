import { existsSync, readFileSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { describe, expect, it, vi } from 'vitest';
import { createProbeAdapterFromConfig, loadEnvConfig } from '../../src/config/runtime';
import { createDefaultConfig, toProbeConfig } from '../../src/contracts/config';
import { parseProxyTarget } from '../../src/domain/proxy-target';
import { APP_VERSION } from '../../src/worker';

const appRoot = new URL('../../', import.meta.url);
const read = (path: string): string => readFileSync(new URL(path, appRoot), 'utf8');

/** 一键部署将 app 复制为仓库根目录，部署配置不得依赖父目录。 */
describe('standalone application layout', () => {
  it('resolves Worker source and static assets from the application root', () => {
    const config = read('wrangler.toml');
    const entry = /^main\s*=\s*"([^"]+)"/m.exec(config)?.[1];
    const assets = /^directory\s*=\s*"([^"]+)"/m.exec(config)?.[1];
    expect(entry).toBe('src/index.ts');
    expect(assets).toBe('dist/web');
    expect(existsSync(new URL(entry!, appRoot))).toBe(true);
    expect(config).toContain('binding = "IP_DATA"');
    expect(config).toContain('run_worker_first = ["/api/*"]');
  });

  it('does not declare optional settings as installer inputs or override built-in defaults', () => {
    const config = read('wrangler.toml');
    expect(config).not.toMatch(/^\[vars\]/m);
    expect(config).not.toMatch(/^CHECK_API(?:_BACKUP)?\s*=/m);
    expect(config).not.toMatch(/^CHECK_TIMEOUT\s*=/m);
    expect(toProbeConfig(loadEnvConfig({})).endpoints).toEqual([
      { name: 'backup', urlTemplate: createDefaultConfig().checkApiBackup },
    ]);
  });

  it('uses the built-in backup when native sockets are unavailable', async () => {
    const fetchImpl = vi.fn(async (_url: RequestInfo | URL) => new Response(JSON.stringify({ success: true })));
    const adapter = createProbeAdapterFromConfig(toProbeConfig(loadEnvConfig({})), { fetchImpl: fetchImpl as typeof fetch });
    const target = parseProxyTarget('203.0.113.10:443');
    if (!target) throw new Error('invalid test target');
    expect(await adapter.probe(target)).toMatchObject({ status: 'alive', endpoint: 'backup' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(String(fetchImpl.mock.calls[0]?.[0])).toBe(`${createDefaultConfig().checkApiBackup}203.0.113.10%3A443`);
  });

  it('uses the same build for npm and native Wrangler deployment without running tests in the hook', () => {
    const { scripts } = JSON.parse(read('package.json'));
    expect(scripts.deploy).toBe('node scripts/deploy.mjs');
    expect(scripts.build).toBe('node scripts/build-worker.mjs');
    expect(scripts.dev).toBe('wrangler dev');
    const config = read('wrangler.toml');
    expect(config).toMatch(/^\[build\]\s*\ncommand = "node scripts\/build-worker\.mjs"/m);
    expect(read('scripts/build-worker.mjs')).toContain("[skipCustomBuild]: '1'");
    expect(read('scripts/build-worker.mjs')).not.toContain("runNpm('test");
    expect(scripts.check).toBe('npm run typecheck && npm run test:contract && npm run test:unit && npm run build && npm run check:size && npm run smoke');
    expect(JSON.stringify(scripts)).not.toContain('../wrangler.toml');
  });

  it('uses the date version without a second npm release identifier', () => {
    const manifest = JSON.parse(read('package.json'));
    const lock = JSON.parse(read('package-lock.json'));
    expect(APP_VERSION).toMatch(/^\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}$/);
    expect(manifest.private).toBe(true);
    expect(manifest.version).toBeUndefined();
    expect(lock.version).toBeUndefined();
    expect(lock.packages[''].version).toBeUndefined();
  });

  it('includes license notices without requiring a secret during deployment', () => {
    expect(read('LICENSE')).toContain('MIT License');
    expect(read('LICENSE')).toContain('Copyright (c) 2025 DDNS-cf-proxyip Contributors');
    expect(read('.dev.vars.example')).toContain('# AUTH_KEY=');
    expect(parseEnv(read('.dev.vars.example'))).toEqual({});
    expect(read('wrangler.toml')).not.toMatch(/^AUTH_KEY\s*=/m);
    expect(loadEnvConfig({}).authKey).toBe('');
  });

  it('selects a supported Node major from the deployment root', () => {
    expect(read('.node-version').trim()).toBe('22');
    const manifest = JSON.parse(read('package.json'));
    expect(manifest.engines.node).toContain('^22.12.0');
  });

  it('describes only the required KV binding in the deployment wizard', () => {
    const manifest = JSON.parse(read('package.json'));
    expect(Object.keys(manifest.cloudflare.bindings)).toEqual(['IP_DATA']);
    for (const binding of Object.values(manifest.cloudflare.bindings) as Array<{ description: string }>) {
      expect(binding.description.length).toBeGreaterThan(0);
    }
  });
});
