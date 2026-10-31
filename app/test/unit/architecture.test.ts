import { readdirSync, readFileSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { describe, expect, it } from 'vitest';
import { architectureViolations } from '../helpers/architecture';

describe('architecture boundaries', () => {
  it.each([
    ['src/domain/address.ts', "import { probe } from '../adapters/probe/external-api'"],
    ['src/domain/address.ts', "import type { ProbeAdapter } from '../ports/probe'"],
    ['src/jobs/maintenance.ts', "import { KvPoolRepository } from '../adapters/storage/kv-pool-repository'"],
    ['src/adapters/probe/custom.ts', "import { createHttpApp } from '../../transport/http'"],
    ['src/application/check.ts', "export { x } from '../transport/http'"],
    ['src/application/check.ts', "const x = import('../adapters/probe/external-api')"],
    ['src/application/check.ts', "import { appFetch } from '../util/fetch'"],
    ['src/domain/address.ts', "globalThis['fetch']('https://example.test')"],
    ['src/application/check.ts', 'let kv: KVNamespace'],
    ['web/src/components/page.tsx', "window.fetch('/api/config')"],
    ['web/src/state/task.ts', "import { createWorker } from '../../../src/worker'"],
  ])('rejects an IO or dependency violation in %s', (file, source) => {
    expect(architectureViolations(file!, source!)).not.toEqual([]);
  });
  it('permits pure rule reuse, ports, and the API client boundary', () => {
    expect(architectureViolations('src/application/check.ts', "import type { ProbeAdapter } from '../ports/probe'\nimport { parseProxyTarget } from '../domain/proxy-target'")).toEqual([]);
    expect(architectureViolations('web/src/api/client.ts', "fetch('/api/config')")).toEqual([]);
    expect(architectureViolations('src/domain/example.ts', "// fetch('example')\nconst text = 'fetch()'")).toEqual([]);
  });
  it('enforces boundaries in the actual maintained source tree', () => {
    const root = resolve(import.meta.dirname, '../..');
    const files = (directory: string): string[] => readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
      const path = resolve(directory, entry.name);
      return entry.isDirectory() ? files(path) : /\.tsx?$/.test(path) ? [path] : [];
    });
    const violations = ['src', 'web/src'].flatMap(directory => files(resolve(root, directory))).flatMap(path => {
      const file = relative(root, path).replaceAll('\\', '/');
      return architectureViolations(file, readFileSync(path, 'utf8')).map(message => `${file}: ${message}`);
    });
    expect(violations).toEqual([]);
  });
});
