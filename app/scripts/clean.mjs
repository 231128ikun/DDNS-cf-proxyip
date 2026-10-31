import { readdir, rm } from 'node:fs/promises';

/**
 * 清理上一次构建的产物，避免旧 bundle 与 sourcemap 残留造成体积误判。
 * 不动 dist/web：wrangler dev 可能正把该目录作为 assets 挂载并占用句柄，
 * 前端产物由 Vite 的 emptyOutDir 自己管理。
 */
const dist = new URL('../dist', import.meta.url);

let entries;
try {
  entries = await readdir(dist, { withFileTypes: true });
} catch (error) {
  if (error?.code === 'ENOENT') process.exit(0);
  throw error;
}

await Promise.all(
  entries
    .filter((entry) => entry.name !== 'web')
    .map((entry) =>
      rm(new URL(`../dist/${entry.name}`, import.meta.url), {
        recursive: true,
        force: true,
        maxRetries: 3,
        retryDelay: 100,
      }),
    ),
);