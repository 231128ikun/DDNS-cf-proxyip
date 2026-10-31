import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // `.wrangler/`、`dist/` 是本地生成目录，历史上出现过被误当作测试文件扫描的情况。
    exclude: [...configDefaults.exclude, '.wrangler/**', 'dist/**'],
  },
});
