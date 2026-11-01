import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // 排除本地运行缓存和构建产物。
    exclude: [...configDefaults.exclude, '.wrangler/**', 'dist/**'],
  },
});
