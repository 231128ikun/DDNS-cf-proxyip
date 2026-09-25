import preact from '@preact/preset-vite';
import { defineConfig } from 'vite';

export default defineConfig({
  root: import.meta.dirname,
  plugins: [preact()],
  build: {
    target: 'es2022',
    outDir: '../dist/web',
    emptyOutDir: true,
    sourcemap: false,
    // 单页静态资源由 Worker 同源返回，不需要 Vite 的 modulepreload 运行时代码。
    modulePreload: false,
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8787',
    },
  },
});