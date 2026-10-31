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
    manifest: true,
    // 前端只在现代浏览器运行；Terser 比 esbuild 多压缩约 5%，且不进入 Worker 产物。
    minify: 'terser',
    // booleans_as_integers 会破坏 Preact 事件绑定，不能启用。
    terserOptions: { ecma: 2022, module: true, compress: { passes: 3 }, mangle: { toplevel: true } },
    // 现代浏览器不需要兼容补丁，但动态模块的共享依赖仍应提前并行加载。
    modulePreload: { polyfill: false },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8787',
    },
  },
});
