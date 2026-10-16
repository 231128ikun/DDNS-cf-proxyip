# 重构分支状态

> [!NOTE]
> `codex/modular-refactor` 是独立重构线，**不与 `main` 合并**：`main` 保持原样，本分支按自己的节奏演进和部署。

## 当前状态

- 状态：第一轮重构完成，已推送到 `origin/codex/modular-refactor`
- 并行分支：`main`（不使用本分支代码，本分支也不回写 `main`）
- Worker 入口：`app/src/index.ts`；面板源码：`app/web/`
- 部署形态：面板是 Cloudflare 静态资源（`app/dist/web`），Worker 只处理 `/api/*`

## 相对 main 的变化（部署前必读）

- 旧 `/api/*` 接口面被替换；面板不再提供 DNS 记录列表与手动增删记录。
- 鉴权改为 `Authorization` 头（面板把密钥存在当前标签页的 `sessionStorage`）；开启 `AUTH_KEY` 时静态面板本身不受保护，只有 `/api/*` 受保护。
- 仓库不再提交 `_worker.js`，不再支持“复制单文件到 Worker 编辑器”的部署方式。
- 新增 `POST /api/check` 统一探测入口：IP/带端口目标直接探测，裸域名解析 A/AAAA，`txt@域名` 读取 TXT 列表。

## 已完成

- Worker 源码拆分为 `contracts / domain / application / ports / adapters / transport / jobs / config`，依赖单向。
- 面板改为 `app/web/` 的 Preact 源码，样式收敛为语义变量，并抽取复用组件。
- 面板由 Workers Static Assets 分发，`npm run smoke` 校验“静态资源 + `/api/*`”分工。
- 移除重构期间夹带的 socket 探针与接口自检。
- 一键洗库为服务端用例；垃圾桶只保留统一写入入口。
- 维护通知按“距上次成功通知”的池数量基线对比。
- 维护补货改为有界探索窗口并按延迟择优，避免全失效的池探测到池底。
- 死代码、不可达样式、空转配置项已清理；文档与实际行为对齐。
- IP 池与存储取舍记录在 [`ip-pool-design.md`](./ip-pool-design.md)。

## 下一步（按优先级）

1. IP 健康历史（D1 表 `ip_health`）：维护按健康分 + 延迟排序，并轮转长时间未检测的地址。
2. 上游列表定时同步：把远程 TXT/订阅地址存进配置，cron 先同步再维护。
3. 批量检测结果导出。

## 最近验证（2026-10-16）

在 `app/` 下运行 `npm run check`、`npm run smoke`、`npm run audit:ui`：

- 类型检查通过；单元测试 27 个文件 / 196 项通过。
- 构建与体积门禁通过：Worker 140.21 KB raw / 33.60 KB gzip；首屏 js + css 95.11 KB raw / 29.78 KB gzip。
- 冒烟检查通过：`/`、`/api/health`、缺失 JS、缺失 API 四项符合预期。
- UI 验收通过：375 / 768 / 992 / 1265 四档无横向溢出、对比度失败、小于 32px 点击目标或 a11y 问题。
- 本机开发环境无法出网，DoH 真机链路未验证：适配器与解析用例由 mock fetch 单测覆盖。
