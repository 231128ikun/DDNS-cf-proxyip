# 安全策略

## 报告问题

- 不要用公开 Issue 贴出密钥、可复现的生产地址或完整请求日志。请通过 GitHub 仓库的 **Security → Report a vulnerability** 私密上报。
- 报告里写清楚：受影响的提交或分支、复现步骤、影响范围；必要时附最小复现。

## 支持范围

只维护默认分支与最新的重构分支；更早的提交不做安全修复。

## 部署安全清单

- 公开部署前设置 `AUTH_KEY` 或在配置中心配置面板密钥；静态前端只在认证成功后渲染管理页面，数据与写入接口统一保护。为空会关闭鉴权。
- 登录后优先使用 HttpOnly Cookie；`?key=` 只用于首次登录，避免后续链接反复暴露密钥。
- Cloudflare API Token 只授予需要维护的 Zone 的 `DNS:Edit`，不要使用 Global API Key。
- 密钥只放在 Cloudflare 环境变量/Secret 或面板配置（KV）里，不要写进仓库、Issue、日志或截图。
- 怀疑泄露时先在 Cloudflare 侧轮换 Token/密钥，再排查访问记录。
