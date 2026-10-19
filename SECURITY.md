# 安全策略

## 报告问题

- 不要用公开 Issue 贴出密钥、可复现的生产地址或完整请求日志。请通过 GitHub 仓库的 **Security → Report a vulnerability** 私密上报。
- 报告里写清楚：受影响的提交或分支、复现步骤、影响范围；必要时附最小复现。

## 支持范围

只维护默认分支与最新的重构分支；更早的提交不做安全修复。

## 部署安全清单

- 当前测试阶段不执行面板 key 校验。公开部署时，Worker API 和面板配置均可被访问与修改，请仅用于可信测试环境。
- Cloudflare API Token 只授予需要维护的 Zone 的 `DNS:Edit`，不要使用 Global API Key。
- 密钥只放在 Cloudflare 环境变量/Secret 或面板配置（KV）里，不要写进仓库、Issue、日志或截图。
- 怀疑泄露时先在 Cloudflare 侧轮换 Token/密钥，再排查访问记录。
