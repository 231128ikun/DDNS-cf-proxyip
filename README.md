# DDNS Pro - Cloudflare Worker ProxyIP 管理面板

部署在 Cloudflare Workers 上的 ProxyIP 维护工具，无需自建服务器。通过外部检测接口验证节点，自动维护域名的 `A`、`AAAA` 或 `TXT` 记录。

## ✨ 核心功能

- **多域名维护**：检测当前节点，从绑定的 IP 池补充可用地址。
- **IP 池管理**：导入、检测、去重、筛选、自定义池与垃圾桶恢复。
- **出口筛选**：支持国家、ASN、IPv4、IPv6 和双栈条件。
- **自动任务**：每 3 小时维护一次，可在面板关闭；支持 Telegram 通知。

## 🚀 快速部署

> **使用顺序：部署 → 配置中心保存域名配置 → 检测并入库 → 绑定 IP 池 → 执行维护。**
> 面板密码和检测接口都可选。未设置密码时直接进入，检测默认使用内置备用接口。

### 已有仓库：直接连接，不新建

适合已经拥有本仓库，或更新已有 Worker 的情况。

1. 在 Cloudflare **Workers & Pages** 中创建 Worker 或打开已有 Worker，连接你的 GitHub 仓库。
2. 选择 `main` 分支，设置：

   | 设置项 | 内容 |
   | --- | --- |
   | 根目录 | `app` |
   | 构建命令 | `npm run build` |
   | 部署命令 | `npm run deploy` |

3. 确认 KV 绑定名为 **`IP_DATA`**，Worker 名称与 `app/wrangler.toml` 一致，默认为 `ddns-cf-proxyip`。
4. 部署完成后打开 Worker 地址，在面板配置中心保存配置。

**更新已有实例时保留原 Worker、域名、Secrets 和 KV，不要用新空库替换原数据。** Cloudflare 日志中的 `Cloning repository` 只是下载代码到构建机，不是在 GitHub 新建仓库。

### 新实例：一键复制模板

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/231128ikun/DDNS-cf-proxyip/tree/main/app)

按 [Cloudflare 官方向导](https://developers.cloudflare.com/workers/platform/deploy-buttons/)授权账号并确认 Worker 与 KV 即可，**无需填写面板密码或检测 API**。

这个按钮会在你的账号下创建新仓库，并把 `app/` 作为新仓库根目录，所以生成的仓库不再填写 `app` 根目录。已有仓库请用上面的直接连接方式，无需重复点击按钮。

<details>
<summary>本地命令行部署</summary>

安装 Node.js 22.12+ 或 24 LTS，在完整仓库的 `app/` 目录执行：

```sh
npm ci
npx wrangler login
npm run build
npm run deploy
```

</details>

面板和 Worker 同时发布，不需要另建 Pages 项目。Cloudflare 自动安装依赖并构建一次；测试由本地和 GitHub CI 执行，不会上传到线上。

## 🔑 配置中心

第一次打开面板，先完成以下配置：

1. **维护域名配置**：填写托管域名、Zone ID 和 Cloudflare API Token。
2. **管理域名**：添加需要维护的子域名，选择 `A/AAAA` 或 `TXT`，设置端口、最小活跃数与出口筛选。
3. **可选设置**：面板密码、Telegram 通知、自建检测接口和自动维护开关。

<details>
<summary>Cloudflare Token 与 Zone ID 获取方式</summary>

- 在 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens) 使用 **Edit zone DNS** 模板，授权需要维护的域名。
- 在该域名的概览页复制 **Zone ID（区域 ID）**。
- Token 与 Zone ID 必须对应目标 DNS；Worker 可以部署在另一账号。

</details>

**面板密码是可选的 `AUTH_KEY`，不是 Cloudflare Token。** 可以在配置中心设置、修改或清空；未设置时，能打开面板地址的人都能操作。

检测默认使用内置接口。自建接口可参考 [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)，地址支持 `https://probe.example.com/check?proxyip=` 或 `{proxyip}` 占位符。只配一个接口时也可检测和复检；配置两个时依次使用主、备用接口。

配置保存到 KV 的 `app_config`。环境变量仅作启动默认值，面板保存的配置优先；密钥和真实资源 ID 不要提交 GitHub。

## 🧭 面板使用

1. **导入地址**：粘贴 IP 列表、Excel 的 IP/端口两列，或加载远程 TXT 链接。
2. **检测并入库**：选择 IP 池，点击“检测”，再点击“入库”。检测中断后可以继续。
3. **绑定并维护**：展开“域名池绑定”选择对应池，点击“执行全部维护”；之后可由定时任务自动维护。

支持纯地址和带元数据、备注的格式：

```text
192.0.2.10:443
[2001:db8::1]:443
192.0.2.20:443,AS64500,JP,v4 # 可选备注
```

IPv6 带端口必须加方括号。标准池格式为 `ip:port,asn,country,stack`，`stack` 为 `v4`、`v6` 或 `v4/v6`，未知字段用 `null`；旧池格式仍可读取。

“解析实况”会读取并检测当前 DNS 地址，也可输入 `example.com`、`txt@example.com` 或 `example.com:8080` 进行探测。

### 操作提醒

- **未知不等于失效**：超时、HTTP、TLS 或接口响应异常不据此删除 DNS 或入桶；查看结果中的原因后重试。
- 出口筛选不匹配可从目标 DNS 移除，但不当作死节点入桶。
- “从库中移除”删除输入框列出的地址；先加载全池再执行会清空该池。
- 服务端“一键洗库”单次最多 200 个不同有效地址；大池可用面板逐地址批量检测。
- 更新前备份 KV；代码回退不会恢复已变更的 KV 或 DNS。公共检测服务不保证长期可用。

## 参考与许可

参考项目：[CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)、[CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D)、[CF-Workers-检测后端](https://github.com/ToiCF/CF-Workers-CheckProxyIP)。

[MIT License](./LICENSE)
