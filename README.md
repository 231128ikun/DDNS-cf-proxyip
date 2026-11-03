# DDNS Pro - Cloudflare Worker ProxyIP 管理面板

DDNS Pro 部署于 Cloudflare Workers，通过外部检测接口验证 ProxyIP，并维护域名的 `A`、`AAAA` 或 `TXT` 记录，无需自建服务器。

## ✨ 核心功能

- **多域名维护**：检测当前节点，从绑定的 IP 池补充可用地址。
- **IP 池管理**：导入、检测、去重、筛选、自定义池与垃圾桶恢复。
- **出口筛选**：支持国家、ASN、IPv4、IPv6 和双栈条件。
- **自动任务**：每 3 小时维护一次，可在配置中心关闭；支持 Telegram 通知。

## 🚀 快速部署

> 面板密码和检测接口均为可选配置。未设置密码时不启用鉴权，检测默认使用内置备用接口。

### ① 一键部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/231128ikun/DDNS-cf-proxyip/tree/main/app)

通过 Cloudflare 部署向导创建仓库及 Worker，按提示完成账号授权和资源设置。面板密码与检测 API 无需预先填写。

此方式适用于新实例，会创建 GitHub 仓库。已有仓库或 Worker 可使用以下 GitHub 部署及迁移/更新方式。

### ② GitHub 仓库部署

<details>
<summary><strong>展开 GitHub 部署步骤</strong></summary>

1. 在 Cloudflare **Workers & Pages** 中创建或选择 Worker，连接对应的 GitHub 仓库。
2. 选择 `main` 分支，设置：

   | 设置项 | 内容 |
   | --- | --- |
   | 根目录 | `app` |
   | 构建命令 | 留空，由 Wrangler 自动构建 |
   | 部署命令 | `npm run deploy` |

3. Worker 名称应与 `app/wrangler.toml` 一致，默认为 `ddns-cf-proxyip`。KV 绑定名固定为 **`IP_DATA`**。
4. 部署完成后打开 Worker 地址，在配置中心保存域名配置。

Cloudflare 自动选择 Node.js 并安装依赖。统一部署入口自动构建面板与 Worker，检查体积后发布；完整测试由本地和 GitHub CI 执行，不进入线上发布文件。

一键部署生成的仓库以 `app/` 为根目录，根目录设置留空；完整仓库的根目录填写 `app`。

**KV 资源：**部署入口自动初始化 `IP_DATA`；创建遇到同名冲突时复用已有命名空间，已有明确绑定保持不变。

</details>

### ③ 本地命令行部署

<details>
<summary><strong>展开 Wrangler 部署步骤</strong></summary>

安装 Node.js 22.12+ 或 24 LTS，在完整仓库的 `app/` 目录执行：

```sh
npm ci
npx wrangler login
npm run deploy
```

部署使用 `npm run deploy`；在仓库根目录执行时使用 `npm --prefix app run deploy`。

</details>

<details>
<summary><strong>已有实例迁移 / 更新</strong></summary>

1. 保留原 Worker、域名、Secrets 和 `IP_DATA` 对应的 KV 命名空间。
2. Worker 名称、部署账号和环境应与原实例一致，已有 `IP_DATA` 绑定或明确资源 ID 保持不变。
3. 使用完整仓库时，将构建根目录设为 `app`，构建命令留空，部署命令设为 `npm run deploy`。未变化的有效产物会被复用。
4. 更新前备份 KV 并保留可回退版本；更新后确认配置、IP 池和域名绑定，再执行维护。

代码回退不会恢复已变更的 KV 或 DNS。

</details>

## 🔑 配置中心

部署后完成配置并保存：

1. **维护域名配置**：托管域名、Zone ID 和 Cloudflare API Token。
2. **管理域名**：子域名、记录类型、端口、最小活跃数与出口筛选。
3. **可选设置**：面板密码、Telegram 通知、自建检测接口和自动维护开关。

面板密码 `AUTH_KEY` 支持设置、修改和清空；为空时管理接口不启用鉴权。密码、Token 和实际资源 ID 不应提交到公共仓库。

<details>
<summary>可选环境变量</summary>

在 Worker 的 **Settings → Variables and Secrets** 中配置。面板密码及 API/Bot Token 建议使用 **Secret**；其他项目可使用普通变量。未设置时使用以下默认值，配置中心保存的 KV 配置优先；环境变量用于首次启动及配置异常回退。

| 变量 | 用途 | 默认值 |
| --- | --- | --- |
| `AUTH_KEY` | 可选面板登录密码；空值免登录 | 空 |
| `CF_KEY` | Cloudflare DNS API Token | 空 |
| `CF_ZONEID` | DNS 区域 ID | 空 |
| `CF_BASE_DOMAIN` | 托管域名，如 `example.com` | 空 |
| `CHECK_API` | 可选主检测接口 | 空 |
| `CHECK_API_BACKUP` | 备用检测接口 | `https://checkapi.dvb.kdns.fr/?candidate=` |
| `DOH_API` | DNS over HTTPS 查询接口 | `https://cloudflare-dns.com/dns-query` |
| `CONCURRENT_CHECKS` | 检测并发，范围 1–128 | `32` |
| `CHECK_TIMEOUT` | 单接口超时，500–30000 毫秒 | `15000` |
| `REMOTE_LOAD_TIMEOUT` | 远程文本加载超时，1000–60000 毫秒 | `8000` |
| `DOH_TIMEOUT` | DNS 查询超时，1000–30000 毫秒 | `5000` |
| `TG_TOKEN` | Telegram Bot Token | 空 |
| `TG_ID` | Telegram Chat ID | 空 |
| `TG_ENABLED` | Telegram 通知开关 | `true` |
| `SCHEDULED_ENABLED` | 定时维护开关 | `true` |

未设置检测接口时沿用默认值；显式清空并保存会禁用对应接口。其他运行参数通过配置中心管理。

`IP_DATA` 是 KV namespace 类型的资源绑定，不是普通文本变量。

</details>

<details>
<summary>Cloudflare Token 与 Zone ID 获取方式</summary>

- 在 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens) 使用 **Edit zone DNS** 模板，授权需要维护的域名。
- 在域名概览页复制 **Zone ID（区域 ID）**。
- Token 与 Zone ID 必须对应目标 DNS；Worker 可部署于另一账号。

</details>

<details>
<summary>自建检测接口（可选）</summary>

检测服务可参考 [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)。接口地址支持：

```text
https://probe.example.com/check?proxyip=
https://probe.example.com/check?proxyip={proxyip}
```

单接口复用自身复检；双接口依次使用主、备用接口。显式清空并保存接口会禁用该接口。公共备用服务不保证长期可用。

配置保存到 KV，优先于环境变量启动默认值。

</details>

## 🧭 面板使用

1. **导入地址**：粘贴 IP 列表、Excel 的 IP/端口两列，或加载远程 TXT 链接。
2. **检测并入库**：选择 IP 池，点击“检测”后“入库”。检测中断后可继续。
3. **绑定并维护**：在“域名池绑定”中选择对应池，执行维护；后续可由定时任务运行。

<details>
<summary>地址格式与域名探测</summary>

支持纯地址和带元数据、备注的格式：

```text
192.0.2.10:443
[2001:db8::1]:443
192.0.2.20:443,AS64500,JP,v4 # 可选备注
```

IPv6 带端口必须加方括号。标准池格式为 `ip:port,asn,country,stack`，`stack` 为 `v4`、`v6` 或 `v4/v6`，未知字段用 `null`；旧池格式仍可读取。

“解析实况”读取并检测当前 DNS 地址，同时支持输入 `example.com`、`txt@example.com` 或 `example.com:8080` 进行探测。

</details>

### 操作提醒

- **失败与未知**：节点检测超时按失效处理，洗库和维护时移入垃圾桶；普通检测和解析实况刷新不改库。网络、HTTP、TLS 错误和坏响应仍为未知，不据此删除 DNS 或入桶；出口筛选不匹配也不当作死节点。
- “从库中移除”删除输入框列出的地址；加载全池后执行会清空该池。
- 服务端“一键洗库”单次最多 200 个不同有效地址；更大的池可使用面板逐地址批量检测。

## 参考与许可

- [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)
- [CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D)
- [CF-Workers-检测后端](https://github.com/ToiCF/CF-Workers-CheckProxyIP)

[MIT License](./LICENSE)
