# DDNS Pro - Cloudflare Worker ProxyIP 管理面板

DDNS Pro 部署于 Cloudflare Workers，使用原生 TCP/TLS 检测 ProxyIP，从绑定的 IP 池补充可用地址，维护一个或多个域名的 `A`、`AAAA` 或 `TXT` 记录。

## ✨ 核心功能

- **多域名维护**：检测当前节点，从绑定的 IP 池补充可用地址。
- **IP 池管理**：导入、检测、去重、筛选、自定义池与垃圾桶恢复。
- **出口筛选**：支持国家、ASN、IPv4、IPv6 和双栈条件。
- **自动任务**：默认每 3 小时维护一次，可在配置中心关闭。确认 DNS 解析地址变化后发送 Telegram 通知，维护异常记录在运行日志中。
- **手动维护**完成后按 Telegram 开关与配置发送报告，DNS 无变化时也可验证通知配置。面板显示实际发送状态。

## 🚀 快速部署

> 面板密码可选，未设置时管理接口免登录。

### ① GitHub Fork（推荐）

在 GitHub 点击 **Fork** 创建自己的仓库。以后可通过 **Sync fork → Update branch** 同步上游 `main`；有冲突时需先合并本地改动。

<details>
<summary><strong>展开 GitHub 部署步骤</strong></summary>

1. 在 Cloudflare **Workers & Pages** 中创建或选择 Worker，连接自己的 Fork。
2. 选择部署分支（默认 `main`），设置：

   | 设置项 | 内容 |
   | --- | --- |
   | 构建命令 | 留空，由部署入口自动构建 |
   | 部署命令 | `npm run deploy` |
   | 根目录 | `app` |

3. Worker 名称应与 `app/wrangler.toml` 一致，默认为 `ddns-cf-proxyip`。KV 绑定名固定为 **`IP_DATA`**。
4. 部署完成后打开 Worker 地址，在配置中心保存域名配置。

Cloudflare 自动安装依赖。部署入口构建面板与 Worker，并检查体积；已完成且未变化的构建结果会被复用。

**KV 资源：**部署入口自动初始化 `IP_DATA`；遇到同名冲突时，仅在对应账号下找到唯一匹配的命名空间后复用。已有明确绑定保持不变。

</details>

### ② Cloudflare 一键部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/231128ikun/DDNS-cf-proxyip/tree/main/app)

此方式在首次部署时创建独立仓库及 Worker。该仓库不是 Fork，不会随上游更新，也没有 **Sync fork** 入口。升级方式见下方「已有实例迁移 / 更新」。

| 设置项 | 内容 |
| --- | --- |
| 构建命令 | `npm run build` |
| 部署命令 | `npm run deploy` |
| 根目录 | 留空，生成的仓库根目录已包含 `wrangler.toml` |

### ③ 本地命令行部署

<details>
<summary><strong>展开 Wrangler 部署步骤</strong></summary>

安装 Node.js 22.12+ 或 24 LTS，在 `wrangler.toml` 所在目录执行（完整仓库的 `app/`，或一键部署生成的仓库根目录）：

```sh
npm ci
npx wrangler login
npm run deploy
```

只有在**完整仓库的根目录**执行时，才使用 `npm --prefix app run deploy`。一键部署生成的仓库在根目录直接执行 `npm run deploy`。

</details>

<details>
<summary><strong>已有实例迁移 / 更新</strong></summary>

更新前备份 KV 并保留可回退版本。沿用原 Worker、域名、部署账号、环境、Secrets 和 `IP_DATA` 绑定，不要重新运行一键部署向导来升级。

| 已有仓库 | 更新方式 | Cloudflare 构建根目录 |
| --- | --- | --- |
| 完整 Fork，`wrangler.toml` 在 `app/` | 使用 **Sync fork** 同步上游 `main`。 | `app` |
| 完整仓库的独立副本，`wrangler.toml` 在 `app/` | 从上游 `main` 合并 `app/` 的内容。 | `app` |
| 一键部署生成的仓库，`wrangler.toml` 在根目录 | 将上游 `main` 的 `app/` 内容（包括隐藏文件）合并到仓库根目录，不新建 `app/` 子目录。 | 留空 |

更新源码时，按项合并 `wrangler.toml` 的变更，不要覆盖已有配置。部署命令仍为 `npm run deploy`。

部署后先确认配置、IP 池和域名绑定，再执行维护。代码回退不会恢复已变更的 KV 或 DNS。

</details>

## 🔑 配置中心

部署后完成配置并保存：

1. **维护域名配置**：托管域名、Zone ID 和 Cloudflare API Token。
2. **管理域名**：子域名、记录类型、端口、最小活跃数与出口筛选。
3. **可选设置**：面板密码、Telegram 通知、检测参数和自动维护开关。

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
| `PROBE_IPV4_URL` | IPv4 出口 JSON 接口 | `https://ipv4.090227.xyz/` |
| `PROBE_IPV6_URL` | IPv6 出口 JSON 接口 | `https://ipv6.090227.xyz/` |
| `CHECK_API_BACKUP` | 备用检测接口 | `https://checkapi.dvb.kdns.fr/?candidate=` |
| `DOH_API` | DNS over HTTPS 查询接口 | `https://cloudflare-dns.com/dns-query` |
| `CONCURRENT_CHECKS` | 同时检测的地址数，范围 1–128，建议 4–16 | `8` |
| `CHECK_TIMEOUT` | 单次原生连接或备用请求超时，500–30000 毫秒 | `15000` |
| `REMOTE_LOAD_TIMEOUT` | 远程文本加载超时，1000–60000 毫秒 | `8000` |
| `DOH_TIMEOUT` | DNS 查询超时，1000–30000 毫秒 | `5000` |
| `TG_TOKEN` | Telegram Bot Token | 空 |
| `TG_ID` | Telegram Chat ID | 空 |
| `TG_ENABLED` | Telegram 通知开关 | `true` |
| `SCHEDULED_ENABLED` | 定时维护开关 | `true` |

出口接口通过候选地址访问，需提供有效 HTTPS 证书并返回含 `ip` 或 `ipAddress` 的 JSON，可附带 `asn`、`country` 等信息。清空某个出口接口可关闭该分支。其他运行参数通过配置中心管理。

`IP_DATA` 是 KV namespace 类型的资源绑定，不是普通文本变量。

</details>

<details>
<summary>Cloudflare Token 与 Zone ID 获取方式</summary>

- 在 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens) 使用 **Edit zone DNS** 模板，授权需要维护的域名。
- 在域名概览页复制 **Zone ID（区域 ID）**。
- Token 与 Zone ID 必须对应目标 DNS；Worker 可部署于另一账号。

</details>

<details>
<summary>自定义检测设置（可选）</summary>

Worker 通过原生 TCP/TLS 检测候选地址，并读取出口信息。

原生检测未成功时使用备用接口复检一次。备用接口可在高级设置中修改或清空，清空后改为原生复检。接口不可用时会报告异常，不作为节点失效。

备用检测接口可参考 [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)。

</details>

## 🧭 面板使用

1. **导入与检测**：选择 IP 池，粘贴地址，或用“从池读取”“远程链接”“本地文件”载入。输入框带格式示例，筛选框旁的问号可查看筛选用法。筛选保留原文，普通检测不写库存。
2. **选择与出入库**：在“结果”页勾选所需条目，点击“保留到输入”；再“追加入库”合并去重，或确认“从库剔除”按地址和端口移除。人工剔除保留其他条目和备注，不进入垃圾桶。检测中断后可继续。
3. **绑定并维护**：新增维护域名时可预选 IP 池，确认后统一保存；已保存域名的池选择立即生效。维护按目标显示现状与结论，后续可由定时任务运行。

<details>
<summary>地址格式与域名探测</summary>

支持纯地址和带元数据、备注的格式：

```text
192.0.2.10:443
[2001:db8::1]:443
192.0.2.20:443,AS64500,JP,v4 # 可选备注
```

IPv6 带端口必须加方括号。粘贴支持换行、逗号、空格或 Tab 分隔多个地址；地址和端口也可用空格、Tab 或中文冒号分隔。标准池格式为 `ip:port,asn,country,stack`，`stack` 为 `v4`、`v6` 或 `v4/v6`，未知字段用 `null`；逗号元数据的空字段保留位置，旧池格式仍可读取。

“解析实况”只读取并检测当前选中的域名，切换域名或点击刷新时重新加载，不预先检测其他域名。同时支持输入 `example.com`、`txt@example.com` 或 `example.com:8080` 进行探测。

</details>

## 参考与许可

- [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)
- [CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D)
- [CF-Workers-检测后端](https://github.com/ToiCF/CF-Workers-CheckProxyIP)
- [subtls](https://github.com/jawj/subtls)（MIT，显式 SNI 与 TLS 1.3 证书校验）

[MIT License](./LICENSE)
