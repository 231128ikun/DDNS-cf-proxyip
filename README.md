# DDNS Pro - Cloudflare Worker ProxyIP 管理面板

部署在 Cloudflare Workers 上的 ProxyIP 维护工具，无需自建服务器。通过外部检测接口验证节点，自动维护域名的 `A`、`AAAA` 或 `TXT` 记录。

## ✨ 核心功能

- **多域名维护**：检测当前节点，从绑定的 IP 池补充可用地址。
- **IP 池管理**：导入、检测、去重、筛选、自定义池与垃圾桶恢复。
- **出口筛选**：支持国家、ASN、IPv4、IPv6 和双栈条件。
- **自动任务**：每 3 小时维护一次，可在面板关闭；支持 Telegram 通知。

## 🚀 快速部署

> 面板密码和检测接口都可选。未设置密码时直接进入，检测默认使用内置备用接口。

### ① 一键部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/231128ikun/DDNS-cf-proxyip/tree/main/app)

按向导授权账号并确认 Worker 与 KV 即可，**无需填写面板密码或检测 API**。

官方按钮会创建新仓库。已经拥有本仓库或已有部署，请使用下面的 GitHub 部署或迁移/更新方式，不必重复创建。

### ② GitHub 仓库部署

<details>
<summary><strong>展开 GitHub 部署步骤</strong></summary>

1. 在 Cloudflare **Workers & Pages** 中创建 Worker，连接你的 GitHub 仓库；已有仓库直接选择，无需重新 Fork。
2. 选择 `main` 分支，设置：

   | 设置项 | 内容 |
   | --- | --- |
   | 根目录 | `app` |
   | 构建命令 | `npm run build` |
   | 部署命令 | `npm run deploy` |

3. 确认 KV 绑定名为 **`IP_DATA`**，Worker 名称与 `app/wrangler.toml` 一致，默认为 `ddns-cf-proxyip`。
4. 部署后打开 Worker 地址，在配置中心保存域名配置。

Cloudflare 自动选择 Node.js 并安装依赖，不要在构建命令里重复执行 `npm ci`。测试由本地和 GitHub CI 执行，线上只发布 Worker 与面板资源。

一键按钮生成的仓库以 `app/` 为根目录，所以根目录留空；完整仓库才填写 `app`。

</details>

### ③ 本地命令行部署

<details>
<summary><strong>展开 Wrangler 部署步骤</strong></summary>

安装 Node.js 22.12+ 或 24 LTS，在完整仓库的 `app/` 目录执行：

```sh
npm ci
npx wrangler login
npm run build
npm run deploy
```

首次部署创建或选择 KV，绑定名为 `IP_DATA`；更新同名 Worker 时保留原绑定。

</details>

<details>
<summary><strong>已有实例迁移 / 更新</strong></summary>

1. 保留原 Worker、域名、Secrets 和 `IP_DATA` 对应的 KV，不要用新空库替换原数据。
2. 使用完整仓库时，把 Cloudflare 构建根目录改为 `app`，构建命令设为 `npm run build`，部署命令设为 `npm run deploy`。
3. 更新前备份 KV 并保留可回退版本；更新后确认原配置、IP 池和域名绑定正常，再执行维护。

日志中的 `Cloning repository` 只是下载代码到构建机，不是在 GitHub 新建仓库。代码回退不会恢复已变更的 KV 或 DNS。

</details>

## 🔑 配置中心

部署后打开面板，完成配置并保存：

1. **维护域名配置**：填写托管域名、Zone ID 和 Cloudflare API Token。
2. **管理域名**：添加子域名，选择记录类型，设置端口、最小活跃数与出口筛选。
3. **可选设置**：面板密码、Telegram 通知、自建检测接口和自动维护开关。

面板密码 `AUTH_KEY` 可随时设置、修改或清空；未设置时，能打开面板地址的人都能操作。不要把密码和 Token 提交 GitHub。

<details>
<summary>Cloudflare Token 与 Zone ID 获取方式</summary>

- 在 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens) 使用 **Edit zone DNS** 模板，授权需要维护的域名。
- 在该域名概览页复制 **Zone ID（区域 ID）**。
- Token 与 Zone ID 必须对应目标 DNS；Worker 可以部署在另一账号。

</details>

<details>
<summary>自建检测接口（可选）</summary>

可参考 [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)，接口地址支持：

```text
https://probe.example.com/check?proxyip=
https://probe.example.com/check?proxyip={proxyip}
```

只配一个接口时复用自身复检；配置两个时依次使用主、备用接口。显式清空并保存接口会禁用它，公共备用服务不保证长期可用。

面板配置保存到 KV，优先于环境变量启动默认值。

</details>

## 🧭 面板使用

1. **导入地址**：粘贴 IP 列表、Excel 的 IP/端口两列，或加载远程 TXT 链接。
2. **检测并入库**：选择 IP 池，点击“检测”，再点击“入库”。检测中断后可以继续。
3. **绑定并维护**：展开“域名池绑定”选择对应池，点击“执行全部维护”；之后可由定时任务自动维护。

<details>
<summary>地址格式与域名探测</summary>

支持纯地址和带元数据、备注的格式：

```text
192.0.2.10:443
[2001:db8::1]:443
192.0.2.20:443,AS64500,JP,v4 # 可选备注
```

IPv6 带端口必须加方括号。标准池格式为 `ip:port,asn,country,stack`，`stack` 为 `v4`、`v6` 或 `v4/v6`，未知字段用 `null`；旧池格式仍可读取。

“解析实况”会读取并检测当前 DNS 地址，也可输入 `example.com`、`txt@example.com` 或 `example.com:8080` 进行探测。

</details>

### 操作提醒

- **未知不等于失效**：接口异常不据此删除 DNS 或入桶；出口筛选不匹配也不当作死节点。
- “从库中移除”删除输入框列出的地址；先加载全池再执行会清空该池。
- 服务端“一键洗库”单次最多 200 个不同有效地址；大池可用面板逐地址批量检测。

## 参考与许可

- [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)
- [CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D)
- [CF-Workers-检测后端](https://github.com/ToiCF/CF-Workers-CheckProxyIP)

[MIT License](./LICENSE)
