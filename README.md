# DDNS Pro - Cloudflare Workers 动态DNS & IP管理

基于外部 ProxyIP 检测 API 做的多域名动态DNS管理系统，支持地址记录（A/AAAA）和 TXT 记录维护，自动检测并替换失效IP。借助 CF 平台，无需服务器。

## 📋 主要功能

- ✅ **多域名管理** - 支持同时管理多个域名的DNS记录
- ✅ **两种模式** - 地址记录（A/AAAA）和 TXT记录
- ✅ **自动维护** - 定时检测失效IP并自动补充
- ✅ **Telegram通知** - 维护完成后推送详细报告
- ✅ **Web管理界面** - 直观的可视化操作面板
- ✅ **域名池绑定** - 支持不同域名绑定到不同的IP池
- ✅ **KV配置** - 支持多套维护域名权限配置，前端保存到 KV 覆盖环境变量
- ✅ **出口筛选** - 支持按 IPv4、IPv6、双栈出口以及国家、ASN 维护



### 简单理解

这是一个**自动管理维护cf-proxyip的工具**，让你的域名始终指向可用的反代cf的IP地址。例如：`kr.dwb.cc.cd:50001`

具体应用场景可参考[什么是PROCYIP?](https://github.com/231128ikun/CF-Workers-CheckProxyIP/blob/main/README.md#-%E4%BB%80%E4%B9%88%E6%98%AF-proxyip-)



<details>
<summary><strong>🚀 快速部署（5分钟完成）</strong></summary>

### 📊 部署流程

```
准备工作 → 部署Worker → 配置环境 → 开始使用
   ↓           ↓            ↓           ↓
获取Token   复制代码    设置变量    访问面板
获取ZoneID  部署到CF    绑定KV      导入IP
```

### 1️⃣ 获取 Cloudflare API Token

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 右上角头像 → **My Profile** → **API Tokens**
3. **Create Token** → 选择 **Edit zone DNS** 模板
4. 配置权限：Zone Resources 选择你的域名
5. **Create Token** → **复制保存**（只显示一次！）

> 💡这个api token 和zone id 都是为了可以修改要维护的域名，所以别填错账号了，要填维护的域名所在账号。而这个项目可以部署在任意账号。

### 2️⃣ 获取 Zone ID

1. 在 Cloudflare Dashboard 中选择你的域名
2. 右侧 **API** 区域可以看到 **Zone ID**
3. 复制保存

### 3️⃣ 部署 Worker

1. 访问 [Cloudflare Workers](https://dash.cloudflare.com/?to=/:account/workers)
2. **Create Application** → **Create Worker**
3. 复制 `_worker.js` 的全部内容，粘贴到编辑器
4. **Save and Deploy**

### 4️⃣ 绑定 KV（必须）

1. 在 [KV](https://dash.cloudflare.com/?to=/:account/workers/kv/namespaces) 创建命名空间，名称建议：`IP_DATA`
2. 回到 Worker → **Settings** → **Bindings** → **Add binding**
3. Type: **KV Namespace**，Variable name 必须填写：`IP_DATA`
4. 选择刚创建的 KV 命名空间并保存

> 未绑定 `IP_DATA` 时，面板会显示明确提示；配置保存、IP 池和维护任务都不可用。

### 5️⃣ 配置面板密钥（可选但建议）

进入 Worker → **Settings** → **Variables**，只建议添加面板访问密钥：

| 变量名 | 值 |
|--------|-----|
| `AUTH_KEY` | 面板访问密钥 |

首次访问可用 `https://你的worker/?key=你的AUTH_KEY` 登录。其他维护配置（CF Key、Zone ID、维护域名、检测 API、TG 等）都可以在前端 **配置中心** 保存到 KV。

### 6️⃣ 配置定时任务（可选）

Worker → **Triggers** → **Cron Triggers** → 添加 `0 */3 * * *`（每3小时执行）

### ✅ 部署完成！

访问 `https://你的worker名.你的子域名.workers.dev` 即可使用管理面板

</details>

---

<details>
<summary><strong>📖 使用教程</strong></summary>

### 第一次使用

#### Step 1: 添加IP到库存

1. 在 **手动输入** 标签页输入IP列表（格式：`IP:端口`）
```
1.2.3.4:443
5.6.7.8:8080
```
2. 点击 **检测清洗**（验证IP可用性）
3. 点击 **追加入库**（保存到库存）

#### Step 2: 执行维护

点击 **执行全部维护**，系统会自动：
- 检测现有DNS记录中的IP
- 删除失效IP
- 从库存补充新IP（若低于最小活跃数）
- 发送Telegram通知（如已配置）

### 日常操作

#### 批量导入IP

**从Excel导入：**
1. Excel中准备 `IP地址` 和 `端口` 两列
2. 选中数据 → Ctrl+C 复制
3. 粘贴到管理面板 → **检测清洗** → **追加入库**

**从远程URL加载：**

 输入TXT文件URL → **加载** → **追加入库**

#### 域名探测

在 **Check ProxyIP** （实况解析右边输入框）输入域名，自动检测IP可用性：
```
example.com          # 探测A/AAAA记录
example.com:8080     # 指定端口
txt@example.com      # 探测TXT记录
```

</details>

---

<details>
<summary><strong>⚙️ 环境变量详解</strong></summary>

### 必须绑定

| 类型 | 名称 | 说明 |
|------|------|------|
| KV Namespace Binding | `IP_DATA` | 保存配置、IP 池、垃圾桶和域名池绑定 |


### 建议环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `AUTH_KEY` | 管理面板访问密钥 | 无 |

除 `AUTH_KEY` 外，其他配置建议在前端 **配置中心** 添加并点击“保存改动”写入 KV。旧环境变量 `CF_KEY`、`CF_ZONEID`、`CF_DOMAIN`、`CHECK_API`、`TG_TOKEN` 等仍兼容读取，但不再推荐作为主要配置方式。

### 配置中心

配置中心分两层：

- **维护的域名配置**：一张卡片对应一套维护权限，包含别名、维护根域、`Zone ID` 和 `CF Key`。可以添加多套 Cloudflare 账号或多个托管域名。
- **管理域名**：选择一套维护配置，只填写前缀，例如维护根域 `b.com` + 前缀 `kr` 会生成 `kr.b.com`。卡片上可单独打开/关闭维护，编辑后点击“保存改动”写入 KV。

自动维护是项目总开关，TG 通知是通知开关，二者都在配置中心用 ON/OFF 开关控制。每个管理域名也有独立维护开关，关闭后会在维护任务中跳过。

> 💡TG通知策略：
a.当出现失效ip，新增ip时，也就是域名内ip变动时会通知 
b.当域名没有补充的ip来维持最小活跃数时 
c.手动执行维护时

### CF_DOMAIN 配置格式

```
[模式]@域名:[端口]&[最小活跃数]
[模式]@域名:[端口]&[最小活跃数]|[出口类型]
```

**示例：**
```bash
# 地址记录模式（自动维护 A/AAAA）
ddns.example.com:443&3

# 只维护出口为 IPv4 的候选
ddns.example.com:443&3|v4

# 只维护出口为 IPv6 的候选
ddns.example.com:443&3|v6

# 只维护双栈出口候选
ddns.example.com:443&3|dual_stack

# TXT记录模式
txt@txt.example.com&5

# 同一域名同时维护地址记录和 TXT：配置两条
multi.example.com:8080&3,txt@multi.example.com&3

# 多域名（逗号分隔）
ddns1.example.com:443,txt@txt.example.com,multi.example.com:8080&3
```

`|出口类型` 可选，支持 `v4`、`v6`、`dual_stack`。不写时默认任意出口。旧的 `all@...` 环境变量会被兼容拆成地址记录和 TXT 两条目标，但新配置建议直接写两条。

出口类型由检测 API 的实时返回结果判断，不依赖 IP 入库时的旧标记。这样可以避免节点出口能力变化后被过期标记误筛。

### IP池存储格式

检测清洗入库后统一保存为：

```text
ip:port,asn,country
```

示例：

```text
121.178.202.91:10095,AS4766,KR
[2606:4700::1]:443,AS13335,US
1.2.3.4:443,AS4766/AS13335,KR/US
```

字段缺失时写 `null`。旧的 `ip:port # 注释` 和旧四字段 `ip:port,asn,country,stack` 格式仍可读取；新检测结果会按三字段 CSV 格式写回。

### 通用筛选

IP 输入框下方的筛选框支持简单表达式：

```text
port:443 country:KR asn:AS4766
country:KR | country:US
port:443-2053 HK
```

- 空格表示“且”，多个条件必须同时匹配。
- `|` 表示“或”，任一分组匹配即可。
- 支持字段：`port:`、`country:`、`asn:`，不带字段的内容按普通关键词匹配。

### 访问保护

设置 `AUTH_KEY` 后，首次访问需带参数：`https://你的域名/?key=你的AUTH_KEY`

浏览器会保存登录状态，之后可直接访问。

</details>

---

<details>
<summary><strong>🔧 高级配置</strong></summary>

### 调整并发检测数量

在代码中修改 `GLOBAL_SETTINGS`：

```javascript
const GLOBAL_SETTINGS = {
    // ── IP 检测 ──
    CONCURRENT_CHECKS: 32,       // 前端批量检测并发数
    CHECK_TIMEOUT: 3000,         // 单次 ProxyIP 检测超时(ms)

    // ── 网络超时 ──
    REMOTE_LOAD_TIMEOUT: 5000,   // 远程 URL 加载超时(ms)
    DOH_TIMEOUT: 5000,           // DNS over HTTPS 查询超时(ms)

    // ── 数据限制 ──
    DEFAULT_MIN_ACTIVE: 3,       // 默认最小活跃 IP 数
    MAX_TRASH_SIZE: 1000,        // 垃圾桶最大条目数
    MAX_POOL_NAME_LENGTH: 50,    // IP池名称最大长度
    MAX_IPS_PER_DOMAIN: 50,      // 域名解析最多取多少个 IP
};
```

### 自建 IP 检测 API

参考项目：[CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)

部署后修改 `CHECK_API` 环境变量为你的 API 地址。
检测后端不再附加 `token` 参数；如果后端需要鉴权，建议在检测服务侧自行处理固定入口或网关规则。

当前 Worker 会把新旧检测接口字段统一成内部格式，优先兼容：

- `success` / `ok` / `status`
- `responseTime` / `latency` / `duration` / `elapsed` / `time`
- `colo`
- `proxyIP` / `proxyIp` / `ip`
- `portRemote` / `port` / `remotePort`
- `probe_results.ipv4.exit`、`probe_results.ipv6.exit`

其中出口信息里的 `country`、`city`、`asn`、`asOrganization` 会用于前端展示、维护筛选、TG 通知，并在检测清洗入库时写入 CSV 元数据。

地址记录模式会同时读取并维护 Cloudflare 的 `A` 和 `AAAA` 记录：IPv4 候选写入 `A`，IPv6 候选写入 `AAAA`。前端探测域名时也会同时解析 `A` / `AAAA`。

### Telegram 通知配置

1. 与 [@BotFather](https://t.me/botfather) 对话，发送 `/newbot` 创建机器人
2. 与 [@userinfobot](https://t.me/userinfobot) 对话获取 Chat ID
3. 配置环境变量 `TG_TOKEN` 和 `TG_ID`

TG 通知会复用维护时的检测结果，展示域名、模式、端口、活跃数、新增/移除 IP、原因、机房、检测耗时、国家和 ASN。

</details>

---

<details>
<summary><strong>🛠️ 工作原理</strong></summary>

### 维护流程

```
定时触发 / 手动触发
        ↓
检测现有DNS记录中的IP
        ↓
按出口类型 / 国家 / ASN 过滤，删除失效或不匹配 IP → 移入垃圾桶
        ↓
活跃IP < 最小活跃数？
    ├─ 是 → 从库存加载IP → 实时检测出口与元数据 → 添加到DNS
    └─ 否 → 跳过
        ↓
按开关和通知条件发送Telegram通知
```

</details>

---

<details>
<summary><strong>❓ 常见问题</strong></summary>

### 1. 检测清洗后库存没变化？

检测清洗只验证IP可用性，**不会自动保存**。请点击 **追加入库** 按钮保存。

### 2. 定时任务不工作？

- 检查 Worker → **Triggers** → **Cron Triggers** 是否已添加
- 检查 Cron 表达式格式（如 `0 */3 * * *`）
- 查看 Worker → **Logs** 是否有执行记录

### 3. IP检测一直失败？

- 确保IP格式正确：`IP:端口`（如 `1.2.3.4:443`）
- 检查 `CHECK_API` 环境变量是否配置正确
- 确保目标IP的端口是开放的

### 4. 如何获取 API Token 和 Zone ID？

👆 请参考上方 **🚀 快速部署** 章节的详细步骤。

</details>

---

## 📚 相关项目

- [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP) - CF ProxyIP检测API
- [CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D) - DDNS-cf域名

## 📄 License

[MIT License](https://github.com/231128ikun/DDNS-cf-proxyip/blob/main/LICENSE)

## 📮 联系方式

如有问题，请在 GitHub 提交 Issue。
