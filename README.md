# DDNS Pro - Cloudflare Workers 动态DNS & IP管理

基于 cmliu 的 CheckProxyIP 项目提供的 API 做的多域名动态DNS管理系统，支持A记录、TXT记录和双模式，自动检测并替换失效IP。借助 CF 平台，无需服务器。

## 📋 主要功能

- ✅ **多域名管理** - 支持同时管理多个域名的DNS记录
- ✅ **三种模式** - A记录、TXT记录、双模式（ALL）
- ✅ **自动维护** - 定时检测失效IP并自动补充
- ✅ **Telegram通知** - 维护完成后推送详细报告
- ✅ **Web管理界面** - 直观的可视化操作面板
- ✅ **域名池绑定** - 支持不同域名绑定到不同的IP池



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

### 4️⃣ 配置环境变量

进入 Worker → **Settings** → **Variables**，添加：

| 变量名 | 值 |
|--------|-----|
| `CF_KEY` | 你的 API Token |
| `CF_ZONEID` | 你的 Zone ID |
| `CF_DOMAIN` | `你的域名:端口&最小活跃数`（如 `ddns.example.com:443&3`） |
> 💡建议后续部署自己的`CHECK_API`ip检测api，公益的稳定性差。

### 5️⃣ 创建 KV 绑定

1. 在 [KV](https://dash.cloudflare.com/?to=/:account/workers/kv/namespaces) 创建命名空间，名称：`IP_DATA`
2. 回到 Worker → **Settings** → **Bindings** → **Add binding**
3. Type: **KV Namespace**，Variable name: `IP_DATA`，选择刚创建的命名空间

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
example.com          # 探测A记录
example.com:8080     # 指定端口
txt@example.com      # 探测TXT记录
```

</details>

---

<details>
<summary><strong>⚙️ 环境变量详解</strong></summary>

### 必填变量

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `CF_KEY` | Cloudflare API Token | `abcd1234...` |
| `CF_ZONEID` | 域名的 Zone ID | `1a2b3c4d...` |
| `CF_DOMAIN` | 要维护的域名配置 | `ddns.example.com:443&3` |


### 可选变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `CHECK_API` | IP检测API地址 | `https://check.proxyip.cmliussss.net/check?proxyip=（建议自建）` |
| `CHECK_API_TOKEN` | 检测接口认证Token | 无 |
| `DOH_API` | DNS over HTTPS 接口 | `https://cloudflare-dns.com/dns-query` |
| `AUTH_KEY` | 管理面板访问密钥 | 无 |
| `TG_TOKEN` | Telegram Bot Token | 无 |
| `TG_ID` | Telegram Chat ID | 无 |
| `IP_INFO_ENABLED` | 开启IP归属地查询 | `false` |
| `IP_INFO_API` | IP归属地查询接口 | `http://ip-api.com/json` |

### CF_DOMAIN 配置格式

```
[模式]@域名:[端口]&[最小活跃数]
```

**示例：**
```bash
# A记录模式
ddns.example.com:443&3

# TXT记录模式
txt@txt.example.com&5

# 双模式
all@multi.example.com:8080&3

# 多域名（逗号分隔）
ddns1.example.com:443,txt@txt.example.com,all@multi.example.com:8080&3
```

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
    CONCURRENT_CHECKS: 10,       // 并发数（网络好可改为15-20）
    CHECK_TIMEOUT: 6000,         // 超时：6秒
    CHECK_RETRY_COUNT: 2,        // 重试次数
    CHECK_RETRY_DELAY: 3000      // 重试间隔：3秒
};
```

### 自建 IP 检测 API

参考项目：[CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)

部署后修改 `CHECK_API` 环境变量为你的 API 地址。

### Telegram 通知配置

1. 与 [@BotFather](https://t.me/botfather) 对话，发送 `/newbot` 创建机器人
2. 与 [@userinfobot](https://t.me/userinfobot) 对话获取 Chat ID
3. 配置环境变量 `TG_TOKEN` 和 `TG_ID`

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
删除失效IP → 移入垃圾桶
        ↓
活跃IP < 最小活跃数？
    ├─ 是 → 从库存加载IP → 检测有效性 → 添加到DNS
    └─ 否 → 跳过
        ↓
发送Telegram通知
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
