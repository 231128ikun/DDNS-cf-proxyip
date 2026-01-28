# DDNS Pro - Cloudflare Workers 动态DNS & IP管理

多域名动态DNS管理系统，支持A记录、TXT记录和双模式，自动检测并替换失效IP。

## 📋 主要功能

- ✅ **多域名管理** - 支持同时管理多个域名的DNS记录
- ✅ **三种模式** - A记录、TXT记录、双模式（ALL）
- ✅ **自动维护** - 定时检测失效IP并自动补充
- ✅ **批量检测** - 并发检测IP可用性，提高效率
- ✅ **追加入库** - 新IP追加到库存，不覆盖现有数据
- ✅ **Telegram通知** - 维护完成后推送详细报告
- ✅ **Web管理界面** - 直观的可视化操作面板

```
主要就是为了维护一个任意端口的proxyip域名用于访问cf类网站，达到的效果就是定时监控自动维护来保证域名中的ip始终可用。比如kr.dwb.cc.cd:50001
```
# 快速开始指南

## 1️⃣ 准备工作

### 获取 Cloudflare API Token

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 点击右上角头像 → **My Profile**
3. 左侧菜单 **API Tokens** → **Create Token**
4. 选择 **Edit zone DNS** 模板
5. 配置权限：
   - **Permissions**: Zone - DNS - Edit
   - **Zone Resources**: 选择你的域名
6. 点击 **Continue to summary** → **Create Token**
7. **复制保存** 生成的 Token（只显示一次）

### 获取 Zone ID

1. 在 [Cloudflare Dashboard](https://dash.cloudflare.com/) 中选择你的域名
2. 右侧 **API** 区域可以看到 **Zone ID**
3. 复制保存

## 2️⃣ 部署 Worker

### 通过 Cloudflare Dashboard

1. 访问 [Cloudflare Workers](https://dash.cloudflare.com/?to=/:account/workers)
2. 点击 **Create Application** → **Create Worker**
3. 复制 `worker.js` 的全部内容
4. 粘贴到编辑器 → **Save and Deploy**
5. 配置环境变量和KV绑定（见下方）

#### 配置环境变量

进入 Worker → **Settings** → **Variables**，添加：

```
CF_MAIL = your-email@example.com
CF_KEY = your-cloudflare-api-token
CF_ZONEID = your-zone-id
CF_DOMAIN = ddns.example.com:port （不填端口默认443）
MIN_ACTIVE = 3
```

#### 创建 KV 绑定

1. 在 [KV](https://dash.cloudflare.com/?to=/:account/workers/kv/namespaces) 创建命名空间
2. 名称：`IP_DATA`
3. 回到 Worker → **Settings** → **Bindings**
4. 点击 **Add binding**
   - Type: **KV Namespace**
   - Variable name: `IP_DATA`
   - KV namespace: 选择刚创建的命名空间

#### 配置定时任务

Worker → **Triggers** → **Cron Triggers** → **Add Cron Trigger**

```
0 */6 * * *  # 每6小时执行一次
```

## 3️⃣ 使用管理面板

访问你的 Worker 地址：
```
https://ddns-pro.你的子域名.workers.dev
```

### 第一次使用

#### Step 1: 添加IP到库存

1. 在 **手动输入** 标签页输入IP列表：
```
1.2.3.4:443
5.6.7.8:8080
```

2. 点击 **检测清洗**（自动验证IP可用性）

3. 点击 **追加入库**（保存到库存）

#### Step 2: 查看解析状态

1. 选择要管理的域名（顶部下拉框）
2. 点击 **刷新** 查看当前DNS记录

#### Step 3: 执行维护

点击 **执行全部维护** 按钮，系统会：
- 检测现有DNS记录
- 删除失效IP
- 从库存补充新IP
- 发送Telegram通知（如已配置）

## 4️⃣ 配置自动维护（可选）

### 设置定时任务

在 `Worker → Triggers → Cron Triggers` 中：
```
[triggers]
crons = ["0 */6 * * *"]  # 每6小时
```

### 配置 Telegram 通知

1. 创建 Telegram Bot:
   - 与 [@BotFather](https://t.me/botfather) 对话
   - 发送 `/newbot` 并按提示操作
   - 获得 Token: `123456789:ABCdef...`

2. 获取 Chat ID:
   - 与 [@userinfobot](https://t.me/userinfobot) 对话
   - 发送任意消息
   - 获得 ID: `123456789`

3. 在 `环境变量` 中添加：
```
TG_TOKEN = "your-bot-token"
TG_ID = "your-chat-id"
```

4. 重新部署

## 5️⃣ 日常使用

### 批量导入IP（从Excel）

1. 在Excel中准备两列：
```
IP地址         端口
1.2.3.4       443
5.6.7.8       8080
```

2. 选中数据 → Ctrl+C 复制

3. 粘贴到管理面板的输入框

4. 点击 **检测清洗** → **追加入库**

### 从远程URL加载IP

1. 切换到 **远程TXT** 标签页

2. 输入TXT文件URL（如GitHub Raw文件）

3. 点击 **加载** → **追加入库**

### 域名探测

在 **Check ProxyIP** 区域：
```
# 探测A记录
example.com
example.com:8080

# 探测TXT记录
txt@example.com
```

自动检测IP可用性，点击 **➕** 添加到输入框


## ⚙️ 环境变量说明

### 必填变量

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `CF_MAIL` | Cloudflare 账号邮箱 | `user@example.com` |
| `CF_KEY` | Cloudflare API Token | `abcd1234...` |
| `CF_ZONEID` | 域名的 Zone ID | `1a2b3c4d...` |
| `CF_DOMAIN` | 目标要维护的域名，具体配置（见下方格式说明） | `ddns.example.com` |
| `MIN_ACTIVE` | 最少活跃IP数量 | `3` |
| `CHECK_API` | ProxyIP检测API地址（下方有项目地址） | `https://check.dwb.pp.ua/check?proxyip=` |

### 可选变量

| 变量名 | 说明 | 默认值 | 示例 |
|--------|------|--------|------|
| `DOMAIN` | 别人维护好的优质域名（自动解析为候选IP） | 无 | `source.example.com:443` |
| `DOH_API` | DNS over HTTPS API | `https://cloudflare-dns.com/dns-query` | 其他DoH服务 |
| `TG_TOKEN` | Telegram Bot Token | 无 | `1234567890:ABCdef...` |
| `TG_ID` | Telegram Chat ID | 无 | `123456789` |
| `IP_INFO_ENABLED` | 查询ip归属地开关 | false | `true` |
| `IP_INFO_API` | 查询ip归属地api | http://ip-api.com/json | `https://example.com/json` |

### CF_DOMAIN 格式说明

支持三种模式，多个域名用逗号分隔：

```bash
# A记录模式（默认。就是将活跃的ip解析到维护的域名的a记录）
CF_DOMAIN="ddns.example.com"                    # 默认端口443
CF_DOMAIN="ddns.example.com:8443"               # 指定端口8443

# TXT记录模式（就是将活跃的ip解析到维护域名的txt记录中）
CF_DOMAIN="txt@txt.example.com"                 # TXT记录，存储 IP:PORT 列表

# 双模式（同时维护A和TXT记录）
CF_DOMAIN="all@multi.example.com:8080"          # 同时创建A记录和TXT记录

# 多域名配置（逗号分隔）
CF_DOMAIN="ddns.example.com,txt@txt.example.com,all@multi.example.com:8080"
```

## 🔧 高级配置

### 调整并发检测数量

在代码中修改 `GLOBAL_SETTINGS`：

```javascript
const GLOBAL_SETTINGS = {
    CONCURRENT_CHECKS: 10,      // 并发数：10（网络好可改为15-20）
    CHECK_TIMEOUT: 6000,        // 超时：6秒
    REMOTE_LOAD_TIMEOUT: 10000  // 远程加载超时：10秒
};
```

### 自建 IP 检测 API

参考项目：[CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)

部署后修改 `CHECK_API` 环境变量为你的 API 地址。

### Telegram 通知配置

1. 创建 Telegram Bot：与 [@BotFather](https://t.me/botfather) 对话
2. 获取 Token：`123456789:ABCdefGHIjklMNOpqrsTUVwxyz`
3. 获取 Chat ID：与 [@userinfobot](https://t.me/userinfobot) 对话
4. 配置环境变量 `TG_TOKEN` 和 `TG_ID`

## 🛠️ 工作原理

### 维护流程

```
1. 定时触发（Cron）或手动触发
   ↓
2. 检测现有DNS记录中的IP/txt记录中的ip
   ↓
3. 删除失效IP 
   ↓
4. 如果活跃IP < MIN_ACTIVE（最小活跃ip数）
   ├─ 从 DOMAIN（若配置） 解析新IP
   └─ 从 IP_DATA (KV) 加载库存
   ↓
5. 检测候选IP
   ↓
6. 添加有效IP到DNS/txt记录
   ↓
7. 更新库存
   ↓
8. 发送Telegram通知
```

## 📚 相关项目

本项目基于以下优秀项目：

- [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP) -CF ProxyIP检测API
- [CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D) - DDNS-cf域名

## ❓ 常见问题

### 1. 为什么检测清洗后库存没变化？

检测清洗只处理当前输入框中的IP，不会影响库存。如需更新库存，请先检测清洗，再点击 **追加入库**。

### 2. 如何获取 Cloudflare API Token？

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 右上角头像 → **My Profile** → **API Tokens**
3. **Create Token** → 使用 **Edit zone DNS** 模板
4. 选择需要管理的域名 → **Continue to summary** → **Create Token**

### 3. 如何找到 Zone ID？

1. 登录 Cloudflare Dashboard
2. 选择域名
3. 右侧 **API** 区域可以看到 **Zone ID**

### 4. 定时任务不工作？

Cloudflare Workers 的免费计划支持 Cron Triggers。检查：
1. 在 Dashboard 的 Worker → **Triggers** → **Cron Triggers** 查看是否生效
2. 查看执行日志：Dashboard → Worker → **Logs**

### 5. IP检测一直失败？

检查：
1. `CHECK_API` 是否配置正确且可访问
2. IP格式是否正确（必须包含端口）
3. 目标端口是否开放

## 📄 License

[MIT License](https://github.com/231128ikun/DDNS-cf-proxyip/blob/main/LICENSE)

## 📮 联系方式

如有问题，请在 GitHub 提交 Issue。
