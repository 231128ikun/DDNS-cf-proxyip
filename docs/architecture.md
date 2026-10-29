# 架构与维护边界

项目采用 TypeScript、Preact 和 Vite，部署为 Cloudflare 静态资源与一个 Worker。运行依赖只有 Preact；没有增加服务端框架、全局状态库或第二套部署程序。

## 源码职责

| 边界 | 职责 | 维护入口 |
| --- | --- | --- |
| 浏览器展示 | 页面组合、语义样式、交互反馈 | `app/web/src/components/`、`styles.css` |
| 浏览器异步状态 | 资源请求、DNS 展示与批量检测生命周期 | `app/web/src/state/` |
| 浏览器 API | 同源请求、鉴权和响应错误解析 | `app/web/src/api/client.ts` |
| HTTP / 任务 | 输入校验、鉴权、状态码和任务触发 | `app/src/transport/`、`jobs/` |
| 用例 | 检测、配置、池、记录与维护的编排 | `app/src/application/` |
| 纯规则与契约 | 地址和池格式、探针语义、共享数据类型 | `app/src/domain/`、`contracts/` |
| 端口 | 存储、DNS、探针、通知、远程文本的依赖接口 | `app/src/ports/` |
| 外部实现 | KV、HTTP、Cloudflare DNS 和 Telegram | `app/src/adapters/` |
| 装配 | 环境解析、依赖注入、fetch 与 scheduled 共用入口 | `app/src/config/`、`worker.ts`、`index.ts` |

`useBatchCheck` 集中管理批量输入、进度、中断、已完成来源和旧请求标识。停止时取消请求，输入替换时清除旧检测状态；恢复检测复用 `batch-resume.ts` 的来源行映射。页面仍拥有导航和排序弹窗状态，hook 通过回调通知页面关闭冲突弹窗。

远程池 HTTP 适配器负责请求、重定向公网校验、超时与响应体限制；应用用例通过 `RemotePoolSource` 获取文本后复用 `cleanPoolText`。任务通知模板位于任务边界，Telegram 适配器只负责发送。

## 自动约束

`test/unit/architecture.test.ts` 随 `npm run check` 执行。检查器遍历维护源码的 TypeScript 语法树，识别静态导入、再导出、动态导入和导入类型，约束核心层、适配器、任务与 HTTP 的依赖方向。领域层不依赖端口实现或基础设施；核心层不得引入 KV、HTTP 请求响应和运行时环境类型。浏览器不能导入 Worker、应用用例或外部适配器，直接 fetch 只允许位于统一客户端。

这是一组代码边界检查，不是完整的程序副作用证明：通过别名隐藏的调用、运行时生成的代码、跨窗口数据冲突和平台资源行为仍需要代码审查与行为测试。新增通用工具必须保持纯规则性质，不能借 `util/` 绕过依赖边界。

## 修改方法

- 调整业务规则时修改领域或用例，并增加可观察行为测试；页面不再实现同一套规则。
- 调整 HTTP、KV 或第三方交互时修改适配器，并通过端口注入测试替身。
- 修改 UI 状态流时同时验证取消、失败恢复、目标切换和旧请求失效；不能只验证成功截图。
- 不按文件行数机械拆分。新的模块必须有明确职责或复用点，不引入只转发参数的层层包装。
- 保持既有体积预算；增加依赖或抽象前先检查重复代码和现有实现。

发布及真实环境验收边界见 [release-readiness.md](release-readiness.md)。
