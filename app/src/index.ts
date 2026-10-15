import { connect } from 'cloudflare:sockets';

import { createWorker } from './worker';

/**
 * 唯一 Worker 入口：运行时模块只在这里导入，入口保持静态，不在构建期生成代码。
 * `createWorker` 本身可以在测试里直接调用，不需要经过这里。
 */
export default createWorker({ connect });