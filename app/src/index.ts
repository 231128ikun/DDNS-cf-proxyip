import { createWorker } from './worker';

/**
 * 唯一 Worker 入口：只做装配，不在构建期生成代码。
 * `createWorker` 本身可以在测试里直接调用，不需要经过这里。
 */
export default createWorker();
