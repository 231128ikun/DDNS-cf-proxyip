/**
 * Workers 里的 `fetch` 是原生绑定，必须以裸函数调用。
 *
 * 把 `fetch` 存进对象字段再写成 `this.fetchImpl(...)`，`this` 会指向实例，
 * 运行时抛 `Illegal invocation: function called with incorrect 'this' reference`。
 * 单元测试注入的都是普通函数，因此只有真机才会暴露；所有适配器统一从这里取默认实现。
 */
export const appFetch: typeof fetch = (input, init) => fetch(input, init);
