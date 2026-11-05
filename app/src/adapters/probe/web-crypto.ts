// subtls 的 Node 回退在 Workers 中复用平台 Web Crypto，不引入 Node 运行时。
export const webcrypto = globalThis.crypto;
