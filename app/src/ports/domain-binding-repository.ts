/** 域名与 IP 池绑定的最小读写端口：映射与显示顺序共用同一个 KV 资源。 */
export interface DomainBindingRepository {
  read(): Promise<Readonly<Record<string, string>>>;
  write(mapping: Readonly<Record<string, string>>): Promise<void>;
  readOrder(): Promise<readonly string[]>;
  writeOrder(order: readonly string[]): Promise<void>;
}
