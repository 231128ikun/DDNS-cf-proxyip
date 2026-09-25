/** 域名与 IP 池绑定的最小读写端口，存储实现负责池 key 白名单。 */
export interface DomainBindingRepository {
  read(): Promise<Readonly<Record<string, string>>>;
  write(mapping: Readonly<Record<string, string>>): Promise<void>;
}