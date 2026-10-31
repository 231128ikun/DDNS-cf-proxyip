/**
 * 远程加载的安全边界。
 *
 * 只允许公网 http(s) 地址，避免面板被当作 SSRF 跳板去读内网服务或云元数据。
 * 判定基于 WHATWG URL 解析后的 hostname，因此十进制/八进制/十六进制等
 * 变形的 IPv4 字面量会先被规范化成点分十进制，再进入这里的黑名单判断。
 */

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
]);

const BLOCKED_SUFFIXES = ['.localhost', '.internal', '.local', '.home.arpa'];

export type RemoteUrlRejection = 'invalid-url' | 'blocked-host';

export type RemoteUrlValidation =
  | { readonly ok: true; readonly url: URL }
  | { readonly ok: false; readonly reason: RemoteUrlRejection };

export function validateRemoteUrl(value: string): RemoteUrlValidation {
  const trimmed = String(value ?? '').trim();
  if (!trimmed || trimmed.length > 2_048) return { ok: false, reason: 'invalid-url' };

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return { ok: false, reason: 'invalid-url' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') return { ok: false, reason: 'invalid-url' };
  if (url.username || url.password) return { ok: false, reason: 'invalid-url' };
  if (isPrivateHost(url.hostname)) return { ok: false, reason: 'blocked-host' };

  return { ok: true, url };
}

export function isPrivateHost(hostname: string): boolean {
  const host = normalizeHost(hostname);
  if (!host) return true;
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  if (BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) return true;

  const ipv4 = parseIpv4(host);
  if (ipv4) return isPrivateIpv4(ipv4);
  if (host.includes(':')) return isPrivateIpv6(host);
  return false;
}

function normalizeHost(hostname: string): string {
  const host = String(hostname ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (host.startsWith('[') && host.endsWith(']')) return host.slice(1, -1);
  // 去掉 IPv6 的区域标识（fe80::1%eth0）
  const zoneIndex = host.indexOf('%');
  return zoneIndex === -1 ? host : host.slice(0, zoneIndex);
}

function parseIpv4(host: string): readonly number[] | null {
  const parts = host.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => (/^\d{1,3}$/.test(part) ? Number(part) : Number.NaN));
  return octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255) ? octets : null;
}

function isPrivateIpv4(octets: readonly number[]): boolean {
  const [a, b] = octets as [number, number, number, number];
  if (a === 0) return true;                              // 0.0.0.0/8
  if (a === 10) return true;                             // 10.0.0.0/8
  if (a === 127) return true;                            // 127.0.0.0/8
  if (a === 169 && b === 254) return true;               // 169.254.0.0/16 链路本地
  if (a === 172 && b >= 16 && b <= 31) return true;      // 172.16.0.0/12
  if (a === 192 && b === 168) return true;               // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true;     // 100.64.0.0/10 运营商级 NAT
  if (a === 192 && b === 0) return true;                 // 192.0.0.0/24 与 192.0.2.0/24
  if (a === 198 && (b === 18 || b === 19)) return true;  // 198.18.0.0/15 基准测试
  if (a >= 224) return true;                             // 组播与保留段
  return false;
}

function isPrivateIpv6(host: string): boolean {
  const groups = expandIpv6(host);
  // 解析失败的地址一律按内网处理：宁可拒绝，也不放过变形写法。
  if (!groups) return true;

  const [first = 0, second = 0, third = 0, fourth = 0, fifth = 0, sixth = 0, seventh = 0, eighth = 0] = groups;

  // IPv4 兼容/映射地址（::a.b.c.d、::ffff:a.b.c.d）按内嵌的 IPv4 判定。
  // 必须放在前面：URL 会把 ::ffff:127.0.0.1 规范化成 ::ffff:7f00:1，
  // 丢掉点分十进制后就再也匹配不上最上面的 IPv4 黑名单。
  const leading = [first, second, third, fourth, fifth, sixth];
  const isV4Compatible = leading.every((group) => group === 0);
  const isV4Mapped = sixth === 0xffff && leading.slice(0, 5).every((group) => group === 0);
  if (isV4Compatible || isV4Mapped) {
    return isPrivateIpv4([seventh >> 8, seventh & 0xff, eighth >> 8, eighth & 0xff]);
  }

  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 唯一本地地址
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 链路本地
  if ((first & 0xff00) === 0xff00) return true; // ff00::/8 组播
  return false;
}

/**
 * 把 IPv6 字面量展开成 8 个 16 位分组，无法解析时返回 null。
 * URL 解析后的主机名仍可能是缩写（::1）或以点分十进制结尾（::ffff:127.0.0.1），
 * 所以统一先展开再判网段，避免每增加一种写法就要加一条正则。
 */
function expandIpv6(address: string): readonly number[] | null {
  let value = address;
  const tailStart = value.lastIndexOf(':') + 1;
  const tail = value.slice(tailStart);
  if (tail.includes('.')) {
    const octets = parseIpv4(tail);
    if (!octets) return null;
    const [a, b, c, d] = octets as [number, number, number, number];
    value = `${value.slice(0, tailStart)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }

  const halves = value.split('::');
  if (halves.length > 2) return null;

  const readGroups = (part: string): readonly number[] | null => {
    if (!part) return [];
    const groups = part.split(':').map((group) => (/^[0-9a-f]{1,4}$/.test(group) ? parseInt(group, 16) : -1));
    return groups.some((group) => group < 0) ? null : groups;
  };

  const head = readGroups(halves[0] ?? '');
  const body = readGroups(halves[1] ?? '');
  if (!head || !body) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;

  const zeros = 8 - head.length - body.length;
  return zeros >= 1 ? [...head, ...new Array<number>(zeros).fill(0), ...body] : null;
}