export type HostFamily = 'ipv4' | 'ipv6' | 'hostname';

export interface ProxyTarget {
  readonly input: string;
  readonly host: string;
  readonly port: number;
  readonly family: HostFamily;
  readonly authority: string;
  readonly key: string;
}

export type DnsRecordType = 'A' | 'AAAA';

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const NUMERIC_DOTTED_RE = /^\d+(?:\.\d+){3}$/;
const HOSTNAME_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export function parseProxyTarget(input: string, defaultPort = 443): ProxyTarget | null {
  const original = input.trim();
  if (!original || original.length > 512) return null;

  const parsed = parseAuthority(original, defaultPort);
  if (!parsed) return null;

  const host = parsed.host.toLowerCase();
  const family = detectFamily(host);
  if (!family) return null;
  if (!Number.isInteger(parsed.port) || parsed.port < 1 || parsed.port > 65_535) return null;

  const authority = formatProxyAuthority(host, parsed.port);
  return {
    input: original,
    host,
    port: parsed.port,
    family,
    authority,
    key: authority.toLowerCase(),
  };
}

export function formatProxyAuthority(host: string, port: number): string {
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}

export function dnsRecordTypeForHost(host: string): DnsRecordType {
  return host.includes(':') ? 'AAAA' : 'A';
}

function parseAuthority(value: string, defaultPort: number): { host: string; port: number } | null {
  if (/^https?:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      const host = stripIpv6Brackets(url.hostname);
      return { host, port: Number(url.port || defaultPort) };
    } catch {
      return null;
    }
  }

  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(value);
  if (bracketed) {
    const host = bracketed[1];
    if (!host) return null;
    const port = bracketed[2] ? Number(bracketed[2]) : defaultPort;
    return { host, port };
  }

  const colonCount = [...value].filter((char) => char === ':').length;
  if (colonCount > 1) return { host: value, port: defaultPort };
  if (colonCount === 1) {
    const separator = value.lastIndexOf(':');
    const host = value.slice(0, separator).trim();
    const portText = value.slice(separator + 1).trim();
    if (!host || !/^\d+$/.test(portText)) return null;
    return { host, port: Number(portText) };
  }

  return { host: value, port: defaultPort };
}

function stripIpv6Brackets(hostname: string): string {
  return hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
}

function detectFamily(host: string): HostFamily | null {
  if (isIpv4(host)) return 'ipv4';
  if (isIpv6(host)) return 'ipv6';
  if (NUMERIC_DOTTED_RE.test(host)) return null;
  return HOSTNAME_RE.test(host) ? 'hostname' : null;
}

function isIpv4(value: string): boolean {
  return IPV4_RE.test(value) && value.split('.').every((part) => Number(part) <= 255);
}

function isIpv6(value: string): boolean {
  if (!value.includes(':')) return false;
  try {
    const parsed = new URL(`http://[${value}]`);
    return parsed.hostname.length > 0;
  } catch {
    return false;
  }
}
