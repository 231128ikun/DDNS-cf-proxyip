var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// app/dist/bundle-build/generated/index.ts
import { connect } from "cloudflare:sockets";

// app/src/adapters/assets/bundled-assets.ts
var INDEX_PATH = "/index.html";
var IMMUTABLE_CACHE = "public, max-age=31536000, immutable";
var REVALIDATE_CACHE = "no-cache";
var TEXT_HEADERS = { "content-type": "text/plain; charset=utf-8" };
function createBundledAssets(assets) {
  const decoded = /* @__PURE__ */ new Map();
  const load = /* @__PURE__ */ __name((path) => {
    const cached = decoded.get(path);
    if (cached) return cached;
    const pending = decodeAsset(assets[path]);
    decoded.set(path, pending);
    return pending;
  }, "load");
  const fetcher = {
    async fetch(input, init) {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.method !== "GET" && request.method !== "HEAD") {
        return new Response("Method Not Allowed", { status: 405, headers: { allow: "GET, HEAD" } });
      }
      const path = normalizePath(new URL(request.url).pathname);
      let asset = await load(path);
      if (!asset && isSpaRoute(path)) asset = await load(INDEX_PATH);
      if (!asset) return new Response("Not Found", { status: 404, headers: TEXT_HEADERS });
      const headers = {
        "content-type": asset.contentType,
        "cache-control": isHashedAsset(path) ? IMMUTABLE_CACHE : REVALIDATE_CACHE
      };
      return new Response(request.method === "HEAD" ? null : asset.bytes, { headers });
    }
  };
  return fetcher;
}
__name(createBundledAssets, "createBundledAssets");
async function decodeAsset(asset) {
  if (!asset) return null;
  const stored = decodeBase64(asset.base64);
  const bytes = asset.gzip ? await gunzip(stored) : stored;
  return { bytes, contentType: asset.contentType };
}
__name(decodeAsset, "decodeAsset");
async function gunzip(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
__name(gunzip, "gunzip");
function isSpaRoute(path) {
  return !path.slice(path.lastIndexOf("/") + 1).includes(".");
}
__name(isSpaRoute, "isSpaRoute");
function isHashedAsset(path) {
  return path.startsWith("/assets/");
}
__name(isHashedAsset, "isHashedAsset");
function normalizePath(pathname) {
  const collapsed = pathname.replace(/\/{2,}/g, "/");
  return collapsed.startsWith("/") ? collapsed : `/${collapsed}`;
}
__name(normalizePath, "normalizePath");
function decodeBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
__name(decodeBase64, "decodeBase64");

// app/src/domain/proxy-target.ts
var IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
var NUMERIC_DOTTED_RE = /^\d+(?:\.\d+){3}$/;
var HOSTNAME_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
function parseProxyTarget(input, defaultPort = 443) {
  const original = input.trim();
  if (!original || original.length > 512) return null;
  const parsed = parseAuthority(original, defaultPort);
  if (!parsed) return null;
  const host = parsed.host.toLowerCase();
  const family = detectFamily(host);
  if (!family) return null;
  if (!Number.isInteger(parsed.port) || parsed.port < 1 || parsed.port > 65535) return null;
  const authority = formatProxyAuthority(host, parsed.port);
  return {
    input: original,
    host,
    port: parsed.port,
    family,
    authority,
    key: authority.toLowerCase()
  };
}
__name(parseProxyTarget, "parseProxyTarget");
function formatProxyAuthority(host, port) {
  return host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
}
__name(formatProxyAuthority, "formatProxyAuthority");
function dnsRecordTypeForHost(host) {
  return host.includes(":") ? "AAAA" : "A";
}
__name(dnsRecordTypeForHost, "dnsRecordTypeForHost");
function parseAuthority(value, defaultPort) {
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
  const colonCount = [...value].filter((char) => char === ":").length;
  if (colonCount > 1) return { host: value, port: defaultPort };
  if (colonCount === 1) {
    const separator = value.lastIndexOf(":");
    const host = value.slice(0, separator).trim();
    const portText = value.slice(separator + 1).trim();
    if (!host || !/^\d+$/.test(portText)) return null;
    return { host, port: Number(portText) };
  }
  return { host: value, port: defaultPort };
}
__name(parseAuthority, "parseAuthority");
function stripIpv6Brackets(hostname) {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}
__name(stripIpv6Brackets, "stripIpv6Brackets");
function detectFamily(host) {
  if (isIpv4(host)) return "ipv4";
  if (isIpv6(host)) return "ipv6";
  if (NUMERIC_DOTTED_RE.test(host)) return null;
  return HOSTNAME_RE.test(host) ? "hostname" : null;
}
__name(detectFamily, "detectFamily");
function isIpv4(value) {
  return IPV4_RE.test(value) && value.split(".").every((part) => Number(part) <= 255);
}
__name(isIpv4, "isIpv4");
function isIpv6(value) {
  if (!value.includes(":")) return false;
  try {
    const parsed = new URL(`http://[${value}]`);
    return parsed.hostname.length > 0;
  } catch {
    return false;
  }
}
__name(isIpv6, "isIpv6");

// app/src/domain/txt-record.ts
function parseTxtAddresses(content) {
  const unquoted = content.trim().replace(/^"|"$/g, "");
  if (!unquoted) return [];
  return [...new Set(unquoted.split(",").map((item) => item.trim()).filter(Boolean))];
}
__name(parseTxtAddresses, "parseTxtAddresses");
function formatTxtAddresses(addresses) {
  return `"${[...new Set(addresses)].join(",")}"`;
}
__name(formatTxtAddresses, "formatTxtAddresses");

// app/src/adapters/dns/cloudflare-dns.ts
var CloudflareDnsRepository = class {
  static {
    __name(this, "CloudflareDnsRepository");
  }
  baseUrl;
  timeoutMs;
  fetchImpl;
  constructor(options = {}) {
    this.baseUrl = (options.baseUrl ?? "https://api.cloudflare.com/client/v4").replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 1e4;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }
  async listAddressRecords(zone, domain) {
    const [a, aaaa] = await Promise.all([
      this.listRecords(zone, domain, "A"),
      this.listRecords(zone, domain, "AAAA")
    ]);
    return [...a, ...aaaa];
  }
  async listTxtRecords(zone, domain) {
    return await this.listRecords(zone, domain, "TXT");
  }
  async addAddressRecord(zone, domain, host, type) {
    const recordType = type ?? dnsRecordTypeForHost(host);
    const result = await this.request(zone, `/zones/${encodeURIComponent(zone.zoneId)}/dns_records`, {
      method: "POST",
      body: JSON.stringify({ type: recordType, name: domain, content: host, ttl: 60, proxied: false })
    });
    return parseRecord(result);
  }
  async upsertTxtRecord(zone, domain, recordId, addresses) {
    const body = JSON.stringify({ type: "TXT", name: domain, content: formatTxtAddresses(addresses), ttl: 60 });
    const result = recordId ? await this.request(zone, `/zones/${encodeURIComponent(zone.zoneId)}/dns_records/${encodeURIComponent(recordId)}`, {
      method: "PUT",
      body
    }) : await this.request(zone, `/zones/${encodeURIComponent(zone.zoneId)}/dns_records`, {
      method: "POST",
      body
    });
    return parseRecord(result);
  }
  async deleteRecord(zone, recordId) {
    await this.request(zone, `/zones/${encodeURIComponent(zone.zoneId)}/dns_records/${encodeURIComponent(recordId)}`, {
      method: "DELETE"
    });
  }
  async listRecords(zone, domain, type) {
    const result = await this.request(
      zone,
      `/zones/${encodeURIComponent(zone.zoneId)}/dns_records?name=${encodeURIComponent(domain)}&type=${type}`,
      { method: "GET" }
    );
    if (!Array.isArray(result)) throw new CloudflareDnsError("Cloudflare \u8FD4\u56DE\u7684 DNS \u8BB0\u5F55\u683C\u5F0F\u65E0\u6548");
    return result.map(parseRecord);
  }
  async request(zone, path, init) {
    if (!zone.apiToken || !zone.zoneId) throw new CloudflareDnsError("Cloudflare \u51ED\u8BC1\u4E0D\u5B8C\u6574");
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${zone.apiToken}`);
    headers.set("Content-Type", "application/json");
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...init,
        headers,
        signal: AbortSignal.timeout(this.timeoutMs)
      });
    } catch {
      throw new CloudflareDnsError("Cloudflare API \u8BF7\u6C42\u5931\u8D25");
    }
    let payload;
    try {
      const value = await response.json();
      if (!isRecord(value)) throw new Error("invalid response");
      payload = value;
    } catch {
      throw new CloudflareDnsError(`Cloudflare API \u54CD\u5E94\u65E0\u6548 (HTTP ${response.status})`);
    }
    if (!response.ok || payload.success !== true) {
      throw new CloudflareDnsError(`Cloudflare API \u64CD\u4F5C\u5931\u8D25 (HTTP ${response.status})`);
    }
    return payload.result;
  }
};
var CloudflareDnsError = class extends Error {
  static {
    __name(this, "CloudflareDnsError");
  }
  constructor(message) {
    super(message);
    this.name = "CloudflareDnsError";
  }
};
function parseRecord(value) {
  if (!isRecord(value)) throw new CloudflareDnsError("Cloudflare DNS \u8BB0\u5F55\u683C\u5F0F\u65E0\u6548");
  const id = readString(value.id);
  const type = readString(value.type);
  const name = readString(value.name);
  const content = readString(value.content);
  if (!id || !type || !["A", "AAAA", "TXT"].includes(type) || !name || content === void 0) {
    throw new CloudflareDnsError("Cloudflare DNS \u8BB0\u5F55\u5B57\u6BB5\u4E0D\u5B8C\u6574");
  }
  return { id, type, name, content };
}
__name(parseRecord, "parseRecord");
function readString(value) {
  return typeof value === "string" ? value : void 0;
}
__name(readString, "readString");
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
__name(isRecord, "isRecord");

// app/src/adapters/notify/telegram.ts
var TelegramNotifier = class {
  static {
    __name(this, "TelegramNotifier");
  }
  enabled;
  token;
  chatId;
  timeoutMs;
  fetchImpl;
  constructor(options) {
    this.enabled = options.enabled;
    this.token = options.token.trim();
    this.chatId = options.chatId.trim();
    this.timeoutMs = options.timeoutMs ?? 1e4;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }
  async send(text3) {
    if (!this.enabled) return { sent: false, reason: "disabled" };
    if (!this.token || !this.chatId) return { sent: false, reason: "not_configured" };
    try {
      const response = await this.fetchImpl(`https://api.telegram.org/bot${this.token}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: this.chatId,
          text: text3,
          parse_mode: "HTML",
          disable_web_page_preview: true
        }),
        signal: AbortSignal.timeout(this.timeoutMs)
      });
      return response.ok ? { sent: true, reason: "sent" } : { sent: false, reason: "failed" };
    } catch {
      return { sent: false, reason: "failed" };
    }
  }
};

// app/src/domain/pool-entry.ts
function parsePoolText(text3) {
  if (!text3) return [];
  return text3.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((raw) => ({ raw, entry: parsePoolEntry(raw) }));
}
__name(parsePoolText, "parsePoolText");
function serializePoolText(lines) {
  return lines.map((line) => line.raw).join("\n");
}
__name(serializePoolText, "serializePoolText");
function parsePoolEntry(line) {
  const raw = line.trim();
  if (!raw || raw.startsWith("#")) return null;
  const commentIndex = raw.indexOf("#");
  const main = (commentIndex >= 0 ? raw.slice(0, commentIndex) : raw).trim();
  const comment = commentIndex >= 0 ? raw.slice(commentIndex).trim() : "";
  const fields = main.split(",").map((field) => field.trim());
  const address = fields[0] ?? "";
  if (!address) return null;
  return {
    address,
    asn: fields[1] || null,
    country: fields[2] || null,
    stack: normalizePoolStack(fields[3]),
    comment
  };
}
__name(parsePoolEntry, "parsePoolEntry");
function formatPoolEntry(entry) {
  const address = normalizePoolAddress(entry.address) ?? entry.address.trim();
  const fields = [
    address,
    formatPoolAsn(entry.asn),
    formatPoolCountry(entry.country),
    entry.stack ?? "null"
  ];
  const comment = normalizeComment(entry.comment);
  return `${fields.join(",")}${comment}`;
}
__name(formatPoolEntry, "formatPoolEntry");
function normalizePoolAddress(value, defaultPort = 443) {
  return parseProxyTarget(value, defaultPort)?.authority ?? null;
}
__name(normalizePoolAddress, "normalizePoolAddress");
function parsePoolAddress(entry, defaultPort = 443) {
  return parseProxyTarget(entry.address, defaultPort);
}
__name(parsePoolAddress, "parsePoolAddress");
function extractPoolAddressKey(value) {
  return value.split("#", 1)[0]?.split(",")[0]?.trim() ?? "";
}
__name(extractPoolAddressKey, "extractPoolAddressKey");
function canonicalAddressKey(value, defaultPort = 443) {
  return parseProxyTarget(value, defaultPort)?.key ?? value.trim().toLowerCase();
}
__name(canonicalAddressKey, "canonicalAddressKey");
function poolMetadataFromProbe(result) {
  if (result.status !== "alive") return {};
  const exits = result.exits.length > 0 ? result.exits : result.exitIp ? [{ family: result.exitFamily === "dual" ? "unknown" : result.exitFamily, ip: result.exitIp }] : [];
  const asn = joinMetadata(exits.map((exit) => normalizeAsn(exit.asn)));
  const country = joinMetadata(exits.map((exit) => normalizeCountry(exit.country)));
  const stack = inferPoolStack(result.exitFamily, exits.map((exit) => exit.family));
  return {
    ...asn ? { asn } : {},
    ...country ? { country } : {},
    ...stack ? { stack } : {}
  };
}
__name(poolMetadataFromProbe, "poolMetadataFromProbe");
function mergePoolMetadata(previous, metadata) {
  return {
    address: normalizePoolAddress(previous.address) ?? previous.address,
    asn: isUnknownMetaValue(metadata.asn) ? previous.asn : formatPoolAsnValue(metadata.asn),
    country: isUnknownMetaValue(metadata.country) ? normalizeCountry(previous.country) ?? previous.country : normalizeCountry(metadata.country) ?? null,
    stack: metadata.stack ?? previous.stack,
    comment: previous.comment
  };
}
__name(mergePoolMetadata, "mergePoolMetadata");
function updatePoolEntryFromProbe(previous, result) {
  if (result.status !== "alive") return previous;
  return mergePoolMetadata(previous, poolMetadataFromProbe(result));
}
__name(updatePoolEntryFromProbe, "updatePoolEntryFromProbe");
function formatPoolAsn(value) {
  if (isUnknownMetaValue(value)) return "null";
  return String(value).split(/[\/,\s\uFF0C\uFF1B;]+/).map((item) => item.trim().replace(/^AS/i, "").toUpperCase()).filter(Boolean).map((item) => `AS${item}`).join("/") || "null";
}
__name(formatPoolAsn, "formatPoolAsn");
function normalizeAsn(value) {
  const text3 = String(value ?? "").trim().replace(/^AS/i, "").toUpperCase();
  return text3 && !isUnknownMetaValue(text3) ? text3 : void 0;
}
__name(normalizeAsn, "normalizeAsn");
function normalizeCountry(value) {
  const text3 = String(value ?? "").trim().toUpperCase();
  return text3 && !isUnknownMetaValue(text3) ? text3 : void 0;
}
__name(normalizeCountry, "normalizeCountry");
function normalizePoolStack(value) {
  const text3 = String(value ?? "").trim().toLowerCase().replace(/_/g, "-");
  if (["v4", "ipv4", "ipv4-only", "only-ipv4"].includes(text3)) return "v4";
  if (["v6", "ipv6", "ipv6-only", "only-ipv6"].includes(text3)) return "v6";
  if (["v4/v6", "v6/v4", "dual", "dual-stack", "both", "all", "ipv4-ipv6"].includes(text3)) return "v4/v6";
  return null;
}
__name(normalizePoolStack, "normalizePoolStack");
function isUnknownMetaValue(value) {
  const text3 = String(value ?? "").trim().toLowerCase();
  return !text3 || ["null", "unknown", "n/a", "-", "asnull", "asunknown"].includes(text3);
}
__name(isUnknownMetaValue, "isUnknownMetaValue");
function formatPoolAsnValue(value) {
  const formatted = formatPoolAsn(value);
  return formatted === "null" ? null : formatted;
}
__name(formatPoolAsnValue, "formatPoolAsnValue");
function formatPoolCountry(value) {
  return normalizeCountry(value) ?? "null";
}
__name(formatPoolCountry, "formatPoolCountry");
function normalizeComment(value) {
  const comment = value.trim();
  if (!comment) return "";
  return comment.startsWith("#") ? ` ${comment}` : ` #${comment}`;
}
__name(normalizeComment, "normalizeComment");
function joinMetadata(values) {
  const unique = [...new Set(values.filter((value) => Boolean(value)))];
  return unique.length ? unique.join("/") : void 0;
}
__name(joinMetadata, "joinMetadata");
function inferPoolStack(family, exitFamilies) {
  const hasIpv4 = family === "ipv4" || family === "dual" || exitFamilies.includes("ipv4");
  const hasIpv6 = family === "ipv6" || family === "dual" || exitFamilies.includes("ipv6");
  if (hasIpv4 && hasIpv6) return "v4/v6";
  if (hasIpv4) return "v4";
  if (hasIpv6) return "v6";
  return void 0;
}
__name(inferPoolStack, "inferPoolStack");
function mergePoolEntry(previous, next) {
  const normalizedAddress = normalizePoolAddress(next.address) ?? previous.address;
  const metadata = {
    ...!isUnknownMetaValue(next.asn) && next.asn ? { asn: next.asn } : {},
    ...!isUnknownMetaValue(next.country) && next.country ? { country: next.country } : {},
    ...next.stack ? { stack: next.stack } : {}
  };
  const merged = mergePoolMetadata({ ...previous, address: normalizedAddress }, metadata);
  return { ...merged, comment: next.comment || previous.comment };
}
__name(mergePoolEntry, "mergePoolEntry");

// app/src/contracts/parse.ts
function parseOk(value) {
  return { ok: true, value };
}
__name(parseOk, "parseOk");
function parseFail(message) {
  return { ok: false, message };
}
__name(parseFail, "parseFail");
function isRecord2(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
__name(isRecord2, "isRecord");
function asRecord(value) {
  return isRecord2(value) ? value : null;
}
__name(asRecord, "asRecord");
function readTrimmedString(value, min, max) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length >= min && trimmed.length <= max ? trimmed : null;
}
__name(readTrimmedString, "readTrimmedString");
function readInteger(value, min, max) {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max ? value : null;
}
__name(readInteger, "readInteger");

// app/src/contracts/config.ts
var PROBE_MODES = ["external-api", "cmliu-check", "socket"];
var MIN_PROBE_TIMEOUT_MS = 500;
var MAX_PROBE_TIMEOUT_MS = 3e4;
var MAX_ENDPOINT_URL_LENGTH = 2048;
var DEFAULT_SOCKET_PROBE_IPV4_URL = "https://ipv4.090227.xyz/";
var DEFAULT_SOCKET_PROBE_IPV6_URL = "https://ipv6.090227.xyz/";
var DEFAULT_SOCKET_READ_LIMIT_BYTES = 65536;
var MIN_SOCKET_READ_LIMIT_BYTES = 1024;
var MAX_SOCKET_READ_LIMIT_BYTES = 262144;
var MAX_SECRET_LENGTH = 512;
var MAX_ZONE_ID_LENGTH = 64;
var MAX_ZONES = 20;
var MAX_TARGETS = 100;
var MAX_TARGET_PORT = 65535;
var MAX_MIN_ACTIVE = 100;
function parseSocketProbeUrl(value) {
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== "https:" || !url.hostname) return null;
    const port = url.port ? Number(url.port) : 443;
    return {
      endpoint: url.hostname,
      hostHeader: port === 443 ? url.hostname : `${url.hostname}:${port}`,
      path: `${url.pathname || "/"}${url.search}`
    };
  } catch {
    return null;
  }
}
__name(parseSocketProbeUrl, "parseSocketProbeUrl");
var SETTINGS_LIMITS = {
  CONCURRENT_CHECKS: { min: 1, max: 128 },
  BACKEND_CONCURRENT_CHECKS: { min: 1, max: 6 },
  CHECK_TIMEOUT: { min: 500, max: 3e4 },
  REMOTE_LOAD_TIMEOUT: { min: 1e3, max: 6e4 },
  DOH_TIMEOUT: { min: 1e3, max: 3e4 },
  DEFAULT_MIN_ACTIVE: { min: 0, max: 100 },
  MAX_TRASH_SIZE: { min: 0, max: 1e5 }
};
var DEFAULT_RUNTIME_SETTINGS = {
  CONCURRENT_CHECKS: 32,
  BACKEND_CONCURRENT_CHECKS: 4,
  CHECK_TIMEOUT: 15e3,
  REMOTE_LOAD_TIMEOUT: 8e3,
  DOH_TIMEOUT: 5e3,
  DEFAULT_MIN_ACTIVE: 3,
  MAX_TRASH_SIZE: 1e3
};
function createDefaultConfig() {
  return {
    apiKey: "",
    zoneId: "",
    zones: [],
    targets: [],
    checkApi: "",
    checkApiBackup: "https://checkapi.dvb.kdns.fr/?candidate=",
    dohApi: "https://cloudflare-dns.com/dns-query",
    authKey: "",
    tgToken: "",
    tgId: "",
    scheduledEnabled: true,
    tgEnabled: true,
    settings: { ...DEFAULT_RUNTIME_SETTINGS },
    projectUrl: "",
    probeMode: "external-api",
    socketProbeIpv4Url: DEFAULT_SOCKET_PROBE_IPV4_URL,
    socketProbeIpv6Url: DEFAULT_SOCKET_PROBE_IPV6_URL,
    socketReadLimitBytes: DEFAULT_SOCKET_READ_LIMIT_BYTES
  };
}
__name(createDefaultConfig, "createDefaultConfig");
function toPublicConfig(config) {
  return {
    zones: config.zones.map(({ name, baseDomain, zoneId, label, apiKey }) => ({
      name,
      baseDomain,
      zoneId,
      label,
      hasApiKey: apiKey.length > 0
    })),
    targets: config.targets,
    zoneId: config.zoneId,
    checkApi: config.checkApi,
    checkApiBackup: config.checkApiBackup,
    dohApi: config.dohApi,
    tgId: config.tgId,
    scheduledEnabled: config.scheduledEnabled,
    tgEnabled: config.tgEnabled,
    settings: config.settings,
    projectUrl: config.projectUrl,
    probeMode: config.probeMode,
    socketProbeIpv4Url: config.socketProbeIpv4Url,
    socketProbeIpv6Url: config.socketProbeIpv6Url,
    socketReadLimitBytes: config.socketReadLimitBytes,
    secrets: {
      apiKey: config.apiKey.length > 0,
      authKey: config.authKey.length > 0,
      tgToken: config.tgToken.length > 0
    }
  };
}
__name(toPublicConfig, "toPublicConfig");
function toProbeConfig(config) {
  const endpoints = [];
  if (config.checkApi.trim()) endpoints.push({ name: "primary", urlTemplate: config.checkApi.trim() });
  if (config.checkApiBackup.trim()) endpoints.push({ name: "backup", urlTemplate: config.checkApiBackup.trim() });
  return {
    primary: config.probeMode === "socket" ? "internal" : "external",
    endpoints,
    fallbackToNext: true,
    timeoutMs: config.settings.CHECK_TIMEOUT,
    ipv4ProbeUrl: config.socketProbeIpv4Url,
    ipv6ProbeUrl: config.socketProbeIpv6Url,
    readLimitBytes: config.socketReadLimitBytes
  };
}
__name(toProbeConfig, "toProbeConfig");
function parseAppConfig(value, previous) {
  const record = asRecord(value);
  if (!record) return parseFail("\u914D\u7F6E\u5FC5\u987B\u662F JSON \u5BF9\u8C61");
  const base = previous ?? createDefaultConfig();
  const settings = parseRuntimeSettings(record.settings ?? base.settings);
  const zones = Array.isArray(record.zones) ? parseZones(record.zones, base.zones) : base.zones;
  const targets = Array.isArray(record.targets) ? parseTargets(record.targets, settings) : base.targets;
  const duplicate = findDuplicate(zones, targets);
  if (duplicate) return parseFail(duplicate);
  const apiKey = zones[0]?.apiKey || text(record.apiKey, base.apiKey, MAX_SECRET_LENGTH);
  const zoneId = zones[0]?.zoneId || text(record.zoneId, base.zoneId, MAX_ZONE_ID_LENGTH);
  const probeMode = PROBE_MODES.includes(record.probeMode) ? record.probeMode : base.probeMode;
  return parseOk({
    apiKey,
    zoneId,
    zones,
    targets,
    checkApi: text(record.checkApi, base.checkApi, MAX_ENDPOINT_URL_LENGTH),
    checkApiBackup: text(record.checkApiBackup, base.checkApiBackup, MAX_ENDPOINT_URL_LENGTH),
    dohApi: text(record.dohApi, base.dohApi, MAX_ENDPOINT_URL_LENGTH),
    authKey: text(record.authKey, base.authKey, MAX_SECRET_LENGTH),
    tgToken: text(record.tgToken, base.tgToken, MAX_SECRET_LENGTH),
    tgId: text(record.tgId, base.tgId, 64),
    scheduledEnabled: booleanValue(record.scheduledEnabled, base.scheduledEnabled),
    tgEnabled: booleanValue(record.tgEnabled, base.tgEnabled),
    settings,
    projectUrl: text(record.projectUrl, base.projectUrl, MAX_ENDPOINT_URL_LENGTH),
    probeMode,
    socketProbeIpv4Url: probeUrl(record.socketProbeIpv4Url, base.socketProbeIpv4Url),
    socketProbeIpv6Url: probeUrl(record.socketProbeIpv6Url, base.socketProbeIpv6Url),
    socketReadLimitBytes: integerValue(
      record.socketReadLimitBytes,
      base.socketReadLimitBytes,
      MIN_SOCKET_READ_LIMIT_BYTES,
      MAX_SOCKET_READ_LIMIT_BYTES
    )
  });
}
__name(parseAppConfig, "parseAppConfig");
function parseRuntimeSettings(value) {
  const raw = asRecord(value) ?? {};
  const result = { ...DEFAULT_RUNTIME_SETTINGS };
  for (const key of Object.keys(SETTINGS_LIMITS)) {
    const limits = SETTINGS_LIMITS[key];
    result[key] = integerValue(raw[key], DEFAULT_RUNTIME_SETTINGS[key], limits.min, limits.max);
  }
  return result;
}
__name(parseRuntimeSettings, "parseRuntimeSettings");
function parseZones(values, previous) {
  return values.slice(0, MAX_ZONES).map((value, index) => normalizeZone(value, previous[index])).filter((zone) => zone !== null);
}
__name(parseZones, "parseZones");
function parseTargets(values, settings) {
  return values.slice(0, MAX_TARGETS).map((item) => normalizeTarget(item, settings)).filter((target) => target !== null);
}
__name(parseTargets, "parseTargets");
function normalizeZone(value, previous) {
  const record = asRecord(value);
  if (!record) return null;
  const baseDomain = text(record.baseDomain, text(record.domain, "", 253), 253).replace(/^\.+|\.+$/g, "");
  const zoneId = text(record.zoneId, "", MAX_ZONE_ID_LENGTH);
  const apiKey = text(record.apiKey, "", MAX_SECRET_LENGTH) || previous?.apiKey || "";
  const label = text(record.label, text(record.name, baseDomain || zoneId || "\u672A\u547D\u540D", 32), 32);
  if (!baseDomain && !zoneId && !apiKey) return null;
  return { name: label, baseDomain, zoneId, apiKey, label };
}
__name(normalizeZone, "normalizeZone");
function normalizeTarget(value, settings) {
  const record = asRecord(value);
  if (!record) return null;
  const mode = String(record.mode ?? "A").trim().toUpperCase() === "TXT" ? "TXT" : "A";
  const prefix = text(record.prefix, "", 63).replace(/^\.+|\.+$/g, "");
  const baseDomain = text(record.baseDomain, "", 253).replace(/^\.+|\.+$/g, "");
  const domain = text(record.domain, buildDomain(prefix, baseDomain), 253).replace(/\.$/, "").toLowerCase();
  if (!domain) return null;
  const rawPort = record.port === void 0 ? "443" : String(record.port).trim();
  const portNumber = Number.parseInt(rawPort, 10);
  const port = mode === "TXT" ? "any" : Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= MAX_TARGET_PORT ? portNumber : 443;
  const countries = normalizeList(record.countries, record.country, normalizeCountry);
  const asns = normalizeList(record.asns, record.asn, normalizeAsn);
  return {
    mode,
    domain,
    baseDomain,
    prefix,
    zoneIndex: readZoneIndex(record.zoneIndex),
    port,
    minActive: integerValue(record.minActive, settings.DEFAULT_MIN_ACTIVE, 0, MAX_MIN_ACTIVE),
    exitFilter: normalizeExitFilter(record.exitFilter),
    country: countries.join(","),
    asn: asns.join(","),
    countries,
    asns,
    enabled: record.enabled !== false
  };
}
__name(normalizeTarget, "normalizeTarget");
function normalizeList(primary, fallback, normalizer) {
  const source = Array.isArray(primary) && primary.length > 0 ? primary : fallback;
  const values = Array.isArray(source) ? source : String(source ?? "").split(/[,;，；\s]+/);
  return [...new Set(values.map((item) => normalizer(String(item).trim())).filter((item) => Boolean(item)))];
}
__name(normalizeList, "normalizeList");
function normalizeExitFilter(value) {
  const textValue = String(value ?? "").trim().toLowerCase().replace(/_/g, "-");
  if (!textValue || ["any", "all", "v4/v6", "v6/v4"].includes(textValue)) return "any";
  if (["v4", "ipv4", "ipv4-only", "only-ipv4"].includes(textValue)) return "v4";
  if (["v6", "ipv6", "ipv6-only", "only-ipv6"].includes(textValue)) return "v6";
  if (["dual", "dual-stack", "both"].includes(textValue)) return "dual";
  return "any";
}
__name(normalizeExitFilter, "normalizeExitFilter");
function findDuplicate(zones, targets) {
  const zoneKeys = /* @__PURE__ */ new Set();
  for (const zone of zones) {
    const key = zone.baseDomain.trim().toLowerCase();
    if (key && zoneKeys.has(key)) return `\u6743\u9650\u914D\u7F6E\u5B58\u5728\u91CD\u590D\u76EE\u6807\u7EF4\u62A4\u57DF\u540D\uFF1A${key}`;
    zoneKeys.add(key);
  }
  const targetKeys = /* @__PURE__ */ new Set();
  for (const target of targets) {
    const key = `${target.domain}|${target.mode}`;
    if (targetKeys.has(key)) return `\u7BA1\u7406\u57DF\u540D\u5B58\u5728\u91CD\u590D\u9879\uFF1A${target.domain} / ${target.mode === "TXT" ? "TXT" : "A/AAAA"}`;
    targetKeys.add(key);
  }
  return "";
}
__name(findDuplicate, "findDuplicate");
function readZoneIndex(value) {
  if (value === void 0 || value === null || value === "") return null;
  const parsed = typeof value === "number" ? value : Number.parseInt(String(value), 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}
__name(readZoneIndex, "readZoneIndex");
function buildDomain(prefix, baseDomain) {
  return prefix ? `${prefix}.${baseDomain}` : baseDomain;
}
__name(buildDomain, "buildDomain");
function text(value, fallback, max) {
  if (value === void 0) return fallback;
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  return trimmed.length <= max ? trimmed : fallback;
}
__name(text, "text");
function integerValue(value, fallback, min, max) {
  const parsed = typeof value === "number" ? value : Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}
__name(integerValue, "integerValue");
function booleanValue(value, fallback) {
  if (value === void 0 || value === null || value === "") return fallback;
  if (typeof value === "boolean") return value;
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on", "enabled"].includes(normalized)) return true;
  if (["0", "false", "no", "off", "disabled"].includes(normalized)) return false;
  return fallback;
}
__name(booleanValue, "booleanValue");
function probeUrl(value, fallback) {
  if (value === void 0) return fallback;
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  if (!trimmed) return "";
  return parseSocketProbeUrl(trimmed) ? trimmed : fallback;
}
__name(probeUrl, "probeUrl");

// app/src/adapters/storage/kv-json.ts
async function readKvJson(kv, key, cacheTtl) {
  const raw = await kv.get(key, { type: "text", cacheTtl });
  if (raw === null) return { status: "missing" };
  if (!raw.trim()) return { status: "invalid", message: "KV \u5185\u5BB9\u4E3A\u7A7A" };
  try {
    return { status: "loaded", value: JSON.parse(raw) };
  } catch {
    return { status: "invalid", message: "KV \u5185\u5BB9\u4E0D\u662F\u6709\u6548 JSON" };
  }
}
__name(readKvJson, "readKvJson");
async function readKvStringRecord(kv, key) {
  const raw = await kv.get(key, { type: "json" }).catch(() => null);
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return {};
  const record = {};
  for (const [field, value] of Object.entries(raw)) {
    if (typeof value === "string" && value.trim()) record[field] = value.trim();
  }
  return record;
}
__name(readKvStringRecord, "readKvStringRecord");

// app/src/adapters/storage/kv-config-repository.ts
var CONFIG_KEY = "app_config";
var KvConfigRepository = class {
  constructor(kv, options = {}) {
    this.kv = kv;
    this.key = options.key ?? CONFIG_KEY;
    this.cacheTtl = options.cacheTtl ?? 60;
  }
  kv;
  static {
    __name(this, "KvConfigRepository");
  }
  key;
  cacheTtl;
  async load(previous) {
    const raw = await readKvJson(this.kv, this.key, this.cacheTtl);
    if (raw.status === "missing") return { status: "missing", source: "kv" };
    if (raw.status === "invalid") return { status: "invalid", source: "kv", message: raw.message };
    const parsed = parseAppConfig(raw.value, previous);
    if (!parsed.ok) return { status: "invalid", source: "kv", message: parsed.message };
    return { status: "loaded", source: "kv", config: parsed.value };
  }
  async save(config) {
    const parsed = parseAppConfig(config);
    if (!parsed.ok) throw new Error(parsed.message);
    await this.kv.put(this.key, JSON.stringify(parsed.value));
  }
};

// app/src/contracts/pool.ts
var POOL_KEY_PREFIX = "ip_pool_";
var DEFAULT_POOL_KEY = "ip_pool_default";
var TRASH_POOL_KEY = "ip_pool_trash";
var POOL_NAMES_KEY = "ip_pool_names";
var POOL_ORDER_KEY = "ip_pool_order";
var DOMAIN_POOL_MAPPING_KEY = "domain_pool_mapping";
var DOMAIN_POOL_ORDER_KEY = "domain_pool_order";
var NUMBERED_POOL_KEY_RE = /^ip_pool_(\d{3})$/;
var MAX_POOL_DISPLAY_NAME_LENGTH = 40;
var MAX_POOL_RESTORE_ITEMS = 1e3;
function isUserPoolKey(value) {
  return value === DEFAULT_POOL_KEY || NUMBERED_POOL_KEY_RE.test(value);
}
__name(isUserPoolKey, "isUserPoolKey");
function isPoolDataKey(value) {
  return isUserPoolKey(value) || value === TRASH_POOL_KEY;
}
__name(isPoolDataKey, "isPoolDataKey");
function formatPoolNumber(value) {
  return String(value).padStart(3, "0");
}
__name(formatPoolNumber, "formatPoolNumber");
function getNumberedPoolKey(value) {
  return `${POOL_KEY_PREFIX}${formatPoolNumber(value)}`;
}
__name(getNumberedPoolKey, "getNumberedPoolKey");
function getPoolFixedName(poolKey) {
  if (poolKey === DEFAULT_POOL_KEY) return "\u9ED8\u8BA4\u6C60";
  if (poolKey === TRASH_POOL_KEY) return "\u5783\u573E\u6876";
  const numbered = NUMBERED_POOL_KEY_RE.exec(poolKey);
  return numbered ? `\u6C60 ${numbered[1]}` : poolKey;
}
__name(getPoolFixedName, "getPoolFixedName");

// app/src/domain/domain-binding.ts
function bindingKey(target) {
  return `${normalizeBindingDomain(target.domain)}|${target.mode}`;
}
__name(bindingKey, "bindingKey");
function normalizeBindingKey(key) {
  const [domain, ...rest] = String(key ?? "").split("|");
  const normalizedDomain = normalizeBindingDomain(domain ?? "");
  if (!normalizedDomain) return "";
  const mode = rest.join("|").trim().toUpperCase();
  return mode === "A" || mode === "TXT" ? `${normalizedDomain}|${mode}` : normalizedDomain;
}
__name(normalizeBindingKey, "normalizeBindingKey");
function resolvePoolKey(mapping, target) {
  const key = bindingKey(target);
  const mapped = mapping[key] ?? mapping[key.toLowerCase()] ?? mapping[key.slice(0, key.indexOf("|"))];
  return mapped && isUserPoolKey(mapped) ? mapped : DEFAULT_POOL_KEY;
}
__name(resolvePoolKey, "resolvePoolKey");
function sortByBindingOrder(items, order) {
  if (order.length === 0) return items;
  const rank = new Map(order.map((key, index) => [key, index]));
  return [...items].sort((left, right) => (rank.get(left.key) ?? order.length) - (rank.get(right.key) ?? order.length));
}
__name(sortByBindingOrder, "sortByBindingOrder");
function normalizeBindingDomain(domain) {
  return String(domain ?? "").trim().replace(/\.$/, "").toLowerCase();
}
__name(normalizeBindingDomain, "normalizeBindingDomain");

// app/src/adapters/storage/kv-domain-binding-repository.ts
var KvDomainBindingRepository = class {
  constructor(kv) {
    this.kv = kv;
  }
  kv;
  static {
    __name(this, "KvDomainBindingRepository");
  }
  async read() {
    return await readKvStringRecord(this.kv, DOMAIN_POOL_MAPPING_KEY);
  }
  async write(mapping) {
    const sanitized = {};
    for (const [rawKey, rawPoolKey] of Object.entries(mapping)) {
      const key = normalizeBindingKey(rawKey);
      const poolKey = rawPoolKey.trim();
      if (key && isUserPoolKey(poolKey)) sanitized[key] = poolKey;
    }
    await this.kv.put(DOMAIN_POOL_MAPPING_KEY, JSON.stringify(sanitized));
  }
  async readOrder() {
    const raw = await this.kv.get(DOMAIN_POOL_ORDER_KEY, { type: "json" }).catch(() => null);
    return toBindingOrder(raw);
  }
  async writeOrder(order) {
    await this.kv.put(DOMAIN_POOL_ORDER_KEY, JSON.stringify(toBindingOrder(order)));
  }
};
function toBindingOrder(value) {
  if (!Array.isArray(value)) return [];
  const order = [];
  for (const item of value) {
    if (typeof item !== "string") continue;
    const key = normalizeBindingKey(item);
    if (key && !order.includes(key)) order.push(key);
  }
  return order;
}
__name(toBindingOrder, "toBindingOrder");

// app/src/domain/managed-target.ts
function normalizeManagedTarget(input) {
  const mode = String(input.mode ?? "A").trim().toUpperCase() === "TXT" ? "TXT" : "A";
  const domain = String(input.domain ?? "").trim().replace(/\.$/, "").toLowerCase();
  if (!domain) return null;
  const parsedPort = Number.parseInt(String(input.port ?? 443), 10);
  const port = mode === "TXT" ? null : Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535 ? parsedPort : 443;
  const parsedMinActive = Number.parseInt(String(input.minActive ?? 1), 10);
  return {
    mode,
    domain,
    port,
    minActive: Number.isFinite(parsedMinActive) ? Math.max(0, parsedMinActive) : 1,
    exitFilter: normalizeExitFilter2(input.exitFilter),
    countries: normalizeList2(input.countries, normalizeCountry),
    asns: normalizeList2(input.asns, normalizeAsn)
  };
}
__name(normalizeManagedTarget, "normalizeManagedTarget");
function normalizeExitFilter2(value) {
  const text3 = String(value ?? "").trim().toLowerCase().replace(/_/g, "-");
  if (!text3 || ["any", "all", "v4/v6", "v6/v4"].includes(text3)) return "any";
  if (["v4", "ipv4", "ipv4-only", "only-ipv4"].includes(text3)) return "v4";
  if (["v6", "ipv6", "ipv6-only", "only-ipv6"].includes(text3)) return "v6";
  if (["dual", "dual-stack", "both"].includes(text3)) return "dual";
  return "any";
}
__name(normalizeExitFilter2, "normalizeExitFilter");
function probeMatchesTarget(result, target) {
  if (result.status !== "alive") return false;
  if (!exitFilterMatches(result.exitFamily, target.exitFilter)) return false;
  if (target.countries.length && !intersects(target.countries, splitMetadata(result.exits.map((exit) => exit.country)))) return false;
  if (target.asns.length && !intersects(target.asns, splitMetadata(result.exits.map((exit) => exit.asn)).map((asn) => normalizeAsn(asn) ?? ""))) return false;
  return true;
}
__name(probeMatchesTarget, "probeMatchesTarget");
function storedEntryMatchesTarget(entry, target) {
  if (target.countries.length && !isUnknownMetaValue(entry.country)) {
    if (!intersects(target.countries, splitMetadata([entry.country]))) return false;
  }
  if (target.asns.length && !isUnknownMetaValue(entry.asn)) {
    if (!intersects(target.asns, splitMetadata([entry.asn]).map((asn) => normalizeAsn(asn) ?? ""))) return false;
  }
  if (target.exitFilter !== "any" && !isUnknownMetaValue(entry.stack)) {
    if (!exitFilterMatches(entry.stack ?? "unknown", target.exitFilter)) return false;
  }
  return true;
}
__name(storedEntryMatchesTarget, "storedEntryMatchesTarget");
function selectCandidateEntries(entries, target, excludedAddresses) {
  return entries.filter((entry) => {
    const address = parseProxyTarget(entry.address);
    if (!address) return false;
    if (target.mode === "A" && (!target.port || address.port !== target.port)) return false;
    if (!storedEntryMatchesTarget(entry, target)) return false;
    return !excludedAddresses.has(address.key);
  });
}
__name(selectCandidateEntries, "selectCandidateEntries");
function activeValueForEntry(entry, target) {
  const parsed = parseProxyTarget(entry.address);
  if (!parsed) return entry.address;
  return target.mode === "A" ? parsed.host : parsed.authority;
}
__name(activeValueForEntry, "activeValueForEntry");
function normalizeList2(value, normalizer) {
  const source = Array.isArray(value) ? value : String(value ?? "").split(/[,;，；\s]+/);
  return [...new Set(source.map((item) => normalizer(String(item).trim())).filter((item) => Boolean(item)))];
}
__name(normalizeList2, "normalizeList");
function exitFilterMatches(family, filter) {
  if (filter === "any") return true;
  if (filter === "v4") return family === "v4" || family === "ipv4";
  if (filter === "v6") return family === "v6" || family === "ipv6";
  return family === "v4/v6" || family === "dual";
}
__name(exitFilterMatches, "exitFilterMatches");
function splitMetadata(values) {
  return values.flatMap((value) => String(value ?? "").split(/[\/,;，；\s]+/).map((item) => item.trim()).filter(Boolean));
}
__name(splitMetadata, "splitMetadata");
function intersects(required, actual) {
  const actualSet = new Set(actual.map((item) => item.toUpperCase()));
  return required.some((item) => actualSet.has(item.toUpperCase()));
}
__name(intersects, "intersects");

// app/src/adapters/storage/kv-maintenance-source.ts
var KvMaintenanceSource = class {
  constructor(kv) {
    this.kv = kv;
  }
  kv;
  static {
    __name(this, "KvMaintenanceSource");
  }
  async load() {
    const [configResult, poolMapping, poolNames] = await Promise.all([
      readKvJson(this.kv, CONFIG_KEY, 60),
      readKvStringRecord(this.kv, DOMAIN_POOL_MAPPING_KEY),
      readKvStringRecord(this.kv, POOL_NAMES_KEY)
    ]);
    if (configResult.status === "invalid") throw new Error(`\u914D\u7F6E\u65E0\u6CD5\u8BFB\u53D6\uFF1A${configResult.message}`);
    const record = asRecord2(configResult.status === "loaded" ? configResult.value : null);
    return {
      zones: toArray(record?.zones).map(normalizeZone2).filter(isPresent),
      targets: toArray(record?.targets).map(normalizeTarget2).filter(isPresent),
      poolMapping,
      poolNames
    };
  }
};
function normalizeZone2(value) {
  const record = asRecord2(value);
  if (!record) return null;
  const baseDomain = text2(record.baseDomain) || text2(record.domain);
  const zoneId = text2(record.zoneId);
  const apiToken = text2(record.apiKey);
  if (!baseDomain && !zoneId && !apiToken) return null;
  return { zoneId, apiToken };
}
__name(normalizeZone2, "normalizeZone");
function normalizeTarget2(value) {
  const record = asRecord2(value);
  if (!record) return null;
  const domain = text2(record.domain) || buildDomain2(text2(record.prefix), text2(record.baseDomain));
  const target = normalizeManagedTarget({
    domain,
    mode: text2(record.mode),
    port: scalar(record.port),
    minActive: scalar(record.minActive),
    exitFilter: text2(record.exitFilter),
    countries: preferList(record.countries, record.country),
    asns: preferList(record.asns, record.asn)
  });
  if (!target) return null;
  return { target, zoneIndex: readZoneIndex2(record.zoneIndex), enabled: record.enabled !== false };
}
__name(normalizeTarget2, "normalizeTarget");
function buildDomain2(prefix, baseDomain) {
  const cleanPrefix = prefix.replace(/^\.+|\.+$/g, "");
  const cleanBase = baseDomain.replace(/^\.+|\.+$/g, "");
  if (!cleanBase) return "";
  return cleanPrefix ? `${cleanPrefix}.${cleanBase}` : cleanBase;
}
__name(buildDomain2, "buildDomain");
function readZoneIndex2(value) {
  const parsed = typeof value === "number" ? value : Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}
__name(readZoneIndex2, "readZoneIndex");
function preferList(primary, fallback) {
  if (Array.isArray(primary) && primary.length > 0) return primary.map((item) => String(item));
  const primaryText = text2(primary);
  if (primaryText) return primaryText;
  return text2(fallback) || void 0;
}
__name(preferList, "preferList");
function toArray(value) {
  return Array.isArray(value) ? value : [];
}
__name(toArray, "toArray");
function text2(value) {
  return typeof value === "string" ? value.trim() : "";
}
__name(text2, "text");
function scalar(value) {
  return typeof value === "string" || typeof value === "number" ? value : void 0;
}
__name(scalar, "scalar");
function asRecord2(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : null;
}
__name(asRecord2, "asRecord");
function isPresent(value) {
  return value !== null;
}
__name(isPresent, "isPresent");

// app/src/util/concurrency.ts
async function mapWithConcurrency(items, limit, task) {
  const results = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(Math.max(1, limit), items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      const item = items[index];
      if (item !== void 0) results[index] = await task(item, index);
    }
  });
  await Promise.all(workers);
  return results;
}
__name(mapWithConcurrency, "mapWithConcurrency");

// app/src/adapters/storage/kv-pool-catalog.ts
var KvPoolCatalog = class {
  constructor(kv) {
    this.kv = kv;
  }
  kv;
  static {
    __name(this, "KvPoolCatalog");
  }
  async list() {
    const [names, order, keys] = await Promise.all([
      this.readNames(),
      this.readOrder(),
      this.listPoolKeys()
    ]);
    const normalizedOrder = normalizeOrder(order, keys);
    const summaries = await mapWithConcurrency(normalizedOrder, 4, async (key) => {
      const content = await this.read(key);
      return {
        key,
        name: names[key] ?? getPoolFixedName(key),
        count: parsePoolText(content).filter((line) => line.entry !== null).length
      };
    });
    return summaries;
  }
  async read(poolKey) {
    return await this.kv.get(poolKey, { type: "text" }) ?? "";
  }
  async write(poolKey, content) {
    await this.kv.put(poolKey, content);
  }
  async create(displayName) {
    const [rawKeys, names, rawOrder] = await Promise.all([
      this.listPoolKeys(),
      this.readNames(),
      this.readOrder()
    ]);
    const keys = toStringArray(rawKeys);
    const savedOrder = rawOrder ? toStringArray(rawOrder) : null;
    let nextIndex = 1;
    for (const key of keys) {
      const match = NUMBERED_POOL_KEY_RE.exec(key);
      if (match) nextIndex = Math.max(nextIndex, Number(match[1]) + 1);
    }
    if (nextIndex > 999) throw new Error("\u7F16\u53F7 IP \u6C60\u6570\u91CF\u5DF2\u8FBE\u4E0A\u9650");
    const poolKey = getNumberedPoolKey(nextIndex);
    await this.kv.put(poolKey, "");
    if (displayName !== getPoolFixedName(poolKey)) {
      await this.writeNames({ ...names, [poolKey]: displayName });
    }
    if (savedOrder) await this.writeOrder(normalizeOrder([...savedOrder, poolKey], [...keys, poolKey]));
    return { key: poolKey, name: displayName, count: 0 };
  }
  async rename(poolKey, displayName) {
    const names = await this.readNames();
    if (displayName === getPoolFixedName(poolKey)) delete names[poolKey];
    else names[poolKey] = displayName;
    await this.writeNames(names);
  }
  async exists(poolKey) {
    if (poolKey === DEFAULT_POOL_KEY || poolKey === TRASH_POOL_KEY) return true;
    return await this.kv.get(poolKey, { type: "text" }) !== null;
  }
  async remove(poolKey) {
    await this.kv.delete(poolKey);
    const [savedOrder, names, mapping] = await Promise.all([
      this.readOrder(),
      this.readNames(),
      this.readMapping()
    ]);
    if (savedOrder?.includes(poolKey)) {
      await this.writeOrder(savedOrder.filter((key) => key !== poolKey));
    }
    if (Object.hasOwn(names, poolKey)) {
      delete names[poolKey];
      await this.writeNames(names);
    }
    let mappingChanged = false;
    for (const [domain, boundPool] of Object.entries(mapping)) {
      if (boundPool === poolKey) {
        mapping[domain] = DEFAULT_POOL_KEY;
        mappingChanged = true;
      }
    }
    if (mappingChanged) await this.kv.put(DOMAIN_POOL_MAPPING_KEY, JSON.stringify(mapping));
  }
  async saveOrder(order) {
    const keys = await this.listPoolKeys();
    await this.writeOrder(normalizeOrder(order, keys));
  }
  async readNames() {
    return await readKvStringRecord(this.kv, POOL_NAMES_KEY);
  }
  async readOrder() {
    const raw = await this.kv.get(POOL_ORDER_KEY, { type: "json" }).catch(() => null);
    return Array.isArray(raw) ? raw.filter((value) => typeof value === "string") : null;
  }
  async readMapping() {
    return await readKvStringRecord(this.kv, DOMAIN_POOL_MAPPING_KEY);
  }
  async writeNames(names) {
    await this.kv.put(POOL_NAMES_KEY, JSON.stringify(names));
  }
  async writeOrder(order) {
    await this.kv.put(POOL_ORDER_KEY, JSON.stringify(order));
  }
  async listPoolKeys() {
    const keys = /* @__PURE__ */ new Set([DEFAULT_POOL_KEY, TRASH_POOL_KEY]);
    let cursor;
    do {
      const page = await this.kv.list({ prefix: POOL_KEY_PREFIX, ...cursor ? { cursor } : {} });
      for (const key of page.keys) if (isPoolDataKey(key.name)) keys.add(key.name);
      cursor = page.list_complete ? void 0 : page.cursor;
    } while (cursor);
    return [...keys];
  }
};
function toStringArray(value) {
  return Array.isArray(value) ? value.filter((entry) => typeof entry === "string") : [];
}
__name(toStringArray, "toStringArray");
function normalizeOrder(saved, actualKeys) {
  const actual = [...new Set(actualKeys.filter(isPoolDataKey))];
  const actualSet = new Set(actual);
  const fallback = [...actual].sort(comparePoolKeys);
  const normalized = [];
  for (const key of saved ?? fallback) {
    if (actualSet.has(key) && !normalized.includes(key)) normalized.push(key);
  }
  for (const key of fallback) if (!normalized.includes(key)) normalized.push(key);
  const middle = normalized.filter((key) => key !== DEFAULT_POOL_KEY && key !== TRASH_POOL_KEY);
  return [
    ...actualSet.has(DEFAULT_POOL_KEY) ? [DEFAULT_POOL_KEY] : [],
    ...middle,
    ...actualSet.has(TRASH_POOL_KEY) ? [TRASH_POOL_KEY] : []
  ];
}
__name(normalizeOrder, "normalizeOrder");
function comparePoolKeys(left, right) {
  const rank = /* @__PURE__ */ __name((key) => key === DEFAULT_POOL_KEY ? 0 : key === TRASH_POOL_KEY ? 2 : 1, "rank");
  const difference = rank(left) - rank(right);
  if (difference !== 0) return difference;
  const leftNumber = NUMBERED_POOL_KEY_RE.exec(left);
  const rightNumber = NUMBERED_POOL_KEY_RE.exec(right);
  if (leftNumber && rightNumber) return Number(leftNumber[1]) - Number(rightNumber[1]);
  return left.localeCompare(right, "zh-CN", { numeric: true });
}
__name(comparePoolKeys, "comparePoolKeys");

// app/src/util/time.ts
function formatBeijingTimestamp(date) {
  return new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(date);
}
__name(formatBeijingTimestamp, "formatBeijingTimestamp");

// app/src/adapters/storage/kv-pool-repository.ts
var KvPoolRepository = class {
  constructor(kv, options = {}) {
    this.kv = kv;
    this.trashKey = options.trashKey ?? TRASH_POOL_KEY;
    this.maxTrashSize = options.maxTrashSize ?? 1e3;
    this.now = options.now ?? (() => /* @__PURE__ */ new Date());
  }
  kv;
  static {
    __name(this, "KvPoolRepository");
  }
  trashKey;
  maxTrashSize;
  now;
  async load(poolKey) {
    return await this.kv.get(poolKey, { type: "text" }) ?? "";
  }
  async save(poolKey, content) {
    await this.kv.put(poolKey, content);
  }
  async addToTrash(entries) {
    if (entries.length === 0) return;
    const existing = (await this.load(this.trashKey)).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const seen = new Set(existing.map(extractPoolAddressKey).map(canonicalAddressKey));
    const timestamp = formatBeijingTimestamp(this.now());
    for (const item of entries) {
      const key = canonicalAddressKey(extractPoolAddressKey(item.entryLine));
      if (!key || seen.has(key)) continue;
      const parsed = parsePoolEntry(item.entryLine);
      const cleanEntry = parsed ? formatPoolEntry({ ...parsed, comment: "" }) : item.entryLine.trim();
      if (!cleanEntry) continue;
      existing.push(`${cleanEntry} # ${item.reason} ${timestamp}${item.poolKey ? ` \u6765\u81EA ${item.poolKey}` : ""}`);
      seen.add(key);
    }
    const limited = this.maxTrashSize > 0 ? existing.slice(-this.maxTrashSize) : [];
    await this.kv.put(this.trashKey, limited.join("\n"));
  }
};

// app/src/application/check-pool.ts
var MAX_BATCH_TARGETS = 200;
var CheckPoolText = class {
  constructor(checkProxy, concurrency = 8) {
    this.checkProxy = checkProxy;
    this.concurrency = Math.max(1, Math.min(16, concurrency));
  }
  checkProxy;
  static {
    __name(this, "CheckPoolText");
  }
  concurrency;
  async execute(text3, context = {}) {
    const { entries, invalid } = collectEntries(text3);
    const items = await mapWithConcurrency(entries, this.concurrency, async (entry) => {
      const target = parseProxyTarget(entry.address) ?? parseProxyTarget(entry.address, 443);
      const address = target?.authority ?? entry.address;
      const result = await this.checkProxy.execute(address, context);
      return { address, entry: updatePoolEntryFromProbe(entry, result), result };
    });
    return {
      total: items.length,
      alive: items.filter((item) => item.result.status === "alive").length,
      dead: items.filter((item) => item.result.status === "dead").length,
      unknown: items.filter((item) => item.result.status === "unknown").length,
      invalid,
      items
    };
  }
};
function collectEntries(text3) {
  const entries = [];
  const invalid = [];
  const seen = /* @__PURE__ */ new Set();
  for (const line of parsePoolText(text3)) {
    if (!line.raw.trim()) continue;
    if (!line.entry) {
      invalid.push(line.raw.trim());
      continue;
    }
    if (entries.length >= MAX_BATCH_TARGETS) break;
    const target = parseProxyTarget(line.entry.address);
    if (!target) {
      invalid.push(line.entry.address);
      continue;
    }
    if (seen.has(target.key)) continue;
    seen.add(target.key);
    entries.push(line.entry);
  }
  return { entries, invalid };
}
__name(collectEntries, "collectEntries");

// app/src/domain/probe-result.ts
function alive(target, details = {}) {
  return withOptionalDetails({ status: "alive", target, exitFamily: details.exitFamily ?? "unknown" }, details);
}
__name(alive, "alive");
function dead(target, details = {}) {
  return withOptionalDetails({ status: "dead", target, exitFamily: "unknown" }, details);
}
__name(dead, "dead");
function unknown(target, code, message, details = {}) {
  return withOptionalDetails({ status: "unknown", target, exitFamily: "unknown", code, message }, details);
}
__name(unknown, "unknown");
var NON_PROBE_ERROR_CODES = /* @__PURE__ */ new Set(["NOT_PROBED", "INVALID_DNS_VALUE"]);
function isProbeErrorResult(result) {
  return result.status === "unknown" && !NON_PROBE_ERROR_CODES.has(result.code ?? "");
}
__name(isProbeErrorResult, "isProbeErrorResult");
function exitFamilyFromIp(ip) {
  if (!ip) return "unknown";
  if (looksLikeIpv4(ip)) return "ipv4";
  if (ip.includes(":")) return "ipv6";
  return "unknown";
}
__name(exitFamilyFromIp, "exitFamilyFromIp");
function withOptionalDetails(base, details) {
  return {
    ...base,
    exits: details.exits ? [...details.exits] : [],
    ...details.endpoint ? { endpoint: details.endpoint } : {},
    ...details.exitIp ? { exitIp: details.exitIp } : {},
    ...typeof details.latencyMs === "number" ? { latencyMs: details.latencyMs } : {},
    ...details.code ? { code: details.code } : {},
    ...details.message ? { message: details.message } : {}
  };
}
__name(withOptionalDetails, "withOptionalDetails");
function looksLikeIpv4(value) {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return false;
  return value.split(".").every((part) => Number(part) <= 255);
}
__name(looksLikeIpv4, "looksLikeIpv4");

// app/src/application/check-proxy.ts
var CheckProxy = class {
  constructor(probeAdapter) {
    this.probeAdapter = probeAdapter;
  }
  probeAdapter;
  static {
    __name(this, "CheckProxy");
  }
  async execute(input, context = {}) {
    const target = parseProxyTarget(input);
    if (!target) {
      return unknown(null, "INVALID_TARGET", "\u8BF7\u8F93\u5165\u6709\u6548\u7684 IP\u3001\u57DF\u540D\u548C\u53EF\u9009\u7AEF\u53E3");
    }
    return this.probeAdapter.probe(target, context);
  }
};

// app/src/application/config-service.ts
var ConfigService = class {
  constructor(options) {
    this.options = options;
  }
  options;
  static {
    __name(this, "ConfigService");
  }
  async resolve() {
    const result = this.options.repository ? await loadSafely(() => this.options.repository.load(this.options.envConfig)) : missing();
    if (result.status === "loaded") return { config: result.config, source: "kv" };
    return {
      config: this.options.envConfig,
      source: "env",
      ...result.status === "invalid" ? { notice: `KV \u914D\u7F6E\u65E0\u6CD5\u8BFB\u53D6\uFF0C\u5DF2\u4F7F\u7528\u73AF\u5883\u53D8\u91CF\uFF1A${result.message}` } : {}
    };
  }
  async save(config) {
    if (!this.options.repository) throw new Error("config repository is not configured");
    await this.options.repository.save(config);
  }
};
function missing() {
  return { status: "missing", source: "kv" };
}
__name(missing, "missing");
async function loadSafely(load) {
  try {
    return await load();
  } catch (error) {
    return {
      status: "invalid",
      source: "kv",
      message: error instanceof Error ? error.message : "\u8BFB\u53D6\u914D\u7F6E\u5931\u8D25"
    };
  }
}
__name(loadSafely, "loadSafely");

// app/src/application/domain-bindings.ts
var DomainBindingsInputError = class extends Error {
  static {
    __name(this, "DomainBindingsInputError");
  }
  constructor(message) {
    super(message);
    this.name = "DomainBindingsInputError";
  }
};
var DomainBindings = class {
  constructor(source, repository) {
    this.source = source;
    this.repository = repository;
  }
  source;
  repository;
  static {
    __name(this, "DomainBindings");
  }
  async list() {
    const data = await this.source.load();
    const mapping = data.poolMapping;
    const items = data.targets.map(({ target, enabled }) => {
      const poolKey = resolvePoolKey(mapping, target);
      return {
        key: bindingKey(target),
        domain: target.domain,
        mode: target.mode,
        poolKey,
        poolName: data.poolNames[poolKey] || getPoolFixedName(poolKey),
        enabled
      };
    });
    return { items: sortByBindingOrder(items, await this.repository.readOrder()) };
  }
  async save(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new DomainBindingsInputError("\u7ED1\u5B9A\u6570\u636E\u683C\u5F0F\u65E0\u6548");
    }
    const allowed = new Set((await this.source.load()).targets.map(({ target }) => bindingKey(target)));
    const mapping = { ...await this.repository.read() };
    for (const [rawKey, rawPoolKey] of Object.entries(value)) {
      const key = normalizeBindingKey(rawKey);
      if (!key || !allowed.has(key)) continue;
      const poolKey = typeof rawPoolKey === "string" ? rawPoolKey.trim() : "";
      if (!isUserPoolKey(poolKey)) throw new DomainBindingsInputError(`IP \u6C60 key \u65E0\u6548\uFF1A${key}`);
      mapping[key] = poolKey;
    }
    await this.repository.write(mapping);
  }
  /** 整体保存显示顺序：提交的 key 必须与实际目标集合一致，避免面板拿旧列表覆盖。 */
  async saveOrder(value) {
    if (!Array.isArray(value)) throw new DomainBindingsInputError("\u6392\u5E8F\u6570\u636E\u683C\u5F0F\u65E0\u6548");
    const actual = (await this.source.load()).targets.map(({ target }) => bindingKey(target));
    const actualSet = new Set(actual);
    const submitted = [...new Set(value.map((item) => typeof item === "string" ? item.trim() : "").filter(Boolean))];
    if (submitted.length !== actualSet.size || submitted.some((key) => !actualSet.has(key))) {
      throw new DomainBindingsInputError("\u7BA1\u7406\u57DF\u540D\u5217\u8868\u5DF2\u53D8\u5316\uFF0C\u8BF7\u5237\u65B0\u540E\u91CD\u8BD5");
    }
    await this.repository.writeOrder(submitted);
  }
};

// app/src/domain/maintenance.ts
function decideCurrentResult(result, target) {
  if (result.status === "unknown") return "keep-unknown";
  if (result.status === "dead") return "remove-dead";
  return probeMatchesTarget(result, target) ? "active" : "remove-mismatch";
}
__name(decideCurrentResult, "decideCurrentResult");
function buildMaintenancePlan(input) {
  const originalPoolText = input.poolText;
  let poolLines = parsePoolText(originalPoolText);
  const trash = [];
  const current = input.current.map((item) => ({
    item,
    decision: decideCurrentResult(item.result, input.target)
  }));
  const retained = current.filter(({ decision }) => decision === "active" || decision === "keep-unknown");
  const additions = [];
  let activeCount = current.filter(({ decision }) => decision === "active").length;
  const updatePoolMetadata = /* @__PURE__ */ __name((address, result) => {
    if (result.status !== "alive") return;
    const key = canonicalAddressKey(address);
    poolLines = poolLines.map((line) => refreshLine(line, key, result));
  }, "updatePoolMetadata");
  const removePoolEntry = /* @__PURE__ */ __name((address, reason, alwaysTrash) => {
    const key = canonicalAddressKey(address);
    let matched = false;
    const next = [];
    for (const line of poolLines) {
      if (line.entry && canonicalAddressKey(line.entry.address) === key) {
        if (!matched) trash.push({ entryLine: line.raw, reason });
        matched = true;
        continue;
      }
      next.push(line);
    }
    poolLines = next;
    if (!matched && alwaysTrash) trash.push({ entryLine: address, reason });
  }, "removePoolEntry");
  for (const { item, decision } of current) {
    if (decision === "active") {
      updatePoolMetadata(item.address, item.result);
    } else if (decision === "remove-mismatch") {
      updatePoolMetadata(item.address, item.result);
    } else if (decision === "remove-dead") {
      removePoolEntry(item.address, "\u7EF4\u62A4\u5931\u6548", true);
    }
  }
  for (const candidate of input.candidates) {
    if (activeCount >= input.target.minActive) break;
    if (candidate.result.status === "alive" && probeMatchesTarget(candidate.result, input.target)) {
      additions.push(candidate);
      activeCount += 1;
      updatePoolMetadata(candidate.address, candidate.result);
      continue;
    }
    if (candidate.result.status === "alive") {
      updatePoolMetadata(candidate.address, candidate.result);
      continue;
    }
    if (candidate.result.status === "dead") {
      removePoolEntry(candidate.address, "\u7EF4\u62A4\u5931\u6548", false);
    }
  }
  const retainedValues = uniqueNonEmpty(retained.map(({ item }) => item.value));
  const dnsValues = uniqueNonEmpty([...retainedValues, ...additions.map((candidate) => candidate.value)]);
  const nextPoolText = serializePoolText(poolLines);
  return {
    target: input.target,
    current,
    additions,
    retainedValues,
    dnsValues,
    nextPoolText,
    poolChanged: nextPoolText !== originalPoolText,
    trash,
    activeCount,
    exhausted: activeCount < input.target.minActive
  };
}
__name(buildMaintenancePlan, "buildMaintenancePlan");
function refreshLine(line, addressKey, result) {
  if (!line.entry || canonicalAddressKey(line.entry.address) !== addressKey) return line;
  const refreshed = updatePoolEntryFromProbe(line.entry, result);
  const raw = formatPoolEntry(refreshed);
  return raw === line.raw ? line : { raw, entry: refreshed };
}
__name(refreshLine, "refreshLine");
function uniqueNonEmpty(values) {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
__name(uniqueNonEmpty, "uniqueNonEmpty");

// app/src/application/maintain-managed-target.ts
var MaintainManagedTarget = class {
  constructor(dependencies) {
    this.dependencies = dependencies;
    this.concurrency = Math.max(1, Math.min(8, dependencies.concurrency ?? 4));
  }
  dependencies;
  static {
    __name(this, "MaintainManagedTarget");
  }
  concurrency;
  async execute(command) {
    const poolText = await this.dependencies.pools.load(command.poolKey);
    const current = await this.probeCurrentRecords(command);
    const currentDecisions = current.map((item) => ({
      item,
      decision: decideCurrentResult(item.result, command.target)
    }));
    const excludedAddresses = new Set(
      currentDecisions.filter(({ decision }) => decision !== "remove-dead" && decision !== "remove-mismatch").map(({ item }) => canonicalAddressKey(item.address))
    );
    const activeCount = currentDecisions.filter(({ decision }) => decision === "active").length;
    const candidates = selectCandidateEntries(
      parsePoolEntries(poolText),
      command.target,
      excludedAddresses
    );
    const probedCandidates = await this.probeCandidatesUntilTarget(command.target, candidates, activeCount);
    const plan = buildMaintenancePlan({ target: command.target, current, candidates: probedCandidates, poolText });
    const probeErrors = current.filter((item) => isProbeErrorResult(item.result)).length + probedCandidates.filter((item) => isProbeErrorResult(item.result)).length;
    const errors = [];
    const dnsResult = await this.applyDnsChanges(command, plan, errors);
    if (plan.poolChanged) {
      try {
        await this.dependencies.pools.save(command.poolKey, plan.nextPoolText);
      } catch {
        errors.push("\u4FDD\u5B58 IP \u6C60\u5931\u8D25");
      }
    }
    if (plan.trash.length > 0) {
      try {
        await this.dependencies.pools.addToTrash(
          plan.trash.map((item) => ({ ...item, poolKey: command.poolKey }))
        );
      } catch {
        errors.push("\u5199\u5165\u5783\u573E\u6876\u5931\u8D25");
      }
    }
    return {
      target: command.target,
      poolKey: command.poolKey,
      plan,
      deleted: dnsResult.deleted,
      added: dnsResult.added,
      dnsUpdated: dnsResult.updated,
      probeErrors,
      errors
    };
  }
  async probeCurrentRecords(command) {
    if (command.target.mode === "A") {
      const records2 = await this.dependencies.dns.listAddressRecords(command.zone, command.target.domain);
      const items2 = records2.map((record2) => currentItemFromAddressRecord(record2, command.target)).filter(isPresent2);
      return await mapWithConcurrency(items2, this.concurrency, async (item) => ({
        ...item,
        result: await probeSafely(this.dependencies.probe, item, command.target)
      }));
    }
    const records = await this.dependencies.dns.listTxtRecords(command.zone, command.target.domain);
    const record = records[0];
    if (!record) return [];
    const items = parseTxtAddresses(record.content).map((address) => currentItemFromTxtAddress(record, address, command.target)).filter(isPresent2);
    return await mapWithConcurrency(items, this.concurrency, async (item) => ({
      ...item,
      result: await probeSafely(this.dependencies.probe, item, command.target)
    }));
  }
  async probeCandidatesUntilTarget(target, candidates, currentActiveCount) {
    const results = [];
    let activeCount = currentActiveCount;
    for (const entry of candidates) {
      if (activeCount >= target.minActive) break;
      const parsed = parseProxyTarget(entry.address, target.port ?? 443);
      if (!parsed) continue;
      const address = target.mode === "A" && target.port ? formatProxyAuthority(parsed.host, target.port) : parsed.authority;
      const item = {
        entry,
        address,
        value: activeValueForEntry(entry, target)
      };
      const result = await probeSafely(this.dependencies.probe, item, target);
      results.push({ ...item, result });
      if (result.status === "alive" && resultMatchesTarget(result, target)) activeCount += 1;
    }
    return results;
  }
  async applyDnsChanges(command, plan, errors) {
    if (command.target.mode === "A") {
      let deleted = 0;
      let added = 0;
      for (const { item, decision } of plan.current) {
        if (decision !== "remove-dead" && decision !== "remove-mismatch" || !item.recordId) continue;
        try {
          await this.dependencies.dns.deleteRecord(command.zone, item.recordId);
          deleted += 1;
        } catch {
          errors.push(`\u5220\u9664 DNS \u8BB0\u5F55\u5931\u8D25: ${item.value}`);
        }
      }
      for (const candidate of plan.additions) {
        try {
          await this.dependencies.dns.addAddressRecord(
            command.zone,
            command.target.domain,
            candidate.value,
            dnsRecordTypeForHost(candidate.value)
          );
          added += 1;
        } catch {
          errors.push(`\u6DFB\u52A0 DNS \u8BB0\u5F55\u5931\u8D25: ${candidate.value}`);
        }
      }
      return { deleted, added, updated: deleted > 0 || added > 0 };
    }
    const original = uniqueValues(plan.current.map(({ item }) => item.value));
    if (sameValues(original, plan.dnsValues)) return { deleted: 0, added: 0, updated: false };
    try {
      if (plan.dnsValues.length === 0) {
        const recordId2 = plan.current.find(({ item }) => item.recordId)?.item.recordId;
        if (recordId2) await this.dependencies.dns.deleteRecord(command.zone, recordId2);
        return { deleted: recordId2 ? 1 : 0, added: 0, updated: Boolean(recordId2) };
      }
      const recordId = plan.current.find(({ item }) => item.recordId)?.item.recordId ?? null;
      await this.dependencies.dns.upsertTxtRecord(command.zone, command.target.domain, recordId, plan.dnsValues);
      return { deleted: 0, added: 0, updated: true };
    } catch {
      errors.push("\u66F4\u65B0 TXT \u8BB0\u5F55\u5931\u8D25");
      return { deleted: 0, added: 0, updated: false };
    }
  }
};
function currentItemFromAddressRecord(record, target) {
  const parsed = parseProxyTarget(record.content, target.port ?? 443);
  const expectedFamily = record.type === "AAAA" ? "ipv6" : "ipv4";
  if (!parsed || parsed.family !== expectedFamily) return invalidDnsItem(record, record.content);
  return {
    recordId: record.id,
    address: target.port ? formatProxyAuthority(parsed.host, target.port) : parsed.authority,
    value: parsed.host,
    result: unknown(null, "NOT_PROBED", "\u7B49\u5F85\u68C0\u6D4B")
  };
}
__name(currentItemFromAddressRecord, "currentItemFromAddressRecord");
function currentItemFromTxtAddress(record, address, target) {
  const parsed = parseProxyTarget(address, target.port ?? 443);
  if (!parsed) return invalidDnsItem(record, address);
  return {
    recordId: record.id,
    address: parsed.authority,
    value: parsed.authority,
    result: unknown(null, "NOT_PROBED", "\u7B49\u5F85\u68C0\u6D4B")
  };
}
__name(currentItemFromTxtAddress, "currentItemFromTxtAddress");
function invalidDnsItem(record, value) {
  return {
    recordId: record.id,
    address: value,
    value,
    result: unknown(null, "INVALID_DNS_VALUE", "DNS \u8BB0\u5F55\u5185\u5BB9\u65E0\u6CD5\u89E3\u6790")
  };
}
__name(invalidDnsItem, "invalidDnsItem");
async function probeSafely(probe, item, target) {
  const parsed = parseProxyTarget(item.address, target.port ?? 443);
  if (!parsed) return unknown(null, "INVALID_DNS_VALUE", "DNS \u8BB0\u5F55\u5185\u5BB9\u65E0\u6CD5\u89E3\u6790");
  try {
    return await probe.probe(parsed);
  } catch {
    return unknown(parsed, "PROBE_ERROR", "\u68C0\u6D4B\u6267\u884C\u5F02\u5E38");
  }
}
__name(probeSafely, "probeSafely");
function resultMatchesTarget(result, target) {
  return decideCurrentResult(result, target) === "active";
}
__name(resultMatchesTarget, "resultMatchesTarget");
function parsePoolEntries(text3) {
  return parsePoolText(text3).map((line) => line.entry).filter((entry) => Boolean(entry));
}
__name(parsePoolEntries, "parsePoolEntries");
function sameValues(left, right) {
  if (left.length !== right.length) return false;
  const rightSet = new Set(right);
  return left.every((value) => rightSet.has(value));
}
__name(sameValues, "sameValues");
function uniqueValues(values) {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
__name(uniqueValues, "uniqueValues");
function isPresent2(value) {
  return value !== null;
}
__name(isPresent2, "isPresent");

// app/src/application/maintain-managed-targets.ts
var MaintainManagedTargets = class {
  constructor(dependencies) {
    this.dependencies = dependencies;
  }
  dependencies;
  static {
    __name(this, "MaintainManagedTargets");
  }
  async execute(data, fallbackZone) {
    const results = [];
    for (const config of data.targets) {
      if (!config.enabled) continue;
      const zone = resolveZone(data.zones, config, fallbackZone);
      const poolKey = resolvePoolKey(data.poolMapping, config.target);
      const poolName = data.poolNames[poolKey] || getPoolFixedName(poolKey);
      try {
        const report = await this.dependencies.maintainer.execute({ target: config.target, zone, poolKey });
        results.push({ target: config.target, zone, poolKey, poolName, report, error: null });
      } catch (error) {
        results.push({
          target: config.target,
          zone,
          poolKey,
          poolName,
          report: null,
          error: error instanceof Error ? error.message : "\u7EF4\u62A4\u6267\u884C\u5931\u8D25"
        });
      }
    }
    return summarize(results);
  }
};
function shouldNotifyMaintenance(run, isManual) {
  return isManual || run.changed || run.insufficient || run.errors.length > 0 || run.probeErrors > 0;
}
__name(shouldNotifyMaintenance, "shouldNotifyMaintenance");
function resolveZone(zones, config, fallback) {
  const indexed = config.zoneIndex === null ? void 0 : zones[config.zoneIndex];
  return {
    apiToken: indexed?.apiToken || fallback.apiToken,
    zoneId: indexed?.zoneId || fallback.zoneId
  };
}
__name(resolveZone, "resolveZone");
function summarize(results) {
  const errors = [];
  let changed = false;
  let insufficient = false;
  let probeErrors = 0;
  for (const result of results) {
    const domain = result.target.domain;
    if (result.error) errors.push(`${domain}: ${result.error}`);
    if (!result.report) continue;
    changed ||= result.report.dnsUpdated;
    insufficient ||= result.report.plan.exhausted;
    probeErrors += result.report.probeErrors;
    for (const error of result.report.errors) errors.push(`${domain}: ${error}`);
  }
  return { results, changed, insufficient, errors, probeErrors };
}
__name(summarize, "summarize");

// app/src/application/pool-service.ts
var MAX_POOL_CONTENT_LENGTH = 512e3;
var PoolInputError = class extends Error {
  static {
    __name(this, "PoolInputError");
  }
  constructor(message) {
    super(message);
    this.name = "PoolInputError";
  }
};
var PoolService = class {
  constructor(catalog) {
    this.catalog = catalog;
  }
  catalog;
  static {
    __name(this, "PoolService");
  }
  async list() {
    return await this.catalog.list();
  }
  async read(poolKey) {
    return await this.catalog.read(requirePoolKey(poolKey));
  }
  async save(poolKey, content, modeValue) {
    const key = requirePoolKey(poolKey);
    const mode = parseSaveMode(modeValue);
    const incoming = poolEntryMap(normalizeContent(content));
    const existing = poolEntryMap(await this.catalog.read(key));
    const existingCount = existing.size;
    let added = 0;
    let removed = 0;
    let replaced = 0;
    if (mode === "append") {
      if (incoming.size === 0) throw new PoolInputError("\u6CA1\u6709\u6709\u6548 IP");
      for (const [addressKey, entry] of incoming) {
        const previous = existing.get(addressKey);
        existing.set(addressKey, previous ? mergePoolEntry(previous, entry) : entry);
      }
      added = existing.size - existingCount;
    } else if (mode === "remove") {
      for (const addressKey of incoming.keys()) {
        if (existing.delete(addressKey)) removed += 1;
      }
    } else {
      replaced = existingCount;
      added = incoming.size;
      existing.clear();
      for (const [addressKey, entry] of incoming) existing.set(addressKey, entry);
    }
    await this.catalog.write(key, serializeEntries(existing));
    return { ok: true, mode, count: existing.size, added, removed, replaced };
  }
  async create(displayNameValue) {
    return await this.catalog.create(normalizeDisplayName(displayNameValue));
  }
  async rename(poolKey, displayNameValue) {
    const key = requireUserPoolKey(poolKey);
    const displayName = normalizeDisplayName(displayNameValue);
    if (!await this.catalog.exists(key)) throw new PoolInputError("\u6C60\u4E0D\u5B58\u5728");
    await this.catalog.rename(key, displayName);
  }
  async remove(poolKey) {
    const key = requirePoolKey(poolKey);
    if (!NUMBERED_POOL_KEY_RE.test(key)) throw new PoolInputError("\u53EA\u80FD\u5220\u9664\u7F16\u53F7 IP \u6C60");
    if (!await this.catalog.exists(key)) throw new PoolInputError("\u6C60\u4E0D\u5B58\u5728");
    await this.catalog.remove(key);
  }
  async saveOrder(orderValue) {
    if (!Array.isArray(orderValue) || orderValue.some((key) => typeof key !== "string")) {
      throw new PoolInputError("\u6392\u5E8F\u6570\u636E\u683C\u5F0F\u65E0\u6548");
    }
    const actual = await this.list();
    const actualKeys = actual.map((pool) => pool.key);
    const actualSet = new Set(actualKeys);
    const submitted = [...new Set(orderValue.map((key) => key.trim()).filter(Boolean))];
    if (submitted.length !== actualKeys.length || submitted.some((key) => !actualSet.has(key))) {
      throw new PoolInputError("\u6C60\u5217\u8868\u5DF2\u53D8\u5316\uFF0C\u8BF7\u5237\u65B0\u540E\u91CD\u8BD5");
    }
    await this.catalog.saveOrder(normalizePoolOrder(submitted, actualKeys));
  }
  async clearTrash() {
    await this.catalog.write(TRASH_POOL_KEY, "");
  }
  async restoreTrash(addressesValue, restoreToSourceValue, targetPoolValue) {
    if (!Array.isArray(addressesValue) || addressesValue.some((value) => typeof value !== "string")) {
      throw new PoolInputError("addresses \u5FC5\u987B\u662F\u6570\u7EC4");
    }
    if (addressesValue.length === 0) throw new PoolInputError("\u6CA1\u6709\u9009\u62E9 IP");
    if (addressesValue.length > MAX_POOL_RESTORE_ITEMS) throw new PoolInputError("\u4E00\u6B21\u6062\u590D\u7684 IP \u6570\u91CF\u8FC7\u591A");
    const requested = [...new Set(addressesValue.map((value) => canonicalAddressKey(value)).filter(Boolean))];
    if (requested.length === 0) throw new PoolInputError("\u6CA1\u6709\u6709\u6548 IP");
    const restoreToSource = restoreToSourceValue === true;
    const fallbackPool = restoreToSource ? DEFAULT_POOL_KEY : requireUserPoolKey(targetPoolValue ?? DEFAULT_POOL_KEY);
    const trash = poolLineMap(await this.catalog.read(TRASH_POOL_KEY));
    const targetPools = /* @__PURE__ */ new Map();
    const restoredByPool = {};
    let restored = 0;
    let trashChanged = false;
    for (const addressKey of requested) {
      const trashItem = trash.get(addressKey);
      if (!trashItem) continue;
      trash.delete(addressKey);
      trashChanged = true;
      const targetPool = restoreToSource ? await this.resolveSourcePool(trashItem.raw, fallbackPool) : fallbackPool;
      let targetEntries = targetPools.get(targetPool);
      if (!targetEntries) {
        targetEntries = poolEntryMap(await this.catalog.read(targetPool));
        targetPools.set(targetPool, targetEntries);
      }
      if (targetEntries.has(addressKey)) continue;
      targetEntries.set(addressKey, { ...trashItem.entry, comment: "" });
      restored += 1;
      restoredByPool[targetPool] = (restoredByPool[targetPool] ?? 0) + 1;
    }
    if (trashChanged) await this.catalog.write(TRASH_POOL_KEY, serializeEntries(lineEntriesToEntries(trash)));
    for (const [poolKey, entries] of targetPools) {
      if ((restoredByPool[poolKey] ?? 0) > 0) await this.catalog.write(poolKey, serializeEntries(entries));
    }
    return { ok: true, restored, restoredByPool };
  }
  async resolveSourcePool(trashLine, fallbackPool) {
    const marker = " \u6765\u81EA ";
    const markerIndex = trashLine.lastIndexOf(marker);
    if (markerIndex < 0) return fallbackPool;
    const candidate = trashLine.slice(markerIndex + marker.length).trim();
    if (!isUserPoolKey(candidate)) return fallbackPool;
    return candidate === DEFAULT_POOL_KEY || await this.catalog.exists(candidate) ? candidate : fallbackPool;
  }
};
function requirePoolKey(value) {
  const key = typeof value === "string" ? value.trim() : "";
  if (!isPoolDataKey(key)) throw new PoolInputError("IP \u6C60\u6807\u8BC6\u65E0\u6548");
  return key;
}
__name(requirePoolKey, "requirePoolKey");
function requireUserPoolKey(value) {
  const key = typeof value === "string" ? value.trim() : "";
  if (!isUserPoolKey(key)) throw new PoolInputError("\u76EE\u6807\u6C60\u65E0\u6548");
  return key;
}
__name(requireUserPoolKey, "requireUserPoolKey");
function normalizeDisplayName(value) {
  const displayName = typeof value === "string" ? value.trim() : "";
  if (!displayName) throw new PoolInputError("\u663E\u793A\u540D\u79F0\u4E0D\u80FD\u4E3A\u7A7A");
  if (displayName.length > MAX_POOL_DISPLAY_NAME_LENGTH || /[\r\n]/.test(displayName)) {
    throw new PoolInputError(`\u663E\u793A\u540D\u79F0\u4E0D\u80FD\u8D85\u8FC7 ${MAX_POOL_DISPLAY_NAME_LENGTH} \u4E2A\u5B57\u7B26\u4E14\u4E0D\u80FD\u6362\u884C`);
  }
  return displayName;
}
__name(normalizeDisplayName, "normalizeDisplayName");
function parseSaveMode(value) {
  if (value === void 0 || value === null || value === "") return "append";
  if (value === "append" || value === "replace" || value === "remove") return value;
  throw new PoolInputError("IP \u6C60\u5199\u5165\u6A21\u5F0F\u65E0\u6548");
}
__name(parseSaveMode, "parseSaveMode");
function normalizeContent(value) {
  if (typeof value !== "string") throw new PoolInputError("IP \u6C60\u5185\u5BB9\u5FC5\u987B\u662F\u6587\u672C");
  if (value.length > MAX_POOL_CONTENT_LENGTH) throw new PoolInputError("IP \u6C60\u5185\u5BB9\u8D85\u51FA\u957F\u5EA6\u9650\u5236");
  return value.replace(/\r\n?/g, "\n").trim();
}
__name(normalizeContent, "normalizeContent");
function poolEntryMap(text3) {
  const entries = /* @__PURE__ */ new Map();
  for (const line of poolLineMap(text3).values()) entries.set(canonicalAddressKey(line.entry.address), line.entry);
  return entries;
}
__name(poolEntryMap, "poolEntryMap");
function poolLineMap(text3) {
  const entries = /* @__PURE__ */ new Map();
  for (const line of parsePoolText(text3)) {
    const entry = line.entry;
    if (!entry || !parsePoolAddress(entry)) continue;
    const key = canonicalAddressKey(entry.address);
    if (key) entries.set(key, { raw: line.raw, entry });
  }
  return entries;
}
__name(poolLineMap, "poolLineMap");
function lineEntriesToEntries(lines) {
  return new Map([...lines].map(([key, line]) => [key, line.entry]));
}
__name(lineEntriesToEntries, "lineEntriesToEntries");
function serializeEntries(entries) {
  return [...entries.values()].map((entry) => formatPoolEntry(entry)).join("\n");
}
__name(serializeEntries, "serializeEntries");
function normalizePoolOrder(submitted, actual) {
  const submittedSet = new Set(submitted);
  const middle = submitted.filter((key) => key !== DEFAULT_POOL_KEY && key !== TRASH_POOL_KEY && submittedSet.has(key));
  const actualMiddle = actual.filter((key) => key !== DEFAULT_POOL_KEY && key !== TRASH_POOL_KEY);
  for (const key of actualMiddle) if (!middle.includes(key)) middle.push(key);
  return [
    ...actual.includes(DEFAULT_POOL_KEY) ? [DEFAULT_POOL_KEY] : [],
    ...middle,
    ...actual.includes(TRASH_POOL_KEY) ? [TRASH_POOL_KEY] : []
  ];
}
__name(normalizePoolOrder, "normalizePoolOrder");

// app/src/domain/pool-text.ts
function cleanPoolText(text3) {
  const entries = /* @__PURE__ */ new Map();
  for (const rawLine of String(text3 ?? "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const entry = parsePoolEntry(line);
    if (!entry) continue;
    const target = parseProxyTarget(entry.address, 443);
    if (!target) continue;
    entries.set(target.key, formatPoolEntry({ ...entry, address: target.authority }));
  }
  return [...entries.values()].join("\n");
}
__name(cleanPoolText, "cleanPoolText");
function countPoolTextLines(text3) {
  const trimmed = String(text3 ?? "").trim();
  return trimmed ? trimmed.split("\n").length : 0;
}
__name(countPoolTextLines, "countPoolTextLines");

// app/src/domain/remote-url.ts
var BLOCKED_HOSTNAMES = /* @__PURE__ */ new Set([
  "localhost",
  "metadata",
  "metadata.google.internal",
  "metadata.goog",
  "instance-data"
]);
var BLOCKED_SUFFIXES = [".localhost", ".internal", ".local", ".home.arpa"];
function validateRemoteUrl(value) {
  const trimmed = String(value ?? "").trim();
  if (!trimmed || trimmed.length > 2048) return { ok: false, reason: "invalid-url" };
  let url;
  try {
    url = new URL(trimmed);
  } catch {
    return { ok: false, reason: "invalid-url" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return { ok: false, reason: "invalid-url" };
  if (url.username || url.password) return { ok: false, reason: "invalid-url" };
  if (isPrivateHost(url.hostname)) return { ok: false, reason: "blocked-host" };
  return { ok: true, url };
}
__name(validateRemoteUrl, "validateRemoteUrl");
function isPrivateHost(hostname) {
  const host = normalizeHost(hostname);
  if (!host) return true;
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  if (BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) return true;
  const ipv4 = parseIpv4(host);
  if (ipv4) return isPrivateIpv4(ipv4);
  if (host.includes(":")) return isPrivateIpv6(host);
  return false;
}
__name(isPrivateHost, "isPrivateHost");
function normalizeHost(hostname) {
  const host = String(hostname ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") && host.endsWith("]")) return host.slice(1, -1);
  const zoneIndex = host.indexOf("%");
  return zoneIndex === -1 ? host : host.slice(0, zoneIndex);
}
__name(normalizeHost, "normalizeHost");
function parseIpv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => /^\d{1,3}$/.test(part) ? Number(part) : Number.NaN);
  return octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255) ? octets : null;
}
__name(parseIpv4, "parseIpv4");
function isPrivateIpv4(octets) {
  const [a, b] = octets;
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224) return true;
  return false;
}
__name(isPrivateIpv4, "isPrivateIpv4");
function isPrivateIpv6(host) {
  const groups = expandIpv6(host);
  if (!groups) return true;
  const [first = 0, second = 0, third = 0, fourth = 0, fifth = 0, sixth = 0, seventh = 0, eighth = 0] = groups;
  const leading = [first, second, third, fourth, fifth, sixth];
  const isV4Compatible = leading.every((group) => group === 0);
  const isV4Mapped = sixth === 65535 && leading.slice(0, 5).every((group) => group === 0);
  if (isV4Compatible || isV4Mapped) {
    return isPrivateIpv4([seventh >> 8, seventh & 255, eighth >> 8, eighth & 255]);
  }
  if ((first & 65024) === 64512) return true;
  if ((first & 65472) === 65152) return true;
  if ((first & 65280) === 65280) return true;
  return false;
}
__name(isPrivateIpv6, "isPrivateIpv6");
function expandIpv6(address) {
  let value = address;
  const tailStart = value.lastIndexOf(":") + 1;
  const tail = value.slice(tailStart);
  if (tail.includes(".")) {
    const octets = parseIpv4(tail);
    if (!octets) return null;
    const [a, b, c, d] = octets;
    value = `${value.slice(0, tailStart)}${(a << 8 | b).toString(16)}:${(c << 8 | d).toString(16)}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const readGroups = /* @__PURE__ */ __name((part) => {
    if (!part) return [];
    const groups = part.split(":").map((group) => /^[0-9a-f]{1,4}$/.test(group) ? parseInt(group, 16) : -1);
    return groups.some((group) => group < 0) ? null : groups;
  }, "readGroups");
  const head = readGroups(halves[0] ?? "");
  const body = readGroups(halves[1] ?? "");
  if (!head || !body) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const zeros = 8 - head.length - body.length;
  return zeros >= 1 ? [...head, ...new Array(zeros).fill(0), ...body] : null;
}
__name(expandIpv6, "expandIpv6");

// app/src/application/remote-pool-loader.ts
var DEFAULT_MAX_REMOTE_BYTES = 512 * 1024;
var DEFAULT_MAX_REDIRECTS = 3;
var REDIRECT_STATUSES = /* @__PURE__ */ new Set([301, 302, 303, 307, 308]);
var RemotePoolLoader = class {
  static {
    __name(this, "RemotePoolLoader");
  }
  timeoutMs;
  maxBytes;
  maxRedirects;
  fetchImpl;
  constructor(options) {
    this.timeoutMs = options.timeoutMs;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_REMOTE_BYTES;
    this.maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }
  async load(rawUrl, options = {}) {
    let target = validateRemoteUrl(rawUrl);
    if (!target.ok) return { ok: false, reason: target.reason };
    for (let hop = 0; hop <= this.maxRedirects; hop += 1) {
      const response = await this.fetchOnce(target.url, options);
      if (!response.ok) return response;
      const location = response.value.headers.get("location");
      if (REDIRECT_STATUSES.has(response.value.status) && location) {
        const next = validateRedirect(location, target.url);
        if (!next.ok) return { ok: false, reason: next.reason };
        target = next;
        continue;
      }
      return await this.readBody(response.value, target.url.toString());
    }
    return { ok: false, reason: "too-many-redirects" };
  }
  async fetchOnce(url, options) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const abortUpstream = /* @__PURE__ */ __name(() => controller.abort(), "abortUpstream");
    options.signal?.addEventListener("abort", abortUpstream, { once: true });
    try {
      const response = await this.fetchImpl(url.toString(), {
        redirect: "manual",
        signal: controller.signal,
        headers: { accept: "text/plain, text/*;q=0.9, */*;q=0.8" }
      });
      if (REDIRECT_STATUSES.has(response.status) && response.headers.get("location")) return { ok: true, value: response };
      if (!response.ok) return { ok: false, reason: "http-error" };
      return { ok: true, value: response };
    } catch {
      return this.timedOut(options.signal, controller.signal) ? { ok: false, reason: "timeout" } : { ok: false, reason: "network-error" };
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abortUpstream);
    }
  }
  async readBody(response, finalUrl) {
    const declared = Number(response.headers.get("content-length") ?? Number.NaN);
    if (Number.isFinite(declared) && declared > this.maxBytes) return { ok: false, reason: "too-large" };
    let text3;
    try {
      text3 = await response.text();
    } catch {
      return { ok: false, reason: "network-error" };
    }
    if (text3.length > this.maxBytes) return { ok: false, reason: "too-large" };
    return { ok: true, content: cleanPoolText(text3), finalUrl };
  }
  /** 只有本地超时控制器被触发、且调用方没有主动取消，才算超时。 */
  timedOut(upstream, local) {
    return local.aborted && !upstream?.aborted;
  }
};
function validateRedirect(location, base) {
  try {
    return validateRemoteUrl(new URL(location, base).toString());
  } catch {
    return { ok: false, reason: "invalid-url" };
  }
}
__name(validateRedirect, "validateRedirect");

// app/src/contracts/probe.ts
var MAX_PROXYIP_LENGTH = 512;
function parseCheckProxyInput(value) {
  const proxyip = readTrimmedString(value, 1, MAX_PROXYIP_LENGTH);
  if (!proxyip) return parseFail(`proxyip must be 1-${MAX_PROXYIP_LENGTH} characters`);
  return parseOk(proxyip);
}
__name(parseCheckProxyInput, "parseCheckProxyInput");
var DRAFT_URL_KEYS = ["checkApi", "checkApiBackup", "socketProbeIpv4Url", "socketProbeIpv6Url"];
var PROBE_TEST_ITEM_IDS = [
  "internal-ipv4",
  "internal-ipv6",
  "external-primary",
  "external-backup"
];
function parseProbeTestRequest(value) {
  const record = asRecord(value);
  if (!record) return parseFail("\u81EA\u68C0\u8BF7\u6C42\u5FC5\u987B\u662F JSON \u5BF9\u8C61");
  const proxyip = parseCheckProxyInput(record.proxyip);
  if (!proxyip.ok) return proxyip;
  return parseOk({
    proxyip: proxyip.value,
    ...record.draft === void 0 ? {} : { draft: parseProbeTestDraft(record.draft) }
  });
}
__name(parseProbeTestRequest, "parseProbeTestRequest");
function parseProbeTestDraft(value) {
  const record = asRecord(value) ?? {};
  const mode = readTrimmedString(record.probeMode, 1, 32);
  const readLimit = readInteger(record.socketReadLimitBytes, MIN_SOCKET_READ_LIMIT_BYTES, MAX_SOCKET_READ_LIMIT_BYTES);
  return {
    ...PROBE_MODES.includes(mode) ? { probeMode: mode } : {},
    ...readDraftUrls(record),
    ...readLimit === null ? {} : { socketReadLimitBytes: readLimit }
  };
}
__name(parseProbeTestDraft, "parseProbeTestDraft");
function readDraftUrls(record) {
  const urls = {};
  for (const key of DRAFT_URL_KEYS) {
    if (record[key] === void 0) continue;
    urls[key] = readTrimmedString(record[key], 0, MAX_ENDPOINT_URL_LENGTH) ?? "";
  }
  return urls;
}
__name(readDraftUrls, "readDraftUrls");

// app/src/application/probe-self-test.ts
var SELF_TEST_ITEMS = [
  {
    id: "internal-ipv4",
    label: "\u5185\u90E8\u68C0\u6D4B \xB7 IPv4",
    isConfigured: /* @__PURE__ */ __name((config) => config.socketProbeIpv4Url.trim().length > 0, "isConfigured"),
    probeConfig: /* @__PURE__ */ __name((base) => ({ ...base, endpoints: [], ipv6ProbeUrl: "" }), "probeConfig")
  },
  {
    id: "internal-ipv6",
    label: "\u5185\u90E8\u68C0\u6D4B \xB7 IPv6",
    isConfigured: /* @__PURE__ */ __name((config) => config.socketProbeIpv6Url.trim().length > 0, "isConfigured"),
    probeConfig: /* @__PURE__ */ __name((base) => ({ ...base, endpoints: [], ipv4ProbeUrl: "" }), "probeConfig")
  },
  {
    id: "external-primary",
    label: "\u5916\u90E8\u590D\u68C0 \xB7 \u4E3B\u63A5\u53E3",
    isConfigured: /* @__PURE__ */ __name((config) => config.checkApi.trim().length > 0, "isConfigured"),
    probeConfig: /* @__PURE__ */ __name((base) => ({
      ...base,
      ipv4ProbeUrl: "",
      ipv6ProbeUrl: "",
      fallbackToNext: false,
      endpoints: [{ name: "primary", urlTemplate: base.endpoints[0]?.urlTemplate ?? "" }]
    }), "probeConfig")
  },
  {
    id: "external-backup",
    label: "\u5916\u90E8\u590D\u68C0 \xB7 \u5907\u7528\u63A5\u53E3",
    isConfigured: /* @__PURE__ */ __name((config) => config.checkApiBackup.trim().length > 0, "isConfigured"),
    probeConfig: /* @__PURE__ */ __name((base) => ({
      ...base,
      ipv4ProbeUrl: "",
      ipv6ProbeUrl: "",
      fallbackToNext: false,
      endpoints: [{ name: "backup", urlTemplate: base.endpoints[1]?.urlTemplate ?? "" }]
    }), "probeConfig")
  }
];
var SELF_TEST_ITEM_BY_ID = Object.fromEntries(
  SELF_TEST_ITEMS.map((item) => [item.id, item])
);
var ProbeSelfTest = class {
  constructor(createAdapter) {
    this.createAdapter = createAdapter;
  }
  createAdapter;
  static {
    __name(this, "ProbeSelfTest");
  }
  async execute(input, context = {}) {
    const effective = applyDraft(input.config, input.draft);
    const target = parseProxyTarget(input.proxyip);
    if (!target) {
      const error = "\u8BF7\u8F93\u5165\u6709\u6548\u7684 IP\u3001\u57DF\u540D\u548C\u53EF\u9009\u7AEF\u53E3";
      return {
        proxyip: input.proxyip,
        items: SELF_TEST_ITEMS.map((item) => ({ id: item.id, label: item.label, configured: false, error }))
      };
    }
    const base = toProbeConfig(effective);
    const items = await Promise.all(
      PROBE_TEST_ITEM_IDS.map((id) => this.runItem(SELF_TEST_ITEM_BY_ID[id], effective, base, target, context))
    );
    return { proxyip: input.proxyip, items };
  }
  async runItem(item, effective, base, target, context) {
    if (!item.isConfigured(effective)) {
      return { id: item.id, label: item.label, configured: false };
    }
    try {
      const adapter = this.createAdapter(item.probeConfig(base));
      return { id: item.id, label: item.label, configured: true, result: await adapter.probe(target, context) };
    } catch (error) {
      return {
        id: item.id,
        label: item.label,
        configured: true,
        error: error instanceof Error ? error.message : "\u63A2\u9488\u6267\u884C\u5931\u8D25"
      };
    }
  }
};
function applyDraft(config, draft) {
  if (!draft) return config;
  return {
    ...config,
    ...draft.probeMode === void 0 ? {} : { probeMode: draft.probeMode },
    ...draft.checkApi === void 0 ? {} : { checkApi: draft.checkApi },
    ...draft.checkApiBackup === void 0 ? {} : { checkApiBackup: draft.checkApiBackup },
    ...draft.socketProbeIpv4Url === void 0 ? {} : { socketProbeIpv4Url: draft.socketProbeIpv4Url },
    ...draft.socketProbeIpv6Url === void 0 ? {} : { socketProbeIpv6Url: draft.socketProbeIpv6Url },
    ...draft.socketReadLimitBytes === void 0 ? {} : { socketReadLimitBytes: draft.socketReadLimitBytes }
  };
}
__name(applyDraft, "applyDraft");

// app/src/adapters/probe/probe-payload.ts
function readText(value) {
  return typeof value === "string" && value.trim() ? value.trim() : void 0;
}
__name(readText, "readText");
function firstText(record, keys) {
  for (const key of keys) {
    const value = readText(record[key]);
    if (value) return value;
  }
  return void 0;
}
__name(firstText, "firstText");
function readProbeExit(record, stackHint) {
  const ip = firstText(record, ["ip", "ipAddress", "exitIp", "exit_ip", "address", "query"]);
  const family = normalizeSingleExitFamily(readText(record.ipType) ?? readText(record.type) ?? stackHint, ip);
  const asn = normalizeAsn2(firstText(record, ["asn", "as", "asNumber"]));
  const country = firstText(record, ["country", "countryCode"]);
  const organization = firstText(record, ["asOrganization", "asname", "org", "isp"]);
  if (!ip && !asn && !country && !organization && family === "unknown") return null;
  return {
    family,
    ...ip ? { ip } : {},
    ...asn ? { asn } : {},
    ...country ? { country: country.toUpperCase() } : {},
    ...organization ? { organization } : {}
  };
}
__name(readProbeExit, "readProbeExit");
function normalizeSingleExitFamily(value, ip) {
  const normalized = value?.trim().toLowerCase().replace(/_/g, "-");
  if (normalized === "ipv4" || normalized === "v4" || normalized === "ipv4-only" || normalized === "only-ipv4") return "ipv4";
  if (normalized === "ipv6" || normalized === "v6" || normalized === "ipv6-only" || normalized === "only-ipv6") return "ipv6";
  const inferred = exitFamilyFromIp(ip);
  return inferred === "ipv4" || inferred === "ipv6" ? inferred : "unknown";
}
__name(normalizeSingleExitFamily, "normalizeSingleExitFamily");
function normalizeAsn2(value) {
  if (!value) return void 0;
  const normalized = value.trim().replace(/^AS/i, "").toUpperCase();
  return normalized || void 0;
}
__name(normalizeAsn2, "normalizeAsn");
function uniqueExits(exits) {
  const seen = /* @__PURE__ */ new Set();
  return exits.filter((exit) => {
    const key = `${exit.family}:${exit.ip ?? ""}:${exit.asn ?? ""}:${exit.country ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
__name(uniqueExits, "uniqueExits");

// app/src/adapters/probe/composite.ts
var CompositeProbeAdapter = class {
  static {
    __name(this, "CompositeProbeAdapter");
  }
  name = "composite";
  internal;
  external;
  primary;
  constructor(options) {
    this.internal = options.internal;
    this.external = options.external;
    this.primary = options.primary;
  }
  async probe(target, context = {}) {
    const first = this.primary === "internal" ? this.internal : this.external;
    const second = this.primary === "internal" ? this.external : this.internal;
    const primary = await first.probe(target, context);
    if (primary.status === "alive" || context.signal?.aborted) return primary;
    const recheck = await second.probe(target, context);
    return combine(primary, recheck);
  }
};
function combine(primary, recheck) {
  const exits = uniqueExits([...primary.exits, ...recheck.exits]);
  const recheckAlive = recheck.status === "alive";
  const exitIp = recheckAlive ? recheck.exitIp ?? primary.exitIp : primary.exitIp;
  const target = primary.target ?? recheck.target;
  const shared = {
    exitFamily: recheckAlive ? recheck.exitFamily : primary.exitFamily,
    exits,
    ...exitIp ? { exitIp } : {},
    ...recheck.latencyMs === void 0 ? {} : { latencyMs: recheck.latencyMs }
  };
  if (recheckAlive) return { ...recheck, ...shared };
  if (primary.status === "dead") return { ...primary, ...shared };
  if (recheck.status === "dead") return { ...recheck, ...shared };
  const details = [primary.message, recheck.message].filter((value) => Boolean(value));
  return unknown(
    target,
    primary.code ?? recheck.code ?? "UNKNOWN",
    details.length ? details.join("\uFF1B") : "\u5185\u90E8\u68C0\u6D4B\u4E0E\u5916\u90E8\u590D\u68C0\u90FD\u6CA1\u6709\u8FD4\u56DE\u53EF\u7528\u7ED3\u8BBA",
    { ...shared, ...primary.endpoint ? { endpoint: primary.endpoint } : {} }
  );
}
__name(combine, "combine");

// app/src/adapters/probe/external-api.ts
var ExternalApiProbeAdapter = class {
  static {
    __name(this, "ExternalApiProbeAdapter");
  }
  name = "external-api";
  endpoints;
  timeoutMs;
  fallbackToNext;
  fetchImpl;
  constructor(options) {
    if (options.endpoints.length === 0) throw new Error("external-api probe requires at least one endpoint");
    this.endpoints = options.endpoints;
    this.timeoutMs = options.timeoutMs;
    this.fallbackToNext = options.fallbackToNext ?? true;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }
  async probe(target, context = {}) {
    const attempts = [];
    for (const endpoint of this.endpoints) {
      const result = await this.probeEndpoint(target, endpoint, context);
      attempts.push(result);
      if (result.status === "alive") return result;
      if (!this.fallbackToNext) return result;
      if (context.signal?.aborted) return result;
    }
    return attempts.find((result) => result.status === "dead") ?? attempts.at(-1) ?? unknown(target, "NO_ENDPOINT", "\u6CA1\u6709\u53EF\u7528\u7684\u68C0\u6D4B\u63A5\u53E3");
  }
  async probeEndpoint(target, endpoint, context) {
    const startedAt = Date.now();
    const timeout = createRequestTimeout(endpoint.timeoutMs ?? this.timeoutMs, context.signal);
    try {
      const url = buildProbeUrl(endpoint.urlTemplate, target);
      const init = { method: "GET", signal: timeout.signal };
      if (endpoint.headers) init.headers = endpoint.headers;
      const response = await this.fetchImpl(url, init);
      if (!response.ok) {
        await response.body?.cancel().catch(() => void 0);
        return unknown(target, "HTTP_ERROR", `\u68C0\u6D4B\u63A5\u53E3 HTTP ${response.status}`, {
          endpoint: endpoint.name,
          latencyMs: Date.now() - startedAt
        });
      }
      const text3 = await response.text();
      let payload;
      try {
        payload = JSON.parse(text3);
      } catch {
        return unknown(target, "INVALID_JSON", "\u68C0\u6D4B\u63A5\u53E3\u8FD4\u56DE\u7684 JSON \u65E0\u6CD5\u89E3\u6790", {
          endpoint: endpoint.name,
          latencyMs: Date.now() - startedAt
        });
      }
      return parseProbePayload(payload, target, endpoint.name, Date.now() - startedAt);
    } catch (error) {
      const latencyMs = Date.now() - startedAt;
      if (context.signal?.aborted) {
        return unknown(target, "CANCELLED", "\u68C0\u6D4B\u5DF2\u53D6\u6D88", { endpoint: endpoint.name, latencyMs });
      }
      if (timeout.didTimeout() || isAbortError(error)) {
        return unknown(target, "TIMEOUT", `\u68C0\u6D4B\u8D85\u65F6 (${endpoint.timeoutMs ?? this.timeoutMs}ms)`, {
          endpoint: endpoint.name,
          latencyMs
        });
      }
      return unknown(target, "NETWORK_ERROR", "\u68C0\u6D4B\u63A5\u53E3\u7F51\u7EDC\u5F02\u5E38", {
        endpoint: endpoint.name,
        latencyMs
      });
    } finally {
      timeout.cleanup();
    }
  }
};
function buildProbeUrl(urlTemplate, target) {
  const encoded = encodeURIComponent(target.authority);
  return urlTemplate.includes("{proxyip}") ? urlTemplate.replaceAll("{proxyip}", encoded) : `${urlTemplate}${encoded}`;
}
__name(buildProbeUrl, "buildProbeUrl");
function createRequestTimeout(timeoutMs, externalSignal) {
  const controller = new AbortController();
  let timedOut = false;
  const handleExternalAbort = /* @__PURE__ */ __name(() => controller.abort(externalSignal?.reason), "handleExternalAbort");
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  if (externalSignal?.aborted) handleExternalAbort();
  else externalSignal?.addEventListener("abort", handleExternalAbort, { once: true });
  return {
    signal: controller.signal,
    didTimeout: /* @__PURE__ */ __name(() => timedOut, "didTimeout"),
    cleanup: /* @__PURE__ */ __name(() => {
      clearTimeout(timer);
      externalSignal?.removeEventListener("abort", handleExternalAbort);
    }, "cleanup")
  };
}
__name(createRequestTimeout, "createRequestTimeout");
function parseProbePayload(payload, target, endpoint, latencyMs) {
  const record = unwrapPayload(payload);
  if (!record) return unknown(target, "INVALID_RESPONSE", "\u68C0\u6D4B\u63A5\u53E3\u54CD\u5E94\u4E0D\u662F\u5BF9\u8C61", { endpoint, latencyMs });
  if (!isRecognizedPayload(record)) return unknown(target, "INVALID_RESPONSE", "\u68C0\u6D4B\u63A5\u53E3\u54CD\u5E94\u683C\u5F0F\u4E0D\u53EF\u8BC6\u522B", { endpoint, latencyMs });
  const statusText = readText(record.status)?.toLowerCase();
  if (statusText === "error" || statusText === "invalid") {
    return unknown(target, "API_ERROR", readMessage(record) ?? "\u68C0\u6D4B\u63A5\u53E3\u8FD4\u56DE\u9519\u8BEF", { endpoint, latencyMs });
  }
  const decision = readBooleanDecision(record) ?? readStatusDecision(statusText) ?? readProbeResultsDecision(record.probe_results);
  const exits = readProbeExits(record);
  const exitIp = pickExitIp(record, exits);
  const exitFamily = pickExitFamily(record, exitIp);
  const message = readMessage(record);
  if (decision === true) {
    return alive(target, {
      endpoint,
      latencyMs,
      exitFamily,
      exits,
      ...exitIp ? { exitIp } : {}
    });
  }
  if (decision === false) {
    return dead(target, {
      endpoint,
      latencyMs,
      ...message ? { message } : {}
    });
  }
  if (exitIp) {
    return alive(target, {
      endpoint,
      latencyMs,
      exitFamily,
      exits,
      exitIp
    });
  }
  return unknown(target, "INVALID_RESPONSE", message ?? "\u68C0\u6D4B\u63A5\u53E3\u672A\u8FD4\u56DE\u53EF\u4FE1\u7684\u6210\u529F\u6216\u5931\u8D25\u7ED3\u8BBA", {
    endpoint,
    latencyMs
  });
}
__name(parseProbePayload, "parseProbePayload");
function unwrapPayload(payload) {
  if (Array.isArray(payload)) {
    if (payload.length !== 1) return null;
    return asRecord(payload[0]);
  }
  return asRecord(payload);
}
__name(unwrapPayload, "unwrapPayload");
function isRecognizedPayload(record) {
  return [
    "success",
    "ok",
    "status",
    "proxyIP",
    "proxy_ip",
    "probe_results",
    "exitIp",
    "exit_ip",
    "inferred_stack",
    "supports_ipv4",
    "supports_ipv6"
  ].some((key) => key in record);
}
__name(isRecognizedPayload, "isRecognizedPayload");
function readBooleanDecision(record) {
  if (typeof record.success === "boolean") return record.success;
  if (typeof record.ok === "boolean") return record.ok;
  return void 0;
}
__name(readBooleanDecision, "readBooleanDecision");
function readStatusDecision(status) {
  if (!status) return void 0;
  if (["success", "ok", "alive", "available", "healthy", "up"].includes(status)) return true;
  if (["failed", "failure", "dead", "unavailable", "down"].includes(status)) return false;
  return void 0;
}
__name(readStatusDecision, "readStatusDecision");
function readProbeResultsDecision(value) {
  const probes = asRecord(value);
  if (!probes) return void 0;
  const values = Object.values(probes).map(asRecord).filter((probe) => probe !== null);
  if (values.length === 0) return void 0;
  const okValues = values.map((probe) => probe.ok).filter((ok) => typeof ok === "boolean");
  if (okValues.includes(true)) return true;
  if (okValues.length > 0 && okValues.every((ok) => !ok)) return false;
  return void 0;
}
__name(readProbeResultsDecision, "readProbeResultsDecision");
function pickExitIp(record, exits) {
  const fromExits = exits.find((exit2) => exit2.ip)?.ip;
  if (fromExits) return fromExits;
  const direct = firstText(record, ["exitIp", "exit_ip", "ipAddress"]);
  if (direct) return direct;
  const exit = asRecord(record.exit);
  if (exit) {
    const fromExit = firstText(exit, ["ip", "ipAddress", "exitIp", "exit_ip"]);
    if (fromExit) return fromExit;
  } else if (typeof record.exit === "string" && record.exit) {
    return record.exit;
  }
  const candidate = readText(record.proxyIP) ?? readText(record.proxy_ip);
  const topLevelIp = readText(record.ip);
  if (topLevelIp && topLevelIp !== candidate) return topLevelIp;
  const probes = asRecord(record.probe_results);
  if (!probes) return void 0;
  for (const probeValue of Object.values(probes)) {
    const probe = asRecord(probeValue);
    if (!probe) continue;
    const probeExit = asRecord(probe.exit);
    const fromProbe = probeExit ? firstText(probeExit, ["ip", "ipAddress", "exitIp", "exit_ip"]) : firstText(probe, ["exitIp", "exit_ip"]);
    if (fromProbe) return fromProbe;
  }
  return void 0;
}
__name(pickExitIp, "pickExitIp");
function readProbeExits(record) {
  const exits = [];
  const probes = asRecord(record.probe_results) ?? asRecord(record.probeResults) ?? asRecord(record.probes);
  if (probes) {
    for (const [stack, value] of Object.entries(probes)) {
      const probe = asRecord(value);
      if (!probe || !isSuccessfulProbe(probe)) continue;
      const exit = asRecord(probe.exit) ?? asRecord(probe.egress) ?? asRecord(probe.result) ?? probe;
      const parsed = readProbeExit(exit, stack);
      if (parsed) exits.push(parsed);
    }
  }
  const directValues = Array.isArray(record.exits) ? record.exits : [];
  for (const value of directValues) {
    const exit = asRecord(value);
    if (!exit) continue;
    const parsed = readProbeExit(exit, readText(exit.stack) ?? readText(exit.ipType));
    if (parsed) exits.push(parsed);
  }
  const directExit = asRecord(record.exit) ?? asRecord(record.egress);
  if (directExit) {
    const parsed = readProbeExit(directExit, readText(record.stack) ?? readText(record.ipType));
    if (parsed) exits.push(parsed);
  }
  return uniqueExits(exits);
}
__name(readProbeExits, "readProbeExits");
function isSuccessfulProbe(probe) {
  return probe.ok === true || probe.success === true || readText(probe.status)?.toLowerCase() === "success" || asRecord(probe.exit) !== null;
}
__name(isSuccessfulProbe, "isSuccessfulProbe");
function pickExitFamily(record, exitIp) {
  const stack = (readText(record.inferred_stack) ?? readText(record.stack) ?? readText(record.ipType) ?? "").toLowerCase();
  if (stack === "dual_stack" || stack === "dual" || stack === "v4/v6") return "dual";
  if (stack === "ipv4_only" || stack === "ipv4" || stack === "v4") return "ipv4";
  if (stack === "ipv6_only" || stack === "ipv6" || stack === "v6") return "ipv6";
  const supportsIpv4 = record.supports_ipv4 === true;
  const supportsIpv6 = record.supports_ipv6 === true;
  if (supportsIpv4 && supportsIpv6) return "dual";
  if (supportsIpv4) return "ipv4";
  if (supportsIpv6) return "ipv6";
  return exitFamilyFromIp(exitIp);
}
__name(pickExitFamily, "pickExitFamily");
function readMessage(record) {
  const direct = firstText(record, ["message", "errorMessage"]);
  if (direct) return trimMessage(direct);
  const error = record.error;
  if (typeof error === "string") return trimMessage(error);
  const errorRecord = asRecord(error);
  return errorRecord ? trimMessage(firstText(errorRecord, ["message", "detail", "code"]) ?? "") : void 0;
}
__name(readMessage, "readMessage");
function trimMessage(value) {
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, 240) : void 0;
}
__name(trimMessage, "trimMessage");
function isAbortError(error) {
  return error instanceof Error && ["AbortError", "TimeoutError"].includes(error.name);
}
__name(isAbortError, "isAbortError");

// app/src/adapters/probe/socket.ts
var SocketProbeAdapter = class {
  static {
    __name(this, "SocketProbeAdapter");
  }
  name = "socket";
  targets;
  timeoutMs;
  readLimitBytes;
  connect;
  constructor(options) {
    this.targets = [options.ipv4Url, options.ipv6Url].map(buildTarget).filter((target) => target !== null);
    this.timeoutMs = options.timeoutMs;
    this.readLimitBytes = options.readLimitBytes;
    this.connect = options.connect;
  }
  async probe(target, context = {}) {
    if (this.targets.length === 0) {
      return unknown(target, "NOT_CONFIGURED", "\u672A\u914D\u7F6E IPv4/IPv6 Socket \u63A2\u9488\u5730\u5740");
    }
    if (context.signal?.aborted) return cancelled(target);
    const attempts = await Promise.all(this.targets.map((probe) => this.runProbe(probe, target, context)));
    return combineAttempts(target, attempts);
  }
  async runProbe(probe, target, context) {
    const startedAt = Date.now();
    let live = null;
    try {
      const connection = this.connect({ hostname: connectHostname(target), port: target.port }, { secureTransport: "starttls", allowHalfOpen: true });
      live = connection;
      const response = await withDeadline(async () => {
        await connection.opened;
        const tls = connection.startTls({ expectedServerHostname: probe.endpoint });
        live = tls;
        await tls.opened;
        return parseResponse(await exchange(tls, probe.request, this.readLimitBytes));
      }, this.timeoutMs, context.signal);
      const latencyMs = Date.now() - startedAt;
      if (response.ok) {
        return { ok: true, exit: response.exit, statusCode: response.statusCode, latencyMs, endpoint: probe.endpoint };
      }
      return { ok: false, failure: "INVALID_RESPONSE", message: response.message, latencyMs, endpoint: probe.endpoint };
    } catch (error) {
      const failure = classifyError(error, context.signal);
      return {
        ok: false,
        failure,
        message: describeFailure(failure, error),
        latencyMs: Date.now() - startedAt,
        endpoint: probe.endpoint
      };
    } finally {
      await closeQuietly(live);
    }
  }
};
function combineAttempts(target, attempts) {
  const succeeded = attempts.filter((attempt) => attempt.ok);
  const latencyMs = Math.min(...attempts.map((attempt) => attempt.latencyMs));
  if (succeeded.length > 0) {
    const exits = uniqueExits(succeeded.map((attempt) => attempt.exit));
    const exitIp = exits.find((exit) => exit.family === "ipv4")?.ip ?? exits[0]?.ip;
    return alive(target, {
      endpoint: "socket",
      exitFamily: familyFromExits(exits),
      exits,
      ...exitIp ? { exitIp } : {},
      latencyMs
    });
  }
  const failed = attempts.filter((attempt) => !attempt.ok);
  const failure = dominantFailure(failed);
  const message = failed[0]?.message ?? "Socket \u63A2\u9488\u672A\u8FD4\u56DE\u53EF\u7528\u51FA\u53E3";
  if (failure === "REFUSED") {
    return dead(target, { endpoint: "socket", latencyMs, message: "\u4E24\u4E2A Socket \u63A2\u9488\u90FD\u65E0\u6CD5\u8FDE\u63A5\u5019\u9009\u5730\u5740" });
  }
  return unknown(target, failure, message, { endpoint: "socket", latencyMs });
}
__name(combineAttempts, "combineAttempts");
function dominantFailure(failed) {
  const kinds = new Set(failed.map((attempt) => attempt.failure));
  if (kinds.size === 1) return failed[0]?.failure ?? "NETWORK_ERROR";
  return kinds.has("CANCELLED") ? "CANCELLED" : "NETWORK_ERROR";
}
__name(dominantFailure, "dominantFailure");
function familyFromExits(exits) {
  const families = new Set(exits.map((exit) => exit.family));
  const hasIpv4 = families.has("ipv4");
  const hasIpv6 = families.has("ipv6");
  if (hasIpv4 && hasIpv6) return "dual";
  if (hasIpv4) return "ipv4";
  if (hasIpv6) return "ipv6";
  return "unknown";
}
__name(familyFromExits, "familyFromExits");
function buildTarget(url) {
  const parsed = parseSocketProbeUrl(url);
  if (!parsed) return null;
  return { endpoint: parsed.endpoint, request: buildRequest(parsed) };
}
__name(buildTarget, "buildTarget");
function connectHostname(target) {
  return target.family === "ipv6" ? `[${target.host}]` : target.host;
}
__name(connectHostname, "connectHostname");
function buildRequest(parsed) {
  const request = [
    `GET ${parsed.path} HTTP/1.1`,
    `Host: ${parsed.hostHeader}`,
    "Accept: application/json, text/plain, */*",
    "Accept-Encoding: identity",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Connection: close",
    "",
    ""
  ].join("\r\n");
  return new TextEncoder().encode(request);
}
__name(buildRequest, "buildRequest");
async function exchange(tls, request, readLimitBytes) {
  const writer = tls.writable.getWriter();
  try {
    await writer.write(request);
  } finally {
    writer.releaseLock();
  }
  return readLimited(tls.readable, readLimitBytes);
}
__name(exchange, "exchange");
async function readLimited(stream, limit) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      const remaining = limit - total;
      const chunk = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      chunks.push(chunk);
      total += chunk.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  return concatBytes(chunks, total);
}
__name(readLimited, "readLimited");
var HEADER_SEPARATOR = Uint8Array.of(13, 10, 13, 10);
var LINE_SEPARATOR = Uint8Array.of(13, 10);
var HTTP_STATUS_RE = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/;
var CHUNKED_RE = /transfer-encoding:\s*chunked/i;
function parseResponse(raw) {
  if (raw.byteLength === 0) return { ok: false, message: "Socket \u63A2\u9488\u8FD4\u56DE\u7A7A\u54CD\u5E94" };
  const splitIndex = indexOfBytes(raw, HEADER_SEPARATOR);
  const headerText = decode(splitIndex < 0 ? raw : raw.subarray(0, splitIndex));
  const bodyBytes = splitIndex < 0 ? new Uint8Array(0) : raw.subarray(splitIndex + HEADER_SEPARATOR.byteLength);
  const statusCode = Number(HTTP_STATUS_RE.exec(headerText)?.[1] ?? 0);
  if (statusCode !== 200) {
    return { ok: false, message: `Socket \u63A2\u9488 HTTP \u72B6\u6001\u5F02\u5E38\uFF08${statusCode || "unknown"}\uFF09`, ...statusCode ? { statusCode } : {} };
  }
  let body = bodyBytes;
  if (CHUNKED_RE.test(headerText)) {
    const decoded = decodeChunked(bodyBytes);
    if (!decoded) return { ok: false, message: "Socket \u63A2\u9488\u54CD\u5E94\u5206\u5757\u6570\u636E\u4E0D\u5B8C\u6574", statusCode };
    body = decoded;
  }
  let payload;
  try {
    payload = JSON.parse(decode(body));
  } catch {
    return { ok: false, message: "Socket \u63A2\u9488\u54CD\u5E94\u4E0D\u662F\u5408\u6CD5 JSON", statusCode };
  }
  const exit = readProbeExit(asRecord(payload) ?? {}, void 0);
  if (!exit?.ip) return { ok: false, message: "Socket \u63A2\u9488\u54CD\u5E94\u7F3A\u5C11\u51FA\u53E3 IP", statusCode };
  return { ok: true, exit, statusCode };
}
__name(parseResponse, "parseResponse");
function decodeChunked(body) {
  const chunks = [];
  let offset = 0;
  let total = 0;
  while (offset < body.byteLength) {
    const lineEnd = indexOfBytes(body, LINE_SEPARATOR, offset);
    if (lineEnd < 0) return null;
    const sizeHex = decode(body.subarray(offset, lineEnd)).split(";")[0]?.trim() ?? "";
    const size = Number.parseInt(sizeHex, 16);
    if (!Number.isFinite(size) || size < 0) return null;
    const bodyStart = lineEnd + LINE_SEPARATOR.byteLength;
    if (size === 0) return concatBytes(chunks, total);
    const bodyEnd = bodyStart + size;
    if (bodyEnd > body.byteLength) return null;
    const chunk = body.subarray(bodyStart, bodyEnd);
    chunks.push(chunk);
    total += chunk.byteLength;
    offset = bodyEnd + LINE_SEPARATOR.byteLength;
  }
  return null;
}
__name(decodeChunked, "decodeChunked");
function indexOfBytes(haystack, needle, start = 0) {
  const limit = haystack.byteLength - needle.byteLength;
  outer: for (let index = start; index <= limit; index += 1) {
    for (let offset = 0; offset < needle.byteLength; offset += 1) {
      if (haystack[index + offset] !== needle[offset]) continue outer;
    }
    return index;
  }
  return -1;
}
__name(indexOfBytes, "indexOfBytes");
function concatBytes(chunks, total) {
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}
__name(concatBytes, "concatBytes");
function decode(bytes) {
  return new TextDecoder().decode(bytes);
}
__name(decode, "decode");
var ProbeTimeoutError = class extends Error {
  static {
    __name(this, "ProbeTimeoutError");
  }
};
var ProbeAbortedError = class extends Error {
  static {
    __name(this, "ProbeAbortedError");
  }
};
async function withDeadline(work, timeoutMs, externalSignal) {
  let timer;
  let onAbort;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new ProbeTimeoutError(`socket probe timeout after ${timeoutMs}ms`)), timeoutMs);
  });
  timeout.catch(() => void 0);
  const marks = [timeout];
  if (externalSignal) {
    const aborted = new Promise((_, reject) => {
      onAbort = /* @__PURE__ */ __name(() => reject(new ProbeAbortedError("socket probe aborted")), "onAbort");
      if (externalSignal.aborted) onAbort();
      else externalSignal.addEventListener("abort", onAbort, { once: true });
    });
    aborted.catch(() => void 0);
    marks.push(aborted);
  }
  try {
    return await Promise.race([work(), ...marks]);
  } finally {
    if (timer !== void 0) clearTimeout(timer);
    if (onAbort) externalSignal?.removeEventListener("abort", onAbort);
  }
}
__name(withDeadline, "withDeadline");
function classifyError(error, externalSignal) {
  if (error instanceof ProbeTimeoutError) return "TIMEOUT";
  if (error instanceof ProbeAbortedError || externalSignal?.aborted) return "CANCELLED";
  if (isConnectionRefused(error)) return "REFUSED";
  return "NETWORK_ERROR";
}
__name(classifyError, "classifyError");
function isConnectionRefused(error) {
  return error instanceof Error && /refused|ECONNREFUSED/i.test(error.message);
}
__name(isConnectionRefused, "isConnectionRefused");
function describeFailure(failure, error) {
  const detail = error instanceof Error ? trimMessage2(error.message) : void 0;
  if (failure === "CANCELLED") return "\u68C0\u6D4B\u5DF2\u53D6\u6D88";
  if (failure === "TIMEOUT") return "Socket \u63A2\u9488\u8D85\u65F6";
  if (failure === "REFUSED") return "Socket \u63A2\u9488\u8FDE\u63A5\u88AB\u62D2\u7EDD";
  if (failure === "INVALID_RESPONSE") return detail ?? "Socket \u63A2\u9488\u54CD\u5E94\u4E0D\u53EF\u7528";
  return detail ? `Socket \u63A2\u9488\u7F51\u7EDC\u5F02\u5E38\uFF1A${detail}` : "Socket \u63A2\u9488\u7F51\u7EDC\u5F02\u5E38";
}
__name(describeFailure, "describeFailure");
function cancelled(target) {
  return unknown(target, "CANCELLED", "\u68C0\u6D4B\u5DF2\u53D6\u6D88", { endpoint: "socket" });
}
__name(cancelled, "cancelled");
function trimMessage2(value) {
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, 160) : void 0;
}
__name(trimMessage2, "trimMessage");
async function closeQuietly(socket) {
  if (!socket) return;
  try {
    await socket.close();
  } catch {
  }
}
__name(closeQuietly, "closeQuietly");

// app/src/adapters/probe/unconfigured.ts
var UnconfiguredProbeAdapter = class {
  static {
    __name(this, "UnconfiguredProbeAdapter");
  }
  name = "unconfigured";
  async probe(target) {
    return unknown(target, "NOT_CONFIGURED", "\u672A\u914D\u7F6E\u68C0\u6D4B\u63A5\u53E3");
  }
};

// app/src/config/runtime.ts
function loadEnvConfig(env) {
  const defaults = createDefaultConfig();
  const mode = readProbeMode(env.PROBE_MODE);
  const apiKey = env.CF_KEY?.trim() ?? "";
  const zoneId = env.CF_ZONEID?.trim() ?? "";
  const baseDomain = env.CF_BASE_DOMAIN?.trim().replace(/^\.+|\.+$/g, "") ?? "";
  return {
    ...defaults,
    apiKey,
    zoneId,
    zones: apiKey || zoneId || baseDomain ? [{ name: baseDomain || "\u73AF\u5883\u53D8\u91CF\u914D\u7F6E", baseDomain, zoneId, apiKey, label: baseDomain || "\u73AF\u5883\u53D8\u91CF\u914D\u7F6E" }] : defaults.zones,
    checkApi: normalizeCheckApi(env.CHECK_API ?? defaults.checkApi, mode),
    checkApiBackup: normalizeCheckApi(env.CHECK_API_BACKUP ?? defaults.checkApiBackup, mode),
    dohApi: readLengthBounded(env.DOH_API, defaults.dohApi),
    authKey: readLengthBounded(env.AUTH_KEY, defaults.authKey),
    tgToken: readLengthBounded(env.TG_TOKEN, defaults.tgToken),
    tgId: readLengthBounded(env.TG_ID, defaults.tgId, 64),
    scheduledEnabled: readBooleanEnv(env.SCHEDULED_ENABLED, defaults.scheduledEnabled),
    tgEnabled: readBooleanEnv(env.TG_ENABLED, defaults.tgEnabled),
    probeMode: mode,
    socketProbeIpv4Url: readProbeUrlEnv(env.SOCKET_PROBE_IPV4_URL, defaults.socketProbeIpv4Url),
    socketProbeIpv6Url: readProbeUrlEnv(env.SOCKET_PROBE_IPV6_URL, defaults.socketProbeIpv6Url),
    settings: {
      ...DEFAULT_RUNTIME_SETTINGS,
      CHECK_TIMEOUT: parseInteger(env.CHECK_TIMEOUT, defaults.settings.CHECK_TIMEOUT, MIN_PROBE_TIMEOUT_MS, MAX_PROBE_TIMEOUT_MS),
      REMOTE_LOAD_TIMEOUT: parseInteger(
        env.REMOTE_LOAD_TIMEOUT,
        defaults.settings.REMOTE_LOAD_TIMEOUT,
        SETTINGS_LIMITS.REMOTE_LOAD_TIMEOUT.min,
        SETTINGS_LIMITS.REMOTE_LOAD_TIMEOUT.max
      )
    }
  };
}
__name(loadEnvConfig, "loadEnvConfig");
function createProbeAdapterFromConfig(config, deps = {}) {
  const internal = createInternalAdapter(config, deps);
  const external = createExternalAdapter(config, deps);
  if (internal && external) return new CompositeProbeAdapter({ internal, external, primary: config.primary });
  return internal ?? external ?? new UnconfiguredProbeAdapter();
}
__name(createProbeAdapterFromConfig, "createProbeAdapterFromConfig");
function createInternalAdapter(config, deps) {
  if (!deps.connect || !config.ipv4ProbeUrl && !config.ipv6ProbeUrl) return null;
  return new SocketProbeAdapter({
    ipv4Url: config.ipv4ProbeUrl,
    ipv6Url: config.ipv6ProbeUrl,
    timeoutMs: config.timeoutMs,
    readLimitBytes: config.readLimitBytes,
    connect: deps.connect
  });
}
__name(createInternalAdapter, "createInternalAdapter");
function createExternalAdapter(config, deps) {
  if (config.endpoints.length === 0) return null;
  return new ExternalApiProbeAdapter({
    endpoints: config.endpoints.map(({ name, urlTemplate }) => ({ name, urlTemplate })),
    timeoutMs: config.timeoutMs,
    fallbackToNext: config.fallbackToNext,
    fetchImpl: deps.fetchImpl ?? fetch
  });
}
__name(createExternalAdapter, "createExternalAdapter");
function readProbeMode(value) {
  const trimmed = value?.trim();
  return PROBE_MODES.find((mode) => mode === trimmed) ?? "external-api";
}
__name(readProbeMode, "readProbeMode");
function readProbeUrlEnv(value, fallback) {
  const trimmed = value?.trim();
  if (!trimmed) return fallback;
  return parseSocketProbeUrl(trimmed) ? trimmed : fallback;
}
__name(readProbeUrlEnv, "readProbeUrlEnv");
function normalizeCheckApi(rawValue, mode) {
  const value = rawValue.trim();
  if (!value) return "";
  return mode === "cmliu-check" ? buildCmliuUrlTemplate(value) ?? "" : value;
}
__name(normalizeCheckApi, "normalizeCheckApi");
function buildCmliuUrlTemplate(baseUrl) {
  try {
    const url = new URL(baseUrl);
    if (!url.pathname.replace(/\/+$/, "").endsWith("/check")) {
      url.pathname = `${url.pathname.replace(/\/+$/, "")}/check`;
    }
    url.searchParams.set("proxyip", "{proxyip}");
    return url.toString().replace("%7Bproxyip%7D", "{proxyip}");
  } catch {
    return null;
  }
}
__name(buildCmliuUrlTemplate, "buildCmliuUrlTemplate");
function parseInteger(value, fallback, min, max) {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}
__name(parseInteger, "parseInteger");
function readLengthBounded(value, fallback, max = MAX_ENDPOINT_URL_LENGTH) {
  if (value === void 0) return fallback;
  const trimmed = value.trim();
  return trimmed.length <= max ? trimmed : fallback;
}
__name(readLengthBounded, "readLengthBounded");
function readBooleanEnv(value, fallback) {
  if (value === void 0) return fallback;
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on", "enabled"].includes(normalized)) return true;
  if (["0", "false", "no", "off", "disabled"].includes(normalized)) return false;
  return fallback;
}
__name(readBooleanEnv, "readBooleanEnv");

// app/src/adapters/notify/telegram-message.ts
function buildTelegramMaintenanceMessage(run, options) {
  const title = options.isManual ? "DDNS \u624B\u52A8\u7EF4\u62A4\u62A5\u544A" : "DDNS \u81EA\u52A8\u7EF4\u62A4\u62A5\u544A";
  const lines = [
    `${options.isManual ? "\u{1F527}" : "\u2699\uFE0F"} <b>${title}</b>`,
    `\u23F0 ${escapeHtml(formatBeijingTimestamp(options.now ?? /* @__PURE__ */ new Date()))}`
  ];
  if (run.errors.length > 0) lines.push(`\u26A0\uFE0F <b>\u6267\u884C\u9519\u8BEF ${run.errors.length} \u9879</b>`);
  if (run.probeErrors > 0) lines.push(`\u26A0\uFE0F <b>\u68C0\u6D4B\u5F02\u5E38 ${run.probeErrors} \u6B21</b>\uFF0C\u76F8\u5173\u8282\u70B9\u672A\u505A\u5220\u9664\u6216\u66FF\u6362`);
  if (run.results.length === 0) lines.push("\u6CA1\u6709\u542F\u7528\u4E2D\u7684\u7EF4\u62A4\u76EE\u6807\u3002");
  for (const result of run.results) {
    lines.push("", `\u2501\u2501 <code>${escapeHtml(result.target.domain)}</code> \u2501\u2501`, formatTarget(result));
  }
  return lines.join("\n");
}
__name(buildTelegramMaintenanceMessage, "buildTelegramMaintenanceMessage");
function formatTarget(result) {
  if (result.error) return `\u274C \u6267\u884C\u5931\u8D25\uFF1A${escapeHtml(result.error)}`;
  if (!result.report) return "\u274C \u6CA1\u6709\u7EF4\u62A4\u62A5\u544A";
  const { report } = result;
  const mode = report.target.mode === "A" ? `A/AAAA \xB7 \u7AEF\u53E3 ${report.target.port}` : "TXT";
  const lines = [
    `${mode} \xB7 \u6700\u5C0F\u6D3B\u8DC3\u6570 ${report.target.minActive}`,
    `\u{1F4E6} \u4F7F\u7528\u6C60\uFF1A<b>${escapeHtml(result.poolName)}</b>`,
    `${report.plan.exhausted ? "\u274C" : "\u2705"} \u5B8C\u6210\uFF1A${report.plan.activeCount}/${report.target.minActive}`
  ];
  if (report.dnsUpdated) {
    lines.push(`\u{1F4DD} DNS \u66F4\u65B0\uFF1A\u65B0\u589E ${report.added}\uFF0C\u79FB\u9664 ${report.deleted}`);
  } else {
    lines.push("\u2728 DNS \u65E0\u53D8\u5316");
  }
  const additions = report.plan.additions.slice(0, 5).map(({ address }) => address);
  if (additions.length > 0) {
    lines.push(`\u65B0\u589E\u5019\u9009\uFF1A${additions.map((address) => `<code>${escapeHtml(address)}</code>`).join("\u3001")}${report.plan.additions.length > additions.length ? " \u2026" : ""}`);
  }
  const removed = report.plan.current.filter(({ decision }) => decision === "remove-dead" || decision === "remove-mismatch").slice(0, 5).map(({ item }) => item.address);
  if (removed.length > 0) lines.push(`\u79FB\u9664\u5730\u5740\uFF1A${removed.map((address) => `<code>${escapeHtml(address)}</code>`).join("\u3001")}`);
  if (report.plan.trash.length > 0) lines.push(`\u{1F5D1}\uFE0F \u653E\u5165\u5783\u573E\u6876\uFF1A${report.plan.trash.length} \u4E2A`);
  if (report.plan.exhausted) lines.push("\u26A0\uFE0F \u5019\u9009\u4E0D\u8DB3\uFF0C\u672A\u8FBE\u5230\u6700\u5C0F\u6D3B\u8DC3\u6570");
  for (const error of report.errors.slice(0, 5)) lines.push(`\u26A0\uFE0F ${escapeHtml(error)}`);
  return lines.join("\n");
}
__name(formatTarget, "formatTarget");
function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char] ?? char);
}
__name(escapeHtml, "escapeHtml");

// app/src/jobs/maintenance-job.ts
async function runMaintenanceJob(options) {
  const data = await options.source.load();
  const run = await options.maintainer.execute(data, options.fallbackZone);
  if (!shouldNotifyMaintenance(run, options.isManual)) return { run, notification: null };
  const notification = await options.notifier.send(buildTelegramMaintenanceMessage(run, {
    isManual: options.isManual,
    ...options.now ? { now: options.now() } : {}
  }));
  return { run, notification };
}
__name(runMaintenanceJob, "runMaintenanceJob");

// app/src/transport/auth.ts
function isAuthorized(request, expectedKey) {
  const expected = expectedKey?.trim();
  if (!expected) return true;
  const authorization = request.headers.get("authorization") ?? "";
  const bearer = authorization.toLowerCase().startsWith("bearer ") ? authorization.slice(7).trim() : "";
  const headerKey = request.headers.get("x-auth-key")?.trim() ?? "";
  const queryKey = new URL(request.url).searchParams.get("key")?.trim() ?? "";
  return [bearer, headerKey, queryKey].some((candidate) => candidate && constantTimeEqual(candidate, expected));
}
__name(isAuthorized, "isAuthorized");
function constantTimeEqual(left, right) {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.max(leftBytes.length, rightBytes.length);
  let diff = leftBytes.length ^ rightBytes.length;
  for (let index = 0; index < length; index += 1) {
    diff |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return diff === 0;
}
__name(constantTimeEqual, "constantTimeEqual");

// app/src/transport/router.ts
var Router = class {
  static {
    __name(this, "Router");
  }
  routes = [];
  get(path, handler) {
    return this.add("GET", path, handler);
  }
  post(path, handler) {
    return this.add("POST", path, handler);
  }
  put(path, handler) {
    return this.add("PUT", path, handler);
  }
  delete(path, handler) {
    return this.add("DELETE", path, handler);
  }
  add(method, path, handler) {
    this.routes.push({ method, segments: path.split("/").filter(Boolean), handler });
    return this;
  }
  async handle(request) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    for (const route of this.routes) {
      if (route.method !== request.method || route.segments.length !== parts.length) continue;
      const params = matchSegments(route.segments, parts);
      if (!params) continue;
      return await route.handler({ request, url, params });
    }
    return null;
  }
};
function matchSegments(routeSegments, parts) {
  const params = {};
  for (let index = 0; index < routeSegments.length; index += 1) {
    const segment = routeSegments[index];
    const part = parts[index];
    if (segment.startsWith(":")) {
      params[segment.slice(1)] = decodeURIComponent(part);
      continue;
    }
    if (segment !== part) return null;
  }
  return params;
}
__name(matchSegments, "matchSegments");
function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}
__name(jsonResponse, "jsonResponse");
function errorResponse(error, status) {
  const body = { error };
  return jsonResponse(body, status);
}
__name(errorResponse, "errorResponse");
async function readJsonBody(request) {
  try {
    return { ok: true, value: await request.json() };
  } catch {
    return { ok: false };
  }
}
__name(readJsonBody, "readJsonBody");

// app/src/transport/http.ts
function createHttpApp(dependencies) {
  const router = new Router();
  const guard = /* @__PURE__ */ __name((context) => isAuthorized(context.request, dependencies.authKey) ? null : errorResponse("unauthorized", 401), "guard");
  router.get("/", (context) => {
    if (dependencies.assets) return dependencies.assets.fetch(context.request);
    return jsonResponse({
      name: "ddns-cf-proxyip",
      version: dependencies.version,
      api: "/api/check?proxyip=1.2.3.4:443"
    });
  });
  router.get("/api/health", () => {
    const response = {
      ok: true,
      version: dependencies.version,
      ...dependencies.configSource ? { configSource: dependencies.configSource } : {}
    };
    return jsonResponse(response);
  });
  router.get("/api/check", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const parsed = parseCheckProxyInput(context.url.searchParams.get("proxyip"));
    if (!parsed.ok) return errorResponse("invalid proxyip", 400);
    const result = await dependencies.checkProxy.execute(parsed.value, { signal: context.request.signal });
    return jsonResponse(toProbeResponse(result));
  });
  router.post("/api/check", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    const parsed = parseCheckProxyInput(body.value?.proxyip);
    if (!parsed.ok) return errorResponse("invalid proxyip", 400);
    const result = await dependencies.checkProxy.execute(parsed.value, { signal: context.request.signal });
    return jsonResponse(toProbeResponse(result));
  });
  router.post("/api/check/batch", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const checkPool = dependencies.checkPool;
    if (!checkPool) return errorResponse("probe unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    const text3 = body.value?.text;
    if (typeof text3 !== "string" || !text3.trim()) return errorResponse("invalid text", 400);
    const report = await checkPool.execute(text3, { signal: context.request.signal });
    return jsonResponse(toPoolCheckResponse(report));
  });
  router.get("/api/pools", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const pools = dependencies.pools;
    if (!pools) return errorResponse("pool storage unavailable", 503);
    const response = { pools: await pools.list() };
    return jsonResponse(response);
  });
  router.post("/api/pools", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const pools = dependencies.pools;
    if (!pools) return errorResponse("pool storage unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    return await mapApplicationInputError(async () => {
      const pool = await pools.create(body.value?.displayName);
      const response = { ok: true, key: pool.key, displayName: pool.name };
      return jsonResponse(response);
    });
  });
  router.put("/api/pools/order", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const pools = dependencies.pools;
    if (!pools) return errorResponse("pool storage unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    return await mapApplicationInputError(async () => {
      await pools.saveOrder(body.value?.order);
      return jsonResponse({ ok: true });
    });
  });
  router.post("/api/pools/trash/clear", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const pools = dependencies.pools;
    if (!pools) return errorResponse("pool storage unavailable", 503);
    await pools.clearTrash();
    return jsonResponse({ ok: true });
  });
  router.post("/api/pools/trash/restore", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const pools = dependencies.pools;
    if (!pools) return errorResponse("pool storage unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    return await mapApplicationInputError(async () => {
      const input = body.value;
      const result = await pools.restoreTrash(input?.addresses, input?.restoreToSource, input?.targetPool);
      const response = result;
      return jsonResponse(response);
    });
  });
  router.get("/api/pools/:key", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const pools = dependencies.pools;
    if (!pools) return errorResponse("pool storage unavailable", 503);
    return await mapApplicationInputError(async () => {
      const response = {
        key: context.params.key,
        content: await pools.read(context.params.key)
      };
      return jsonResponse(response);
    });
  });
  router.put("/api/pools/:key", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const pools = dependencies.pools;
    if (!pools) return errorResponse("pool storage unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    return await mapApplicationInputError(async () => {
      const input = body.value;
      const result = await pools.save(context.params.key, input?.content, input?.mode);
      const response = result;
      return jsonResponse(response);
    });
  });
  router.add("PATCH", "/api/pools/:key", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const pools = dependencies.pools;
    if (!pools) return errorResponse("pool storage unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    return await mapApplicationInputError(async () => {
      await pools.rename(context.params.key, body.value?.displayName);
      return jsonResponse({ ok: true });
    });
  });
  router.delete("/api/pools/:key", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const pools = dependencies.pools;
    if (!pools) return errorResponse("pool storage unavailable", 503);
    return await mapApplicationInputError(async () => {
      await pools.remove(context.params.key);
      return jsonResponse({ ok: true });
    });
  });
  router.get("/api/domain-bindings", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const bindings = dependencies.domainBindings;
    if (!bindings) return errorResponse("binding storage unavailable", 503);
    return jsonResponse(await bindings.list());
  });
  router.put("/api/domain-bindings", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const bindings = dependencies.domainBindings;
    if (!bindings) return errorResponse("binding storage unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    return await mapApplicationInputError(async () => {
      await bindings.save(body.value?.mapping);
      return jsonResponse({ ok: true });
    });
  });
  router.put("/api/domain-bindings/order", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const bindings = dependencies.domainBindings;
    if (!bindings) return errorResponse("binding storage unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    return await mapApplicationInputError(async () => {
      await bindings.saveOrder(body.value?.order);
      return jsonResponse({ ok: true });
    });
  });
  router.post("/api/maintenance/run", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const maintenance = dependencies.maintenance;
    if (!maintenance) return errorResponse("maintenance unavailable", 503);
    const { run } = await maintenance.run(true);
    return jsonResponse(toMaintenanceResponse(run));
  });
  router.get("/api/config", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const config = dependencies.config;
    if (!config) return errorResponse("config storage unavailable", 503);
    return jsonResponse(toConfigResponse(await config.resolve()));
  });
  router.put("/api/config", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const config = dependencies.config;
    if (!config) return errorResponse("config storage unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    const resolved = await config.resolve();
    const parsed = parseAppConfig(body.value, resolved.config);
    if (!parsed.ok) return errorResponse(parsed.message, 400);
    await config.save(parsed.value);
    return jsonResponse(toConfigResponse({ config: parsed.value, source: "kv" }));
  });
  router.post("/api/config/probe/test", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const selfTest = dependencies.probeSelfTest;
    if (!selfTest) return errorResponse("probe self test unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    const parsed = parseProbeTestRequest(body.value);
    if (!parsed.ok) return errorResponse(parsed.message, 400);
    const config = dependencies.config ? (await dependencies.config.resolve()).config : createDefaultConfig();
    const result = await selfTest.execute(
      { proxyip: parsed.value.proxyip, config, ...parsed.value.draft ? { draft: parsed.value.draft } : {} },
      { signal: context.request.signal }
    );
    return jsonResponse(toProbeTestResponse(result));
  });
  router.post("/api/remote-load", async (context) => {
    const denied = guard(context);
    if (denied) return denied;
    const loader = dependencies.remotePoolLoader;
    if (!loader) return errorResponse("remote load unavailable", 503);
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    const url = body.value?.url;
    const result = await loader.load(typeof url === "string" ? url : "", { signal: context.request.signal });
    if (!result.ok) return errorResponse(result.reason, remoteLoadStatus(result.reason));
    const response = {
      url: result.finalUrl,
      content: result.content,
      count: countPoolTextLines(result.content)
    };
    return jsonResponse(response);
  });
  const fetch2 = /* @__PURE__ */ __name(async (request) => {
    try {
      const matched = await router.handle(request);
      if (matched) return matched;
      const path = new URL(request.url).pathname;
      const canServeAsset = request.method === "GET" || request.method === "HEAD";
      if (dependencies.assets && canServeAsset && !path.startsWith("/api/")) {
        return await dependencies.assets.fetch(request);
      }
      return errorResponse("not found", 404);
    } catch (error) {
      console.error("Unhandled worker error", error);
      return errorResponse("internal error", 500);
    }
  }, "fetch");
  return {
    fetch: fetch2,
    request: /* @__PURE__ */ __name((input, init) => fetch2(typeof input === "string" ? new Request(new URL(input, "http://localhost"), init) : input), "request")
  };
}
__name(createHttpApp, "createHttpApp");
async function mapApplicationInputError(run) {
  try {
    return await run();
  } catch (error) {
    if (error instanceof PoolInputError || error instanceof DomainBindingsInputError) {
      return errorResponse(error.message, 400);
    }
    throw error;
  }
}
__name(mapApplicationInputError, "mapApplicationInputError");
function toConfigResponse(resolved) {
  return {
    source: resolved.source,
    ...resolved.notice ? { notice: resolved.notice } : {},
    config: toPublicConfig(resolved.config)
  };
}
__name(toConfigResponse, "toConfigResponse");
function remoteLoadStatus(reason) {
  if (reason === "invalid-url" || reason === "blocked-host") return 400;
  if (reason === "too-large") return 413;
  if (reason === "timeout") return 504;
  return 502;
}
__name(remoteLoadStatus, "remoteLoadStatus");
function toMaintenanceResponse(run) {
  return {
    ok: true,
    changed: run.changed,
    insufficient: run.insufficient,
    errors: run.errors,
    probeErrors: run.probeErrors,
    results: run.results.map(({ target, poolKey, poolName, report, error }) => ({
      domain: target.domain,
      mode: target.mode,
      poolKey,
      poolName,
      dnsUpdated: report?.dnsUpdated ?? false,
      added: report?.added ?? 0,
      deleted: report?.deleted ?? 0,
      probeErrors: report?.probeErrors ?? 0,
      error: error ?? (report?.errors.length ? report.errors.join("\uFF1B") : null)
    }))
  };
}
__name(toMaintenanceResponse, "toMaintenanceResponse");
function toProbeResponse(result) {
  const { target: _target, ...response } = result;
  return response;
}
__name(toProbeResponse, "toProbeResponse");
function toProbeTestResponse(result) {
  return {
    proxyip: result.proxyip,
    items: result.items.map((item) => ({
      id: item.id,
      label: item.label,
      configured: item.configured,
      ...item.result ? { result: toProbeResponse(item.result) } : {},
      ...item.error ? { error: item.error } : {}
    }))
  };
}
__name(toProbeTestResponse, "toProbeTestResponse");
function toPoolCheckResponse(report) {
  return {
    total: report.total,
    alive: report.alive,
    dead: report.dead,
    unknown: report.unknown,
    invalid: report.invalid,
    items: report.items.map(toPoolCheckItemResponse)
  };
}
__name(toPoolCheckResponse, "toPoolCheckResponse");
function toPoolCheckItemResponse(item) {
  const { result, entry } = item;
  const primary = result.exits[0];
  const asn = primary?.asn ?? entry.asn ?? void 0;
  const country = primary?.country ?? entry.country ?? void 0;
  return {
    address: item.address,
    status: result.status,
    exitFamily: result.exitFamily,
    ...result.exitIp ? { exitIp: result.exitIp } : {},
    ...result.latencyMs === void 0 ? {} : { latencyMs: result.latencyMs },
    ...result.code ? { code: result.code } : {},
    ...result.message ? { message: result.message } : {},
    ...asn ? { asn } : {},
    ...country ? { country } : {},
    // 复用领域层的序列化规则，保证入库文本与监控流程完全一致。
    line: formatPoolEntry(entry)
  };
}
__name(toPoolCheckItemResponse, "toPoolCheckItemResponse");

// app/src/worker.ts
var APP_VERSION = "2026.09.26-10.21";
var BATCH_CHECK_CONCURRENCY = 8;
var DNS_TIMEOUT_MS = 1e4;
function createWorker(overrides = {}) {
  const handler = {
    async fetch(request, env, executionContext) {
      const configService = createConfigService(env);
      const resolved = await configService.resolve();
      const probeDeps = probeAdapterDeps(overrides);
      const createProbe = /* @__PURE__ */ __name((config) => createProbeAdapterFromConfig(config, probeDeps), "createProbe");
      const checkProxy = new CheckProxy(createProbe(toProbeConfig(resolved.config)));
      const authKey = resolved.config.authKey || env.AUTH_KEY?.trim();
      const kv = env.IP_DATA;
      const assets = overrides.assets;
      const maintenanceSource = kv ? new KvMaintenanceSource(kv) : null;
      const maintenance = kv && maintenanceSource ? createMaintenanceRunner(kv, resolved.config, overrides, maintenanceSource) : null;
      const dependencies = {
        checkProxy,
        checkPool: new CheckPoolText(checkProxy, BATCH_CHECK_CONCURRENCY),
        version: APP_VERSION,
        configSource: resolved.source,
        config: configService,
        probeSelfTest: new ProbeSelfTest(createProbe),
        remotePoolLoader: new RemotePoolLoader({ timeoutMs: resolved.config.settings.REMOTE_LOAD_TIMEOUT }),
        ...authKey ? { authKey } : {},
        ...assets ? { assets } : {},
        ...kv ? {
          pools: new PoolService(new KvPoolCatalog(kv)),
          domainBindings: new DomainBindings(maintenanceSource, new KvDomainBindingRepository(kv)),
          ...maintenance ? { maintenance } : {}
        } : {}
      };
      return createHttpApp(dependencies).fetch(request, env, executionContext);
    },
    /**
     * 定时维护：缺少 KV 绑定或没开启定时维护时直接跳过。
     * 手动维护复用同一个 runner，保证两条路径的装配与行为完全一致。
     */
    async scheduled(_controller, env, executionContext) {
      if (!env.IP_DATA) {
        console.error("\u8DF3\u8FC7\u5B9A\u65F6\u7EF4\u62A4\uFF1A\u8BF7\u5148\u7ED1\u5B9A\u540D\u4E3A IP_DATA \u7684 KV Namespace");
        return;
      }
      const resolved = await createConfigService(env).resolve();
      if (!resolved.config.scheduledEnabled) {
        console.log("\u5B9A\u65F6\u7EF4\u62A4\u5DF2\u5173\u95ED\uFF0C\u8DF3\u8FC7\u6267\u884C");
        return;
      }
      const source = new KvMaintenanceSource(env.IP_DATA);
      executionContext.waitUntil(createMaintenanceRunner(env.IP_DATA, resolved.config, overrides, source).run(false));
    }
  };
  return handler;
}
__name(createWorker, "createWorker");
function probeAdapterDeps(overrides) {
  return overrides.connect ? { connect: overrides.connect } : {};
}
__name(probeAdapterDeps, "probeAdapterDeps");
function createConfigService(env) {
  return new ConfigService({
    envConfig: loadEnvConfig(env),
    ...env.IP_DATA ? {
      repository: new KvConfigRepository(env.IP_DATA)
    } : {}
  });
}
__name(createConfigService, "createConfigService");
function createMaintenanceRunner(kv, config, overrides = {}, source) {
  const maintenanceSource = source ?? new KvMaintenanceSource(kv);
  const maintainer = new MaintainManagedTargets({
    maintainer: new MaintainManagedTarget({
      probe: createProbeAdapterFromConfig(toProbeConfig(config), probeAdapterDeps(overrides)),
      pools: new KvPoolRepository(kv, { maxTrashSize: config.settings.MAX_TRASH_SIZE }),
      dns: new CloudflareDnsRepository({ timeoutMs: DNS_TIMEOUT_MS })
    })
  });
  const notifier = new TelegramNotifier({
    enabled: config.tgEnabled,
    token: config.tgToken,
    chatId: config.tgId
  });
  return {
    run: /* @__PURE__ */ __name((isManual) => runMaintenanceJob({
      source: maintenanceSource,
      maintainer,
      notifier,
      fallbackZone: { zoneId: config.zoneId, apiToken: config.apiKey },
      isManual
    }), "run")
  };
}
__name(createMaintenanceRunner, "createMaintenanceRunner");

// app/dist/bundle-build/generated/assets.ts
var BUNDLED_WEB_ASSETS = {
  "/assets/config-page-5NPBZckn.js": { contentType: "text/javascript; charset=utf-8", base64: "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", gzip: true },
  "/assets/index-BdN8oN7H.js": { contentType: "text/javascript; charset=utf-8", base64: "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", gzip: true },
  "/assets/index-DgaTua5-.css": { contentType: "text/css; charset=utf-8", base64: "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", gzip: true },
  "/index.html": { contentType: "text/html; charset=utf-8", base64: "H4sIAAAAAAACCm1Sy24TMRTdV8o/XMxiFnTiKSjqQ+NZlAjRTRSJ8gGufTNj8NijsTuZ9ANYIEBZI1URqGtWLJBY8DO0ETs+ATmThkTqwvL19T1H5x6d9JG0ws8qhMKXOuvtpeEGzU3OyFURPx+RrLcHkBbI5aoCSEv0HETBa4eekdfnL+IjAnTn1/ASGWkUTitbewLCGo/GMzJV0hdMYqMExqvHPiijvOI6doJrZAcPc/kCS4yF1bbeons8GUwGk8OHIRKdqFXllTVbkOFw9ArGtYXbm8+3i8Xt/OPy25fl/N3vH59Cu52djWH58/vd+5s/11/vrn9tcWtl3nYlQI2aESWsIfedosYJI5J7fqJKniN1Tf6kLfV+6poc2lIbx6LC++qE0ul02p8+69s6p0+TJAmjEQS7Tm3LogQSOEhWJ8pSj62HGYuS/jGWEUys8bFTV8ii4yTK/i4+zFMaZrI00GRrPRvRXnmN2WbrGM7G3cLdeintBtbTnWMQIsFIaeWlRgKits7ZWuXKgKsFI5Q7h95RZSS28akcHdnR4cv+G0eCiBVF9t+yzivnZxpdgeh3CTvbdhmHOT+/5IO4L5wjgSmlmwCmF1bOQGjuHCPVRTwg99qlakBJRnhVBR1SNVlvhaABEsJN1yn/ByVXjF33AgAA", gzip: true }
};

// app/dist/bundle-build/generated/index.ts
var index_default = createWorker({ connect, assets: createBundledAssets(BUNDLED_WEB_ASSETS) });
export {
  index_default as default
};
