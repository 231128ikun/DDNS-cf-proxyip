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
    mode: config.probeMode,
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
    const [keys, names, savedOrder] = await Promise.all([
      this.listPoolKeys(),
      this.readNames(),
      this.readOrder()
    ]);
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
  if (config.mode === "socket") {
    if (!deps.connect || !config.ipv4ProbeUrl && !config.ipv6ProbeUrl) return new UnconfiguredProbeAdapter();
    return new SocketProbeAdapter({
      ipv4Url: config.ipv4ProbeUrl,
      ipv6Url: config.ipv6ProbeUrl,
      timeoutMs: config.timeoutMs,
      readLimitBytes: config.readLimitBytes,
      connect: deps.connect
    });
  }
  if (config.endpoints.length === 0) return new UnconfiguredProbeAdapter();
  return new ExternalApiProbeAdapter({
    endpoints: config.endpoints.map(({ name, urlTemplate }) => ({ name, urlTemplate })),
    timeoutMs: config.timeoutMs,
    fallbackToNext: config.fallbackToNext,
    fetchImpl: deps.fetchImpl ?? fetch
  });
}
__name(createProbeAdapterFromConfig, "createProbeAdapterFromConfig");
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

// app/src/contracts/probe.ts
var MAX_PROXYIP_LENGTH = 512;
function parseCheckProxyInput(value) {
  const proxyip = readTrimmedString(value, 1, MAX_PROXYIP_LENGTH);
  if (!proxyip) return parseFail(`proxyip must be 1-${MAX_PROXYIP_LENGTH} characters`);
  return parseOk(proxyip);
}
__name(parseCheckProxyInput, "parseCheckProxyInput");

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
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse("invalid json", 400);
    const input = body.value;
    const parsed = parseCheckProxyInput(input?.proxyip);
    if (!parsed.ok) return errorResponse("invalid proxyip", 400);
    const template = input?.urlTemplate?.trim();
    const defaultConfig = createDefaultConfig();
    const checker = template ? new CheckProxy(
      createProbeAdapterFromConfig(toProbeConfig({
        ...defaultConfig,
        checkApi: template,
        checkApiBackup: "",
        probeMode: "external-api"
      }))
    ) : dependencies.checkProxy;
    const result = await checker.execute(parsed.value, { signal: context.request.signal });
    return jsonResponse(toProbeResponse(result));
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
      const checkProxy = new CheckProxy(createProbeAdapterFromConfig(toProbeConfig(resolved.config), probeDeps(overrides)));
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
function probeDeps(overrides) {
  return overrides.connect ? { connect: overrides.connect } : {};
}
__name(probeDeps, "probeDeps");
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
      probe: createProbeAdapterFromConfig(toProbeConfig(config), probeDeps(overrides)),
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
  "/assets/config-page-DkiHDIzs.js": { contentType: "text/javascript; charset=utf-8", base64: "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", gzip: true },
  "/assets/index-CivMVuwy.js": { contentType: "text/javascript; charset=utf-8", base64: "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", gzip: true },
  "/assets/index-Dhy-G5EY.css": { contentType: "text/css; charset=utf-8", base64: "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", gzip: true },
  "/index.html": { contentType: "text/html; charset=utf-8", base64: "H4sIAAAAAAACCm1Su24UMRTtV+IfLqaYgsx6AlpBInsKEkApiFbiIVE69t0Zg8cejZ155ANSIEBbI0UrUGoqCiQKfobNio5PQLOTwEZKYdm+Pvf43KPDbisnQ1ci5KEw6Yj1GxhhM05O8njvkKQjAJajUP0BgBUYBMhcVB4DJy9fPIkfEqCbj1YUyEmtsSldFQhIZwPawEmjVci5wlpLjNeXLdBWBy1M7KUwyLdvpAo5FhhLZ1y1wXZnNplNZg9u7FDoZaXLoJ3d6NjfP3wO08rB8vzTcrFYzj+svn5ezU9/ff/Yl9vuYAqrH98u3p3/PvtycfbzP7XR9u36BFCh4URLZ8llIa9wxokSQezqQmRIfZ3dbQuzxXydQVsY63mUh1DuUto0zbi5P3ZVRu8lSdJDI+ideuRaHiWQwHayXlHKArYBOh4l4x0sIpg5G2KvT5BHO0mU/lm8nzPaY1LW06SDnCvBQQeD6b+BYziYDrMOkzE6AAbw4BX0MeCkcOrYIAFZOe9dpTNtwVeSEyq8x+CptgrbeE/Xz14dN934jSe9gjXFhluDTz50Bn2OGK4TDp5dZ9zPu/jp5PHrsfR+SB29ih07cqoDaYT3nJRH8YRc/qR0DVpxIsqyV6F0PTT2+HTE6DrUt0Z/ASQ+HRrmAgAA", gzip: true }
};

// app/dist/bundle-build/generated/index.ts
var index_default = createWorker({ connect, assets: createBundledAssets(BUNDLED_WEB_ASSETS) });
export {
  index_default as default
};
