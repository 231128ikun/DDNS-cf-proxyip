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
  "/assets/config-page-DVopqECr.js": { contentType: "text/javascript; charset=utf-8", base64: "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", gzip: true },
  "/assets/index-B4q1688A.js": { contentType: "text/javascript; charset=utf-8", base64: "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", gzip: true },
  "/assets/index-Dhy-G5EY.css": { contentType: "text/css; charset=utf-8", base64: "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", gzip: true },
  "/index.html": { contentType: "text/html; charset=utf-8", base64: "H4sIAAAAAAACCm1Su24UMRTtV+IfLqaYgszOLLCwicYjEZagNNFKQEHp2HdnDB57GJt55AMoEKCtkaIVKDUVBRIFP8NmRccnIO8ksJFSWLavzz0+9+gkN4XhrisRcleodJD4DRTTGSUnefjoiKQDgCRHJvwBICnQMeA5qyw6Sp4/OwgnBKLtR80KpKSW2JSmcgS40Q61o6SRwuVUYC05hpvLDkgtnWQqtJwppKNrqVyOBYbcKFNtsd2aj+fj+YNrOwRaXsnSSaO3OqbTo6cwqwyszj6tlsvV4sP66+f14u2v7x99ue0OZ7D+8e383dnv0y/npz//UyupX21OABUqSiQ3mlwU8grnlAjm2J4sWIaRrbPbbaF2Eltn0BZKWxrkzpV7UdQ0zbC5OzRVFt2J49hDA/BO7ZuWBjHEMIo3K0gTh62DjgbxcBeLAOZGu9DKE6TBbhykf5bvF0nkMWniadJezqVgJ53C9N/AIRzO+ln7yZKoB/Tg3ivwMaCkMOKNQgK8MtaaSmZSg604JRGzFp2NpBbYhvv3Xo/uTyYPhy8t8Qo2FFtu9T5Z1ym0OaK7Sth7dpVxmnfhk/HjF0NubZ+66DJ2ybERHXDFrKWkPA7H5OInIWuQghJWll6FkHXf6PHpIIk2ob4x+AvWnAuF5gIAAA==", gzip: true }
};

// app/dist/bundle-build/generated/index.ts
var index_default = createWorker({ connect, assets: createBundledAssets(BUNDLED_WEB_ASSETS) });
export {
  index_default as default
};
