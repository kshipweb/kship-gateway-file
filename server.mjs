import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";

const MAX_BODY_BYTES = 1024;
const RELAY_BODY_BYTES = 8192;
const UPSTREAM_TIMEOUT_MS = 15_000;
const DEFAULT_PAGE_SIZE = 100;
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?!.*\.\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const ACCOUNT = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;
const WHMCS_ACTIONS = new Set(["GetClients", "GetClientsProducts", "GetClientsDomains", "GetInvoices"]);
const RELAY_PATHS = new Set(["/v1/relay/whmcs", "/v1/relay/whm"]);

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function getConfiguration() {
  return {
    apiKey: requiredEnvironment("RESELLERCLUB_API_KEY"),
    gatewayToken: requiredEnvironment("KSHIP_GATEWAY_TOKEN"),
    port: Number.parseInt(process.env.PORT ?? "8787", 10),
    resellerId: requiredEnvironment("RESELLERCLUB_RESELLER_ID"),
  };
}

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(body),
    "Content-Security-Policy": "default-src 'none'",
    "Content-Type": "application/json; charset=utf-8",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  });
  response.end(body);
}

function isAuthorized(request, expectedToken) {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return false;
  const suppliedToken = header.slice("Bearer ".length);
  const expected = Buffer.from(expectedToken);
  const supplied = Buffer.from(suppliedToken);
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}

function readJsonBody(request, limit = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > limit) {
        reject(new Error("Request body too large."));
        request.destroy();
      }
    });
    request.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("Invalid JSON body."));
      }
    });
    request.on("error", reject);
  });
}

function parsePaging(body) {
  const rawPage = Number(body.page ?? 1);
  const rawPageSize = Number(body.pageSize ?? DEFAULT_PAGE_SIZE);
  if (!Number.isInteger(rawPage) || rawPage < 1 || rawPage > 100_000) throw new Error("Invalid page.");
  if (!Number.isInteger(rawPageSize) || rawPageSize < 10 || rawPageSize > 500) throw new Error("Invalid pageSize.");
  return { page: rawPage, pageSize: rawPageSize };
}

function parseDomain(body) {
  const domain = typeof body.domain === "string" ? body.domain.trim().toLowerCase().replace(/\.$/, "") : "";
  if (!DOMAIN_PATTERN.test(domain)) throw new Error("Invalid domain.");
  return domain;
}

function numericValue(value) {
  const candidate = typeof value === "number" || typeof value === "string" ? String(value) : "";
  return /^\d+$/.test(candidate) && Number(candidate) > 0 ? candidate : null;
}

function emailValue(value) {
  if (typeof value !== "string") return null;
  const email = value.trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254 ? email : null;
}

function registrantEmail(details) {
  if (!details || typeof details !== "object") return null;
  const contact = details.registrantcontact ?? details.registrantContactDetails;
  if (!contact || typeof contact !== "object") return null;
  return emailValue(contact.emailaddr) || emailValue(contact.email);
}

function badRequest(message) {
  const error = new Error(message);
  error.statusCode = 400;
  error.publicMessage = message;
  return error;
}

function blockedHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host || host === "localhost" || host.endsWith(".local") || host.endsWith(".internal") || host === "metadata.google.internal") return true;
  const mapped = host.startsWith("::ffff:") ? host.slice(7) : host;
  if (mapped.includes(":")) return mapped === "::1";
  const parts = mapped.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

async function fetchRegistrarJson(config, path, parameters) {
  const url = new URL(`https://httpapi.com${path}`);
  url.search = new URLSearchParams({
    "api-key": config.apiKey,
    "auth-userid": config.resellerId,
    ...parameters,
  }).toString();
  const upstream = await (config.fetchImpl ?? fetch)(url, {
    headers: { Accept: "application/json" },
    method: "GET",
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
  const payload = await upstream.json().catch(() => null);
  if (!upstream.ok || !payload || (typeof payload === "object" && String(payload.status ?? "").toUpperCase() === "ERROR")) {
    console.error("ResellerClub read-only request failed", { path, status: upstream.status });
    const error = new Error("Registrar request failed.");
    error.statusCode = 502;
    throw error;
  }
  return payload;
}

async function fetchDomainOrders(config, paging) {
  const payload = await fetchRegistrarJson(config, "/api/domains/search.json", {
    "no-of-records": String(paging.pageSize),
    "page-no": String(paging.page),
  });
  if (!Array.isArray(payload) && (typeof payload !== "object" || payload === null)) {
    const error = new Error("Registrar returned an unexpected inventory payload.");
    error.statusCode = 502;
    throw error;
  }
  return payload;
}

async function fetchRegistrantContactEmail(config, domain) {
  const orderResult = await fetchRegistrarJson(config, "/api/domains/orderid.json", { "domain-name": domain });
  const orderId = numericValue(orderResult) || numericValue(orderResult?.orderid);
  if (!orderId) {
    const error = new Error("Registrant contact was not found.");
    error.statusCode = 404;
    throw error;
  }
  const details = await fetchRegistrarJson(config, "/api/domains/details.json", {
    "order-id": orderId,
    options: "RegistrantContactDetails",
  });
  if (String(details?.domainname || "").trim().toLowerCase().replace(/\.$/, "") !== domain) {
    const error = new Error("Registrant contact was not found.");
    error.statusCode = 404;
    throw error;
  }
  const email = registrantEmail(details);
  if (!email) {
    const error = new Error("Registrant contact was not found.");
    error.statusCode = 404;
    throw error;
  }
  return email;
}

async function relayWhmcs(config, body) {
  let url;
  try {
    url = new URL(String(body.endpoint ?? ""));
  } catch {
    throw badRequest("WHMCS address is not a URL.");
  }
  if (url.protocol !== "https:" || (url.port && url.port !== "443") || !url.pathname.endsWith("/includes/api.php") || blockedHost(url.hostname)) {
    throw badRequest("WHMCS address is not allowed.");
  }
  const action = String(body.action ?? "");
  if (!WHMCS_ACTIONS.has(action)) throw badRequest("That WHMCS action is not relayed.");
  const form = new URLSearchParams({
    identifier: String(body.identifier ?? ""),
    secret: String(body.secret ?? ""),
    action,
    responsetype: "json",
  });
  if (body.accessKey) form.set("accesskey", String(body.accessKey));
  const params = body.params && typeof body.params === "object" ? body.params : {};
  for (const [key, value] of Object.entries(params)) {
    if (!/^[a-z0-9_]{1,40}$/i.test(key)) continue;
    form.set(key, String(value).slice(0, 200));
  }
  const upstream = await (config.fetchImpl ?? fetch)(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: form,
    redirect: "manual",
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
  const payload = await upstream.json().catch(() => null);
  if (!payload || typeof payload !== "object") {
    const error = new Error("WHMCS did not return JSON.");
    error.statusCode = 502;
    error.publicMessage = "WHMCS did not return JSON.";
    throw error;
  }
  return { upstreamStatus: upstream.status, body: payload };
}

async function relayWhm(config, body) {
  const host = String(body.host ?? "").toLowerCase();
  const port = String(body.port ?? "2087");
  if (!/^[a-z0-9.-]+$/.test(host) || blockedHost(host) || port !== "2087") throw badRequest("WHM address is not allowed.");
  const user = String(body.user ?? "root");
  const token = String(body.token ?? "");
  if (!ACCOUNT.test(user) || !token) throw badRequest("WHM login is not valid.");
  const call = String(body.call ?? "");
  const path = call === "version" ? "/json-api/version" : call === "session" ? "/json-api/create_user_session" : "";
  if (!path) throw badRequest("That WHM call is not relayed.");
  const url = new URL(`https://${host}:${port}${path}`);
  if (call === "session") {
    const username = String(body.username ?? "");
    if (!ACCOUNT.test(username)) throw badRequest("cPanel username is not valid.");
    url.searchParams.set("api.version", "1");
    url.searchParams.set("user", username);
    url.searchParams.set("service", "cpaneld");
  }
  const upstream = await (config.fetchImpl ?? fetch)(url, {
    headers: { Accept: "application/json", Authorization: `whm ${user}:${token}` },
    redirect: "manual",
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
  const payload = await upstream.json().catch(() => null);
  if (!payload || typeof payload !== "object") {
    const error = new Error("WHM did not return JSON.");
    error.statusCode = 502;
    error.publicMessage = "WHM did not return JSON.";
    throw error;
  }
  return { upstreamStatus: upstream.status, body: payload };
}

export function createGatewayServer(configuration = getConfiguration()) {
  return createServer(async (request, response) => {
    const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method === "GET" && requestUrl.pathname === "/v1/health") {
      sendJson(response, 200, { service: "kship-registrar-gateway", status: "ok" });
      return;
    }
    const registrarPath = ["/v1/resellerclub/domains/list", "/v1/resellerclub/domains/registrant-contact"].includes(requestUrl.pathname);
    const relayPath = RELAY_PATHS.has(requestUrl.pathname);
    if (request.method !== "POST" || (!registrarPath && !relayPath)) {
      sendJson(response, 404, { error: "not_found" });
      return;
    }
    if (!isAuthorized(request, configuration.gatewayToken)) {
      sendJson(response, 401, { error: "unauthorized" });
      return;
    }
    try {
      const body = await readJsonBody(request, relayPath ? RELAY_BODY_BYTES : MAX_BODY_BYTES);
      if (requestUrl.pathname === "/v1/resellerclub/domains/list") {
        const paging = parsePaging(body);
        const orders = await fetchDomainOrders(configuration, paging);
        sendJson(response, 200, { orders });
        return;
      }
      if (requestUrl.pathname === "/v1/resellerclub/domains/registrant-contact") {
        const email = await fetchRegistrantContactEmail(configuration, parseDomain(body));
        sendJson(response, 200, { email });
        return;
      }
      const relayed = requestUrl.pathname === "/v1/relay/whmcs" ? await relayWhmcs(configuration, body) : await relayWhm(configuration, body);
      sendJson(response, 200, relayed);
    } catch (error) {
      const status = typeof error?.statusCode === "number" ? error.statusCode : 400;
      if (error?.publicMessage) {
        sendJson(response, status, { error: String(error.publicMessage).slice(0, 180) });
        return;
      }
      const code = status === 502 ? "registrar_read_failed" : status === 404 ? "registrant_contact_not_found" : "invalid_request";
      sendJson(response, status, { error: code });
    }
  });
}

if (import.meta.url === new URL(process.argv[1], "file:").href) {
  const configuration = getConfiguration();
  const server = createGatewayServer(configuration);
  server.listen(configuration.port, "127.0.0.1", () => {
    console.log(`Kship registrar gateway listening on 127.0.0.1:${configuration.port}`);
  });
}
