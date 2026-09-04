import { createRemoteJWKSet, jwtVerify } from "jose";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
const SESSION_NAME_RE = /^[\p{L}\p{N}_.:@+\- ]{1,80}$/u;
const MAX_JSON_BYTES = 4096;
const MAX_FRAME_BYTES = 65536;
const MAX_NOTIFICATION_ERROR_BYTES = 1000;
const MAX_PRODUCERS = 3;
const MAX_DASHBOARDS = 5;
const TICKET_TTL_SECONDS = 30;
const MAX_SOCKET_AGE_MS = 6 * 60 * 60 * 1000;

let remoteJwks;
let remoteJwksUrl;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...securityHeaders(),
      ...extraHeaders,
    },
  });
}

function error(code, message, status, requestId, extra = {}) {
  return json({ error: { code, message, request_id: requestId, ...extra } }, status);
}

function securityHeaders() {
  return {
    "content-security-policy": [
      "default-src 'self'",
      "script-src 'self' https://challenges.cloudflare.com",
      "frame-src https://challenges.cloudflare.com",
      "connect-src 'self' https: wss:",
      "img-src 'self' data:",
      "style-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
    ].join("; "),
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
  };
}

function normalizeUsername(value) {
  const username = typeof value === "string" ? value.trim().toLowerCase() : "";
  return USERNAME_RE.test(username) ? username : null;
}

function normalizeSessionName(value) {
  const name = typeof value === "string" ? value.trim() : "";
  return SESSION_NAME_RE.test(name) ? name : null;
}

function boundedText(value, maxBytes) {
  const text = typeof value === "string" ? value.trim() : "";
  if (!text) return "";
  const bytes = encoder.encode(text);
  if (bytes.byteLength <= maxBytes) return text;
  for (let end = maxBytes; end > 0; end -= 1) {
    try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes.slice(0, end)) + "…"; }
    catch { /* retry before a partial UTF-8 code point */ }
  }
  return "…";
}

function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function fromB64url(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function hmacBytes(secret, value) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function signTicket(env, claims) {
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(encoder.encode(JSON.stringify({ ...claims, iat: now, exp: now + TICKET_TTL_SECONDS, jti: crypto.randomUUID() })));
  return `${payload}.${b64url(await hmacBytes(env.REALTIME_TICKET_SECRET, payload))}`;
}

async function verifyTicket(env, ticket, role) {
  if (typeof ticket !== "string" || ticket.length > 2048) throw new Error("invalid_ticket");
  const parts = ticket.split(".");
  if (parts.length !== 2) throw new Error("invalid_ticket");
  const [payload, signature] = parts;
  const supplied = fromB64url(signature);
  const key = await crypto.subtle.importKey("raw", encoder.encode(env.REALTIME_TICKET_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  if (!(await crypto.subtle.verify("HMAC", key, supplied, encoder.encode(payload)))) throw new Error("invalid_ticket");
  const claims = JSON.parse(decoder.decode(fromB64url(payload)));
  const now = Math.floor(Date.now() / 1000);
  if (claims.role !== role || !claims.sub || !claims.jti || claims.exp < now || claims.iat > now + 5) throw new Error("invalid_ticket");
  return claims;
}

async function parseJson(request, maxBytes = MAX_JSON_BYTES) {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw Object.assign(new Error("content_type"), { status: 415 });
  if (request.headers.get("content-encoding")) throw Object.assign(new Error("content_encoding"), { status: 415 });
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > maxBytes) throw Object.assign(new Error("body_too_large"), { status: 413 });
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > maxBytes) throw Object.assign(new Error("body_too_large"), { status: 413 });
  try { return JSON.parse(decoder.decode(bytes)); } catch { throw Object.assign(new Error("invalid_json"), { status: 400 }); }
}

function bearer(request) {
  const value = request.headers.get("authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7) : null;
}

function requireBrowserOrigin(request, env) {
  const origin = request.headers.get("origin");
  if (origin && origin !== env.APP_ORIGIN) throw Object.assign(new Error("origin"), { status: 403 });
}

async function verifyUserJwt(env, token) {
  if (!token || token.length > 8192) throw Object.assign(new Error("unauthorized"), { status: 401 });
  const base = env.SUPABASE_URL.replace(/\/$/u, "");
  const jwksUrl = `${base}/auth/v1/.well-known/jwks.json`;
  if (!remoteJwks || remoteJwksUrl !== jwksUrl) {
    remoteJwksUrl = jwksUrl;
    remoteJwks = createRemoteJWKSet(new URL(jwksUrl));
  }
  const { payload } = await jwtVerify(token, remoteJwks, { issuer: `${base}/auth/v1`, audience: "authenticated" });
  if (!payload.sub) throw Object.assign(new Error("unauthorized"), { status: 401 });
  return payload;
}

async function supabaseRpc(env, name, body, userJwt = null) {
  const key = env.SUPABASE_BROWSER_KEY;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const headers = new Headers({
      apikey: key,
      "content-type": "application/json",
      "content-profile": "api",
      "accept-profile": "api",
      accept: "application/json",
    });
    if (userJwt) headers.set("authorization", `Bearer ${userJwt}`);
    return await fetch(`${env.SUPABASE_URL.replace(/\/$/u, "")}/rest/v1/rpc/${name}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } finally { clearTimeout(timeout); }
}

async function ownerRpc(request, env, name, body = {}) {
  const token = bearer(request);
  await verifyUserJwt(env, token);
  const response = await supabaseRpc(env, name, body, token, false);
  if (!response.ok) {
    const text = await response.text();
    if (response.status === 409 || text.includes("username unavailable")) throw Object.assign(new Error("username_unavailable"), { status: 409 });
    if (response.status === 400 || text.includes("invalid username")) throw Object.assign(new Error("invalid_username"), { status: 400 });
    throw Object.assign(new Error("upstream"), { status: 503 });
  }
  return response.status === 204 ? null : response.json();
}

async function rateLimit(request, env) {
  if (!env.AUTH_RATE_LIMITER) return true;
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const digest = hex(await hmacBytes(env.REALTIME_TICKET_SECRET, `ip:${ip}`));
  return (await env.AUTH_RATE_LIMITER.limit({ key: digest })).success;
}

async function verifyTurnstile(request, env, token) {
  if (!env.TURNSTILE_SECRET_KEY) return env.APP_ORIGIN.startsWith("http://localhost");
  if (typeof token !== "string" || token.length > 2048) return false;
  const form = new FormData();
  form.set("secret", env.TURNSTILE_SECRET_KEY);
  form.set("response", token);
  form.set("remoteip", request.headers.get("cf-connecting-ip") || "");
  form.set("idempotency_key", crypto.randomUUID());
  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
  if (!response.ok) return false;
  const result = await response.json();
  return result.success === true && result.hostname === new URL(env.APP_ORIGIN).hostname && result.action === "stream-password";
}

async function sendCompletionEmail(env, recipient, details) {
  if (!env.ZOHO_SMTP_USERNAME || !env.ZOHO_SMTP_PASSWORD || !env.NOTIFICATION_FROM_EMAIL) {
    throw Object.assign(new Error("notification_unavailable"), { status: 503 });
  }
  const host = env.ZOHO_SMTP_HOST || "smtp.zoho.in";
  const port = Number(env.ZOHO_SMTP_PORT || 465);
  const fromEmail = env.NOTIFICATION_FROM_EMAIL.trim();
  const fromName = boundedText(env.NOTIFICATION_FROM_NAME || "notification-flashout", 80);
  const emailPattern = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/u;
  if (port !== 465 || !emailPattern.test(fromEmail) || !emailPattern.test(recipient)) {
    throw Object.assign(new Error("notification_unavailable"), { status: 503 });
  }
  const statusLabel = details.status === "success" ? "succeeded" : "failed";
  const lines = [
    `Your Flushout run ${statusLabel}.`,
    "",
    `Session: ${details.sessionName}`,
    `Status: ${statusLabel}`,
    `Duration: ${details.durationSeconds.toFixed(1)} seconds`,
    `Finished: ${details.finishedAt}`,
    `Session ID: ${details.sessionId}`,
  ];
  if (details.status === "error") {
    lines.push(`Error type: ${details.errorType || "Exception"}`);
    if (details.errorMessage) lines.push(`Error: ${details.errorMessage}`);
  }
  lines.push("", "Streamed stdout/stderr and tracebacks are never included or stored by Flushout.");
  const header = (value) => `=?UTF-8?B?${base64(encoder.encode(value))}?=`;
  const body = base64(encoder.encode(lines.join("\r\n"))).match(/.{1,76}/gu)?.join("\r\n") || "";
  const message = [
    `From: ${header(fromName)} <${fromEmail}>`,
    `To: <${recipient}>`,
    `Subject: ${header(`Flushout: ${details.sessionName} ${statusLabel}`)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomUUID()}@${fromEmail.split("@")[1]}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    body,
  ].join("\r\n");

  let socket;
  let reader;
  let writer;
  let timer;
  try {
    const { connect } = await import("cloudflare:sockets");
    socket = connect({ hostname: host, port }, { secureTransport: "on", allowHalfOpen: false });
    reader = socket.readable.getReader();
    writer = socket.writable.getWriter();
    const smtp = smtpConversation(reader, writer, {
      username: env.ZOHO_SMTP_USERNAME,
      password: env.ZOHO_SMTP_PASSWORD,
      fromEmail,
      recipient,
      message,
    });
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("smtp_timeout")), 12000);
    });
    await socket.opened;
    await Promise.race([smtp, timeout]);
  } catch {
    throw Object.assign(new Error("notification_delivery_failed"), { status: 502 });
  } finally {
    clearTimeout(timer);
    try { reader?.releaseLock(); } catch { /* already released */ }
    try { writer?.releaseLock(); } catch { /* already released */ }
    try { await socket?.close(); } catch { /* already closed */ }
  }
}

async function smtpConversation(reader, writer, options) {
  let buffered = "";
  const smtpDecoder = new TextDecoder("utf-8", { fatal: true });
  const readLine = async () => {
    while (!buffered.includes("\r\n")) {
      const { value, done } = await reader.read();
      if (done) throw new Error("smtp_closed");
      buffered += smtpDecoder.decode(value, { stream: true });
      if (buffered.length > 16384) throw new Error("smtp_response_too_large");
    }
    const end = buffered.indexOf("\r\n");
    const line = buffered.slice(0, end);
    buffered = buffered.slice(end + 2);
    return line;
  };
  const reply = async (allowed) => {
    let code = null;
    while (true) {
      const line = await readLine();
      if (!/^\d{3}[- ]/u.test(line)) throw new Error("smtp_invalid_response");
      const current = Number(line.slice(0, 3));
      if (code === null) code = current;
      if (current !== code) throw new Error("smtp_invalid_response");
      if (line[3] === " ") break;
    }
    if (!allowed.includes(code)) throw new Error("smtp_rejected");
  };
  const command = async (value, allowed) => {
    await writer.write(encoder.encode(`${value}\r\n`));
    await reply(allowed);
  };

  await reply([220]);
  await command("EHLO flushout.online", [250]);
  await command("AUTH LOGIN", [334]);
  await command(base64(encoder.encode(options.username)), [334]);
  await command(base64(encoder.encode(options.password)), [235]);
  await command(`MAIL FROM:<${options.fromEmail}>`, [250]);
  await command(`RCPT TO:<${options.recipient}>`, [250, 251]);
  await command("DATA", [354]);
  await writer.write(encoder.encode(`${options.message}\r\n.\r\n`));
  await reply([250]);
  await command("QUIT", [221]);
}

function randomStreamPassword() {
  const value = new Uint8Array(32);
  crypto.getRandomValues(value);
  return `fl_stream_${b64url(value)}`;
}

function routeToRelay(request, env, claims) {
  const stub = env.LIVE_RELAY.get(env.LIVE_RELAY.idFromName(`user:${claims.sub}`));
  const headers = new Headers({
    upgrade: "websocket",
    "x-flushout-internal-role": claims.role,
    "x-flushout-user": claims.sub,
    "x-flushout-jti": claims.jti,
  });
  if (claims.sid) headers.set("x-flushout-session", claims.sid);
  if (claims.name) headers.set("x-flushout-name", b64url(encoder.encode(claims.name)));
  if (request.headers.get("sec-websocket-protocol")) headers.set("sec-websocket-protocol", "flushout.v1");
  return stub.fetch(new Request("https://relay.internal/connect", { headers }));
}

async function handleApi(request, env, url, requestId) {
  if (url.pathname === "/api/v1/health/live" && request.method === "GET") return json({ ok: true }, 200, { "x-request-id": requestId });
  if (url.pathname === "/api/v1/config" && request.method === "GET") {
    return json({ app_origin: env.APP_ORIGIN, supabase_url: env.SUPABASE_URL, supabase_publishable_key: env.SUPABASE_BROWSER_KEY, turnstile_site_key: env.TURNSTILE_SITE_KEY || null, github_auth_enabled: env.GITHUB_AUTH_ENABLED !== "false", google_auth_enabled: env.GOOGLE_AUTH_ENABLED === "true", email_auth_enabled: env.EMAIL_AUTH_ENABLED !== "false" }, 200, { "x-request-id": requestId });
  }

  requireBrowserOrigin(request, env);

  if (url.pathname === "/api/v1/profile" && request.method === "GET") {
    const rows = await ownerRpc(request, env, "get_my_profile");
    return json({ profile: rows?.[0] || null }, 200, { "x-request-id": requestId });
  }
  if (url.pathname === "/api/v1/profile/username" && request.method === "POST") {
    const body = await parseJson(request);
    const username = normalizeUsername(body.username);
    if (!username) return error("invalid_username", "Use 3-32 lowercase letters, numbers, or underscores", 400, requestId);
    const rows = await ownerRpc(request, env, "claim_username", { requested_username: username });
    return json({ profile: rows?.[0] || null }, 200, { "x-request-id": requestId });
  }
  if (url.pathname === "/api/v1/profile/stream-password" && request.method === "POST") {
    const body = await parseJson(request);
    const token = bearer(request);
    await verifyUserJwt(env, token);
    if (!(await verifyTurnstile(request, env, body.turnstile_token))) return error("challenge_failed", "Please complete the security check", 403, requestId);
    const streamPassword = randomStreamPassword();
    const digestHex = hex(await hmacBytes(env.STREAM_PASSWORD_PEPPER, streamPassword));
    const response = await supabaseRpc(env, "set_stream_password", { digest_hex: digestHex }, token, false);
    if (!response.ok) throw Object.assign(new Error("profile_required"), { status: 409 });
    return json({ stream_password: streamPassword }, 201, { "x-request-id": requestId });
  }
  if (url.pathname === "/api/v1/profile/stream-password" && request.method === "DELETE") {
    await ownerRpc(request, env, "revoke_stream_password");
    return json({ ok: true }, 200, { "x-request-id": requestId });
  }
  if (url.pathname === "/api/v1/stream-ticket" && request.method === "POST") {
    if (!(await rateLimit(request, env))) return error("rate_limited", "Try again later", 429, requestId, { retry_after: 60 });
    const body = await parseJson(request);
    const username = normalizeUsername(body.username);
    const name = normalizeSessionName(body.session_name || "python-stream");
    if (!username || typeof body.stream_password !== "string" || body.stream_password.length > 128 || !name) return error("invalid_credentials", "Invalid username or streaming password", 401, requestId);
    const digestHex = hex(await hmacBytes(env.STREAM_PASSWORD_PEPPER, body.stream_password));
    const response = await supabaseRpc(env, "verify_stream_login", { requested_username: username, digest_hex: digestHex });
    const rows = response.ok ? await response.json() : [];
    if (!rows?.[0]?.user_id) {
      await new Promise((resolve) => setTimeout(resolve, 120 + Math.floor(Math.random() * 100)));
      return error("invalid_credentials", "Invalid username or streaming password", 401, requestId);
    }
    const sessionId = crypto.randomUUID();
    const ticket = await signTicket(env, { role: "producer", sub: rows[0].user_id, sid: sessionId, name });
    return json({ ticket, session_id: sessionId, live_url: `${env.APP_ORIGIN}/live/${sessionId}` }, 201, { "x-request-id": requestId });
  }
  if (url.pathname === "/api/v1/notifications/completion" && request.method === "POST") {
    if (!(await rateLimit(request, env))) return error("rate_limited", "Try again later", 429, requestId, { retry_after: 60 });
    const body = await parseJson(request);
    const username = normalizeUsername(body.username);
    const sessionName = normalizeSessionName(body.session_name || "python-stream");
    const sessionId = typeof body.session_id === "string" && /^[0-9a-f-]{36}$/u.test(body.session_id) ? body.session_id : null;
    const status = body.status === "success" || body.status === "error" ? body.status : null;
    const durationSeconds = Number(body.duration_seconds);
    if (!username || typeof body.stream_password !== "string" || body.stream_password.length > 128 || !sessionName || !sessionId || !status || !Number.isFinite(durationSeconds) || durationSeconds < 0 || durationSeconds > 604800) {
      return error("invalid_notification", "Invalid completion notification", 400, requestId);
    }
    const digestHex = hex(await hmacBytes(env.STREAM_PASSWORD_PEPPER, body.stream_password));
    const recipientResponse = await supabaseRpc(env, "get_notification_recipient", { requested_username: username, digest_hex: digestHex });
    const recipients = recipientResponse.ok ? await recipientResponse.json() : [];
    if (!recipients?.[0]?.user_id) return error("invalid_credentials", "Invalid username or streaming password", 401, requestId);
    if (!recipients[0].notification_email) return error("verified_email_required", "Add and verify an email address in your Flushout profile to use completion notifications", 409, requestId);
    await sendCompletionEmail(env, recipients[0].notification_email, {
      sessionName,
      sessionId,
      status,
      durationSeconds,
      finishedAt: new Date().toISOString(),
      errorType: boundedText(body.error_type, 120),
      errorMessage: boundedText(body.error_message, MAX_NOTIFICATION_ERROR_BYTES),
    });
    return json({ sent: true }, 202, { "x-request-id": requestId });
  }
  if (url.pathname === "/api/v1/dashboard-ticket" && request.method === "POST") {
    const payload = await verifyUserJwt(env, bearer(request));
    return json({ ticket: await signTicket(env, { role: "dashboard", sub: payload.sub }) }, 201, { "x-request-id": requestId });
  }
  if (url.pathname === "/api/v1/stream" && request.method === "GET") {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return error("upgrade_required", "WebSocket upgrade required", 426, requestId);
    try { return routeToRelay(request, env, await verifyTicket(env, bearer(request), "producer")); }
    catch { return error("invalid_ticket", "Connection ticket is invalid or expired", 401, requestId); }
  }
  if (url.pathname === "/api/v1/dashboard" && request.method === "GET") {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return error("upgrade_required", "WebSocket upgrade required", 426, requestId);
    const ticketPart = (request.headers.get("sec-websocket-protocol") || "").split(",").map((part) => part.trim()).find((part) => part.startsWith("ticket."));
    try { return routeToRelay(request, env, await verifyTicket(env, ticketPart?.slice(7), "dashboard")); }
    catch { return error("invalid_ticket", "Connection ticket is invalid or expired", 401, requestId); }
  }
  return error("not_found", "Not found", 404, requestId);
}

export class LiveRelay {
  constructor(ctx) { this.ctx = ctx; }
  sockets(role) { return this.ctx.getWebSockets(role); }
  safeSend(socket, message) {
    try { socket.send(typeof message === "string" ? message : JSON.stringify(message)); return true; }
    catch { try { socket.close(1011, "delivery failed"); } catch { /* closed */ } return false; }
  }
  sessionSnapshot() {
    return this.sockets("producer").map((socket) => {
      const data = socket.deserializeAttachment();
      return { id: data.session_id, name: data.session_name, started_at: data.started_at, status: "live" };
    });
  }
  broadcastDashboards(message, sessionId = null) {
    const encoded = JSON.stringify(message);
    for (const socket of this.sockets("dashboard")) {
      const data = socket.deserializeAttachment();
      if (!sessionId || data.subscription === sessionId) this.safeSend(socket, encoded);
    }
  }
  async fetch(request) {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return new Response("Not found", { status: 404 });
    const role = request.headers.get("x-flushout-internal-role");
    const userId = request.headers.get("x-flushout-user");
    const jti = request.headers.get("x-flushout-jti");
    if (!userId || !jti || !["producer", "dashboard"].includes(role)) return new Response("Unauthorized", { status: 401 });
    const all = [...this.sockets("producer"), ...this.sockets("dashboard")];
    if (all.some((socket) => socket.deserializeAttachment()?.jti === jti)) return new Response("Ticket already used", { status: 409 });
    if (role === "producer" && this.sockets("producer").length >= MAX_PRODUCERS) return new Response("Too many streams", { status: 429 });
    if (role === "dashboard" && this.sockets("dashboard").length >= MAX_DASHBOARDS) return new Response("Too many dashboards", { status: 429 });
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const now = new Date().toISOString();
    const attachment = { role, user_id: userId, jti, connected_at: Date.now() };
    if (role === "producer") {
      attachment.session_id = request.headers.get("x-flushout-session");
      try { attachment.session_name = decoder.decode(fromB64url(request.headers.get("x-flushout-name") || "")); }
      catch { return new Response("Invalid session", { status: 400 }); }
      attachment.started_at = now;
      attachment.last_sequence = -1;
    } else attachment.subscription = null;
    server.serializeAttachment(attachment);
    this.ctx.acceptWebSocket(server, [role]);
    if (role === "producer") {
      this.safeSend(server, { type: "ready", session_id: attachment.session_id });
      this.broadcastDashboards({ type: "session_started", session: { id: attachment.session_id, name: attachment.session_name, started_at: now, status: "live" } });
    } else this.safeSend(server, { type: "sessions", items: this.sessionSnapshot() });
    const headers = role === "dashboard" ? { "sec-websocket-protocol": "flushout.v1" } : {};
    return new Response(null, { status: 101, webSocket: client, headers });
  }
  webSocketMessage(socket, rawMessage) {
    const attachment = socket.deserializeAttachment();
    if (!attachment) return socket.close(1008, "missing identity");
    if (Date.now() - attachment.connected_at > MAX_SOCKET_AGE_MS) return socket.close(1008, "reauthenticate");
    const bytes = typeof rawMessage === "string" ? encoder.encode(rawMessage) : new Uint8Array(rawMessage);
    if (bytes.byteLength > MAX_FRAME_BYTES) return socket.close(1009, "frame too large");
    let message;
    try { message = JSON.parse(typeof rawMessage === "string" ? rawMessage : decoder.decode(bytes)); }
    catch { return socket.close(1007, "invalid json"); }
    if (attachment.role === "producer") {
      if (message.type === "session_end") return socket.close(1000, "ended");
      if (message.type === "ping") return this.safeSend(socket, { type: "pong" });
      if (message.type !== "output" || !Number.isSafeInteger(message.sequence) || message.sequence <= attachment.last_sequence || !["stdout", "stderr", "mixed"].includes(message.stream) || typeof message.content !== "string") return socket.close(1008, "invalid producer message");
      attachment.last_sequence = message.sequence;
      socket.serializeAttachment(attachment);
      this.broadcastDashboards({ type: "output", session_id: attachment.session_id, sequence: message.sequence, stream: message.stream, content: message.content }, attachment.session_id);
      return;
    }
    if (message.type === "ping") return this.safeSend(socket, { type: "pong" });
    if (message.type === "unsubscribe") {
      attachment.subscription = null;
      socket.serializeAttachment(attachment);
      return this.safeSend(socket, { type: "unsubscribed" });
    }
    if (message.type !== "subscribe" || typeof message.session_id !== "string") return socket.close(1008, "invalid dashboard message");
    const producer = this.sockets("producer").find((candidate) => candidate.deserializeAttachment()?.session_id === message.session_id);
    if (!producer) return this.safeSend(socket, { type: "session_unavailable", session_id: message.session_id });
    attachment.subscription = message.session_id;
    socket.serializeAttachment(attachment);
    return this.safeSend(socket, { type: "subscribed", session_id: message.session_id, replay: false });
  }
  webSocketClose(socket) {
    const attachment = socket.deserializeAttachment();
    if (attachment?.role === "producer") this.broadcastDashboards({ type: "session_ended", session_id: attachment.session_id });
  }
  webSocketError(socket) {
    this.webSocketClose(socket);
    try { socket.close(1011, "socket error"); } catch { /* closed */ }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const requestId = request.headers.get("cf-ray") || crypto.randomUUID();
    try {
      if (url.pathname.startsWith("/api/")) return await handleApi(request, env, url, requestId);
      const response = await env.ASSETS.fetch(request);
      const headers = new Headers(response.headers);
      for (const [name, value] of Object.entries(securityHeaders())) headers.set(name, value);
      if (response.headers.get("content-type")?.includes("text/html")) headers.set("cache-control", "no-cache");
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    } catch (cause) {
      const status = Number.isInteger(cause?.status) ? cause.status : (cause?.code === "ERR_JWT_EXPIRED" ? 401 : 500);
      const code = status === 401 ? "unauthorized" : status === 403 ? "forbidden" : status === 409 ? cause.message : status >= 500 ? "service_unavailable" : cause.message;
      if (status >= 500) console.error(JSON.stringify({ event: "request_failed", request_id: requestId, status }));
      return error(code, status >= 500 ? "Service temporarily unavailable" : "Request rejected", status, requestId);
    }
  },
};

export const internals = { normalizeUsername, normalizeSessionName, b64url, fromB64url, securityHeaders, signTicket, verifyTicket, smtpConversation };
