import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { internals } from "../src/index.js";

test("username normalization is strict", () => {
  assert.equal(internals.normalizeUsername(" Souvik_99 "), "souvik_99");
  assert.equal(internals.normalizeUsername("bad-name"), null);
  assert.equal(internals.normalizeUsername("ab"), null);
});

test("session names are bounded and safe", () => {
  assert.equal(internals.normalizeSessionName("training-run"), "training-run");
  assert.equal(internals.normalizeSessionName("<script>"), null);
  assert.equal(internals.normalizeSessionName("x".repeat(81)), null);
});

test("email validation is bounded and deterministic", () => {
  assert.equal(internals.validEmailAddress("sender+alerts@example.test"), true);
  assert.equal(internals.validEmailAddress("bad..local@example.test"), false);
  assert.equal(internals.validEmailAddress("missing-domain@example"), false);
  assert.equal(internals.validEmailAddress(`sender@${"a".repeat(64)}.test`), false);
  assert.equal(internals.validEmailAddress(`sender@${"a.".repeat(130)}test`), false);
});

test("base64url round trips bytes", () => {
  const input = new TextEncoder().encode("hello, flushout");
  assert.deepEqual(internals.fromB64url(internals.b64url(input)), input);
});

test("security headers deny framing and referrers", () => {
  const headers = internals.securityHeaders();
  assert.equal(headers["x-frame-options"], "DENY");
  assert.equal(headers["referrer-policy"], "no-referrer");
  assert.match(headers["content-security-policy"], /object-src 'none'/u);
});

test("relay never uses persistent Cloudflare storage", async () => {
  const source = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /ctx\.storage|state\.storage|\.put\s*\(/u);
});

test("Supabase RPC calls explicitly target the restricted api schema", async () => {
  const source = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
  assert.match(source, /"content-profile": "api"/u);
  assert.match(source, /"accept-profile": "api"/u);
});

test("short-lived relay tickets are role-bound and tamper-evident", async () => {
  const env = { REALTIME_TICKET_SECRET: "test-secret-with-at-least-thirty-two-bytes" };
  const ticket = await internals.signTicket(env, { role: "producer", sub: "user-1", sid: "session-1", name: "test" });
  const claims = await internals.verifyTicket(env, ticket, "producer");
  assert.equal(claims.sub, "user-1");
  assert.equal(claims.sid, "session-1");
  await assert.rejects(() => internals.verifyTicket(env, ticket, "dashboard"), /invalid_ticket/u);
  await assert.rejects(() => internals.verifyTicket(env, `${ticket.slice(0, -1)}x`, "producer"), /invalid_ticket/u);
});

test("completion emails never include streamed output or tracebacks", async () => {
  const source = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
  const emailFunction = source.match(/async function sendCompletionEmail[\s\S]*?\n\}\n/u)?.[0] || "";
  assert.match(emailFunction, /sessionName/u);
  assert.match(emailFunction, /errorMessage/u);
  assert.doesNotMatch(emailFunction, /details\.(output|stdout|stderr|traceback|content)/u);
});

test("SMTP conversation authenticates and submits a message over the provided TLS streams", async () => {
  const replies = new TextEncoder().encode([
    "220 ready",
    "250-server",
    "250 AUTH LOGIN",
    "334 username",
    "334 password",
    "235 authenticated",
    "250 sender ok",
    "250 recipient ok",
    "354 send data",
    "250 queued",
    "221 bye",
    "",
  ].join("\r\n"));
  let read = false;
  const reader = { read: async () => read ? { done: true } : (read = true, { value: replies, done: false }) };
  const writes = [];
  const writer = { write: async (value) => writes.push(new TextDecoder().decode(value)) };
  await internals.smtpConversation(reader, writer, {
    username: "sender@example.test",
    password: "app-password",
    fromEmail: "sender@example.test",
    recipient: "recipient@example.test",
    message: "Subject: test\r\n\r\nbody",
  });
  const transcript = writes.join("");
  assert.match(transcript, /AUTH LOGIN\r\n/u);
  assert.match(transcript, /MAIL FROM:<sender@example\.test>/u);
  assert.match(transcript, /RCPT TO:<recipient@example\.test>/u);
  assert.match(transcript, /Subject: test\r\n\r\nbody\r\n\.\r\n/u);
  assert.doesNotMatch(transcript, /app-password/u);
});
