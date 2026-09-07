import assert from "node:assert/strict";
import test from "node:test";
import { appendCachedOutput, cacheKey, readCache, sanitizeCache, STREAM_CACHE_TTL_MS, writeCache } from "../../dashboard/stream-cache.mjs";

function session(overrides = {}) {
  return {
    id: "0f3b1ce6-99e8-4d38-a327-09dc5fa66eac",
    name: "training-run",
    started_at: "2026-09-07T00:00:00.000Z",
    ended_at: null,
    updated_at: 1_000_000,
    last_sequence: -1,
    lines: [],
    ...overrides,
  };
}

test("browser stream cache expires sessions after 24 hours", () => {
  const now = 2_000_000;
  const fresh = session({ updated_at: now - STREAM_CACHE_TTL_MS + 1 });
  const expired = session({ id: "expired", updated_at: now - STREAM_CACHE_TTL_MS });
  assert.deepEqual(sanitizeCache({ sessions: [fresh, expired] }, now).sessions.map((item) => item.id), [fresh.id]);
});

test("cache keys isolate output by signed-in owner", () => {
  assert.notEqual(cacheKey("user-a"), cacheKey("user-b"));
});

test("sequence gaps are visible and duplicate frames are ignored", () => {
  const cached = session({ last_sequence: 3 });
  const result = appendCachedOutput(cached, { sequence: 6, stream: "stdout", content: "done\n" }, 2_000_000);
  assert.equal(result.missed, 2);
  assert.match(cached.lines[0].content, /2 output frames missed/u);
  assert.equal(cached.lines[1].content, "done\n");
  assert.equal(appendCachedOutput(cached, { sequence: 6, stream: "stdout", content: "duplicate" }).duplicate, true);
});

test("cache survives a write and read round trip", () => {
  const values = new Map();
  const storage = { getItem: (key) => values.get(key) || null, setItem: (key, value) => values.set(key, value) };
  const now = 2_000_000;
  const result = writeCache(storage, "owner", { sessions: [session({ updated_at: now, lines: [{ stream: "stdout", content: "hello\n" }] })] }, now);
  assert.equal(result.saved, true);
  assert.equal(readCache(storage, "owner", now).sessions[0].lines[0].content, "hello\n");
});

test("quota errors progressively retain metadata instead of crashing", () => {
  let written = "";
  const storage = {
    setItem: (_key, value) => {
      if (value.length > 300) throw new Error("quota");
      written = value;
    },
  };
  const now = 2_000_000;
  const result = writeCache(storage, "owner", { sessions: [session({ updated_at: now, lines: Array.from({ length: 30 }, () => ({ stream: "stdout", content: "a long line of output\n" })) })] }, now);
  assert.equal(result.saved, true);
  assert.ok(written.length <= 300);
  assert.equal(result.cache.sessions[0].name, "training-run");
});
