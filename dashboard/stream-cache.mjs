export const STREAM_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
export const MAX_CACHED_SESSIONS = 20;
export const MAX_CACHED_LINES = 2000;
export const MAX_CACHE_CHARACTERS = 1_500_000;

const CACHE_PREFIX = "flushout.stream-cache.v1.";
const VALID_STREAMS = new Set(["stdout", "stderr", "mixed", "system"]);
const SESSION_ID_RE = /^[0-9a-f-]{36}$/u;

export function cacheKey(ownerId) {
  return `${CACHE_PREFIX}${encodeURIComponent(String(ownerId || "unknown"))}`;
}

function validLine(line) {
  return line && typeof line.content === "string" && VALID_STREAMS.has(line.stream || "mixed");
}

export function sanitizeCache(value, now = Date.now()) {
  const cutoff = now - STREAM_CACHE_TTL_MS;
  const input = Array.isArray(value?.sessions) ? value.sessions : [];
  const sessions = input
    .filter((session) => session && SESSION_ID_RE.test(session.id) && typeof session.name === "string" && session.name.length <= 80 && Number.isFinite(Number(session.updated_at)) && Number(session.updated_at) > cutoff)
    .map((session) => ({
      id: session.id,
      name: session.name,
      started_at: session.started_at || new Date(Number(session.updated_at)).toISOString(),
      ended_at: session.ended_at || null,
      updated_at: Number(session.updated_at),
      last_sequence: Number.isSafeInteger(session.last_sequence) ? session.last_sequence : -1,
      lines: Array.isArray(session.lines) ? session.lines.filter(validLine).slice(-MAX_CACHED_LINES) : [],
    }))
    .sort((left, right) => right.updated_at - left.updated_at)
    .slice(0, MAX_CACHED_SESSIONS);

  let characters = sessions.reduce((total, session) => total + session.lines.reduce((sum, line) => sum + line.content.length, 0), 0);
  for (let index = sessions.length - 1; index >= 0 && characters > MAX_CACHE_CHARACTERS; index -= 1) {
    while (sessions[index].lines.length && characters > MAX_CACHE_CHARACTERS) {
      characters -= sessions[index].lines.shift().content.length;
    }
  }
  return { version: 1, sessions };
}

export function readCache(storage, ownerId, now = Date.now()) {
  try {
    const raw = storage.getItem(cacheKey(ownerId));
    return sanitizeCache(raw ? JSON.parse(raw) : null, now);
  } catch {
    return sanitizeCache(null, now);
  }
}

export function writeCache(storage, ownerId, cache, now = Date.now()) {
  const sanitized = sanitizeCache(cache, now);
  const key = cacheKey(ownerId);
  while (true) {
    try {
      storage.setItem(key, JSON.stringify(sanitized));
      return { cache: sanitized, saved: true };
    } catch {
      const oldestWithOutput = [...sanitized.sessions].reverse().find((session) => session.lines.length);
      if (oldestWithOutput) {
        oldestWithOutput.lines.splice(0, Math.max(1, Math.ceil(oldestWithOutput.lines.length / 2)));
        continue;
      }
      if (sanitized.sessions.length > 1) {
        sanitized.sessions.pop();
        continue;
      }
      return { cache: sanitized, saved: false };
    }
  }
}

export function appendCachedOutput(session, message, now = Date.now()) {
  const sequence = Number.isSafeInteger(message.sequence) ? message.sequence : session.last_sequence + 1;
  if (sequence <= session.last_sequence) return { appended: [], missed: 0, duplicate: true };
  const missed = session.last_sequence >= 0 ? Math.max(0, sequence - session.last_sequence - 1) : 0;
  const appended = [];
  if (missed) appended.push({ content: `[flushout: ${missed} output frame${missed === 1 ? "" : "s"} missed while this browser was disconnected]\n`, stream: "system" });
  for (const content of String(message.content || "").split(/(?<=\n)/u)) {
    if (content) appended.push({ content, stream: VALID_STREAMS.has(message.stream) ? message.stream : "mixed" });
  }
  session.lines.push(...appended);
  if (session.lines.length > MAX_CACHED_LINES) {
    session.lines.splice(0, session.lines.length - MAX_CACHED_LINES);
    if (session.lines[0]?.stream !== "system") session.lines.unshift({ content: "[flushout: older browser-saved lines removed]\n", stream: "system" });
    if (session.lines.length > MAX_CACHED_LINES) session.lines.splice(1, session.lines.length - MAX_CACHED_LINES);
  }
  session.last_sequence = sequence;
  session.updated_at = now;
  return { appended, missed, duplicate: false };
}
