// mechanic-intake: write-only upload intake. POST /v1/contribute only; no read, list or delete routes.
const J = (obj, status) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
const bad = (why, status = 400) => J({ ok: false, error: why }, status);

async function readCapped(request, max) {
  const len = request.headers.get("content-length");
  if (len && Number(len) > max) return null;
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = []; let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > max) { await reader.cancel(); return null; }
    chunks.push(value);
  }
  const out = new Uint8Array(n); let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

async function gunzipCapped(bytes, max) {
  const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip")).getReader();
  const chunks = []; let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > max) { await reader.cancel(); throw new Error("too large"); }
    chunks.push(value);
  }
  const out = new Uint8Array(n); let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

function validate(text) {
  const lines = text.split("\n");
  while (lines.length && lines[lines.length - 1].trim() === "") lines.pop();
  if (!lines.length) return "empty";
  let first;
  for (let i = 0; i < lines.length; i++) {
    let v;
    try { v = JSON.parse(lines[i]); } catch { return "line " + (i + 1) + " is not valid JSON"; }
    if (i === 0) first = v;
  }
  if (!first || typeof first !== "object" || Array.isArray(first)) return "first line must be an object";
  if (first.consent !== true) return "consent must be true";
  if (typeof first.licence !== "string" || !first.licence) return "licence missing";
  if (typeof first.mechanic_version !== "string" || !first.mechanic_version) return "mechanic_version missing";
  return null;
}

async function sha(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/v1/contribute") return new Response("not found", { status: 404 });
    if (request.method !== "POST") return new Response("method not allowed", { status: 405, headers: { allow: "POST" } });

    const ct = (request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    if (ct !== "application/jsonl" && ct !== "application/gzip") return bad("content-type must be application/jsonl or application/gzip");

    const limiter = env.LIMITER.get(env.LIMITER.idFromName("global"));
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const r1 = await limiter.fetch("https://l/ip", { method: "POST", body: JSON.stringify({ key: await sha(ip), max: Number(env.PER_IP_HOUR) }) });
    if (r1.status === 429) return bad("rate limit", 429);

    const max = Number(env.MAX_BYTES);
    const body = await readCapped(request, max);
    if (body === null) return bad("body too large", 413);
    if (!body.length) return bad("empty body");

    let plain = body, gz = ct === "application/gzip";
    if (gz) {
      if (body[0] !== 0x1f || body[1] !== 0x8b) return bad("not gzip");
      try { plain = await gunzipCapped(body, Number(env.MAX_UNZIPPED)); } catch { return bad("invalid or oversized gzip"); }
    }
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(plain); } catch { return bad("not utf-8"); }
    const why = validate(text);
    if (why) return bad(why);

    const r2 = await limiter.fetch("https://l/day", { method: "POST", body: JSON.stringify({ max: Number(env.DAILY_CAP) }) });
    if (r2.status === 429) return bad("daily limit reached", 429);

    const id = crypto.randomUUID();
    const day = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    await env.BUCKET.put("incoming/" + day + "/" + id + (gz ? ".jsonl.gz" : ".jsonl"), body, {
      httpMetadata: { contentType: gz ? "application/gzip" : "application/jsonl" },
    });
    return J({ ok: true, id }, 200);
  },
};

// One SQLite-backed Durable Object holds the counters (per-IP per hour, total per UTC day).
export class Limiter {
  constructor(state) {
    this.sql = state.storage.sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, n INTEGER NOT NULL, t INTEGER NOT NULL)");
  }
  bump(k, max) {
    const now = Date.now();
    this.sql.exec("DELETE FROM c WHERE t < ?", now - 2 * 86400000);
    const row = this.sql.exec("SELECT n FROM c WHERE k = ?", k).toArray()[0];
    if (row && row.n >= max) return false;
    this.sql.exec("INSERT INTO c (k, n, t) VALUES (?, 1, ?) ON CONFLICT(k) DO UPDATE SET n = n + 1", k, now);
    return true;
  }
  async fetch(request) {
    const { key, max } = await request.json();
    const path = new URL(request.url).pathname;
    const hour = new Date().toISOString().slice(0, 13);
    const k = path === "/ip" ? "ip:" + key + ":" + hour : "day:" + new Date().toISOString().slice(0, 10);
    return new Response(null, { status: this.bump(k, max) ? 204 : 429 });
  }
}
