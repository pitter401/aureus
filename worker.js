// ===================== AUREUS single-file Worker =====================
// Paste this whole file into Cloudflare → Workers → Edit code.
// Bindings needed (Settings → Bindings):   D1 database  → variable name: DB
// Variables needed (Settings → Variables): ADMIN_PASSWORD (secret)
// Routes: /            landing page (CTA → your DApp link)
//         /admin       admin panel (settings, Meta, manual CompleteRegistration fire)
//         /api/*       API
// Tables auto-create on first request. No contracts, no wallet connect here.

const PUBLIC_KEYS = ["site_name","token_symbol","amount_per_wallet","max_claims","claims_open","dapp_link","trust_deeplink","append_ref","pixel_id","ev_page_view","ev_cta_click","telegram_link","bscscan_link","gas_fee_text"];
const SECRET_KEYS = ["capi_token"];

const SCHEMA = [
`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
`CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, type TEXT NOT NULL, address TEXT, vid TEXT, event_id TEXT, fbp TEXT, fbc TEXT, ip TEXT, ua TEXT, url TEXT, meta_event TEXT, capi_status TEXT, matched INTEGER DEFAULT 0, click_id INTEGER, note TEXT, extra TEXT)`,
`CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC)`,
`CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)`,
`CREATE INDEX IF NOT EXISTS idx_events_addr ON events(address)`,
`CREATE INDEX IF NOT EXISTS idx_events_vid ON events(vid)`,
`INSERT OR IGNORE INTO settings(key,value) VALUES ('site_name','AUREUS'),('token_symbol','AUR'),('amount_per_wallet','1000'),('max_claims','500'),('claims_base','0'),('claims_open','1'),('dapp_link',''),('trust_deeplink','1'),('append_ref','1'),('pixel_id',''),('capi_token',''),('capi_test_code',''),('ev_page_view','PageView'),('ev_cta_click','Lead'),('ev_registration','CompleteRegistration'),('capi_on_page_view','0'),('capi_on_cta_click','1'),('auto_match_minutes','120'),('telegram_link',''),('bscscan_link',''),('gas_fee_text','~$0.10 in BNB')`
];

// ---------------- icon (coin logo as SVG, served at /icon.svg + /favicon.ico) ----------------
const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7C4DFF"/><stop offset=".5" stop-color="#6CE5FF"/><stop offset="1" stop-color="#B794FF"/></linearGradient><linearGradient id="t" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#B794FF"/><stop offset="1" stop-color="#6CE5FF"/></linearGradient></defs><circle cx="32" cy="32" r="31" fill="url(#g)"/><circle cx="32" cy="32" r="25" fill="#0b0718"/><text x="32" y="43" text-anchor="middle" font-family="Space Grotesk,Inter,Arial,sans-serif" font-weight="700" font-size="32" fill="url(#t)">A</text></svg>`;
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  await env.DB.batch(SCHEMA.map(s => env.DB.prepare(s)));
  // if an older events table exists, add the new columns (ignore "duplicate column" errors)
  for (const c of ["vid TEXT","matched INTEGER DEFAULT 0","click_id INTEGER","note TEXT"]) { try { await env.DB.prepare("ALTER TABLE events ADD COLUMN " + c).run(); } catch (e) {} }
  schemaReady = true;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;
    try {
      if (!env.DB) return new Response("D1 binding 'DB' missing. Worker → Settings → Bindings → add D1 database, variable name DB.", { status: 500 });
      await ensureSchema(env);
      if (p === "/icon.svg" || p === "/favicon.ico" || p === "/favicon.svg") return new Response(ICON_SVG, { headers: { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" } });
      if (p === "/" || p === "/index.html") return html(LANDING_HTML);
      if (p === "/admin" || p === "/admin/" || p === "/admin/index.html") return html(ADMIN_HTML, { "x-robots-tag": "noindex" });
      if (p.startsWith("/api/")) return api(p.slice(4), request, env, ctx);
      return new Response("Not found", { status: 404 });
    } catch (e) {
      return json({ error: String(e && e.message || e) }, 500);
    }
  }
};

// ---------------- helpers ----------------
const html = (s, h) => new Response(s, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...(h || {}) } });
const json = (d, status = 200) => cors(new Response(JSON.stringify(d), { status, headers: { "content-type": "application/json" } }));
function cors(r) { r.headers.set("access-control-allow-origin", "*"); r.headers.set("access-control-allow-headers", "content-type"); r.headers.set("access-control-allow-methods", "GET,POST,PUT,OPTIONS"); return r; }
const now = () => Math.floor(Date.now() / 1000);
const isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(a || "");
async function sha256(s) { const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)); return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join(""); }
async function hmac(secret, msg) { const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg)); return [...new Uint8Array(sig)].map(x => x.toString(16).padStart(2, "0")).join(""); }
async function allSettings(env) { const { results } = await env.DB.prepare("SELECT key,value FROM settings").all(); const o = {}; for (const r of results) o[r.key] = r.value; return o; }
async function setSetting(env, key, value) { await env.DB.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key, String(value)).run(); }
async function registrations(env) { const c = await env.DB.prepare("SELECT COUNT(*) n FROM events WHERE type='registration' AND capi_status='sent'").first(); return c.n; }

// ---------------- API router ----------------
async function api(path, request, env, ctx) {
  if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));
  if (path === "/config" && request.method === "GET") return json(await getConfig(env));
  if (path === "/event" && request.method === "POST") return event(request, env);
  if (path.startsWith("/admin")) return admin(path.slice(6) || "/", request, env);
  return json({ error: "not found" }, 404);
}

async function getConfig(env) {
  const s = await allSettings(env);
  const pub = {}; for (const k of PUBLIC_KEYS) pub[k] = s[k] ?? "";
  const total = Number(s.claims_base || 0) + await registrations(env);
  const max = Number(s.max_claims || 500);
  return { ...pub, total_claims: total, remaining: Math.max(0, max - total) };
}

// Public page events: page_view, cta_click
async function event(request, env) {
  const s = await allSettings(env);
  const b = await request.json();
  const type = String(b.type || "");
  if (!["page_view","cta_click"].includes(type)) return json({ error: "bad type" }, 400);
  const ip = request.headers.get("cf-connecting-ip") || "";
  const ua = (request.headers.get("user-agent") || "").slice(0, 300);
  const vid = String(b.vid || "").slice(0, 64) || null;
  const evName = s["ev_" + type] || "";
  const fire = s["capi_on_" + type] === "1" && evName && s.pixel_id && s.capi_token;
  let capi = "skipped";
  const eventId = b.event_id || crypto.randomUUID();
  if (fire) {
    try { await sendCapi(s, { name: evName, eventId, ip, ua, fbp: b.fbp, fbc: b.fbc, url: b.url, extId: vid, test: false }); capi = "sent"; }
    catch (e) { capi = "error:" + String(e.message).slice(0, 180); }
  }
  await env.DB.prepare("INSERT INTO events(ts,type,vid,event_id,fbp,fbc,ip,ua,url,meta_event,capi_status,extra) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(now(), type, vid, eventId, b.fbp || null, b.fbc || null, ip, ua, b.url || null, fire ? evName : null, capi, "{}").run();
  return json({ ok: true });
}

async function sendCapi(s, o) {
  const user_data = { client_ip_address: o.ip || undefined, client_user_agent: o.ua || undefined, fbp: o.fbp || undefined, fbc: o.fbc || undefined };
  if (o.extId) user_data.external_id = [await sha256(String(o.extId).toLowerCase())];
  const body = { data: [{ event_name: o.name, event_time: o.time || now(), event_id: o.eventId, action_source: "website", event_source_url: o.url || undefined, user_data }] };
  if (o.test && s.capi_test_code) body.test_event_code = s.capi_test_code;
  const r = await fetch(`https://graph.facebook.com/v21.0/${s.pixel_id}/events?access_token=${encodeURIComponent(s.capi_token)}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error?.message || "capi failed");
  return j;
}

// ---------------- admin ----------------
async function adminToken(env) { return hmac(env.ADMIN_PASSWORD, "aureus-admin-session"); }
async function isAuthed(request, env) { const m = (request.headers.get("cookie") || "").match(/aur_admin=([a-f0-9]+)/); return !!(m && m[1] === await adminToken(env)); }
async function admin(path, request, env) {
  if (!env.ADMIN_PASSWORD) return json({ error: "ADMIN_PASSWORD variable not set (Worker → Settings → Variables)" }, 500);
  if (path === "/login" && request.method === "POST") {
    const { password } = await request.json();
    if (password !== env.ADMIN_PASSWORD) return json({ error: "wrong password" }, 401);
    const r = json({ ok: true });
    r.headers.set("set-cookie", `aur_admin=${await adminToken(env)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${86400 * 7}`);
    return r;
  }
  if (path === "/logout") { const r = json({ ok: true }); r.headers.set("set-cookie", "aur_admin=; Path=/; Max-Age=0"); return r; }
  if (!(await isAuthed(request, env))) return json({ error: "unauthorized" }, 401);
  const s = await allSettings(env);
  const host = new URL(request.url).host;

  if (path === "/settings" && request.method === "GET") { const o = { ...s }; for (const k of SECRET_KEYS) o[k] = o[k] ? "••••" + o[k].slice(-4) : ""; return json(o); }
  if (path === "/settings" && request.method === "PUT") {
    const b = await request.json();
    for (const [k, v] of Object.entries(b)) { if (SECRET_KEYS.includes(k) && String(v).startsWith("••••")) continue; await setSetting(env, k, v); }
    return json({ ok: true });
  }
  if (path === "/stats") {
    const q = sql => env.DB.prepare(sql).first().then(r => r.n);
    const [pv, cc, uniq, reg, regErr, pending, capiErr] = await Promise.all([
      q("SELECT COUNT(*) n FROM events WHERE type='page_view'"),
      q("SELECT COUNT(*) n FROM events WHERE type='cta_click'"),
      q("SELECT COUNT(DISTINCT vid) n FROM events WHERE type='page_view' AND vid IS NOT NULL"),
      q("SELECT COUNT(*) n FROM events WHERE type='registration' AND capi_status='sent'"),
      q("SELECT COUNT(*) n FROM events WHERE type='registration' AND capi_status LIKE 'error%'"),
      q("SELECT COUNT(*) n FROM events WHERE type='cta_click' AND matched=0 AND ts>" + (now() - 86400)),
      q("SELECT COUNT(*) n FROM events WHERE capi_status LIKE 'error%'")]);
    return json({ page_view: pv, cta_click: cc, unique_visitors: uniq, registrations: reg, registration_errors: regErr, pending_clicks: pending, capi_errors: capiErr, total_display: Number(s.claims_base || 0) + reg, max_claims: Number(s.max_claims || 500) });
  }
  if (path === "/events") {
    const u = new URL(request.url);
    const type = u.searchParams.get("type"), limit = Math.min(500, Number(u.searchParams.get("limit") || 100)), before = Number(u.searchParams.get("before") || 0);
    let sql = "SELECT id,ts,type,address,vid,event_id,fbp,fbc,ip,meta_event,capi_status,matched,click_id,note FROM events WHERE 1=1"; const args = [];
    if (type) { sql += " AND type=?"; args.push(type); }
    if (before) { sql += " AND id<?"; args.push(before); }
    sql += " ORDER BY id DESC LIMIT ?"; args.push(limit);
    const { results } = await env.DB.prepare(sql).bind(...args).all();
    return json(results);
  }
  // recent CTA clicks for the Fire tab (to attach ad-click data to a manual registration)
  if (path === "/clicks") {
    const { results } = await env.DB.prepare("SELECT id,ts,vid,ip,ua,fbp,fbc,matched FROM events WHERE type='cta_click' ORDER BY id DESC LIMIT 40").all();
    return json(results.map(r => ({ id: r.id, ts: r.ts, vid: r.vid, ip: r.ip, ua: (r.ua || "").slice(0, 60), has_fbc: !!r.fbc, has_fbp: !!r.fbp, matched: !!r.matched })));
  }
  if (path === "/export.csv") {
    const { results } = await env.DB.prepare("SELECT ts,type,address,vid,event_id,fbp,fbc,ip,meta_event,capi_status,matched,click_id,note FROM events ORDER BY id").all();
    const head = "time_utc,type,address,visitor_id,event_id,fbp,fbc,ip,meta_event,capi_status,matched,click_id,note\n";
    const rows = results.map(r => [new Date(r.ts * 1000).toISOString(), r.type, r.address, r.vid, r.event_id, r.fbp, r.fbc, r.ip, r.meta_event, r.capi_status, r.matched, r.click_id, r.note].map(v => `"${String(v ?? "").replace(/"/g, '""')}"`).join(",")).join("\n");
    return new Response(head + rows, { headers: { "content-type": "text/csv", "content-disposition": "attachment; filename=aureus-events.csv" } });
  }
  if (path === "/test-capi" && request.method === "POST") {
    const { event } = await request.json();
    try { const r = await sendCapi(s, { name: event || "Lead", eventId: "test-" + Date.now(), ip: request.headers.get("cf-connecting-ip"), ua: "aureus-admin-test", url: "https://" + host, test: true }); return json({ ok: true, meta: r }); }
    catch (e) { return json({ ok: false, error: e.message }, 400); }
  }

  // ===== MANUAL FIRE: admin got the claim message from the DApp → fire CompleteRegistration for that wallet =====
  if (path === "/fire" && request.method === "POST") {
    if (!s.pixel_id || !s.capi_token) return json({ ok: false, error: "Set Pixel ID + CAPI token in Meta tab first" }, 400);
    const b = await request.json();
    const wallets = String(b.wallets || "").split(/[\s,;]+/).map(w => w.trim()).filter(Boolean);
    if (!wallets.length) return json({ ok: false, error: "no wallet address" }, 400);
    const evName = (b.event || s.ev_registration || "CompleteRegistration").trim();
    const mode = b.match || "auto";           // auto | none | click:<id> | vid:<visitor id>
    const force = !!b.force;
    const test = !!b.test;
    const windowSec = Number(s.auto_match_minutes || 120) * 60;
    const out = [];
    for (const w of wallets) {
      const res = { wallet: w };
      if (!isAddr(w)) { res.status = "bad address"; out.push(res); continue; }
      const addr = w.toLowerCase();
      if (!force) {
        const dup = await env.DB.prepare("SELECT id FROM events WHERE type='registration' AND address=? AND capi_status='sent'").bind(addr).first();
        if (dup) { res.status = "already fired (tick 'fire again' to force)"; out.push(res); continue; }
      }
      // pick the ad click to attach (gives Meta fbp/fbc/ip/ua for attribution)
      let click = null;
      if (mode.startsWith("click:")) click = await env.DB.prepare("SELECT * FROM events WHERE id=? AND type='cta_click'").bind(Number(mode.slice(6))).first();
      else if (mode.startsWith("vid:")) click = await env.DB.prepare("SELECT * FROM events WHERE vid=? AND type='cta_click' ORDER BY id DESC LIMIT 1").bind(mode.slice(4).trim()).first();
      else if (mode === "auto") click = await env.DB.prepare("SELECT * FROM events WHERE type='cta_click' AND matched=0 AND ts>? ORDER BY id DESC LIMIT 1").bind(now() - windowSec).first();
      const eventId = "reg-" + addr.slice(2, 10) + "-" + Date.now();
      let capi = "skipped", meta = null;
      try {
        meta = await sendCapi(s, { name: evName, eventId, ip: click ? click.ip : undefined, ua: click ? click.ua : undefined, fbp: click ? click.fbp : undefined, fbc: click ? click.fbc : undefined, url: "https://" + host + "/", extId: addr, test });
        capi = "sent";
      } catch (e) { capi = "error:" + String(e.message).slice(0, 180); }
      await env.DB.prepare("INSERT INTO events(ts,type,address,vid,event_id,fbp,fbc,ip,ua,url,meta_event,capi_status,matched,click_id,note,extra) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(now(), "registration", addr, click ? click.vid : null, eventId, click ? click.fbp : null, click ? click.fbc : null, click ? click.ip : null, click ? click.ua : null, "https://" + host + "/", evName, capi, click ? 1 : 0, click ? click.id : null, String(b.note || "").slice(0, 120) || null, JSON.stringify({ match: mode, test })).run();
      if (click && capi === "sent" && !test) await env.DB.prepare("UPDATE events SET matched=1 WHERE id=?").bind(click.id).run();
      res.status = capi; res.matched_click = click ? click.id : null; res.events_received = meta && meta.events_received;
      out.push(res);
    }
    return json({ ok: true, results: out });
  }
  return json({ error: "not found" }, 404);
}


// ===================== LANDING PAGE =====================
const LANDING_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AUREUS — Claim 1,000 AUR</title>
<meta name="theme-color" content="#070510">
<meta name="color-scheme" content="dark">
<meta name="description" content="Free 1,000 AUR for the first 500 wallets on BNB Chain. One claim per wallet.">
<meta property="og:title" content="AUREUS — Claim 1,000 AUR">
<meta property="og:description" content="Free allocation for the first 500 wallets on BNB Chain. One claim per wallet.">
<meta property="og:image" content="/icon.svg">
<link rel="icon" type="image/svg+xml" href="/icon.svg">
<link rel="apple-touch-icon" href="/icon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#070510; --v1:#7C4DFF; --v2:#9E8CFF; --v3:#B794FF; --cyan:#6CE5FF;
    --ink:#F4F2FB; --mut:#A9A3C2; --mut2:#6B6880; --brd:rgba(255,255,255,0.1);
    --card:rgba(255,255,255,0.035);
    --font-d:'Space Grotesk',sans-serif; --font-b:'Inter',-apple-system,sans-serif;
  }
  *{margin:0;padding:0;box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{background:var(--bg);color:var(--ink);font-family:var(--font-b);-webkit-font-smoothing:antialiased;overflow-x:hidden;
    background-image:radial-gradient(760px 380px at 28% -6%,rgba(124,77,255,0.34),transparent 64%),radial-gradient(640px 420px at 102% 12%,rgba(0,200,255,0.16),transparent 58%),radial-gradient(560px 480px at 0% 72%,rgba(124,77,255,0.1),transparent 60%);}
  .wrap{max-width:470px;margin:0 auto;padding:0 22px}
  main{position:relative;z-index:1}
  .reveal{opacity:0;transform:translateY(18px);transition:opacity .7s ease,transform .7s cubic-bezier(.2,.8,.2,1)}
  .reveal.in{opacity:1;transform:none}

  nav{display:flex;justify-content:space-between;align-items:center;padding:18px 22px;max-width:470px;margin:0 auto}
  .brand{display:flex;align-items:center;gap:10px}
  .mark{width:30px;height:30px;border-radius:50%;background:conic-gradient(from 210deg,#7C4DFF,#6CE5FF,#B794FF,#7C4DFF);display:flex;align-items:center;justify-content:center;font-family:var(--font-d);font-weight:700;font-size:14px;color:#0a0618;box-shadow:0 0 18px rgba(124,77,255,0.5)}
  .brand b{font-family:var(--font-d);font-weight:600;font-size:16px;letter-spacing:3px}
  .nav-cta{font-size:12.5px;color:var(--ink);border:1px solid var(--brd);padding:9px 16px;border-radius:30px;background:rgba(255,255,255,0.03);transition:.25s;text-decoration:none}
  .nav-cta:hover{border-color:var(--v1);color:var(--v3)}

  .hero{text-align:center;padding:36px 0 32px}
  .pill{display:inline-flex;align-items:center;gap:8px;font-family:var(--font-d);font-size:11px;letter-spacing:1.4px;color:#C9C2E8;background:rgba(255,255,255,0.05);border:1px solid var(--brd);padding:8px 15px;border-radius:30px;margin-bottom:26px}
  .pdot{width:6px;height:6px;border-radius:50%;background:var(--v1);box-shadow:0 0 9px var(--v1);animation:pls 2s infinite}
  @keyframes pls{0%,100%{opacity:1}50%{opacity:.32}}
  .hcoin{width:84px;height:84px;border-radius:50%;margin:0 auto 24px;background:conic-gradient(from 200deg,#7C4DFF,#6CE5FF,#B794FF,#7C4DFF);display:flex;align-items:center;justify-content:center;box-shadow:0 0 50px rgba(124,77,255,0.5),inset 0 0 20px rgba(255,255,255,0.2);animation:float 4s ease-in-out infinite}
  .hcoin span{width:70px;height:70px;border-radius:50%;background:#0b0718;display:flex;align-items:center;justify-content:center;font-family:var(--font-d);font-weight:700;font-size:30px;background-clip:padding-box;color:transparent;background-image:linear-gradient(135deg,#B794FF,#6CE5FF);-webkit-background-clip:text}
  @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-7px)}}
  h1{font-family:var(--font-d);font-weight:700;font-size:42px;line-height:1.06;letter-spacing:-1.6px;margin-bottom:15px}
  h1 span{background:linear-gradient(95deg,#B794FF,#6CE5FF);-webkit-background-clip:text;background-clip:text;color:transparent}
  .sub{font-size:14.5px;line-height:1.62;color:var(--mut);max-width:356px;margin:0 auto 28px}

  .card{background:var(--card);border:1px solid var(--brd);border-radius:22px;padding:22px;backdrop-filter:blur(12px);box-shadow:0 24px 70px rgba(40,10,90,0.5)}
  .alloc{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
  .alloc .k{font-size:12px;color:var(--mut)}
  .alloc .v{font-family:var(--font-d);font-size:23px;font-weight:700;background:linear-gradient(95deg,#B794FF,#6CE5FF);-webkit-background-clip:text;background-clip:text;color:transparent}
  .btn{display:block;width:100%;text-align:center;background:linear-gradient(95deg,#7C4DFF,#5B8CFF);color:#fff;font-family:var(--font-d);font-size:15px;font-weight:600;padding:16px;border:none;border-radius:13px;cursor:pointer;letter-spacing:.2px;box-shadow:0 12px 34px rgba(124,77,255,0.45);transition:.2s;text-decoration:none}
  .btn:hover{transform:translateY(-2px);box-shadow:0 16px 40px rgba(124,77,255,0.6)}
  .btn:active{transform:translateY(0)}
  .btn[disabled],.btn.off{opacity:.55;cursor:not-allowed;transform:none!important;pointer-events:none}
  .hint{margin-top:12px;font-size:12px;color:var(--mut);display:flex;align-items:center;justify-content:center;gap:7px}
  .hint .tw{width:16px;height:16px;border-radius:4px;background:#0500ff;display:inline-block;background:linear-gradient(135deg,#3375BB,#0B5FD0)}
  .meter{margin-top:18px}
  .mt{display:flex;justify-content:space-between;font-size:11.5px;color:var(--mut);margin-bottom:8px}
  .mt b{font-family:var(--font-d);color:#C9C2E8;font-weight:600}
  .track{height:7px;background:rgba(255,255,255,0.08);border-radius:5px;overflow:hidden}
  .fill{height:100%;width:0;background:linear-gradient(90deg,#7C4DFF,#6CE5FF);border-radius:5px;transition:width 1.8s cubic-bezier(.2,.8,.2,1)}

  section{padding:36px 0;border-top:1px solid rgba(255,255,255,0.055)}
  .eyebrow{font-family:var(--font-d);font-size:11px;letter-spacing:2.5px;color:var(--v3);text-align:center;margin-bottom:8px}
  .sec-h{font-family:var(--font-d);font-weight:600;font-size:25px;text-align:center;margin-bottom:26px;letter-spacing:-0.4px}

  .step{display:flex;gap:16px;align-items:flex-start;padding:16px 0}
  .step:not(:last-child){border-bottom:1px solid rgba(255,255,255,0.05)}
  .step .n{font-family:var(--font-d);min-width:36px;height:36px;border-radius:50%;background:rgba(124,77,255,0.15);border:1px solid rgba(124,77,255,0.35);color:var(--v3);display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:600}
  .step .t{font-size:15px;margin-bottom:3px;font-weight:500}
  .step .d{font-size:13px;color:var(--mut);line-height:1.55}

  .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .tok{background:var(--card);border:1px solid var(--brd);border-radius:16px;padding:18px}
  .tok .k{font-size:11.5px;color:var(--mut);margin-bottom:7px}
  .tok .v{font-family:var(--font-d);font-size:21px;font-weight:600}
  .bar{margin-top:16px}
  .bar-top{display:flex;justify-content:space-between;font-size:11.5px;color:var(--mut);margin-bottom:7px}
  .bar-track{height:10px;border-radius:6px;overflow:hidden;display:flex;background:rgba(255,255,255,0.06)}
  .bar-air{width:5%;background:linear-gradient(90deg,#7C4DFF,#6CE5FF)}
  .bar-res{width:95%;background:rgba(255,255,255,0.1)}

  .trust{background:rgba(124,77,255,0.06);border:1px solid rgba(124,77,255,0.18);border-radius:18px;padding:22px}
  .tr{display:flex;gap:12px;align-items:center;padding:11px 0;font-size:13.5px;color:#D6D1EC}
  .tr:not(:last-child){border-bottom:1px solid rgba(255,255,255,0.055)}
  .check{min-width:24px;height:24px;border-radius:50%;background:rgba(124,77,255,0.2);color:var(--v3);display:flex;align-items:center;justify-content:center;font-size:12px}

  .road{display:flex;flex-direction:column;gap:0}
  .rstep{display:flex;gap:14px;padding-bottom:20px;position:relative}
  .rstep:not(:last-child)::before{content:"";position:absolute;left:7px;top:18px;bottom:0;width:1px;background:rgba(255,255,255,0.12)}
  .rdot{min-width:15px;height:15px;border-radius:50%;background:rgba(124,77,255,0.25);border:2px solid var(--v2);margin-top:3px;z-index:1}
  .rdot.done{background:var(--v1);box-shadow:0 0 10px var(--v1)}
  .rt{font-size:14px;font-weight:500;margin-bottom:2px}
  .rd{font-size:12.5px;color:var(--mut)}

  details{border-bottom:1px solid rgba(255,255,255,0.06);padding:15px 0}
  summary{font-size:14.5px;cursor:pointer;list-style:none;display:flex;justify-content:space-between;align-items:center;gap:12px}
  summary::-webkit-details-marker{display:none}
  .chev{color:var(--v3);transition:.25s;font-size:19px;min-width:16px;text-align:center}
  details[open] .chev{transform:rotate(45deg)}
  details p{font-size:13px;color:var(--mut);line-height:1.6;margin-top:10px}

  .final{text-align:center;padding:40px 0}
  footer{text-align:center;padding:34px 0 48px;border-top:1px solid rgba(255,255,255,0.055)}
  .fl{font-family:var(--font-d);font-size:16px;font-weight:600;letter-spacing:3px;color:var(--v3);margin-bottom:10px}
  .fs{font-size:11.5px;color:var(--mut2);line-height:1.7}
  .fnote{font-size:10.5px;color:var(--mut2);margin-top:14px;opacity:.8}
</style>
</head>
<body>
<main>
  <nav>
    <div class="brand"><div class="mark">A</div><b>AUREUS</b></div>
    <a class="nav-cta" href="#claim">Claim</a>
  </nav>

  <div class="wrap">
    <div class="hero" id="claim">
      <div class="hcoin"><span>A</span></div>
      <div class="pill"><span class="pdot"></span> <span id="pillTxt">500 SPOTS ONLY · LIVE NOW</span></div>
      <h1>Claim your<br><span id="h1Amt">1,000 AUR</span></h1>
      <p class="sub">A free allocation for the first 500 wallets on BNB Chain. One claim per wallet. Only a small network fee (<b id="gas1" style="color:#C9C2E8;font-weight:500">~$0.10 in BNB</b>) to process the claim.</p>
      <div class="card">
        <div class="alloc"><span class="k">Your allocation</span><span class="v" id="allocV">1,000 AUR</span></div>
        <a class="btn" id="mainBtn" href="#" rel="noopener">Claim now</a>
        <div class="hint" id="hint"><span class="tw"></span> Opens in Trust Wallet · takes 30 seconds</div>
        <div class="hint" style="margin-top:6px">Keep <b id="gas2" style="color:#C9C2E8;font-weight:500;margin:0 4px">~$0.10 in BNB</b> in your wallet for the network fee</div>
        <div class="meter">
          <div class="mt"><span><b id="c1">0</b> claimed</span><span><b id="c2">500</b> remaining</span></div>
          <div class="track"><div class="fill" id="fill"></div></div>
        </div>
      </div>
    </div>

    <section class="reveal">
      <div class="eyebrow">HOW IT WORKS</div>
      <div class="sec-h">Claim in three steps</div>
      <div class="step"><div class="n">1</div><div><div class="t">Tap “Claim now”</div><div class="d">The claim app opens inside Trust Wallet (or your BEP20 wallet’s browser).</div></div></div>
      <div class="step"><div class="n">2</div><div><div class="t">Connect your wallet</div><div class="d">Approve the connection on BNB Chain. No token approvals, ever.</div></div></div>
      <div class="step"><div class="n">3</div><div><div class="t">Confirm &amp; receive your AUR</div><div class="d">Approve the claim transaction (network fee <span id="gas3">~$0.10 in BNB</span>). Tokens land in your wallet. One claim per address.</div></div></div>
    </section>

    <section class="reveal">
      <div class="eyebrow">TOKENOMICS</div>
      <div class="sec-h">Clean and fixed</div>
      <div class="grid">
        <div class="tok"><div class="k">Total supply</div><div class="v">10,000,000</div></div>
        <div class="tok"><div class="k">Symbol</div><div class="v" id="symV">AUR</div></div>
        <div class="tok"><div class="k">Airdrop pool</div><div class="v" id="poolV">500,000</div></div>
        <div class="tok"><div class="k">Network</div><div class="v">BNB Chain</div></div>
      </div>
      <div class="bar">
        <div class="bar-top"><span>Airdrop 5%</span><span>Reserve &amp; liquidity 95%</span></div>
        <div class="bar-track"><div class="bar-air"></div><div class="bar-res"></div></div>
      </div>
    </section>

    <section class="reveal">
      <div class="eyebrow">WHY TRUST IT</div>
      <div class="sec-h">Built to be verified</div>
      <div class="trust">
        <div class="tr"><span class="check">✓</span> Claim-only — never requests token approvals</div>
        <div class="tr"><span class="check">✓</span> Fixed supply, no hidden mint function</div>
        <div class="tr"><span class="check">✓</span> Runs inside Trust Wallet’s own DApp browser</div>
        <div class="tr"><span class="check">✓</span> One claim per wallet, enforced on-chain</div>
      </div>
    </section>

    <section class="reveal">
      <div class="eyebrow">ROADMAP</div>
      <div class="sec-h">The path ahead</div>
      <div class="road">
        <div class="rstep"><div class="rdot done"></div><div><div class="rt">Token deployed on BNB Chain</div><div class="rd">Contract live on BNB Smart Chain.</div></div></div>
        <div class="rstep"><div class="rdot done"></div><div><div class="rt">Airdrop opens — first 500</div><div class="rd">Claim portal live, allocations distributing.</div></div></div>
        <div class="rstep"><div class="rdot"></div><div><div class="rt">Liquidity added</div><div class="rd">Trading pair goes live after the airdrop closes.</div></div></div>
        <div class="rstep"><div class="rdot"></div><div><div class="rt">Community &amp; listings</div><div class="rd">Growth, partnerships and exchange outreach.</div></div></div>
      </div>
    </section>

    <section class="reveal">
      <div class="eyebrow">QUESTIONS</div>
      <div class="sec-h">Good to know</div>
      <details open><summary>Is it really free?<span class="chev">+</span></summary><p>Yes. The tokens cost nothing and nobody is paid for them. The only cost is the BNB Chain network fee (gas) for the claim transaction — about <span id="gas4">~$0.10 in BNB</span>, which goes to the network, not to us. Make sure your wallet holds a little BNB.</p></details>
      <details><summary>What happens after 500 claims?<span class="chev">+</span></summary><p>The pool closes. The page shows the airdrop as fully claimed and no further claims are possible.</p></details>
      <details><summary>Which wallets are supported?<span class="chev">+</span></summary><p>Trust Wallet is recommended. Any BEP20-compatible wallet with a DApp browser on BNB Chain also works.</p></details>
      <details><summary>Why do I need BNB?<span class="chev">+</span></summary><p>Every transaction on BNB Chain needs a tiny gas fee paid in BNB. The claim is one transaction, so you need roughly <span id="gas5">~$0.10 in BNB</span> in the same wallet. If you have zero BNB, the wallet will not let you confirm.</p></details>
      <details><summary>Can I claim twice?<span class="chev">+</span></summary><p>No. Each address is recorded and allowed a single claim.</p></details>
    </section>

    <div class="final reveal">
      <a class="btn" id="btn2" href="#" style="max-width:360px;margin:0 auto" rel="noopener">Claim now</a>
    </div>

    <footer>
      <div class="brand" style="justify-content:center;margin-bottom:12px"><div class="mark" style="width:26px;height:26px;font-size:12px">A</div><b style="font-size:14px">AUREUS</b></div>
      <div class="fs"><span id="symF">AUR</span> · BNB Chain<span id="contractWrap"> · <a id="contractLink" href="#" style="color:var(--v3);text-decoration:none" target="_blank" rel="noopener">Contract on BscScan</a></span><span id="tgWrap"> · <a id="tgLink" href="#" style="color:var(--v3);text-decoration:none" target="_blank" rel="noopener">Telegram</a></span><br>Network gas fee (<span id="gas6">~$0.10 in BNB</span>) applies.</div>
      <div class="fnote">This is an airdrop of a free token with no guaranteed value. Not financial advice. Do your own research.</div>
    </footer>
  </div>
</main>
<script>
(function(){
  var $=function(id){return document.getElementById(id)};
  var CFG=null, target='';

  // ---------- visitor id (stays same across visits; forwarded to the DApp as ?ref=) ----------
  function uid(){return (crypto.randomUUID?crypto.randomUUID():('e'+Date.now()+Math.random()))}
  var VID=null; try{VID=localStorage.getItem('aur_vid');if(!VID){VID=uid().replace(/-/g,'').slice(0,20);localStorage.setItem('aur_vid',VID)}}catch(e){VID=uid().replace(/-/g,'').slice(0,20)}

  // ---------- cookies ----------
  function cookie(n){var m=document.cookie.match('(^|;)\\s*'+n+'=([^;]+)');return m?decodeURIComponent(m[2]):null}
  function fbc(){var c=cookie('_fbc');if(c)return c;var q=new URLSearchParams(location.search).get('fbclid');return q?('fb.1.'+Date.now()+'.'+q):null}

  // ---------- pixel + server event (same event_id = dedup) ----------
  function track(type){
    var eid=uid();
    var evName=CFG&&CFG['ev_'+type];
    if(window.fbq&&evName&&CFG.pixel_id){try{fbq('track',evName,{},{eventID:eid});}catch(e){}}
    var body=JSON.stringify({type:type,event_id:eid,vid:VID,fbp:cookie('_fbp'),fbc:fbc(),url:location.href});
    try{fetch('/api/event',{method:'POST',headers:{'content-type':'application/json'},body:body,keepalive:true}).catch(function(){})}catch(e){}
  }

  function fmt(n){return Number(n).toLocaleString('en-US')}
  function counter(claimed,total){
    var c1=$('c1'),c2=$('c2'),fill=$('fill'),cur=0,tgt=Number(claimed);
    fill.style.width=(total?Math.min(100,tgt/total*100):0)+'%';
    var t=setInterval(function(){cur+=Math.ceil((tgt-cur)/10);if(cur>=tgt){cur=tgt;clearInterval(t);}c1.textContent=fmt(cur);c2.textContent=fmt(Math.max(0,total-cur));},40);
  }
  function inWallet(){return !!(window.ethereum||window.trustwallet)}
  function buildTarget(c){
    var u=c.dapp_link||'';
    if(!u)return '';
    if(c.append_ref==='1'){u+=(u.indexOf('?')>-1?'&':'?')+'ref='+encodeURIComponent(VID);}
    // already inside a wallet DApp browser → open directly; else → Trust Wallet deep link
    if(c.trust_deeplink==='1'&&!inWallet())return 'https://link.trustwallet.com/open_url?coin_id=20000714&url='+encodeURIComponent(u);
    return u;
  }
  function setOff(txt){[$('mainBtn'),$('btn2')].forEach(function(b){b.textContent=txt;b.classList.add('off');b.removeAttribute('href')});$('hint').style.display='none'}

  function loadConfig(){
    return fetch('/api/config').then(function(r){return r.json()}).then(function(c){
      CFG=c;
      var sym=c.token_symbol||'AUR', amt=c.amount_per_wallet||'1000', max=Number(c.max_claims||500);
      $('allocV').textContent=fmt(amt)+' '+sym; $('h1Amt').textContent=fmt(amt)+' '+sym;
      $('symV').textContent=sym; $('symF').textContent=sym; $('poolV').textContent=fmt(Number(amt)*max);
      $('pillTxt').textContent=fmt(max)+' SPOTS ONLY · LIVE NOW';
      var g=c.gas_fee_text||'~$0.10 in BNB';['gas1','gas2','gas3','gas4','gas5','gas6'].forEach(function(id){if($(id))$(id).textContent=g});
      counter(c.total_claims||0,max);
      if(c.bscscan_link)$('contractLink').href=c.bscscan_link;else $('contractWrap').style.display='none';
      if(c.telegram_link)$('tgLink').href=c.telegram_link;else $('tgWrap').style.display='none';
      if(c.pixel_id&&!window.fbq){
        !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
        fbq('init',c.pixel_id,{external_id:VID});
      }
      track('page_view');
      target=buildTarget(c);
      if(c.claims_open!=='1'){setOff('Claims paused');return}
      if(c.remaining!==undefined&&c.remaining<=0){setOff('All spots claimed');return}
      if(!target){setOff('Opening soon');return}
      [$('mainBtn'),$('btn2')].forEach(function(b){b.href=target});
      if(inWallet()){$('hint').innerHTML='Opens the claim app · takes 30 seconds'}
    });
  }

  function go(ev){
    if(!target)return;
    ev.preventDefault();
    track('cta_click');
    setTimeout(function(){location.href=target},180);
  }
  $('mainBtn').addEventListener('click',go);
  $('btn2').addEventListener('click',go);

  window.addEventListener('load',function(){
    var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting)e.target.classList.add('in');});},{threshold:0.12});
    document.querySelectorAll('.reveal').forEach(function(el){io.observe(el);});
    loadConfig().catch(function(){setOff('Try again shortly')});
  });
})();
</script>
</body>
</html>
`;

// ===================== ADMIN PANEL =====================
const ADMIN_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>AUREUS — Admin</title>
<meta name="theme-color" content="#070510">
<meta name="color-scheme" content="dark">
<link rel="icon" type="image/svg+xml" href="/icon.svg">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{--bg:#070510;--v1:#7C4DFF;--v3:#B794FF;--cyan:#6CE5FF;--ink:#F4F2FB;--mut:#A9A3C2;--mut2:#6B6880;--brd:rgba(255,255,255,0.1);--card:rgba(255,255,255,0.035);--ok:#9BF0C9;--err:#FF9DB0;--fd:'Space Grotesk',sans-serif;--fb:'Inter',sans-serif}
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:var(--bg);color:var(--ink);font-family:var(--fb);-webkit-font-smoothing:antialiased;background-image:radial-gradient(760px 380px at 28% -6%,rgba(124,77,255,0.25),transparent 64%)}
  .wrap{max-width:1100px;margin:0 auto;padding:18px 16px 60px}
  nav{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;padding:6px 0 18px;border-bottom:1px solid var(--brd);margin-bottom:18px}
  .brand{display:flex;align-items:center;gap:10px;font-family:var(--fd);font-weight:600;letter-spacing:3px}
  .mark{width:28px;height:28px;border-radius:50%;background:conic-gradient(from 210deg,#7C4DFF,#6CE5FF,#B794FF,#7C4DFF);display:flex;align-items:center;justify-content:center;font-size:13px;color:#0a0618}
  .tabs{display:flex;gap:6px;flex-wrap:wrap}
  .tabs button{font-family:var(--fb);font-size:12.5px;color:var(--mut);background:rgba(255,255,255,0.04);border:1px solid var(--brd);padding:8px 14px;border-radius:30px;cursor:pointer}
  .tabs button.on{color:#fff;background:var(--v1);border-color:var(--v1)}
  .tabs button.hot{border-color:rgba(155,240,201,0.5);color:var(--ok)}
  .tabs button.hot.on{background:#1f8a5f;border-color:#1f8a5f;color:#fff}
  .panel{display:none}.panel.on{display:block}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
  .stat{background:var(--card);border:1px solid var(--brd);border-radius:14px;padding:16px}
  .stat .k{font-size:11.5px;color:var(--mut);margin-bottom:6px}
  .stat .v{font-family:var(--fd);font-size:24px;font-weight:700}
  .stat .s{font-size:11px;color:var(--mut2);margin-top:4px}
  .card{background:var(--card);border:1px solid var(--brd);border-radius:16px;padding:18px;margin-bottom:14px}
  h3{font-family:var(--fd);font-size:15px;font-weight:600;margin-bottom:12px;letter-spacing:.3px}
  h3 small{font-weight:400;color:var(--mut);font-size:12px;margin-left:8px}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th{text-align:left;color:var(--mut);font-weight:500;font-size:11px;letter-spacing:.8px;padding:8px 8px;border-bottom:1px solid var(--brd);white-space:nowrap}
  td{padding:9px 8px;border-bottom:1px solid rgba(255,255,255,0.05);vertical-align:top;font-family:ui-monospace,Menlo,monospace;font-size:12px;white-space:nowrap}
  tr:hover td{background:rgba(255,255,255,0.025)}
  .tag{display:inline-block;padding:3px 8px;border-radius:20px;font-size:11px;font-family:var(--fb)}
  .t-page_view{background:rgba(255,255,255,0.08);color:var(--mut)}
  .t-cta_click{background:rgba(108,229,255,0.12);color:var(--cyan)}
  .t-registration{background:rgba(155,240,201,0.15);color:var(--ok)}
  .ok{color:var(--ok)}.err{color:var(--err)}.mut{color:var(--mut2)}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
  input,select,textarea{background:rgba(255,255,255,0.05);border:1px solid var(--brd);color:var(--ink);font-family:var(--fb);font-size:13px;padding:10px 12px;border-radius:10px;outline:none;width:100%}
  textarea{font-family:ui-monospace,Menlo,monospace;min-height:90px;resize:vertical}
  input:focus,select:focus,textarea:focus{border-color:var(--v1)}
  label{display:block;font-size:11.5px;color:var(--mut);margin-bottom:5px}
  .f{margin-bottom:12px}
  .cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
  .btn{font-family:var(--fd);font-size:13px;font-weight:600;color:#fff;background:linear-gradient(95deg,#7C4DFF,#5B8CFF);border:none;padding:11px 18px;border-radius:10px;cursor:pointer}
  .btn.go{background:linear-gradient(95deg,#1f8a5f,#2fbf86);font-size:14px;padding:13px 22px}
  .btn.sec{background:rgba(255,255,255,0.06);border:1px solid var(--brd);color:var(--ink);font-weight:500}
  .btn.sm{padding:8px 12px;font-size:12px}
  .btn[disabled]{opacity:.5;cursor:wait}
  .toggle{display:flex;align-items:center;gap:10px;font-size:13px;padding:8px 0}
  .toggle input{width:auto}
  .msg{font-size:12.5px;margin-top:8px;min-height:16px}
  .login{max-width:380px;margin:80px auto;text-align:center}
  .login h1{font-family:var(--fd);font-size:22px;margin:14px 0 20px}
  .funnel{display:flex;gap:6px;align-items:flex-end;height:90px;margin:8px 0 4px}
  .fbar{flex:1;background:linear-gradient(180deg,#7C4DFF,#5B8CFF);border-radius:6px 6px 2px 2px;min-height:4px;position:relative}
  .fbar span{position:absolute;top:-18px;left:0;right:0;text-align:center;font-size:11px;color:var(--mut)}
  .flab{display:flex;gap:6px}.flab div{flex:1;text-align:center;font-size:10.5px;color:var(--mut2)}
  .pill{font-size:11px;color:var(--mut);border:1px solid var(--brd);padding:4px 10px;border-radius:20px}
  .res{font-family:ui-monospace,Menlo,monospace;font-size:12px;line-height:1.8;margin-top:10px}
  .note{font-size:12px;color:var(--mut);line-height:1.6}
  code{background:rgba(255,255,255,0.08);padding:1px 5px;border-radius:4px;font-size:11.5px}
</style>
</head>
<body>
<div class="wrap">

<div id="loginView" class="login" style="display:none">
  <div class="brand" style="justify-content:center"><div class="mark">A</div>AUREUS</div>
  <h1>Admin access</h1>
  <input id="pw" type="password" placeholder="Admin password" style="margin-bottom:10px">
  <button class="btn" style="width:100%" onclick="login()">Sign in</button>
  <div class="msg err" id="loginMsg"></div>
</div>

<div id="app" style="display:none">
<nav>
  <div class="brand"><div class="mark">A</div>AUREUS <span class="pill" style="letter-spacing:0;margin-left:6px">admin</span></div>
  <div class="tabs">
    <button class="on hot" data-t="fire">Fire to Meta</button>
    <button data-t="dash">Dashboard</button>
    <button data-t="events">Events</button>
    <button data-t="settings">Settings</button>
    <button data-t="meta">Meta / CAPI</button>
    <button onclick="logout()">Logout</button>
  </div>
</nav>

<!-- ============ FIRE ============ -->
<div class="panel on" id="p-fire">
  <div class="cols">
    <div class="card">
      <h3>Fire CompleteRegistration <small>customer claimed in DApp → paste wallet → fire</small></h3>
      <div class="f"><label>Wallet address(es) — one per line for bulk</label><textarea id="fWallets" placeholder="0x…"></textarea></div>
      <div class="cols">
        <div class="f"><label>Attach ad-click data <span class="mut">(gives Meta fbc / fbp / IP for attribution)</span></label>
          <select id="fMatch"><option value="auto">Auto — latest unmatched click</option><option value="none">None — wallet only</option></select></div>
        <div class="f"><label>Or paste click ref <span class="mut">(the <code>?ref=</code> your DApp received)</span></label><input id="fRef" placeholder="e.g. 7f3a9c2b1d…"></div>
      </div>
      <div class="cols">
        <div class="f"><label>Meta event name</label><input id="fEvent" placeholder="CompleteRegistration"></div>
        <div class="f"><label>Note (optional)</label><input id="fNote" placeholder="e.g. from TG message 01:32"></div>
      </div>
      <div class="toggle"><input type="checkbox" id="fForce"> Fire again even if this wallet was already fired</div>
      <div class="toggle"><input type="checkbox" id="fTest"> Test mode (uses test event code — shows in Test events, not counted)</div>
      <div class="row" style="margin-top:6px"><button class="btn go" id="fireBtn" onclick="fire()">Fire to Meta</button><span class="msg" id="fireMsg"></span></div>
      <div class="res" id="fireRes"></div>
    </div>
    <div class="card">
      <h3>Recent CTA clicks <small>who tapped "Claim now" · newest first</small></h3>
      <div class="note" style="margin-bottom:10px">Auto mode picks the newest <b>unmatched</b> click within the window set in Settings. If several people clicked around the same time, pick the right one here.</div>
      <div style="overflow:auto"><table><thead><tr><th>Time (IST)</th><th>Ref</th><th>IP</th><th>fbc</th><th>Used</th><th></th></tr></thead><tbody id="clicks"></tbody></table></div>
    </div>
  </div>
  <div class="card">
    <h3>Last fired <small>latest 20</small></h3>
    <div style="overflow:auto"><table><thead><tr><th>Time (IST)</th><th>Wallet</th><th>Meta</th><th>CAPI</th><th>Click</th><th>Note</th></tr></thead><tbody id="fired"></tbody></table></div>
  </div>
</div>

<!-- ============ DASHBOARD ============ -->
<div class="panel" id="p-dash">
  <div class="grid" id="stats"></div>
  <div class="card">
    <h3>Funnel <small>all time</small></h3>
    <div class="funnel" id="funnel"></div>
    <div class="flab"><div>Page views</div><div>Claim clicks</div><div>Registrations fired</div></div>
  </div>
  <div class="card">
    <h3>Live feed <small>latest 30 · auto-refresh 10s</small></h3>
    <div style="overflow:auto"><table><thead><tr><th>Time (IST)</th><th>Event</th><th>Wallet</th><th>Ref</th><th>Meta</th><th>CAPI</th><th>fbc</th></tr></thead><tbody id="feed"></tbody></table></div>
  </div>
</div>

<!-- ============ EVENTS ============ -->
<div class="panel" id="p-events">
  <div class="card">
    <div class="row">
      <select id="fType" style="width:auto"><option value="">All events</option><option>page_view</option><option>cta_click</option><option>registration</option></select>
      <button class="btn sm sec" onclick="loadEvents()">Refresh</button>
      <button class="btn sm sec" onclick="loadMore()">Load older</button>
      <a class="btn sm" href="/api/admin/export.csv" style="text-decoration:none">Export CSV</a>
      <span class="pill" id="evCount"></span>
    </div>
    <div style="overflow:auto"><table><thead><tr><th>Time (IST)</th><th>Event</th><th>Wallet</th><th>Ref</th><th>Meta</th><th>CAPI</th><th>IP</th><th>Note</th></tr></thead><tbody id="evBody"></tbody></table></div>
  </div>
</div>

<!-- ============ SETTINGS ============ -->
<div class="panel" id="p-settings">
  <div class="card">
    <h3>Claim link</h3>
    <div class="f"><label>DApp link (the "Claim now" button opens this)</label><input data-k="dapp_link" placeholder="https://…"></div>
    <div class="toggle"><input type="checkbox" data-k="trust_deeplink" data-bool> Open through Trust Wallet deep link when user is in a normal browser (inside a wallet browser it opens directly)</div>
    <div class="toggle"><input type="checkbox" data-k="append_ref" data-bool> Append <code>?ref=&lt;visitor id&gt;</code> to the link (if your DApp forwards it in the claim message, paste it in Fire tab for exact matching)</div>
    <div class="toggle"><input type="checkbox" data-k="claims_open" data-bool> Claims open (off = button shows "Claims paused")</div>
  </div>
  <div class="card">
    <h3>Page text &amp; counters</h3>
    <div class="cols">
      <div class="f"><label>Site name</label><input data-k="site_name"></div>
      <div class="f"><label>Token symbol</label><input data-k="token_symbol"></div>
      <div class="f"><label>Amount per wallet (display)</label><input data-k="amount_per_wallet"></div>
      <div class="f"><label>Max claims (display)</label><input data-k="max_claims"></div>
      <div class="f"><label>Claimed counter base <span class="mut">(added to fired registrations)</span></label><input data-k="claims_base" placeholder="0"></div>
      <div class="f"><label>Auto-match window (minutes)</label><input data-k="auto_match_minutes" placeholder="120"></div>
      <div class="f"><label>Network fee text <span class="mut">(shown on page)</span></label><input data-k="gas_fee_text" placeholder="~$0.10 in BNB"></div>
      <div class="f"><label>BscScan link (footer, optional)</label><input data-k="bscscan_link" placeholder="https://bscscan.com/token/0x…"></div>
      <div class="f"><label>Telegram link (footer, optional)</label><input data-k="telegram_link" placeholder="https://t.me/…"></div>
    </div>
    <div class="note">Counter on the page = base + registrations you fired. Page shows "All spots claimed" when counter reaches max.</div>
  </div>
  <button class="btn" onclick="saveSettings()">Save settings</button> <span class="msg" id="setMsg"></span>
</div>

<!-- ============ META ============ -->
<div class="panel" id="p-meta">
  <div class="card">
    <h3>Pixel &amp; Conversions API</h3>
    <div class="cols">
      <div class="f"><label>Pixel / Dataset ID</label><input data-k="pixel_id"></div>
      <div class="f"><label>CAPI access token</label><input data-k="capi_token" type="password" placeholder="EAAB…"></div>
      <div class="f"><label>Test event code (Events Manager → Test events)</label><input data-k="capi_test_code" placeholder="TEST12345"></div>
    </div>
  </div>
  <div class="card">
    <h3>Event mapping</h3>
    <div class="cols">
      <div class="f"><label>Page view → <span class="mut">(pixel)</span></label><input data-k="ev_page_view"></div>
      <div class="f"><label>Claim button click → <span class="mut">(pixel + CAPI)</span></label><input data-k="ev_cta_click"></div>
      <div class="f"><label>Registration (fired by you) → <span class="mut">(CAPI only)</span></label><input data-k="ev_registration"></div>
    </div>
    <div class="toggle"><input type="checkbox" data-k="capi_on_page_view" data-bool> Also send page view via CAPI</div>
    <div class="toggle"><input type="checkbox" data-k="capi_on_cta_click" data-bool> Also send claim click via CAPI (recommended)</div>
    <div class="note" style="margin-top:8px">Registration goes server-side only (the user is in your DApp, not on this page). It carries the ad-click's fbc/fbp/IP/UA + hashed wallet so Meta attributes it to the ad. Build the lookalike on <b>CompleteRegistration</b>.</div>
  </div>
  <div class="row">
    <button class="btn" onclick="saveSettings()">Save</button>
    <button class="btn sec" onclick="testCapi()">Send test event to Meta</button>
    <span class="msg" id="metaMsg"></span>
  </div>
</div>

</div>
</div>

<script>
var $=function(id){return document.getElementById(id)};
var api=function(p,o){return fetch('/api/admin'+p,Object.assign({headers:{'content-type':'application/json'}},o||{})).then(function(r){return r.json().then(function(j){if(r.status===401){showLogin();throw new Error('unauthorized')}return j})})};
var oldest=0, timer=null, SET={};

function showLogin(){$('loginView').style.display='block';$('app').style.display='none';clearInterval(timer)}
function showApp(){$('loginView').style.display='none';$('app').style.display='block';loadAll();timer=setInterval(function(){if($('p-dash').classList.contains('on'))loadDash();if($('p-fire').classList.contains('on'))loadFire()},10000)}
function login(){api('/login',{method:'POST',body:JSON.stringify({password:$('pw').value})}).then(function(j){if(j.ok)showApp();else $('loginMsg').textContent=j.error||'Login failed'}).catch(function(){$('loginMsg').textContent='Login failed'})}
function logout(){api('/logout',{method:'POST'}).then(showLogin)}
$('pw').addEventListener('keydown',function(e){if(e.key==='Enter')login()});

document.querySelectorAll('.tabs button[data-t]').forEach(function(b){b.addEventListener('click',function(){
  document.querySelectorAll('.tabs button[data-t]').forEach(function(x){x.classList.remove('on')});
  document.querySelectorAll('.panel').forEach(function(p){p.classList.remove('on')});
  b.classList.add('on');$('p-'+b.dataset.t).classList.add('on');
  if(b.dataset.t==='events')loadEvents();if(b.dataset.t==='dash')loadDash();if(b.dataset.t==='fire')loadFire();
})});

function ist(ts){return new Date(ts*1000).toLocaleString('en-IN',{timeZone:'Asia/Kolkata',hour12:false,day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit',second:'2-digit'})}
function sh(a){return a?'<span title="'+a+'">'+a.slice(0,6)+'…'+a.slice(-4)+'</span>':'<span class="mut">—</span>'}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function capiCell(s){if(!s)return'';if(s==='sent')return'<span class="ok">sent</span>';if(s==='skipped')return'<span class="mut">—</span>';return'<span class="err" title="'+esc(s)+'">error</span>'}
function rowHtml(e,withIp){
  return '<tr><td>'+ist(e.ts)+'</td><td><span class="tag t-'+e.type+'">'+e.type.replace('_',' ')+'</span></td><td>'+sh(e.address)+'</td><td>'+(e.vid?'<span class="mut">'+esc(e.vid).slice(0,8)+'</span>':'<span class="mut">—</span>')+'</td><td>'+(e.meta_event||'<span class="mut">—</span>')+'</td><td>'+capiCell(e.capi_status)+'</td><td>'+(withIp?esc(e.ip||''):(e.fbc?'<span class="ok">✓</span>':'<span class="mut">—</span>'))+'</td>'+(withIp?'<td>'+esc(e.note||'')+'</td>':'')+'</tr>';
}

// ---- Fire tab ----
function loadFire(){
  api('/clicks').then(function(cl){
    var sel=$('fMatch'),cur=sel.value;
    sel.innerHTML='<option value="auto">Auto — latest unmatched click</option><option value="none">None — wallet only</option>'+cl.map(function(c){return'<option value="click:'+c.id+'">'+ist(c.ts)+' · '+(c.ip||'')+(c.has_fbc?' · fbc✓':'')+(c.matched?' · used':'')+'</option>'}).join('');
    sel.value=cur||'auto';
    $('clicks').innerHTML=cl.length?cl.map(function(c){return'<tr><td>'+ist(c.ts)+'</td><td class="mut">'+esc(c.vid||'').slice(0,8)+'</td><td>'+esc(c.ip||'')+'</td><td>'+(c.has_fbc?'<span class="ok">✓</span>':'<span class="mut">—</span>')+'</td><td>'+(c.matched?'<span class="mut">used</span>':'<span class="ok">free</span>')+'</td><td><button class="btn sm sec" onclick="pick('+c.id+')">use</button></td></tr>'}).join(''):'<tr><td colspan="6" class="mut">No clicks yet.</td></tr>';
  }).catch(function(){});
  api('/events?type=registration&limit=20').then(function(ev){
    $('fired').innerHTML=ev.length?ev.map(function(e){return'<tr><td>'+ist(e.ts)+'</td><td>'+sh(e.address)+'</td><td>'+(e.meta_event||'')+'</td><td>'+capiCell(e.capi_status)+'</td><td>'+(e.click_id?'<span class="ok">#'+e.click_id+'</span>':'<span class="mut">none</span>')+'</td><td>'+esc(e.note||'')+'</td></tr>'}).join(''):'<tr><td colspan="6" class="mut">Nothing fired yet.</td></tr>';
  }).catch(function(){});
}
function pick(id){$('fMatch').value='click:'+id;$('fRef').value='';window.scrollTo({top:0,behavior:'smooth'})}
function fire(){
  var w=$('fWallets').value.trim();if(!w){$('fireMsg').textContent='Paste a wallet address';$('fireMsg').className='msg err';return}
  var match=$('fRef').value.trim()?('vid:'+$('fRef').value.trim()):$('fMatch').value;
  $('fireBtn').disabled=true;$('fireMsg').textContent='Sending…';$('fireMsg').className='msg';
  api('/fire',{method:'POST',body:JSON.stringify({wallets:w,match:match,event:$('fEvent').value.trim()||SET.ev_registration,note:$('fNote').value,force:$('fForce').checked,test:$('fTest').checked})}).then(function(j){
    $('fireBtn').disabled=false;
    if(!j.ok){$('fireMsg').textContent='Error: '+j.error;$('fireMsg').className='msg err';return}
    var okN=j.results.filter(function(r){return r.status==='sent'}).length;
    $('fireMsg').textContent=okN+' / '+j.results.length+' sent';$('fireMsg').className='msg '+(okN?'ok':'err');
    $('fireRes').innerHTML=j.results.map(function(r){return'<div>'+sh(r.wallet)+' → <span class="'+(r.status==='sent'?'ok':'err')+'">'+esc(r.status)+'</span>'+(r.matched_click?' <span class="mut">(click #'+r.matched_click+')</span>':' <span class="mut">(no click data)</span>')+'</div>'}).join('');
    if(okN){$('fWallets').value='';$('fNote').value='';$('fRef').value='';$('fMatch').value='auto'}
    loadFire();
  }).catch(function(e){$('fireBtn').disabled=false;$('fireMsg').textContent='Error';$('fireMsg').className='msg err'});
}

// ---- Dashboard ----
function loadDash(){
  api('/stats').then(function(s){
    var cards=[['Page views',s.page_view],['Claim clicks',s.cta_click,s.unique_visitors+' unique visitors'],['Registrations fired',s.registrations,s.registration_errors?s.registration_errors+' failed':'to Meta'],['Clicks pending',s.pending_clicks,'unmatched, last 24h'],['Counter on page',s.total_display+' / '+s.max_claims],['CAPI errors',s.capi_errors]];
    $('stats').innerHTML=cards.map(function(c){return'<div class="stat"><div class="k">'+c[0]+'</div><div class="v">'+(c[1]||0)+'</div>'+(c[2]?'<div class="s">'+c[2]+'</div>':'')+'</div>'}).join('');
    var f=[s.page_view,s.cta_click,s.registrations],mx=Math.max.apply(null,f.concat([1]));
    $('funnel').innerHTML=f.map(function(v){return'<div class="fbar" style="height:'+Math.max(4,v/mx*100)+'%"><span>'+(v||0)+'</span></div>'}).join('');
  }).catch(function(){});
  api('/events?limit=30').then(function(ev){$('feed').innerHTML=ev.map(function(e){return rowHtml(e,false)}).join('')}).catch(function(){});
}
function loadEvents(){oldest=0;var t=$('fType').value;api('/events?limit=100'+(t?'&type='+t:'')).then(function(ev){$('evBody').innerHTML=ev.map(function(e){return rowHtml(e,true)}).join('');if(ev.length)oldest=ev[ev.length-1].id;$('evCount').textContent=ev.length+' shown'})}
function loadMore(){if(!oldest)return;var t=$('fType').value;api('/events?limit=100&before='+oldest+(t?'&type='+t:'')).then(function(ev){$('evBody').innerHTML+=ev.map(function(e){return rowHtml(e,true)}).join('');if(ev.length)oldest=ev[ev.length-1].id})}

// ---- Settings ----
function loadSettings(){api('/settings').then(function(s){SET=s;document.querySelectorAll('[data-k]').forEach(function(el){var k=el.dataset.k;if(el.hasAttribute('data-bool'))el.checked=s[k]==='1';else el.value=s[k]||''});$('fEvent').placeholder=s.ev_registration||'CompleteRegistration'})}
function collect(){var o={};document.querySelectorAll('[data-k]').forEach(function(el){o[el.dataset.k]=el.hasAttribute('data-bool')?(el.checked?'1':'0'):el.value.trim()});return o}
function saveSettings(){api('/settings',{method:'PUT',body:JSON.stringify(collect())}).then(function(j){var m=j.ok?'Saved.':'Error: '+j.error;['setMsg','metaMsg'].forEach(function(id){$(id).textContent=m;$(id).className='msg '+(j.ok?'ok':'err')});loadSettings();loadDash()})}
function testCapi(){$('metaMsg').textContent='Sending…';api('/test-capi',{method:'POST',body:JSON.stringify({event:$('p-meta').querySelector('[data-k=ev_cta_click]').value||'Lead'})}).then(function(j){$('metaMsg').textContent=j.ok?'Sent. Check Events Manager → Test events.':'Error: '+j.error;$('metaMsg').className='msg '+(j.ok?'ok':'err')})}
function loadAll(){loadFire();loadDash();loadSettings()}

api('/stats').then(showApp).catch(showLogin);
</script>
</body>
</html>
`;
