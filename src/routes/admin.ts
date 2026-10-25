import { Router } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { db } from '../db';
import { validateDeadline } from '../validate';
import { adminGate, endSession, hasSession, sameOrigin, startSession, tokenMatches, adminToken, recentRejects } from '../adminauth';
import { fuelMemoState, fuelSnapshot, fuelCacheFile } from './fuel';

export const adminRouter = Router();

// Brute-force guard: 8 failed attempts per IP per 15 minutes.
const failures = new Map<string, { n: number; reset: number }>();
const WINDOW = 15 * 60 * 1000;
const LIMIT = 8;

function tooMany(ip: string): boolean {
  const rec = failures.get(ip);
  if (!rec) return false;
  if (Date.now() > rec.reset) { failures.delete(ip); return false; }
  return rec.n >= LIMIT;
}

function noteFailure(ip: string): void {
  const rec = failures.get(ip);
  if (!rec || Date.now() > rec.reset) failures.set(ip, { n: 1, reset: Date.now() + WINDOW });
  else rec.n += 1;
}

type Row = { id: string; title: string; detail: string; due: string; url: string; source: string; verified: string };

const esc = (s: unknown) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));

const daysUntil = (iso: string) => {
  const d = Date.parse(iso + 'T00:00:00Z');
  if (Number.isNaN(d)) return null;
  return Math.round((d - Date.now()) / 86_400_000);
};

const badge = (days: number | null) => {
  if (days === null) return '<span class="pill muted">—</span>';
  const cls = days <= 2 ? 'danger' : days <= 7 ? 'warn' : 'muted';
  const label = days < 0 ? `${Math.abs(days)}d ago` : days === 0 ? 'today' : `${days}d`;
  return `<span class="pill ${cls}">${label}</span>`;
};

const page = (title: string, body: string, opts: { refresh?: boolean } = {}) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title>
<style>
  :root{--ink:#0B1F3A;--paper:#F4F6F8;--line:#E3E7ED;--muted:#5B6779;--teal:#0E7C7B;--warn:#B26A00;--danger:#B3261E}
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--paper);color:var(--ink)}
  header{background:var(--ink);color:#fff;padding:14px 20px;display:flex;align-items:center;gap:16px}
  header h1{font-size:16px;margin:0;font-weight:600;letter-spacing:.2px}
  header .sp{flex:1}
  header a,header button{color:#fff;opacity:.85;text-decoration:none;background:none;border:0;font:inherit;cursor:pointer}
  main{max-width:1000px;margin:0 auto;padding:20px}
  .card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:18px}
  h2{font-size:14px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:0 0 12px}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);padding:8px 6px;border-bottom:1px solid var(--line)}
  td{padding:10px 6px;border-bottom:1px solid var(--line);vertical-align:top}
  tr:last-child td{border-bottom:0}
  .title{font-weight:500}
  .sub{color:var(--muted);font-size:12px}
  .pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}
  .pill.warn{background:#FDF3E3;color:var(--warn)}
  .pill.danger{background:#FBEAE8;color:var(--danger)}
  .pill.muted{background:#EEF1F5;color:var(--muted)}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .row > label{flex:1 1 220px;display:block}
  label{display:block;font-size:12px;color:var(--muted);margin-bottom:10px}
  input,textarea{width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:10px;font:inherit;background:#fff}
  textarea{min-height:70px;resize:vertical}
  button.primary{background:var(--ink);color:#fff;border:0;border-radius:10px;padding:11px 18px;font:inherit;font-weight:600;cursor:pointer}
  button.ghost{background:none;border:1px solid var(--line);border-radius:10px;padding:8px 12px;font:inherit;cursor:pointer}
  .danger-text{color:var(--danger);background:none;border:0;cursor:pointer;font:inherit;padding:0}
  .note{padding:10px 14px;border-radius:10px;background:#EAF5F4;color:#0B5F5E;margin-bottom:14px;font-size:14px}
  .note.err{background:#FBEAE8;color:var(--danger)}
  .stats{display:flex;gap:24px;flex-wrap:wrap}
  .stat b{display:block;font-size:26px;font-variant-numeric:tabular-nums}
  .stat span{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
  a{color:var(--teal)}
</style></head><body>
<header>
  <h1>Spidmax Kenya · admin</h1><div class="sp"></div>
  <a href="/admin">deadlines</a>
  <a href="/admin/status">status</a>
  <a href="/v1/deadlines" target="_blank">feed JSON</a>
  <a href="/health" target="_blank">health</a>
  ${opts.refresh ? '<button onclick="location.reload()">refresh</button>' : ''}
  <form method="post" action="/admin/logout" style="margin:0"><button>sign out</button></form>
</header>
<main>${body}</main><script src="/admin.js" defer></script></body></html>`;

// ---- login ---------------------------------------------------------------

adminRouter.get('/admin/login', (req, res) => {
  if (hasSession(req)) { res.redirect('/admin'); return; }
  if (!adminToken()) {
    res.status(503).send(page('Not configured', '<div class="card">ADMIN_TOKEN is not set on the server.</div>'));
    return;
  }
  const err = req.query.error ? '<div class="note err">Wrong token.</div>' : '';
  res.send(page('Sign in', `
    <div class="card" style="max-width:420px;margin:40px auto">
      <h2>Admin sign in</h2>
      ${err}
      <form method="post" action="/admin/login">
        <label>Admin token<input type="password" name="token" autofocus required></label>
        <button class="primary" type="submit">Sign in</button>
      </form>
      <p class="sub" style="margin-top:14px">The token is the ADMIN_TOKEN environment variable.</p>
    </div>`));
});

adminRouter.post('/admin/login', (req, res) => {
  if (!sameOrigin(req)) {
    res.status(403).send(`forbidden: origin ${req.headers.origin ?? 'none'} host ${req.headers.host ?? 'none'} forwarded ${req.headers['x-forwarded-host'] ?? 'none'}`);
    return;
  }
  const ip = (req.ip ?? '').replace(/^::ffff:/, '');
  if (tooMany(ip)) { res.status(429).send('too many attempts, try again later'); return; }
  const token = String((req.body ?? {}).token ?? '').trim();
  if (!tokenMatches(token)) { noteFailure(ip); res.redirect('/admin/login?error=1'); return; }
  failures.delete(ip);
  startSession(res);
  res.redirect('/admin');
});

adminRouter.post('/admin/logout', (req, res) => {
  endSession(req, res);
  res.redirect('/admin/login');
});

// ---- JSON (scripts / automations) ----------------------------------------

adminRouter.get('/api/admin/deadlines', adminGate, (req, res) => {
  const rows = db.prepare(
    'SELECT id, title, detail, due, url, source, verified FROM deadlines ORDER BY due ASC'
  ).all();
  res.setHeader('Cache-Control', 'no-store');
  res.json({ ok: true, count: rows.length, items: rows });
});

adminRouter.get('/admin.js', (_req, res) => {
  res.type('application/javascript').send(`
document.querySelectorAll('form.del').forEach(function (f) {
  f.addEventListener('submit', function (e) {
    var t = f.getAttribute('data-title') || 'this deadline';
    if (!confirm('Delete "' + t + '"?')) e.preventDefault();
  });
});`);
});

// ---- dashboard -----------------------------------------------------------

adminRouter.get('/admin', adminGate, (req, res) => {
  const rows = db.prepare(
    'SELECT id, title, detail, due, url, source, verified FROM deadlines ORDER BY due ASC'
  ).all() as unknown as Row[];

  const editing = typeof req.query.edit === 'string'
    ? rows.find((r) => r.id === req.query.edit) ?? null
    : null;

  const now = Date.now();
  const upcoming = rows.filter((r) => Date.parse(r.due + 'T00:00:00Z') >= now).length;
  const next = rows.find((r) => Date.parse(r.due + 'T00:00:00Z') >= now);

  const flash = req.query.saved ? '<div class="note">Saved.</div>'
    : req.query.deleted ? '<div class="note">Deleted.</div>'
    : req.query.error ? `<div class="note err">${esc(String(req.query.error))}</div>` : '';

  const tableRows = rows.map((r) => `
    <tr>
      <td>
        <div class="title">${esc(r.title)}</div>
        <div class="sub">${esc(r.id)}</div>
      </td>
      <td style="white-space:nowrap">${esc(r.due)}<br>${badge(daysUntil(r.due))}</td>
      <td><a href="${esc(r.url)}" target="_blank" rel="noreferrer noopener">source</a></td>
      <td style="white-space:nowrap">
        <a href="/admin?edit=${encodeURIComponent(r.id)}">edit</a>
        <form method="post" action="/admin/delete" class="del" data-title="${esc(r.title)}"
              style="display:inline;margin-left:10px">
          <input type="hidden" name="id" value="${esc(r.id)}">
          <button class="danger-text">delete</button>
        </form>
      </td>
    </tr>`).join('');

  const f = editing;
  res.send(page('Dashboard', `
    ${flash}
    <div class="card">
      <div class="stats">
        <div class="stat"><b>${rows.length}</b><span>deadlines</span></div>
        <div class="stat"><b>${upcoming}</b><span>upcoming</span></div>
        <div class="stat"><b>${next ? esc(next.due) : '—'}</b><span>next due</span></div>
      </div>
    </div>

    <div class="card">
      <h2>${f ? 'Edit deadline' : 'Add deadline'}</h2>
      <form method="post" action="/admin/save">
        <div class="row">
          <label>ID (lowercase slug)
            <input name="id" value="${esc(f?.id ?? '')}" ${f ? 'readonly' : ''} required pattern="[a-z0-9-]{3,60}">
          </label>
          <label>Due (YYYY-MM-DD)
            <input name="due" value="${esc(f?.due ?? '')}" required placeholder="2026-11-30">
          </label>
        </div>
        <label>Title<input name="title" value="${esc(f?.title ?? '')}" required maxlength="120"></label>
        <label>Detail (one sentence, max 300)
          <textarea name="detail" maxlength="300">${esc(f?.detail ?? '')}</textarea>
        </label>
        <div class="row">
          <label>Official URL (*.go.ke)
            <input name="url" value="${esc(f?.url ?? '')}" required placeholder="https://www.kra.go.ke/...">
          </label>
          <label>Source page you verified
            <input name="source" value="${esc(f?.source ?? '')}" placeholder="https://...">
          </label>
        </div>
        <button class="primary" type="submit">${f ? 'Save changes' : 'Publish'}</button>
        ${f ? '<a href="/admin" style="margin-left:12px">cancel</a>' : ''}
      </form>
      <p class="sub" style="margin-bottom:0">Only *.go.ke URLs and future dates are accepted — the same guardrails as the API.</p>
    </div>

    <div class="card">
      <h2>Published (${rows.length})</h2>
      ${rows.length ? `<table><thead><tr><th>Deadline</th><th>Due</th><th>Source</th><th></th></tr></thead><tbody>${tableRows}</tbody></table>`
        : '<p class="sub">Nothing published yet.</p>'}
    </div>
  `, { refresh: true }));
});

adminRouter.post('/admin/save', adminGate, (req, res) => {
  if (!sameOrigin(req)) {
    res.status(403).send(`forbidden: origin ${req.headers.origin ?? 'none'} host ${req.headers.host ?? 'none'} forwarded ${req.headers['x-forwarded-host'] ?? 'none'}`);
    return;
  }
  const body = req.body ?? {};
  const item = {
    id: String(body.id ?? '').trim(),
    title: String(body.title ?? '').trim(),
    detail: String(body.detail ?? '').trim(),
    due: String(body.due ?? '').trim(),
    url: String(body.url ?? '').trim(),
    source: String(body.source ?? '').trim(),
    verified: new Date().toISOString().slice(0, 10),
  };
  const bad = validateDeadline(item);
  if (bad) { res.redirect('/admin?error=' + encodeURIComponent(bad)); return; }

  db.prepare(
    `INSERT INTO deadlines (id, title, detail, due, url, verified, source, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
     ON CONFLICT(id) DO UPDATE SET
       title = excluded.title, detail = excluded.detail, due = excluded.due,
       url = excluded.url, verified = excluded.verified, source = excluded.source,
       updated_at = datetime('now')`,
  ).run(item.id, item.title, item.detail, item.due, item.url, item.verified, item.source);

  res.redirect('/admin?saved=1');
});

adminRouter.post('/admin/delete', adminGate, (req, res) => {
  if (!sameOrigin(req)) {
    res.status(403).send(`forbidden: origin ${req.headers.origin ?? 'none'} host ${req.headers.host ?? 'none'} forwarded ${req.headers['x-forwarded-host'] ?? 'none'}`);
    return;
  }
  const id = String((req.body ?? {}).id ?? '');
  db.prepare('DELETE FROM deadlines WHERE id = ?').run(id);
  res.redirect('/admin?deleted=1');
});

// ---- status --------------------------------------------------------------

const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');

type Apk = { name: string; size: number; sha: string; mtime: string };
const hashCache = new Map<string, { mtimeMs: number; size: number; sha: string }>();

function apks(): Apk[] {
  let names: string[] = [];
  try { names = fs.readdirSync(PUBLIC_DIR).filter((f) => f.endsWith('.apk')); } catch { return []; }
  return names.sort().map((name) => {
    const file = path.join(PUBLIC_DIR, name);
    const st = fs.statSync(file);
    let hit = hashCache.get(file);
    if (!hit || hit.mtimeMs !== st.mtimeMs) {
      hit = {
        mtimeMs: st.mtimeMs,
        size: st.size,
        sha: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
      };
      hashCache.set(file, hit);
    }
    return { name, size: hit.size, sha: hit.sha, mtime: st.mtime.toISOString() };
  });
}

function fuelState(): { snap: any | null; source: string; at: number | null } {
  const memo = fuelMemoState();
  if (memo.data) return { snap: memo.data, source: 'live fetch', at: memo.at };
  try {
    const cached = JSON.parse(fs.readFileSync(fuelCacheFile(), 'utf8'));
    return { snap: cached, source: 'cache file', at: fs.statSync(fuelCacheFile()).mtimeMs };
  } catch { return { snap: null, source: 'none', at: null }; }
}

function ageLabel(at: number | null): string {
  if (!at) return '--';
  const m = Math.round((Date.now() - at) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return m + ' min ago';
  const h = Math.round(m / 60);
  if (h < 24) return h + ' h ago';
  return Math.round(h / 24) + ' d ago';
}

const mb = (n: number) => (n / 1024 / 1024).toFixed(2) + ' MB';

adminRouter.get('/admin/status', adminGate, (_req, res) => {
  const counted = db.prepare('SELECT COUNT(*) AS n FROM deadlines').get() as unknown as { n: number };
  const fuel = fuelState();
  const list = apks();
  const stable = list.find((a) => a.name === 'spidmax-kenya.apk');
  const versioned = list
    .filter((a) => /-\d+\.\d+\.\d+\.apk$/.test(a.name))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
  const newest = versioned[versioned.length - 1];
  const aliasOk = Boolean(stable && newest && stable.sha === newest.sha);

  const flash = _req.query.refreshed ? '<div class="note">Fuel refreshed from EPRA.</div>'
    : _req.query.error ? `<div class="note err">${esc(String(_req.query.error))}</div>` : '';

  const aliasNote = stable
    ? (aliasOk ? '<span class="pill muted">matches newest</span>'
               : '<span class="pill danger">differs from newest</span>')
    : '<span class="pill danger">missing</span>';

  res.send(page('Status', `
    ${flash}
    <div class="card">
      <h2>Service</h2>
      <div class="stats">
        <div class="stat"><b>${esc(process.env.APP_VERSION ?? '1.3.0')}</b><span>version</span></div>
        <div class="stat"><b>${Math.round(process.uptime() / 60)}</b><span>minutes up</span></div>
        <div class="stat"><b>${counted.n}</b><span>deadlines</span></div>
        <div class="stat"><b>${esc(process.version)}</b><span>node</span></div>
      </div>
    </div>

    <div class="card">
      <h2>Fuel prices</h2>
      ${fuel.snap ? `
      <div class="stats" style="margin-bottom:14px">
        <div class="stat"><b>${esc(fuel.snap.cycle.from)} &rarr; ${esc(fuel.snap.cycle.to)}</b><span>cycle</span></div>
        <div class="stat"><b>${fuel.snap.prices.length}</b><span>towns</span></div>
        <div class="stat"><b>${esc(ageLabel(fuel.at))}</b><span>${esc(fuel.source)}</span></div>
      </div>` : '<p class="sub">No fuel data in memory or on disk yet.</p>'}
      <form method="post" action="/admin/fuel-refresh" style="margin:0">
        <button class="primary" type="submit">Refresh from EPRA now</button>
      </form>
      <p class="sub" style="margin:12px 0 0">Refreshed automatically at most every 6 hours; falls back to the cached file when EPRA is unreachable.</p>
    </div>

    <div class="card">
      <h2>Released APKs (${list.length})</h2>
      ${list.length ? `
      <table><thead><tr><th>File</th><th>Size</th><th>sha256</th><th>Built</th></tr></thead><tbody>
        ${list.map((a) => `<tr>
          <td><a href="/${encodeURIComponent(a.name)}" target="_blank" rel="noreferrer noopener">${esc(a.name)}</a></td>
          <td style="white-space:nowrap">${mb(a.size)}</td>
          <td><code style="font-size:11px">${esc(a.sha.slice(0, 16))}...</code></td>
          <td style="white-space:nowrap" class="sub">${esc(a.mtime.slice(0, 10))}</td>
        </tr>`).join('')}
      </tbody></table>
      <p class="sub" style="margin:12px 0 0">Stable alias: ${aliasNote}</p>`
      : '<p class="sub">No APKs in public/.</p>'}
    </div>

    ${recentRejects().length ? `
    <div class="card">
      <h2>Rejected form posts (${recentRejects().length})</h2>
      <table><thead><tr><th>When</th><th>Origin sent</th><th>Host seen</th></tr></thead><tbody>
      ${recentRejects().map((r) => `<tr>
        <td class="sub">${esc(new Date(r.at).toISOString().slice(11, 19))}Z</td>
        <td><code style="font-size:11px">${esc(r.origin || '(none)')}</code></td>
        <td><code style="font-size:11px">${esc(r.host)}</code></td>
      </tr>`).join('')}
      </tbody></table>
      <p class="sub" style="margin:12px 0 0">A burst here is either a misconfigured proxy or someone probing the login.</p>
    </div>` : ''}
  `, { refresh: true }));
});

adminRouter.post('/admin/fuel-refresh', adminGate, async (req, res) => {
  if (!sameOrigin(req)) {
    res.status(403).send(`forbidden: origin ${req.headers.origin ?? 'none'} host ${req.headers.host ?? 'none'} forwarded ${req.headers['x-forwarded-host'] ?? 'none'}`);
    return;
  }
  try {
    await fuelSnapshot(true);
    res.redirect('/admin/status?refreshed=1');
  } catch (err) {
    res.redirect('/admin/status?error=' + encodeURIComponent(String(err)));
  }
});
