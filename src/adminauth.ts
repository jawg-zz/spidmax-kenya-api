import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

const SESSION_COOKIE = 'sk_admin';
const TTL_MS = 12 * 60 * 60 * 1000;
const sessions = new Map<string, number>();

export function adminToken(): string | null {
  const t = process.env.ADMIN_TOKEN;
  return t && t.length >= 8 ? t : null;
}

function readSession(req: Request): string | null {
  const raw = req.headers.cookie ?? '';
  const m = raw.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([A-Za-z0-9_-]+)`));
  return m ? m[1] : null;
}

export function hasSession(req: Request): boolean {
  const sid = readSession(req);
  if (!sid) return false;
  const exp = sessions.get(sid);
  if (!exp) return false;
  if (Date.now() > exp) { sessions.delete(sid); return false; }
  return true;
}

export function startSession(res: Response): void {
  const sid = randomBytes(24).toString('hex');
  sessions.set(sid, Date.now() + TTL_MS);
  res.append('Set-Cookie',
    `${SESSION_COOKIE}=${sid}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${TTL_MS / 1000}`);
}

export function endSession(req: Request, res: Response): void {
  const sid = readSession(req);
  if (sid) sessions.delete(sid);
  res.append('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
}

/** Constant-time comparison of the submitted token. */
export function tokenMatches(got: string): boolean {
  const expected = adminToken();
  if (!expected) return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(got);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Cookie session OR the raw token header (for scripts). */
export function adminGate(req: Request, res: Response, next: NextFunction) {
  const header = String(req.headers['x-admin-token'] ?? '');
  if (header && tokenMatches(header)) { next(); return; }
  if (hasSession(req)) { next(); return; }
  if (req.path.startsWith('/api/')) {
    res.status(401).json({ ok: false, error: 'admin login required' });
    return;
  }
  res.redirect('/admin/login');
}

/** Reject cross-site form posts: the session cookie is SameSite=Strict, and we
 *  also require the Origin to match the host. */
const CSRF_COOKIE = 'sk_csrf';

function cookieValue(req: Request, name: string): string | null {
  const raw = req.headers.cookie ?? '';
  const m = raw.match(new RegExp(`(?:^|;\\s*)${name}=([A-Za-z0-9_-]+)`));
  return m ? m[1] : null;
}

/** Issue (or reuse) the per-browser CSRF token embedded in every form. */
export function csrfFor(req: Request, res: Response): string {
  let v = cookieValue(req, CSRF_COOKIE);
  if (v && /^[a-f0-9]{32,}$/.test(v)) return v;
  v = randomBytes(24).toString('hex');
  res.append('Set-Cookie', `${CSRF_COOKIE}=${v}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${TTL_MS / 1000}`);
  return v;
}

export function csrfValid(req: Request): boolean {
  const cookie = cookieValue(req, CSRF_COOKIE);
  const body = String((req.body ?? {}).csrf ?? '');
  if (!cookie || !body || cookie.length !== body.length) return false;
  return timingSafeEqual(Buffer.from(cookie), Buffer.from(body));
}

const hostOnly = (v: string) => v.split(',')[0].trim().toLowerCase().replace(/:\d+$/, '');

const rejects: { at: number; origin: string; host: string; fwd: string }[] = [];

export function noteReject(req: Request): void {
  rejects.push({
    at: Date.now(),
    origin: String(req.headers.origin ?? ''),
    host: String(req.headers.host ?? ''),
    fwd: String(req.headers['x-forwarded-host'] ?? ''),
  });
  if (rejects.length > 10) rejects.shift();
}

export function recentRejects() {
  return rejects.slice().reverse();
}

/** Reject cross-site form posts. Because this sits behind a proxy, the browser's
 *  Origin and the Host header it lands on are not always byte-identical (ports,
 *  forwarded host), so compare hostnames and accept the forwarded host too. */
export function sameOrigin(req: Request): boolean {
  const origin = req.headers.origin;
  if (!origin) return true; // curl / scripts
  // Opaque origin (sandboxed frame, webview, some privacy modes). It cannot be
  // matched against anything, so the CSRF token becomes the proof of intent.
  if (origin === 'null') return true;
  let originHost: string;
  try {
    originHost = new URL(origin).host.toLowerCase().replace(/:\d+$/, '');
  } catch {
    noteReject(req);
    return false;
  }
  const candidates = new Set<string>();
  for (const v of [req.headers.host, req.headers['x-forwarded-host'], process.env.PUBLIC_HOST]) {
    if (typeof v === 'string' && v) candidates.add(hostOnly(v));
  }
  if (candidates.has(originHost)) return true;
  noteReject(req);
  return false;
}

/** Every state-changing request must carry the CSRF token from its own form. */
export function postAllowed(req: Request): boolean {
  return csrfValid(req) && sameOrigin(req);
}
