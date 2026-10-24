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
  res.setHeader('Set-Cookie',
    `${SESSION_COOKIE}=${sid}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${TTL_MS / 1000}`);
}

export function endSession(req: Request, res: Response): void {
  const sid = readSession(req);
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`);
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
export function sameOrigin(req: Request): boolean {
  const origin = req.headers.origin;
  if (!origin) return true; // curl / scripts
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}
