import { Router } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { db } from '../db.js';

export const deadlinesRouter = Router();

const SEED = path.join(__dirname, '..', '..', 'public', 'data', 'deadlines.json');

type Row = { id: string; title: string; detail: string; due: string; url: string; verified: string; source: string };

function seedIfEmpty() {
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM deadlines').get() as { n: number };
  if (n > 0) return;
  try {
    const items = JSON.parse(fs.readFileSync(SEED, 'utf8')) as Row[];
    const ins = db.prepare(
      'INSERT OR IGNORE INTO deadlines (id, title, detail, due, url, verified, source) VALUES (?, ?, ?, ?, ?, ?, ?)',
    );
    for (const i of items) ins.run(i.id, i.title, i.detail ?? '', i.due, i.url ?? '', i.verified ?? '', 'seed');
  } catch {
    /* no seed available: the feed simply starts empty */
  }
}

function requireAdmin(req: any, res: any, next: any) {
  const expected = process.env.ADMIN_TOKEN;
  const got = String(req.headers['x-admin-token'] ?? '');
  if (!expected || expected.length < 8) {
    res.status(503).json({ ok: false, error: 'admin token not configured' });
    return;
  }
  const a = Buffer.from(expected);
  const b = Buffer.from(got);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    res.status(401).json({ ok: false, error: 'bad admin token' });
    return;
  }
  next();
}

/** Guardrails: a bad scrape must not be able to publish arbitrary content. */
function validate(item: any): string | null {
  if (!item || typeof item !== 'object') return 'item must be an object';
  if (!/^[a-z0-9-]{3,60}$/.test(String(item.id ?? ''))) return 'id must be lowercase slug (3-60 chars)';
  if (typeof item.title !== 'string' || item.title.length < 3 || item.title.length > 120) return 'title must be 3-120 chars';
  if (typeof item.due !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(item.due)) return 'due must be YYYY-MM-DD';
  const due = Date.parse(item.due + 'T00:00:00Z');
  if (Number.isNaN(due)) return 'due is not a real date';
  if (due < Date.now() - 86_400_000) return 'due is in the past';
  const url = String(item.url ?? '');
  if (!/^https:\/\/([a-z0-9-]+\.)+go\.ke(\/|$)/i.test(url)) return 'url must be an official *.go.ke page';
  if (String(item.detail ?? '').length > 300) return 'detail is too long';
  return null;
}

deadlinesRouter.get('/', (_req, res) => {
  try {
    seedIfEmpty();
    const items = db.prepare('SELECT id, title, detail, due, url, verified, source FROM deadlines ORDER BY due ASC').all();
    res.set('Cache-Control', 'public, max-age=300');
    res.json({ ok: true, items });
  } catch {
    res.set('Cache-Control', 'no-store');
    res.status(500).json({ ok: false, error: 'deadlines unavailable' });
  }
});

/** Upsert one or many. Used by the scheduled checker; requires x-admin-token. */
deadlinesRouter.post('/', requireAdmin, (req, res) => {
  const body = req.body ?? {};
  const items = Array.isArray(body.items) ? body.items : [body];
  if (items.length === 0 || items.length > 20) {
    res.status(400).json({ ok: false, error: 'send 1-20 items' });
    return;
  }
  const saved: string[] = [];
  for (const item of items) {
    const bad = validate(item);
    if (bad) {
      res.status(400).json({ ok: false, error: bad, item });
      return;
    }
    db.prepare(
      `INSERT INTO deadlines (id, title, detail, due, url, verified, source, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(id) DO UPDATE SET
         title = excluded.title, detail = excluded.detail, due = excluded.due,
         url = excluded.url, verified = excluded.verified, source = excluded.source,
         updated_at = datetime('now')`,
    ).run(
      item.id,
      item.title,
      String(item.detail ?? ''),
      item.due,
      String(item.url ?? ''),
      String(item.verified ?? new Date().toISOString().slice(0, 10)),
      String(item.source ?? ''),
    );
    saved.push(item.id);
  }
  res.json({ ok: true, saved });
});

/** Remove one (used for pruning expired rows). */
deadlinesRouter.delete('/:id', requireAdmin, (req, res) => {
  const info = db.prepare('DELETE FROM deadlines WHERE id = ?').run(req.params.id);
  res.json({ ok: true, removed: Number(info.changes ?? 0) });
});
