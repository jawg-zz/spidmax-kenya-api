import { Router } from 'express';
import fs from 'node:fs';
import path from 'node:path';

export const fuelRouter = Router();

type Price = { town: string; petrol: number; diesel: number; kerosene: number };
type Cycle = { from: string; to: string };
type Snapshot = { cycle: Cycle; updatedAt: string; prices: Price[] };

const CACHE_FILE = path.resolve(process.env.FUEL_CACHE ?? './data/fuel-cache.json');
const TTL_MS = 6 * 60 * 60 * 1000;
const SOURCE = 'https://www.epra.go.ke/pump-prices';

let memo: { at: number; data: Snapshot } | null = null;

function parse(html: string): Snapshot {
  const rows = [...html.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/g)];
  const all: (Price & { from: string; to: string })[] = [];
  for (const r of rows) {
    const cells = [...r[1].matchAll(/<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/g)]
      .map((m) => m[1].replace(/<[^>]+>/g, '').trim());
    if (cells.length < 6) continue;
    const [from, to, town, pms, ago, ik] = cells;
    if (!/^\d{2}-\d{2}-\d{4}$/.test(from ?? '')) continue;
    all.push({ from, to, town, petrol: Number(pms), diesel: Number(ago), kerosene: Number(ik) });
  }
  if (!all.length) throw new Error('no price rows parsed');
  const cycles = [...new Set(all.map((x) => x.from))];
  const latest = cycles.sort((a, b) => {
    const k = (s: string) => {
      const [d, m, y] = s.split('-').map(Number);
      return new Date(y, m - 1, d).getTime();
    };
    return k(b) - k(a);
  })[0];
  const cur = all.filter((x) => x.from === latest);
  return {
    cycle: { from: cur[0].from, to: cur[0].to },
    updatedAt: new Date().toISOString(),
    prices: cur
      .filter((x) => Number.isFinite(x.petrol) && Number.isFinite(x.diesel) && Number.isFinite(x.kerosene))
      .map(({ town, petrol, diesel, kerosene }) => ({ town, petrol, diesel, kerosene }))
      .sort((a, b) => a.town.localeCompare(b.town)),
  };
}

async function load(): Promise<Snapshot> {
  if (memo && Date.now() - memo.at < TTL_MS) return memo.data;
  try {
    const res = await fetch(SOURCE, { headers: { 'user-agent': 'Mozilla/5.0 (SpidmaxKenya)' } });
    if (!res.ok) throw new Error(`source HTTP ${res.status}`);
    const data = parse(await res.text());
    memo = { at: Date.now(), data };
    try {
      fs.mkdirSync(path.dirname(CACHE_FILE), { recursive: true });
      fs.writeFileSync(CACHE_FILE, JSON.stringify(data));
    } catch { /* cache is best-effort */ }
    return data;
  } catch (err) {
    try {
      const cached = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8')) as Snapshot;
      if (cached?.prices?.length) return cached;
    } catch { /* fall through */ }
    throw err;
  }
}

fuelRouter.get('/', async (req, res) => {
  try {
    const snap = await load();
    const town = typeof req.query.town === 'string' ? req.query.town.toLowerCase() : null;
    const prices = town
      ? snap.prices.filter((p) => p.town.toLowerCase().includes(town))
      : snap.prices;
    res.json({ ok: true, cycle: snap.cycle, updatedAt: snap.updatedAt, count: prices.length, prices });
  } catch (err) {
    res.status(502).json({ ok: false, error: 'fuel prices unavailable', detail: String(err) });
  }
});

/** Admin surface: force a scrape that bypasses the 6h memo. */
export async function fuelSnapshot(force = false): Promise<Snapshot> {
  if (force) memo = null;
  return load();
}

/** Admin surface: what is in memory right now, without touching the network. */
export function fuelMemoState(): { at: number | null; data: Snapshot | null } {
  return { at: memo?.at ?? null, data: memo?.data ?? null };
}

export function fuelCacheFile(): string {
  return CACHE_FILE;
}
