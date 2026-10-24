import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';

const DB_PATH = process.env.DB_PATH ?? './data/kenya.db';

fs.mkdirSync(path.dirname(path.resolve(DB_PATH)), { recursive: true });

export const db = new DatabaseSync(DB_PATH);

db.exec(`
CREATE TABLE IF NOT EXISTS deadlines (
  id         TEXT PRIMARY KEY,
  title      TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  due        TEXT NOT NULL,
  url        TEXT NOT NULL DEFAULT '',
  verified   TEXT NOT NULL DEFAULT '',
  source     TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);
