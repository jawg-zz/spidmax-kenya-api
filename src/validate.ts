/** Shared guardrails: a bad scrape must never be able to publish arbitrary content. */
export type DeadlineInput = {
  id?: unknown; title?: unknown; detail?: unknown; due?: unknown;
  url?: unknown; source?: unknown; verified?: unknown;
};

export function validateDeadline(item: DeadlineInput): string | null {
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
