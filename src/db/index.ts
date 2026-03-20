// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import fs from 'fs';
import path from 'path';

import { STORE_DIR, readSecret } from '../config.js';
import type { QuarantineEntry, AuditEntry, FilterRule, FilterDecision } from '../types.js';
import type { DbAdapter, Dialect } from './adapter.js';
import { runMigrations } from './migrations.js';

let adapter: DbAdapter;
let dialect: Dialect;

export async function initDatabase(): Promise<void> {
  const dbType = (process.env.DB_TYPE || 'sqlite') as Dialect;
  dialect = dbType;

  if (dbType === 'postgres') {
    const { PgAdapter } = await import('./pg-adapter.js');
    let url = process.env.DATABASE_URL;
    if (!url) throw new Error('DATABASE_URL is required when DB_TYPE=postgres');
    // Inject postgres password from Docker secret into connection URL
    const pgPassword = readSecret('POSTGRES_PASSWORD');
    if (pgPassword) {
      const parsed = new URL(url);
      if (!parsed.password) {
        parsed.password = pgPassword;
        url = parsed.toString();
      }
    }
    adapter = await PgAdapter.create(url);
  } else {
    const { SqliteAdapter } = await import('./sqlite-adapter.js');
    const dbPath = path.join(STORE_DIR, 'carapamail.db');
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    adapter = new SqliteAdapter(dbPath);
  }

  await runMigrations(adapter, dialect);
}

// --- Accounts ---

export interface AccountRow {
  id: string;
  email: string;
  imap_host: string;
  imap_port: number;
  imap_user: string;
  imap_pass_enc: string;
  smtp_host: string;
  smtp_port: number;
  smtp_user: string;
  smtp_pass_enc: string;
  smtp_secure: string;
  local_pass_enc: string;
  inbound_enabled: number;
  outbound_enabled: number;
  mcp_receive_enabled: number;
  mcp_send_enabled: number;
  mcp_delete_enabled: number;
  custom_inbound_prompt: string;
  custom_outbound_prompt: string;
  custom_agent_prompt: string;
  use_custom_inbound_prompt: number;
  use_custom_outbound_prompt: number;
  use_custom_agent_prompt: number;
  mcp_token_hash: string;
  strict_tls: number;
  created_at: string;
  updated_at: string;
}

export async function listAccounts(): Promise<AccountRow[]> {
  return adapter.query<AccountRow>('SELECT * FROM accounts ORDER BY created_at ASC');
}

export async function getAccountRowById(id: string): Promise<AccountRow | null> {
  return adapter.queryOne<AccountRow>('SELECT * FROM accounts WHERE id = ?', [id]);
}

export async function getAccountRowByEmail(email: string): Promise<AccountRow | null> {
  return adapter.queryOne<AccountRow>('SELECT * FROM accounts WHERE email = ?', [email]);
}

export async function insertAccount(row: AccountRow): Promise<void> {
  await adapter.run(
    `INSERT INTO accounts (id, email, imap_host, imap_port, imap_user, imap_pass_enc, smtp_host, smtp_port, smtp_user, smtp_pass_enc, smtp_secure, local_pass_enc, inbound_enabled, outbound_enabled, mcp_receive_enabled, mcp_send_enabled, mcp_delete_enabled, custom_inbound_prompt, custom_outbound_prompt, custom_agent_prompt, use_custom_inbound_prompt, use_custom_outbound_prompt, use_custom_agent_prompt, mcp_token_hash, strict_tls, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [row.id, row.email, row.imap_host, row.imap_port, row.imap_user, row.imap_pass_enc, row.smtp_host, row.smtp_port, row.smtp_user, row.smtp_pass_enc, row.smtp_secure, row.local_pass_enc, row.inbound_enabled, row.outbound_enabled, row.mcp_receive_enabled, row.mcp_send_enabled, row.mcp_delete_enabled, row.custom_inbound_prompt, row.custom_outbound_prompt, row.custom_agent_prompt, row.use_custom_inbound_prompt, row.use_custom_outbound_prompt, row.use_custom_agent_prompt, row.mcp_token_hash, row.strict_tls, row.created_at, row.updated_at],
  );
}

export async function updateAccountRow(id: string, row: Partial<Omit<AccountRow, 'id' | 'created_at'>>): Promise<void> {
  const sets: string[] = [];
  const values: any[] = [];
  for (const [key, value] of Object.entries(row)) {
    if (value !== undefined) {
      sets.push(`${key} = ?`);
      values.push(value);
    }
  }
  if (sets.length === 0) return;
  values.push(id);
  await adapter.run(`UPDATE accounts SET ${sets.join(', ')} WHERE id = ?`, values);
}

export async function deleteAccountRow(id: string): Promise<void> {
  await adapter.run('DELETE FROM accounts WHERE id = ?', [id]);
}

export async function getAccountIdsByTokenHash(tokenHash: string): Promise<string[]> {
  const rows = await adapter.query<{ id: string }>('SELECT id FROM accounts WHERE mcp_token_hash = ?', [tokenHash]);
  return rows.map(r => r.id);
}

// --- Quarantine ---

export async function insertQuarantine(entry: {
  id: string;
  direction: string;
  from_addr: string;
  to_addr: string;
  subject: string;
  body_preview: string;
  raw_eml: Buffer;
  reason: string;
  categories: string[];
  confidence: number;
  accountId?: string;
}): Promise<void> {
  await adapter.run(
    `INSERT INTO quarantine (id, direction, from_addr, to_addr, subject, body_preview, raw_eml, reason, categories, confidence, status, account_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
    [
      entry.id,
      entry.direction,
      entry.from_addr,
      entry.to_addr,
      entry.subject,
      entry.body_preview,
      entry.raw_eml,
      entry.reason,
      JSON.stringify(entry.categories),
      entry.confidence,
      entry.accountId || 'default',
      new Date().toISOString(),
    ],
  );
}

export async function listQuarantine(status?: string, accountId?: string, limit = 100, offset = 0): Promise<QuarantineEntry[]> {
  const where: string[] = [];
  const params: any[] = [];
  if (status) { where.push('status = ?'); params.push(status); }
  if (accountId) { where.push('account_id = ?'); params.push(accountId); }
  const clause = where.length > 0 ? ` WHERE ${where.join(' AND ')}` : '';
  params.push(limit, offset);
  return adapter.query<QuarantineEntry>(`SELECT * FROM quarantine${clause} ORDER BY created_at DESC LIMIT ? OFFSET ?`, params);
}

export async function getQuarantineEntry(id: string): Promise<QuarantineEntry | null> {
  return adapter.queryOne<QuarantineEntry>('SELECT * FROM quarantine WHERE id = ?', [id]);
}

export async function updateQuarantineStatus(id: string, status: 'released' | 'deleted'): Promise<void> {
  await adapter.run('UPDATE quarantine SET status = ?, reviewed_at = ? WHERE id = ?', [status, new Date().toISOString(), id]);
}

// --- Audit Log ---

export async function logAudit(entry: {
  direction: string;
  from_addr: string;
  to_addr: string;
  subject: string;
  decision: FilterDecision;
  latency_ms: number;
  accountId?: string;
}): Promise<void> {
  await adapter.run(
    `INSERT INTO audit_log (direction, from_addr, to_addr, subject, action, reason, categories, confidence, latency_ms, account_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      entry.direction,
      entry.from_addr,
      entry.to_addr,
      entry.subject,
      entry.decision.action,
      entry.decision.reason,
      JSON.stringify(entry.decision.categories),
      entry.decision.confidence,
      entry.latency_ms,
      entry.accountId || 'default',
      new Date().toISOString(),
    ],
  );
}

export async function listAuditLog(limit = 100, offset = 0, accountId?: string): Promise<AuditEntry[]> {
  if (accountId) {
    return adapter.query<AuditEntry>('SELECT * FROM audit_log WHERE account_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?', [accountId, limit, offset]);
  }
  return adapter.query<AuditEntry>('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?', [limit, offset]);
}

// --- Rules ---

export async function listRules(): Promise<FilterRule[]> {
  return adapter.query<FilterRule>('SELECT * FROM rules ORDER BY priority DESC, created_at ASC');
}

// --- Whitelist ---

export async function addToWhitelist(accountId: string, type: 'email' | 'domain', pattern: string, source: 'outbound' | 'manual' = 'manual'): Promise<void> {
  const id = `wl-${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  await adapter.run(
    `INSERT INTO whitelist (id, account_id, type, pattern, source, created_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(account_id, type, pattern) DO UPDATE SET source = EXCLUDED.source, created_at = EXCLUDED.created_at`,
    [id, accountId, type, pattern.toLowerCase(), source, now]
  );
}

export async function isWhitelisted(accountId: string, email: string): Promise<boolean> {
  const cleanEmail = email.toLowerCase();
  const domain = cleanEmail.split('@')[1];

  // Check for exact email match
  const emailMatch = await adapter.queryOne<{ id: string }>(
    "SELECT id FROM whitelist WHERE account_id = ? AND type = 'email' AND pattern = ?",
    [accountId, cleanEmail]
  );
  if (emailMatch) return true;

  // Check for domain match
  if (domain) {
    const domainMatch = await adapter.queryOne<{ id: string }>(
      "SELECT id FROM whitelist WHERE account_id = ? AND type = 'domain' AND pattern = ?",
      [accountId, domain]
    );
    if (domainMatch) return true;
  }

  return false;
}

export async function removeFromWhitelist(accountId: string, type: 'email' | 'domain', pattern: string): Promise<void> {
  await adapter.run(
    'DELETE FROM whitelist WHERE account_id = ? AND type = ? AND pattern = ?',
    [accountId, type, pattern.toLowerCase()]
  );
}

export async function listWhitelist(accountId?: string): Promise<{ id: string; type: string; pattern: string; source: string; created_at: string }[]> {
  if (accountId) {
    return adapter.query('SELECT * FROM whitelist WHERE account_id = ? ORDER BY created_at DESC', [accountId]);
  }
  return adapter.query('SELECT * FROM whitelist ORDER BY created_at DESC');
}

export async function insertRule(rule: { id: string; type: string; match_field: string; match_pattern: string; priority?: number; direction?: string }): Promise<void> {
  await adapter.run(
    'INSERT INTO rules (id, type, match_field, match_pattern, priority, direction, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [rule.id, rule.type, rule.match_field, rule.match_pattern, rule.priority ?? 0, rule.direction ?? 'both', new Date().toISOString()],
  );
}

export async function deleteRule(id: string): Promise<void> {
  await adapter.run('DELETE FROM rules WHERE id = ?', [id]);
}

export async function updateRule(id: string, fields: { type?: string; match_field?: string; match_pattern?: string; priority?: number; direction?: string }): Promise<void> {
  const sets: string[] = [];
  const values: unknown[] = [];
  if (fields.type !== undefined) { sets.push('type = ?'); values.push(fields.type); }
  if (fields.match_field !== undefined) { sets.push('match_field = ?'); values.push(fields.match_field); }
  if (fields.match_pattern !== undefined) { sets.push('match_pattern = ?'); values.push(fields.match_pattern); }
  if (fields.priority !== undefined) { sets.push('priority = ?'); values.push(fields.priority); }
  if (fields.direction !== undefined) { sets.push('direction = ?'); values.push(fields.direction); }
  if (sets.length === 0) return;
  values.push(id);
  await adapter.run(`UPDATE rules SET ${sets.join(', ')} WHERE id = ?`, values);
}

/**
 * Automatically create an 'allow' rule for a sender's email address.
 * Used when a message is released from quarantine.
 */
export async function autoWhitelistSender(email: string): Promise<void> {
  // Extract email address if it's in "Name <email@domain.com>" format
  const emailRegex = /<([^>]+)>/;
  const match = email.match(emailRegex);
  const cleanEmail = match ? match[1].toLowerCase() : email.trim().toLowerCase();

  if (!cleanEmail) return;

  // Escape regex special characters to match the exact email
  const escaped = cleanEmail.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = `^${escaped}$`;
  const id = `auto-${Buffer.from(cleanEmail).toString('hex').slice(0, 16)}`;

  // Check if an 'allow' rule for this email already exists
  const existing = await adapter.queryOne<{ id: string }>(
    "SELECT id FROM rules WHERE type = 'allow' AND match_field = 'from' AND match_pattern = ?",
    [pattern]
  );
  if (existing) return;

  await insertRule({
    id,
    type: 'allow',
    match_field: 'from',
    match_pattern: pattern,
    priority: 10, // Higher priority than general rules
    direction: 'inbound',
  });
}

export async function getMatchingRules(email: { from: string; to: string; subject: string; body: string }, direction?: 'inbound' | 'outbound'): Promise<FilterRule | null> {
  const VALID_FIELDS = ['from', 'to', 'subject', 'body'] as const;
  const rules = await listRules();
  for (const rule of rules) {
    // Skip rules that don't apply to this direction
    if (direction && rule.direction !== 'both' && rule.direction !== direction) continue;
    if (!VALID_FIELDS.includes(rule.match_field as (typeof VALID_FIELDS)[number])) continue;
    try {
      const re = new RegExp(rule.match_pattern, 'i');
      const value = email[rule.match_field as keyof typeof email];
      if (value && re.test(value)) {
        return rule;
      }
    } catch {
      // Skip invalid regex patterns
    }
  }
  return null;
}

// --- Scanner State ---

export async function getScannerState(folder: string, accountId = 'default'): Promise<{ uid_validity: number; last_uid: number } | null> {
  return adapter.queryOne<{ uid_validity: number; last_uid: number }>('SELECT uid_validity, last_uid FROM scanner_state WHERE account_id = ? AND folder = ?', [accountId, folder]);
}

export async function setScannerState(folder: string, uidValidity: number, lastUid: number, accountId = 'default'): Promise<void> {
  const now = new Date().toISOString();
  await adapter.run(
    `INSERT INTO scanner_state (account_id, folder, uid_validity, last_uid, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(account_id, folder) DO UPDATE SET uid_validity = ?, last_uid = ?, updated_at = ?`,
    [accountId, folder, uidValidity, lastUid, now, uidValidity, lastUid, now],
  );
}

// --- Message Scans ---

export async function getScan(folder: string, uid: number, uidValidity: number, context = 'inbound', accountId = 'default'): Promise<{ action: string; reason: string | null } | null> {
  return adapter.queryOne<{ action: string; reason: string | null }>('SELECT action, reason FROM message_scans WHERE account_id = ? AND folder = ? AND uid = ? AND uid_validity = ? AND context = ?', [accountId, folder, uid, uidValidity, context]);
}

export async function getScannedUids(
  folder: string, uids: number[], uidValidity: number, context = 'inbound', accountId = 'default',
): Promise<Map<number, { action: string; reason: string | null }>> {
  const result = new Map<number, { action: string; reason: string | null }>();
  if (uids.length === 0) return result;
  const placeholders = uids.map(() => '?').join(',');
  const rows = await adapter.query<{ uid: number; action: string; reason: string | null }>(
    `SELECT uid, action, reason FROM message_scans WHERE account_id = ? AND folder = ? AND uid_validity = ? AND context = ? AND uid IN (${placeholders})`,
    [accountId, folder, uidValidity, context, ...uids],
  );
  for (const row of rows) {
    result.set(row.uid, { action: row.action, reason: row.reason });
  }
  return result;
}

export async function recordScan(folder: string, uid: number, uidValidity: number, action: string, reason: string, context = 'inbound', accountId = 'default'): Promise<void> {
  const now = new Date().toISOString();
  await adapter.run(
    `INSERT INTO message_scans (account_id, folder, uid, uid_validity, context, action, reason, scanned_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(account_id, folder, uid, uid_validity, context) DO UPDATE SET action = ?, reason = ?, scanned_at = ?`,
    [accountId, folder, uid, uidValidity, context, action, reason, now, action, reason, now],
  );
}

/**
 * Delete scan records for UIDs at or below a threshold.
 * Called after the scanner advances its baseline — older records are dead weight.
 */
export async function pruneScans(folder: string, belowUid: number, uidValidity: number, context = 'inbound', accountId = 'default'): Promise<number> {
  const result = await adapter.run(
    `DELETE FROM message_scans WHERE account_id = ? AND folder = ? AND uid_validity = ? AND context = ? AND uid <= ?`,
    [accountId, folder, uidValidity, context, belowUid],
  );
  return (result as any)?.changes ?? 0;
}

// --- Stats ---

export async function getStats(accountId?: string): Promise<{ total: number; passed: number; rejected: number; quarantined: number; pending_quarantine: number }> {
  const where = accountId ? ' WHERE account_id = ?' : '';
  const whereAnd = accountId ? ' AND account_id = ?' : '';
  const params = accountId ? [accountId] : [];
  const [total, passed, rejected, quarantined, pending_quarantine] = await Promise.all([
    adapter.queryOne<{ c: number }>(`SELECT COUNT(*) as c FROM audit_log${where}`, params),
    adapter.queryOne<{ c: number }>(`SELECT COUNT(*) as c FROM audit_log WHERE action = 'pass'${whereAnd}`, params),
    adapter.queryOne<{ c: number }>(`SELECT COUNT(*) as c FROM audit_log WHERE action = 'reject'${whereAnd}`, params),
    adapter.queryOne<{ c: number }>(`SELECT COUNT(*) as c FROM audit_log WHERE action = 'quarantine'${whereAnd}`, params),
    adapter.queryOne<{ c: number }>(`SELECT COUNT(*) as c FROM quarantine WHERE status = 'pending'${whereAnd}`, params),
  ]);
  return {
    total: total?.c ?? 0,
    passed: passed?.c ?? 0,
    rejected: rejected?.c ?? 0,
    quarantined: quarantined?.c ?? 0,
    pending_quarantine: pending_quarantine?.c ?? 0,
  };
}

// --- Rate Limits ---

export async function loadRateLimits(): Promise<{ key: string; count: number; last_attempt: number; blocked_until: number | null }[]> {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  return adapter.query('SELECT * FROM rate_limits WHERE last_attempt > ?', [cutoff]);
}

export async function upsertRateLimit(key: string, count: number, lastAttempt: number, blockedUntil?: number): Promise<void> {
  await adapter.run(
    `INSERT INTO rate_limits (key, count, last_attempt, blocked_until)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET count = ?, last_attempt = ?, blocked_until = ?`,
    [key, count, lastAttempt, blockedUntil ?? null, count, lastAttempt, blockedUntil ?? null],
  );
}

export async function deleteRateLimit(key: string): Promise<void> {
  await adapter.run('DELETE FROM rate_limits WHERE key = ?', [key]);
}

export async function pruneRateLimits(olderThanMs: number): Promise<void> {
  const cutoff = Date.now() - olderThanMs;
  await adapter.run('DELETE FROM rate_limits WHERE last_attempt < ? AND (blocked_until IS NULL OR blocked_until < ?)', [cutoff, Date.now()]);
}
