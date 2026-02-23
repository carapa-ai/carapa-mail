// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import type { Dialect } from './adapter.js';

export function getCreateTablesSql(dialect: Dialect): string {
  const autoId =
    dialect === 'postgres'
      ? 'id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY'
      : 'id INTEGER PRIMARY KEY AUTOINCREMENT';

  const blobType = dialect === 'postgres' ? 'BYTEA' : 'BLOB';

  return `
    CREATE TABLE IF NOT EXISTS quarantine (
      id TEXT PRIMARY KEY,
      direction TEXT NOT NULL,
      from_addr TEXT,
      to_addr TEXT,
      subject TEXT,
      body_preview TEXT,
      raw_eml ${blobType},
      reason TEXT NOT NULL,
      categories TEXT,
      confidence REAL,
      status TEXT DEFAULT 'pending',
      account_id TEXT NOT NULL DEFAULT 'default',
      created_at TEXT NOT NULL,
      reviewed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      ${autoId},
      direction TEXT NOT NULL,
      from_addr TEXT,
      to_addr TEXT,
      subject TEXT,
      action TEXT NOT NULL,
      reason TEXT,
      categories TEXT,
      confidence REAL,
      latency_ms INTEGER,
      account_id TEXT NOT NULL DEFAULT 'default',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

    CREATE TABLE IF NOT EXISTS scanner_state (
      account_id TEXT NOT NULL DEFAULT 'default',
      folder TEXT NOT NULL,
      uid_validity INTEGER NOT NULL,
      last_uid INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (account_id, folder)
    );

    CREATE TABLE IF NOT EXISTS rules (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      match_field TEXT NOT NULL,
      match_pattern TEXT NOT NULL,
      priority INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS message_scans (
      account_id TEXT NOT NULL DEFAULT 'default',
      folder TEXT NOT NULL,
      uid INTEGER NOT NULL,
      uid_validity INTEGER NOT NULL,
      context TEXT NOT NULL DEFAULT 'inbound',
      action TEXT NOT NULL,
      reason TEXT,
      scanned_at TEXT NOT NULL,
      PRIMARY KEY (account_id, folder, uid, uid_validity, context)
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      imap_host TEXT NOT NULL,
      imap_port INTEGER NOT NULL DEFAULT 993,
      imap_user TEXT NOT NULL,
      imap_pass_enc TEXT NOT NULL,
      smtp_host TEXT NOT NULL,
      smtp_port INTEGER NOT NULL DEFAULT 587,
      smtp_user TEXT NOT NULL,
      smtp_pass_enc TEXT NOT NULL,
      smtp_secure TEXT NOT NULL DEFAULT 'starttls',
      local_pass_enc TEXT NOT NULL,
      inbound_enabled INTEGER NOT NULL DEFAULT 1,
      outbound_enabled INTEGER NOT NULL DEFAULT 1,
      mcp_receive_enabled INTEGER NOT NULL DEFAULT 1,
      mcp_send_enabled INTEGER NOT NULL DEFAULT 0,
      custom_inbound_prompt TEXT NOT NULL DEFAULT '',
      custom_outbound_prompt TEXT NOT NULL DEFAULT '',
      custom_agent_prompt TEXT NOT NULL DEFAULT '',
      use_custom_inbound_prompt INTEGER NOT NULL DEFAULT 0,
      use_custom_outbound_prompt INTEGER NOT NULL DEFAULT 0,
      use_custom_agent_prompt INTEGER NOT NULL DEFAULT 0,
      mcp_token_hash TEXT NOT NULL DEFAULT '',
      strict_tls INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS schema_version (
      version INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS whitelist (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL DEFAULT 'default',
      type TEXT NOT NULL, -- 'email' or 'domain'
      pattern TEXT NOT NULL,
      source TEXT NOT NULL, -- 'outbound' or 'manual'
      created_at TEXT NOT NULL,
      UNIQUE(account_id, type, pattern)
    );

    CREATE TABLE IF NOT EXISTS rate_limits (
      key TEXT PRIMARY KEY,
      count INTEGER NOT NULL DEFAULT 0,
      last_attempt ${dialect === 'postgres' ? 'BIGINT' : 'INTEGER'} NOT NULL,
      blocked_until ${dialect === 'postgres' ? 'BIGINT' : 'INTEGER'}
    );
  `;
}
