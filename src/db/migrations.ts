// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import type { DbAdapter, Dialect } from './adapter.js';
import { getCreateTablesSql } from './schema.js';

interface Migration {
  version: number;
  description: string;
  up: (adapter: DbAdapter, dialect: Dialect) => Promise<void>;
}

/**
 * All migrations in order. Version 0 creates the initial schema.
 * Subsequent versions handle incremental changes.
 *
 * For existing SQLite databases that predate the schema_version table,
 * we detect the current state and skip already-applied migrations.
 */
const migrations: Migration[] = [
  {
    version: 0,
    description: 'Initial schema',
    up: async (adapter, dialect) => {
      await adapter.exec(getCreateTablesSql(dialect));
    },
  },
  {
    version: 1,
    description: 'Add permission columns to accounts',
    up: async (adapter, dialect) => {
      const ifNotExists = dialect === 'postgres' ? ' IF NOT EXISTS' : '';
      const queries = [
        `ALTER TABLE accounts ADD COLUMN${ifNotExists} inbound_enabled INTEGER NOT NULL DEFAULT 1;`,
        `ALTER TABLE accounts ADD COLUMN${ifNotExists} outbound_enabled INTEGER NOT NULL DEFAULT 1;`,
        `ALTER TABLE accounts ADD COLUMN${ifNotExists} mcp_receive_enabled INTEGER NOT NULL DEFAULT 1;`,
        `ALTER TABLE accounts ADD COLUMN${ifNotExists} mcp_send_enabled INTEGER NOT NULL DEFAULT 0;`
      ];
      for (const q of queries) {
        try { await adapter.exec(q); } catch { }
      }
    },
  },
  {
    version: 2,
    description: 'Add custom prompt columns to accounts',
    up: async (adapter, dialect) => {
      const ifNotExists = dialect === 'postgres' ? ' IF NOT EXISTS' : '';
      const queries = [
        `ALTER TABLE accounts ADD COLUMN${ifNotExists} custom_inbound_prompt TEXT NOT NULL DEFAULT '';`,
        `ALTER TABLE accounts ADD COLUMN${ifNotExists} custom_outbound_prompt TEXT NOT NULL DEFAULT '';`,
        `ALTER TABLE accounts ADD COLUMN${ifNotExists} custom_agent_prompt TEXT NOT NULL DEFAULT '';`,
        `ALTER TABLE accounts ADD COLUMN${ifNotExists} use_custom_inbound_prompt INTEGER NOT NULL DEFAULT 0;`,
        `ALTER TABLE accounts ADD COLUMN${ifNotExists} use_custom_outbound_prompt INTEGER NOT NULL DEFAULT 0;`,
        `ALTER TABLE accounts ADD COLUMN${ifNotExists} use_custom_agent_prompt INTEGER NOT NULL DEFAULT 0;`
      ];
      for (const q of queries) {
        try { await adapter.exec(q); } catch { }
      }
    },
  },
  {
    version: 3,
    description: 'Add MCP token hash to accounts',
    up: async (adapter, dialect) => {
      const ifNotExists = dialect === 'postgres' ? ' IF NOT EXISTS' : '';
      try {
        await adapter.exec(`ALTER TABLE accounts ADD COLUMN${ifNotExists} mcp_token_hash TEXT NOT NULL DEFAULT '';`);
      } catch { }
    },
  },
  {
    version: 4,
    description: 'Add rate_limits persistence table',
    up: async (adapter, dialect) => {
      await adapter.exec(`
        CREATE TABLE IF NOT EXISTS rate_limits (
          key TEXT PRIMARY KEY,
          count INTEGER NOT NULL DEFAULT 0,
          last_attempt ${dialect === 'postgres' ? 'BIGINT' : 'INTEGER'} NOT NULL,
          blocked_until ${dialect === 'postgres' ? 'BIGINT' : 'INTEGER'}
        );
      `);
    },
  },
  {
    version: 5,
    description: 'Create whitelist table',
    up: async (adapter) => {
      await adapter.exec(`
        CREATE TABLE IF NOT EXISTS whitelist (
          id TEXT PRIMARY KEY,
          account_id TEXT NOT NULL DEFAULT 'default',
          type TEXT NOT NULL,
          pattern TEXT NOT NULL,
          source TEXT NOT NULL,
          created_at TEXT NOT NULL,
          UNIQUE(account_id, type, pattern)
        );
      `);
    },
  },
  {
    version: 6,
    description: 'Create rate_limits table',
    up: async (adapter, dialect) => {
      await adapter.exec(`
        CREATE TABLE IF NOT EXISTS rate_limits (
          key TEXT PRIMARY KEY,
          count INTEGER NOT NULL DEFAULT 0,
          last_attempt ${dialect === 'postgres' ? 'BIGINT' : 'INTEGER'} NOT NULL,
          blocked_until ${dialect === 'postgres' ? 'BIGINT' : 'INTEGER'}
        );
      `);
    },
  },
  {
    version: 7,
    description: 'Add strict_tls column to accounts',
    up: async (adapter, dialect) => {
      const ifNotExists = dialect === 'postgres' ? ' IF NOT EXISTS' : '';
      try {
        await adapter.exec(`ALTER TABLE accounts ADD COLUMN${ifNotExists} strict_tls INTEGER NOT NULL DEFAULT 1;`);
      } catch {
        // Column may already exist if database was created with full schema
      }
    },
  },
  {
    version: 8,
    description: 'Fix rate_limits integer bounds for Postgres defaults',
    up: async (adapter, dialect) => {
      if (dialect === 'postgres') {
        try {
          await adapter.exec('ALTER TABLE rate_limits ALTER COLUMN last_attempt TYPE BIGINT; ALTER TABLE rate_limits ALTER COLUMN blocked_until TYPE BIGINT;');
        } catch {
          // Ignore if it fails or table missing
        }
      }
    },
  },
  {
    version: 9,
    description: 'Add mcp_delete_enabled column',
    up: async (adapter, dialect) => {
      const ifNotExists = dialect === 'postgres' ? ' IF NOT EXISTS' : '';
      try {
        await adapter.exec(`ALTER TABLE accounts ADD COLUMN${ifNotExists} mcp_delete_enabled INTEGER NOT NULL DEFAULT 0;`);
      } catch { }
    },
  },
  {
    version: 10,
    description: 'Add direction column to rules',
    up: async (adapter, dialect) => {
      const ifNotExists = dialect === 'postgres' ? ' IF NOT EXISTS' : '';
      try {
        await adapter.exec(`ALTER TABLE rules ADD COLUMN${ifNotExists} direction TEXT NOT NULL DEFAULT 'both';`);
      } catch { }
    },
  },
];

/**
 * Detect migration level for existing SQLite databases that lack schema_version.
 * Returns the version to seed, or -1 if this is a fresh database.
 */
async function detectExistingState(adapter: DbAdapter, dialect: Dialect): Promise<number> {
  if (dialect !== 'sqlite') return -1;

  // Check if any of our tables exist
  try {
    const result = await adapter.queryOne<{ c: number }>(
      "SELECT COUNT(*) as c FROM sqlite_master WHERE type='table' AND name='accounts'",
    );
    if (!result || result.c === 0) return -1; // Fresh database
  } catch {
    return -1;
  }

  // Tables exist — this is a pre-migration database.
  // All legacy migrations (v0-v4: initial schema, permission columns, custom prompts,
  // mcp token, rate_limits table) were already handled by the old PRAGMA-based system.
  // Seed at v4 so that newer migrations (whitelist table, strict_tls, etc.) still run.
  return 4;
}

export async function runMigrations(adapter: DbAdapter, dialect: Dialect): Promise<void> {
  // Ensure schema_version table exists
  await adapter.exec('CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)');

  // Get current version
  const row = await adapter.queryOne<{ version: number }>(
    'SELECT MAX(version) as version FROM schema_version',
  );
  let current = row?.version ?? -1;

  // Handle pre-migration SQLite databases
  if (current === -1) {
    const detected = await detectExistingState(adapter, dialect);
    if (detected >= 0) {
      // Seed version for existing database — schema already exists
      await adapter.run('INSERT INTO schema_version (version) VALUES (?)', [detected]);
      console.log(`[db] Detected existing database, seeded schema_version at v${detected}`);
      current = detected;
    }
  }

  // getCreateTablesSql() includes columns from all migrations, so any database
  // created by v0 already has the full schema. Detect this by checking for a
  // column added in v1 and skip to v4 (the old latest before whitelist/strict_tls).
  // Newer migrations (v5+) use CREATE IF NOT EXISTS / ADD COLUMN safely.
  if (current < 4 && dialect === 'sqlite') {
    try {
      const col = await adapter.queryOne<{ c: number }>(
        "SELECT COUNT(*) as c FROM pragma_table_info('accounts') WHERE name='inbound_enabled'",
      );
      if (col && col.c > 0) {
        await adapter.run('INSERT INTO schema_version (version) VALUES (?)', [4]);
        console.log(`[db] Schema already up to date through v4 — seeded schema_version to v4`);
        current = 4;
      }
    } catch {
      // pragma_table_info not available or accounts table doesn't exist yet — continue normally
    }
  }

  // Run pending migrations
  for (const m of migrations) {
    if (m.version > current) {
      console.log(`[db] Running migration v${m.version}: ${m.description}`);
      await m.up(adapter, dialect);
      await adapter.run('INSERT INTO schema_version (version) VALUES (?)', [m.version]);
    }
  }
}
