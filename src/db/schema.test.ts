// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe } from 'bun:test';
import { getCreateTablesSql } from './schema.js';

describe('getCreateTablesSql', () => {
  describe('SQLite dialect', () => {
    const sql = getCreateTablesSql('sqlite');

    test('creates quarantine table', () => {
      expect(sql).toContain('CREATE TABLE IF NOT EXISTS quarantine');
      expect(sql).toContain('id TEXT PRIMARY KEY');
    });

    test('creates audit_log table with AUTOINCREMENT', () => {
      expect(sql).toContain('CREATE TABLE IF NOT EXISTS audit_log');
      expect(sql).toContain('INTEGER PRIMARY KEY AUTOINCREMENT');
    });

    test('creates accounts table', () => {
      expect(sql).toContain('CREATE TABLE IF NOT EXISTS accounts');
      expect(sql).toContain('email TEXT NOT NULL UNIQUE');
      expect(sql).toContain('imap_host TEXT NOT NULL');
      expect(sql).toContain('smtp_host TEXT NOT NULL');
    });

    test('creates rules table', () => {
      expect(sql).toContain('CREATE TABLE IF NOT EXISTS rules');
      expect(sql).toContain('match_field TEXT NOT NULL');
      expect(sql).toContain('match_pattern TEXT NOT NULL');
    });

    test('creates message_scans table with composite PK', () => {
      expect(sql).toContain('CREATE TABLE IF NOT EXISTS message_scans');
      expect(sql).toContain('PRIMARY KEY (account_id, folder, uid, uid_validity, context)');
    });

    test('creates scanner_state table', () => {
      expect(sql).toContain('CREATE TABLE IF NOT EXISTS scanner_state');
      expect(sql).toContain('PRIMARY KEY (account_id, folder)');
    });

    test('creates schema_version table', () => {
      expect(sql).toContain('CREATE TABLE IF NOT EXISTS schema_version');
    });

    test('creates whitelist table with unique constraint', () => {
      expect(sql).toContain('CREATE TABLE IF NOT EXISTS whitelist');
      expect(sql).toContain('UNIQUE(account_id, type, pattern)');
    });

    test('creates audit_log index', () => {
      expect(sql).toContain('CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)');
    });

    test('uses BLOB type for raw_eml', () => {
      expect(sql).toContain('raw_eml BLOB');
    });

    test('includes MCP permission columns', () => {
      expect(sql).toContain('mcp_receive_enabled');
      expect(sql).toContain('mcp_send_enabled');
      expect(sql).toContain('mcp_token_hash');
    });
  });

  describe('PostgreSQL dialect', () => {
    const sql = getCreateTablesSql('postgres');

    test('uses GENERATED ALWAYS AS IDENTITY for audit_log', () => {
      expect(sql).toContain('INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY');
      expect(sql).not.toContain('AUTOINCREMENT');
    });

    test('uses BYTEA for raw_eml', () => {
      expect(sql).toContain('raw_eml BYTEA');
      expect(sql).not.toContain('raw_eml BLOB');
    });

    test('creates all the same tables as SQLite', () => {
      const tables = ['quarantine', 'audit_log', 'accounts', 'rules', 'message_scans', 'scanner_state', 'schema_version', 'whitelist'];
      for (const table of tables) {
        expect(sql).toContain(`CREATE TABLE IF NOT EXISTS ${table}`);
      }
    });
  });

  describe('dialect differences', () => {
    const sqliteSql = getCreateTablesSql('sqlite');
    const pgSql = getCreateTablesSql('postgres');

    test('both contain the same tables', () => {
      const tableRegex = /CREATE TABLE IF NOT EXISTS (\w+)/g;
      const sqliteTables = [...sqliteSql.matchAll(tableRegex)].map(m => m[1]).sort();
      const pgTables = [...pgSql.matchAll(tableRegex)].map(m => m[1]).sort();
      expect(sqliteTables).toEqual(pgTables);
    });

    test('only auto-id, blob type, and bigint differ', () => {
      // Replace the known dialect-specific differences and compare
      const normalizedSqlite = sqliteSql
        .replace('id INTEGER PRIMARY KEY AUTOINCREMENT', 'AUTO_ID')
        .replace('BLOB', 'BINARY_TYPE');
      const normalizedPg = pgSql
        .replace('id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY', 'AUTO_ID')
        .replace('BYTEA', 'BINARY_TYPE')
        // rate_limits uses BIGINT on Postgres for Unix-ms timestamps (migration v8)
        .replace(/BIGINT/g, 'INTEGER');
      expect(normalizedSqlite).toBe(normalizedPg);
    });
  });
});
