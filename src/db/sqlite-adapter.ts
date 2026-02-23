// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { Database } from 'bun:sqlite';
import type { DbAdapter } from './adapter.js';

export class SqliteAdapter implements DbAdapter {
  private db: Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
  }

  async exec(sql: string): Promise<void> {
    this.db.exec(sql);
  }

  async query<T>(sql: string, params?: any[]): Promise<T[]> {
    if (params?.length) {
      return this.db.query(sql).all(...params) as T[];
    }
    return this.db.query(sql).all() as T[];
  }

  async queryOne<T>(sql: string, params?: any[]): Promise<T | null> {
    let row: any;
    if (params?.length) {
      row = this.db.query(sql).get(...params);
    } else {
      row = this.db.query(sql).get();
    }
    return (row as T) || null;
  }

  async run(sql: string, params?: any[]): Promise<void> {
    if (params?.length) {
      this.db.query(sql).run(...params);
    } else {
      this.db.run(sql);
    }
  }

  async close(): Promise<void> {
    this.db.close();
  }
}
