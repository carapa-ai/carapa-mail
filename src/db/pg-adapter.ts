// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import type { DbAdapter } from './adapter.js';

/** Convert ? placeholders to $1, $2, ... for PostgreSQL */
function convertPlaceholders(sql: string): string {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}

export class PgAdapter implements DbAdapter {
  private pool: any; // pg.Pool — dynamically imported

  constructor(pool: any) {
    this.pool = pool;
  }

  static async create(connectionString: string): Promise<PgAdapter> {
    const pg = await import('pg');
    const pool = new pg.default.Pool({ connectionString });
    return new PgAdapter(pool);
  }

  async exec(sql: string): Promise<void> {
    await this.pool.query(sql);
  }

  async query<T>(sql: string, params?: any[]): Promise<T[]> {
    const result = await this.pool.query(convertPlaceholders(sql), params);
    return result.rows as T[];
  }

  async queryOne<T>(sql: string, params?: any[]): Promise<T | null> {
    const result = await this.pool.query(convertPlaceholders(sql), params);
    return (result.rows[0] as T) || null;
  }

  async run(sql: string, params?: any[]): Promise<void> {
    await this.pool.query(convertPlaceholders(sql), params);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
