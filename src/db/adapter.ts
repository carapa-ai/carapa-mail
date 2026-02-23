// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

export interface DbAdapter {
  /** Execute DDL or multi-statement SQL (no return value) */
  exec(sql: string): Promise<void>;

  /** Query returning multiple rows */
  query<T = any>(sql: string, params?: any[]): Promise<T[]>;

  /** Query returning a single row or null */
  queryOne<T = any>(sql: string, params?: any[]): Promise<T | null>;

  /** Execute a statement with no return (INSERT, UPDATE, DELETE) */
  run(sql: string, params?: any[]): Promise<void>;

  /** Close the connection/pool */
  close(): Promise<void>;
}

export type Dialect = 'sqlite' | 'postgres';
