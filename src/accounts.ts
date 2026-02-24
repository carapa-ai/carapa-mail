// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import crypto from 'crypto';
import { ImapFlow } from 'imapflow';
import nodemailer from 'nodemailer';
import { encrypt, decrypt, hashPassword, verifyPassword } from './crypto.js';
import {
  listAccounts as dbListAccounts,
  getAccountRowById,
  getAccountRowByEmail,
  insertAccount as dbInsertAccount,
  updateAccountRow,
  deleteAccountRow,
  getAccountIdsByTokenHash,
  type AccountRow,
} from './db/index.js';
import { clearTransporter } from './smtp/relay.js';
import { ALLOW_PROMPT_OVERRIDE, ALLOW_PROMPT_APPEND } from './config.js';

export type PromptMode = 'default' | 'append' | 'replace';

function promptModeFromDb(value: number): PromptMode {
  if (value === 2) return 'append';
  if (value === 1) return 'replace';
  return 'default';
}

function promptModeToDb(mode: PromptMode | undefined): number {
  if (mode === 'append' && ALLOW_PROMPT_APPEND) return 2;
  if (mode === 'replace' && ALLOW_PROMPT_OVERRIDE) return 1;
  return 0;
}

export interface Account {
  id: string;
  email: string;
  imap: { host: string; port: number; user: string; pass: string };
  smtp: { host: string; port: number; user: string; pass: string; secure: string };
  localPasswordHash: string;
  inboundEnabled: boolean;
  outboundEnabled: boolean;
  mcpReceiveEnabled: boolean;
  mcpSendEnabled: boolean;
  mcpDeleteEnabled: boolean;
  customInboundPrompt: string;
  customOutboundPrompt: string;
  customAgentPrompt: string;
  customInboundPromptMode: PromptMode;
  customOutboundPromptMode: PromptMode;
  customAgentPromptMode: PromptMode;
  mcpTokenSet: boolean;
  strictTls: boolean;
}

// In-memory cache of decrypted accounts
let accounts: Account[] = [];

function rowToAccount(row: AccountRow): Account {
  let localHash = row.local_pass_enc;
  // If it's old encrypted format (iv:tag:ciphertext), it will have 3 parts separated by colons.
  // New hash format has 2 parts (salt:hash).
  const isEncrypted = row.local_pass_enc.split(':').length === 3;

  if (isEncrypted) {
    try {
      const plaintext = decrypt(row.local_pass_enc);
      localHash = hashPassword(plaintext);
    } catch {
      // Fallback
    }
  }

  return {
    id: row.id,
    email: row.email,
    imap: {
      host: row.imap_host,
      port: row.imap_port,
      user: row.imap_user,
      pass: decrypt(row.imap_pass_enc),
    },
    smtp: {
      host: row.smtp_host,
      port: row.smtp_port,
      user: row.smtp_user,
      pass: decrypt(row.smtp_pass_enc),
      secure: row.smtp_secure,
    },
    localPasswordHash: localHash,
    inboundEnabled: row.inbound_enabled !== 0,
    outboundEnabled: row.outbound_enabled !== 0,
    mcpReceiveEnabled: row.mcp_receive_enabled !== 0,
    mcpSendEnabled: row.mcp_send_enabled !== 0,
    mcpDeleteEnabled: row.mcp_delete_enabled !== 0,
    customInboundPrompt: row.custom_inbound_prompt || '',
    customOutboundPrompt: row.custom_outbound_prompt || '',
    customAgentPrompt: row.custom_agent_prompt || '',
    customInboundPromptMode: promptModeFromDb(row.use_custom_inbound_prompt),
    customOutboundPromptMode: promptModeFromDb(row.use_custom_outbound_prompt),
    customAgentPromptMode: promptModeFromDb(row.use_custom_agent_prompt),
    mcpTokenSet: row.mcp_token_hash !== '',
    strictTls: row.strict_tls !== 0,
  };
}

/**
 * Load accounts from DB into memory.
 */
export async function loadAccounts(): Promise<void> {
  const rows = await dbListAccounts();
  accounts = rows.map(rowToAccount);
}

export function getAllAccounts(): Account[] {
  return accounts;
}

export function getAccountById(id: string): Account | undefined {
  return accounts.find(a => a.id === id);
}

export function getAccountByEmail(email: string): Account | undefined {
  return accounts.find(a => a.email.toLowerCase() === email.toLowerCase());
}

/**
 * Authenticate by email + local password. Returns the account or null.
 */
export function authenticateAccount(email: string, password: string): Account | null {
  const account = getAccountByEmail(email);
  if (!account) return null;

  // Handle legacy encrypted password or new hash
  const isEncrypted = account.localPasswordHash.split(':').length === 3;
  if (isEncrypted) {
    try {
      const plaintext = decrypt(account.localPasswordHash);
      if (plaintext === password) {
        // Successful legacy login — migrate to hash asynchronously
        const newHash = hashPassword(password);
        account.localPasswordHash = newHash;
        updateAccountRow(account.id, { local_pass_enc: newHash }).catch(console.error);
        return account;
      }
    } catch {
      return null;
    }
  }

  if (!verifyPassword(password, account.localPasswordHash)) return null;
  return account;
}

export interface AccountInput {
  id: string;
  email: string;
  imapHost: string;
  imapPort?: number;
  imapUser: string;
  imapPass: string;
  smtpHost: string;
  smtpPort?: number;
  smtpUser: string;
  smtpPass: string;
  smtpSecure?: string;
  localPassword: string;
  inboundEnabled?: boolean;
  outboundEnabled?: boolean;
  mcpReceiveEnabled?: boolean;
  mcpSendEnabled?: boolean;
  mcpDeleteEnabled?: boolean;
  customInboundPrompt?: string;
  customOutboundPrompt?: string;
  customAgentPrompt?: string;
  customInboundPromptMode?: PromptMode;
  customOutboundPromptMode?: PromptMode;
  customAgentPromptMode?: PromptMode;
  mcpToken?: string;
  strictTls?: boolean;
}

export async function addAccount(input: AccountInput): Promise<Account> {
  const now = new Date().toISOString();
  const row: AccountRow = {
    id: input.id,
    email: input.email,
    imap_host: input.imapHost,
    imap_port: input.imapPort ?? 993,
    imap_user: input.imapUser,
    imap_pass_enc: encrypt(input.imapPass),
    smtp_host: input.smtpHost,
    smtp_port: input.smtpPort ?? 587,
    smtp_user: input.smtpUser,
    smtp_pass_enc: encrypt(input.smtpPass),
    smtp_secure: input.smtpSecure ?? 'starttls',
    local_pass_enc: hashPassword(input.localPassword),
    inbound_enabled: input.inboundEnabled !== false ? 1 : 0,
    outbound_enabled: input.outboundEnabled !== false ? 1 : 0,
    mcp_receive_enabled: input.mcpReceiveEnabled !== false ? 1 : 0,
    mcp_send_enabled: input.mcpSendEnabled === true ? 1 : 0,
    mcp_delete_enabled: input.mcpDeleteEnabled === true ? 1 : 0,
    custom_inbound_prompt: input.customInboundPrompt || '',
    custom_outbound_prompt: input.customOutboundPrompt || '',
    custom_agent_prompt: input.customAgentPrompt || '',
    use_custom_inbound_prompt: promptModeToDb(input.customInboundPromptMode),
    use_custom_outbound_prompt: promptModeToDb(input.customOutboundPromptMode),
    use_custom_agent_prompt: promptModeToDb(input.customAgentPromptMode),
    mcp_token_hash: input.mcpToken ? hashToken(input.mcpToken) : '',
    strict_tls: input.strictTls !== false ? 1 : 0,
    created_at: now,
    updated_at: now,
  };

  await dbInsertAccount(row);
  const account = rowToAccount(row);
  accounts.push(account);
  return account;
}

export async function updateAccount(id: string, input: Partial<AccountInput>): Promise<Account | null> {
  const existing = await getAccountRowById(id);
  if (!existing) return null;

  const updates: Partial<AccountRow> = { updated_at: new Date().toISOString() };
  if (input.email !== undefined) updates.email = input.email;
  if (input.imapHost !== undefined) updates.imap_host = input.imapHost;
  if (input.imapPort !== undefined) updates.imap_port = input.imapPort;
  if (input.imapUser !== undefined) updates.imap_user = input.imapUser;
  if (input.imapPass !== undefined) updates.imap_pass_enc = encrypt(input.imapPass);
  if (input.smtpHost !== undefined) updates.smtp_host = input.smtpHost;
  if (input.smtpPort !== undefined) updates.smtp_port = input.smtpPort;
  if (input.smtpUser !== undefined) updates.smtp_user = input.smtpUser;
  if (input.smtpPass !== undefined) updates.smtp_pass_enc = encrypt(input.smtpPass);
  if (input.smtpSecure !== undefined) updates.smtp_secure = input.smtpSecure;
  if (input.localPassword !== undefined) updates.local_pass_enc = hashPassword(input.localPassword);
  if (input.inboundEnabled !== undefined) updates.inbound_enabled = input.inboundEnabled ? 1 : 0;
  if (input.outboundEnabled !== undefined) updates.outbound_enabled = input.outboundEnabled ? 1 : 0;
  if (input.mcpReceiveEnabled !== undefined) updates.mcp_receive_enabled = input.mcpReceiveEnabled ? 1 : 0;
  if (input.mcpSendEnabled !== undefined) updates.mcp_send_enabled = input.mcpSendEnabled ? 1 : 0;
  if (input.mcpDeleteEnabled !== undefined) updates.mcp_delete_enabled = input.mcpDeleteEnabled ? 1 : 0;
  if (input.customInboundPrompt !== undefined) updates.custom_inbound_prompt = input.customInboundPrompt;
  if (input.customOutboundPrompt !== undefined) updates.custom_outbound_prompt = input.customOutboundPrompt;
  if (input.customAgentPrompt !== undefined) updates.custom_agent_prompt = input.customAgentPrompt;
  if (input.customInboundPromptMode !== undefined) updates.use_custom_inbound_prompt = promptModeToDb(input.customInboundPromptMode);
  if (input.customOutboundPromptMode !== undefined) updates.use_custom_outbound_prompt = promptModeToDb(input.customOutboundPromptMode);
  if (input.customAgentPromptMode !== undefined) updates.use_custom_agent_prompt = promptModeToDb(input.customAgentPromptMode);
  if (input.mcpToken !== undefined) updates.mcp_token_hash = input.mcpToken ? hashToken(input.mcpToken) : '';
  if (input.strictTls !== undefined) updates.strict_tls = input.strictTls ? 1 : 0;

  await updateAccountRow(id, updates);

  // Reload cache
  const row = (await getAccountRowById(id))!;
  const account = rowToAccount(row);
  const idx = accounts.findIndex(a => a.id === id);
  if (idx >= 0) accounts[idx] = account;
  clearTransporter(id);
  return account;
}

export async function removeAccount(id: string): Promise<boolean> {
  const existing = await getAccountRowById(id);
  if (!existing) return false;
  await deleteAccountRow(id);
  accounts = accounts.filter(a => a.id !== id);
  clearTransporter(id);
  return true;
}

// --- MCP token helpers ---

export function hashToken(raw: string): string {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

export async function getAccountIdsByMcpToken(rawToken: string): Promise<string[]> {
  return getAccountIdsByTokenHash(hashToken(rawToken));
}

/**
 * Test IMAP + SMTP connectivity with raw credentials (no saved account needed).
 */
const TEST_TIMEOUT = 10_000; // 10s per connection test

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label}: connection timed out after ${ms / 1000}s`)), ms);
    promise.then(resolve, reject).finally(() => clearTimeout(timer));
  });
}

export async function testCredentials(creds: {
  imap?: { host: string; port: number; user: string; pass: string };
  smtp?: { host?: string; port?: number; user?: string; pass?: string; secure?: string };
}): Promise<{ imap: boolean; smtp: boolean; error?: string }> {
  let imapOk = false;
  let smtpOk = false;
  const errors: string[] = [];

  // Test IMAP
  if (creds.imap?.host) {
    try {
      const client = new ImapFlow({
        host: creds.imap.host,
        port: creds.imap.port,
        secure: creds.imap.port === 993,
        auth: { user: creds.imap.user, pass: creds.imap.pass },
        logger: false,
        tls: { rejectUnauthorized: (creds as any).strictTls !== false },
      });
      await withTimeout(client.connect(), TEST_TIMEOUT, 'IMAP');
      await client.logout();
      imapOk = true;
    } catch (e: any) {
      errors.push(`IMAP: ${e.message}`);
    }
  }

  // Test SMTP
  if (creds.smtp?.host) {
    try {
      const transporter = nodemailer.createTransport({
        host: creds.smtp.host,
        port: creds.smtp.port || 587,
        secure: creds.smtp.secure === 'tls',
        ...(creds.smtp.secure === 'starttls' ? { requireTLS: true } : {}),
        auth: creds.smtp.user ? { user: creds.smtp.user, pass: creds.smtp.pass } : undefined,
        tls: {
          rejectUnauthorized: (creds as any).strictTls !== false,
          checkServerIdentity: () => undefined,
        },
        connectionTimeout: TEST_TIMEOUT,
        greetingTimeout: TEST_TIMEOUT,
        socketTimeout: TEST_TIMEOUT,
      });
      await withTimeout(transporter.verify(), TEST_TIMEOUT, 'SMTP');
      smtpOk = true;
    } catch (e: any) {
      errors.push(`SMTP: ${e.message}`);
    }
  }

  return {
    imap: imapOk,
    smtp: smtpOk,
    error: errors.length > 0 ? errors.join('; ') : undefined,
  };
}

/**
 * Test IMAP + SMTP connectivity for a saved account.
 */
export async function testAccount(id: string): Promise<{ imap: boolean; smtp: boolean; error?: string }> {
  const account = getAccountById(id);
  if (!account) return { imap: false, smtp: false, error: 'Account not found' };
  return testCredentials({
    imap: account.inboundEnabled ? account.imap : undefined,
    smtp: account.outboundEnabled ? account.smtp : undefined,
  });
}
