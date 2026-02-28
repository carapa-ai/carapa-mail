// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { ImapFlow } from 'imapflow';
import { IMAP_PROXY_PORT } from '../config.js';
import { getAllAccounts, getAccountById, getAccountByEmail, type Account } from '../accounts.js';
import { sanitizeBody, sanitizeHtml } from '../imap/sanitizer.js';
import { parseHeaders, SECURITY_HEADERS } from '../email/parser.js';
import { logger } from '../logger.js';


// Per-account client pool
const clients = new Map<string, ImapFlow>();
const connecting = new Set<string>();

function createClient(account: Account): ImapFlow {
  // Connect directly to upstream to avoid needing the plaintext localPassword
  // which is now hashed for security.
  const client = new ImapFlow({
    host: account.imap.host,
    port: account.imap.port,
    secure: account.imap.port === 993,
    auth: {
      user: account.imap.user,
      pass: account.imap.pass,
    },
    logger: false,
    disableAutoIdle: true,
    tls: {
      rejectUnauthorized: true,
    },
  });
  client.on('error', (err: Error) => {
    logger.error('mcp-imap', `[${account.id}] IMAP error: ${err.message}`);
    clients.delete(account.id);
  });
  return client;
}

export type McpMode = 'receive' | 'send' | 'delete';

/**
 * Resolve an account identifier (ID or email) to an Account.
 * When mode is specified, only returns accounts with the corresponding MCP flag enabled.
 * Falls back to the first eligible account if not specified.
 */
export function resolveAccount(accountIdOrEmail?: string, mode?: McpMode): Account | undefined {
  if (!accountIdOrEmail) {
    if (!mode) return getAllAccounts()[0];
    return getAllAccounts().find(a =>
      mode === 'send' ? a.mcpSendEnabled : mode === 'delete' ? a.mcpDeleteEnabled : a.mcpReceiveEnabled,
    );
  }
  const account = getAccountById(accountIdOrEmail) || getAccountByEmail(accountIdOrEmail);
  if (!account || !mode) return account;
  const allowed = mode === 'send' ? account.mcpSendEnabled : mode === 'delete' ? account.mcpDeleteEnabled : account.mcpReceiveEnabled;
  if (!allowed) return undefined;
  return account;
}

async function getClient(accountId?: string): Promise<ImapFlow> {
  const account = resolveAccount(accountId);
  if (!account) throw new Error('No accounts configured');

  const id = account.id;
  const existing = clients.get(id);
  if (existing?.usable) return existing;

  if (connecting.has(id)) {
    // Wait for ongoing connection
    await new Promise(r => setTimeout(r, 500));
    const c = clients.get(id);
    if (c?.usable) return c;
  }

  connecting.add(id);
  try {
    const old = clients.get(id);
    if (old) {
      try { old.close(); } catch { }
    }
    const client = createClient(account);
    await client.connect();
    client.on('close', () => { clients.delete(id); });
    clients.set(id, client);
    return client;
  } finally {
    connecting.delete(id);
  }
}

export interface EmailSummary {
  uid: number;
  from: string;
  to: string;
  subject: string;
  date: string;
  seen: boolean;
}

export interface EmailDetail extends EmailSummary {
  cc: string;
  body_text: string;
  attachments: { name: string; type: string; size: number }[];
  rawHeaders: Record<string, string>;
}

export interface FolderInfo {
  name: string;
  path: string;
  total: number;
  unseen: number;
}

function formatAddress(addrs?: { name?: string; address?: string }[]): string {
  if (!addrs?.length) return '';
  return addrs.map(a => a.name ? `${a.name} <${a.address}>` : a.address || '').join(', ');
}

function findTextPart(structure: any): string | null {
  if (!structure) return null;
  if (structure.type === 'text/plain') return structure.part || '1';
  if (structure.childNodes) {
    for (const child of structure.childNodes) {
      const found = findTextPart(child);
      if (found) return found;
    }
  }
  return null;
}

function findAttachments(structure: any): { name: string; type: string; size: number }[] {
  const result: { name: string; type: string; size: number }[] = [];
  if (!structure) return result;
  if (structure.disposition === 'attachment' || (structure.dispositionParameters?.filename)) {
    result.push({
      name: structure.dispositionParameters?.filename || structure.parameters?.name || 'unknown',
      type: structure.type || 'application/octet-stream',
      size: structure.size || 0,
    });
  }
  if (structure.childNodes) {
    for (const child of structure.childNodes) {
      result.push(...findAttachments(child));
    }
  }
  return result;
}

export async function listFolders(accountId?: string): Promise<FolderInfo[]> {
  const c = await getClient(accountId);
  const mailboxes = await c.list({
    statusQuery: { messages: true, unseen: true },
  });
  return mailboxes
    .filter(m => !m.flags.has('\\Noselect'))
    .map(m => ({
      name: m.name,
      path: m.path,
      total: m.status?.messages ?? 0,
      unseen: m.status?.unseen ?? 0,
    }));
}

export interface PaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  totalPages: number;
  hasMore: boolean;
}

export async function listMessages(folder: string, limit: number, page: number, accountId?: string): Promise<PaginatedResult<EmailSummary>> {
  const c = await getClient(accountId);
  const lock = await c.getMailboxLock(folder, { readOnly: true });
  try {
    const total = c.mailbox ? c.mailbox.exists : 0;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    if (total === 0) return { items: [], total: 0, page, totalPages: 1, hasMore: false };

    // Fetch newest first: sequence range from end
    const end = total - (page - 1) * limit;
    const start = Math.max(1, end - limit + 1);
    if (end < 1) return { items: [], total, page, totalPages, hasMore: false };

    const messages: EmailSummary[] = [];
    for await (const msg of c.fetch(`${start}:${end}`, { envelope: true, flags: true, uid: true })) {
      messages.push({
        uid: msg.uid,
        from: formatAddress(msg.envelope?.from),
        to: formatAddress(msg.envelope?.to),
        subject: msg.envelope?.subject || '',
        date: msg.envelope?.date?.toISOString() || '',
        seen: msg.flags?.has('\\Seen') || false,
      });
    }
    // Return newest first
    return { items: messages.reverse(), total, page, totalPages, hasMore: page < totalPages };
  } finally {
    lock.release();
  }
}

export interface GetMessageResult {
  message: EmailDetail;
  uidValidity: number;
  rawSource: Buffer;
}

export async function getMessage(folder: string, uid: number, accountId?: string): Promise<GetMessageResult | null> {
  const c = await getClient(accountId);
  const lock = await c.getMailboxLock(folder, { readOnly: true });
  try {
    const mailbox = c.mailbox;
    const uidValidity = mailbox && typeof mailbox === 'object' ? Number(mailbox.uidValidity ?? 0) : 0;

    const msg = await c.fetchOne(String(uid), {
      envelope: true,
      flags: true,
      bodyStructure: true,
      headers: SECURITY_HEADERS,
      uid: true,
    }, { uid: true });

    if (!msg) return null;

    // Parse security-relevant headers
    const rawHeaders = msg.headers ? parseHeaders(msg.headers) : {};

    // Get text body (unsanitized — sanitization deferred to tools.ts after AI filter)
    let bodyText = '';
    const textPart = findTextPart(msg.bodyStructure);
    if (textPart) {
      const { content } = await c.download(String(uid), textPart, { uid: true });
      const chunks: Buffer[] = [];
      for await (const chunk of content) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      bodyText = Buffer.concat(chunks).toString('utf-8');
    }

    // Download full RFC822 source for attachment scanning
    const { content: rawContent } = await c.download(String(uid), undefined, { uid: true });
    const rawChunks: Buffer[] = [];
    for await (const chunk of rawContent) {
      rawChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const rawSource = Buffer.concat(rawChunks);

    return {
      message: {
        uid: msg.uid,
        from: formatAddress(msg.envelope?.from),
        to: formatAddress(msg.envelope?.to),
        cc: formatAddress(msg.envelope?.cc),
        subject: msg.envelope?.subject || '',
        date: msg.envelope?.date?.toISOString() || '',
        seen: msg.flags?.has('\\Seen') || false,
        body_text: bodyText,
        attachments: findAttachments(msg.bodyStructure),
        rawHeaders,
      },
      uidValidity,
      rawSource,
    };
  } finally {
    lock.release();
  }
}

export async function searchMessages(
  folder: string,
  query: string,
  field: 'from' | 'to' | 'subject' | 'body' | 'all',
  since: string | undefined,
  before: string | undefined,
  limit: number,
  page: number = 1,
  accountId?: string,
): Promise<PaginatedResult<EmailSummary>> {
  const c = await getClient(accountId);
  const lock = await c.getMailboxLock(folder, { readOnly: true });
  try {
    const searchQuery: any = {};
    if (field === 'all') searchQuery.text = query;
    else if (field === 'body') searchQuery.body = query;
    else searchQuery[field] = query;
    if (since) searchQuery.since = new Date(since);
    if (before) searchQuery.before = new Date(before);

    const uids = await c.search(searchQuery, { uid: true });
    if (!uids || uids.length === 0) return { items: [], total: 0, page, totalPages: 1, hasMore: false };

    const total = uids.length;
    const totalPages = Math.max(1, Math.ceil(total / limit));

    // UIDs are in ascending order; slice from end for newest-first pagination
    const end = total - (page - 1) * limit;
    const start = Math.max(0, end - limit);
    if (end <= 0) return { items: [], total, page, totalPages, hasMore: false };

    const pageUids = uids.slice(start, end);
    const messages: EmailSummary[] = [];
    for await (const msg of c.fetch(pageUids, { envelope: true, flags: true, uid: true }, { uid: true })) {
      messages.push({
        uid: msg.uid,
        from: formatAddress(msg.envelope?.from),
        to: formatAddress(msg.envelope?.to),
        subject: msg.envelope?.subject || '',
        date: msg.envelope?.date?.toISOString() || '',
        seen: msg.flags?.has('\\Seen') || false,
      });
    }
    return { items: messages.reverse(), total, page, totalPages, hasMore: page < totalPages };
  } finally {
    lock.release();
  }
}

export async function deleteMessages(folder: string, uids: number[], accountId?: string): Promise<number> {
  const c = await getClient(accountId);
  const lock = await c.getMailboxLock(folder);
  try {
    await c.messageDelete(uids, { uid: true });
    return uids.length;
  } finally {
    lock.release();
  }
}

export async function moveMessages(folder: string, uids: number[], destination: string, accountId?: string): Promise<number> {
  const c = await getClient(accountId);
  const lock = await c.getMailboxLock(folder);
  try {
    await c.messageMove(uids, destination, { uid: true });
    return uids.length;
  } finally {
    lock.release();
  }
}

/** Sanitize body text for safe delivery to agents. Call after AI filter has inspected the raw text. */
export function sanitizeMessageBody(text: string): string {
  const isHtml = /<html|<body|<div|<p\b/i.test(text);
  const { sanitized } = isHtml ? sanitizeHtml(text) : sanitizeBody(text);
  return sanitized;
}

export async function disconnect(): Promise<void> {
  for (const [id, client] of clients) {
    try { await client.logout(); } catch { }
    clients.delete(id);
  }
}
