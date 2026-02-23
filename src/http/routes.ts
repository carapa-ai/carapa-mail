// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import type { IncomingMessage, ServerResponse } from 'http';
import {
  listQuarantine,
  getQuarantineEntry,
  listAuditLog,
  listRules,
  insertRule,
  deleteRule,
  getStats,
  autoWhitelistSender,
  logAudit,
  listWhitelist,
  addToWhitelist,
  removeFromWhitelist,
} from '../db/index.js';
import { releaseFromQuarantine, deleteFromQuarantine, quarantineMessage } from '../email/quarantine.js';
import { relayRawMessage } from '../smtp/relay.js';
import { inspectEmail } from '../agent/filter.js';
import { toEmailSummary } from '../email/parser.js';
import { simpleParser } from 'mailparser';
import {
  getAllAccounts,
  getAccountById,
  getAccountByEmail,
  authenticateAccount,
  addAccount,
  updateAccount,
  removeAccount,
  testAccount,
  testCredentials,
  type AccountInput,
} from '../accounts.js';
import { getSetupPage } from './setup-ui.js';
import { ALLOW_SIGNUP, HTTP_API_TOKEN, PUBLIC_HOSTNAME, SMTP_PORT, IMAP_PROXY_PORT, MCP_PORT, MCP_ENABLED, MCP_PUBLIC_URL } from '../config.js';
import { randomUUID } from 'crypto';
import { logger } from '../logger.js';
import { checkRateLimit, recordAttempt } from '../rate-limiter.js';

function requireAdmin(req: IncomingMessage, res: ServerResponse): boolean {
  if (req.carapamailAuth?.type !== 'admin') {
    json(res, { error: 'Admin access required' }, 403);
    return false;
  }
  return true;
}

/**
 * Ensures the authenticated user has access to the requested accountId.
 * If the user is a regular user, it forces the accountId to be their own.
 * If the user is an admin, it allows any accountId.
 * Returns the effective accountId to use for the query, or null if access is denied.
 */
function getEffectiveAccountId(req: IncomingMessage, res: ServerResponse, requestedId?: string): string | undefined | null {
  const auth = req.carapamailAuth!;
  if (auth.type === 'admin') {
    return requestedId;
  }
  if (auth.type === 'user') {
    if (requestedId && requestedId !== auth.accountId) {
      json(res, { error: 'Access denied to this account' }, 403);
      return null;
    }
    return auth.accountId;
  }
  json(res, { error: 'Unauthorized' }, 401);
  return null;
}

async function safeJsonParse(req: IncomingMessage, res: ServerResponse): Promise<any> {
  try {
    const body = await readBody(req);
    if (!body) return {};
    return JSON.parse(body);
  } catch (err) {
    json(res, { error: 'Invalid JSON body' }, 400);
    return null;
  }
}

type RouteHandler = (req: IncomingMessage, res: ServerResponse, params: Record<string, string>) => Promise<void>;

function json(res: ServerResponse, data: unknown, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function html(res: ServerResponse, body: string, status = 200) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(body);
}

const MAX_BODY_SIZE = 1024 * 1024; // 1 MB

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let totalLength = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalLength += buf.length;
    if (totalLength > MAX_BODY_SIZE) {
      throw new Error('Request body too large');
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString('utf-8');
}

// Route definitions
const routes: { method: string; pattern: RegExp; handler: RouteHandler }[] = [
  // Setup UI
  {
    method: 'GET',
    pattern: /^\/(?:setup)?$/,
    handler: async (_req, res) => {
      html(res, getSetupPage({ allowSignup: ALLOW_SIGNUP, hasToken: !!HTTP_API_TOKEN, publicHostname: PUBLIC_HOSTNAME, smtpPort: SMTP_PORT, imapProxyPort: IMAP_PROXY_PORT, mcpPort: MCP_PORT, mcpEnabled: MCP_ENABLED, mcpPublicUrl: MCP_PUBLIC_URL }));
    },
  },

  // Health
  {
    method: 'GET',
    pattern: /^\/health$/,
    handler: async (_req, res) => {
      json(res, { status: 'ok' });
    },
  },

  // Stats
  {
    method: 'GET',
    pattern: /^\/stats$/,
    handler: async (req, res) => {
      const url = new URL(req.url || '/', `http://${req.headers.host}`);
      const requestedId = url.searchParams.get('account') || undefined;
      const accountId = getEffectiveAccountId(req, res, requestedId);
      if (accountId === null) return;
      json(res, await getStats(accountId));
    },
  },

  // --- Auth ---
  {
    method: 'POST',
    pattern: /^\/api\/auth$/,
    handler: async (req, res) => {
      const clientIp = req.socket.remoteAddress || 'unknown';
      const rateLimit = checkRateLimit(clientIp, 'api-auth');
      if (!rateLimit.allowed) {
        logger.warn('http', `Rate limit exceeded for IP ${clientIp}`);
        return json(res, { error: `Too many failed attempts. Try again in ${rateLimit.retryAfter} seconds.` }, 429);
      }

      const body = await safeJsonParse(req, res);
      if (body === null) return;
      if (!body.email || !body.password) {
        return json(res, { error: 'Email and password required' }, 400);
      }
      const account = authenticateAccount(body.email, body.password);
      if (!account) {
        recordAttempt(clientIp, 'api-auth', false);
        return json(res, { error: 'Invalid email or password' }, 401);
      }
      recordAttempt(clientIp, 'api-auth', true);
      json(res, { accountId: account.id, email: account.email });
    },
  },

  // --- Accounts ---
  {
    method: 'GET',
    pattern: /^\/api\/accounts$/,
    handler: async (req, res) => {
      const auth = req.carapamailAuth!;
      const toResponse = (a: ReturnType<typeof getAccountById>) => a ? ({
        id: a.id, email: a.email,
        imap: { host: a.imap.host, port: a.imap.port, user: a.imap.user },
        smtp: { host: a.smtp.host, port: a.smtp.port, user: a.smtp.user, secure: a.smtp.secure },
        inboundEnabled: a.inboundEnabled, outboundEnabled: a.outboundEnabled,
        mcpReceiveEnabled: a.mcpReceiveEnabled, mcpSendEnabled: a.mcpSendEnabled,
        mcpTokenSet: a.mcpTokenSet,
        customInboundPrompt: a.customInboundPrompt, customOutboundPrompt: a.customOutboundPrompt, customAgentPrompt: a.customAgentPrompt,
        customInboundPromptMode: a.customInboundPromptMode, customOutboundPromptMode: a.customOutboundPromptMode, customAgentPromptMode: a.customAgentPromptMode,
      }) : null;
      if (auth.type === 'user') {
        const a = getAccountById(auth.accountId);
        if (!a) return json(res, []);
        return json(res, [toResponse(a)]);
      }
      if (auth.type !== 'admin') return json(res, { error: 'Unauthorized' }, 401);
      json(res, getAllAccounts().map(toResponse));
    },
  },
  {
    method: 'POST',
    pattern: /^\/api\/accounts$/,
    handler: async (req, res) => {
      const body = await safeJsonParse(req, res);
      if (body === null) return;

      // Validate required fields
      if (!body.id || !body.email || !body.localPassword) {
        return json(res, { error: 'Missing required fields: id, email, localPassword' }, 400);
      }
      if (!body.imapHost && !body.smtpHost) {
        return json(res, { error: 'At least one of IMAP or SMTP must be configured' }, 400);
      }

      // Validate ID format
      if (!/^[a-z0-9][a-z0-9_-]*$/.test(body.id)) {
        return json(res, { error: 'Account ID must be lowercase alphanumeric with hyphens/underscores' }, 400);
      }

      // Check uniqueness
      if (getAccountById(body.id)) {
        return json(res, { error: `Account '${body.id}' already exists` }, 409);
      }
      if (getAccountByEmail(body.email)) {
        return json(res, { error: `Account with email '${body.email}' already exists` }, 409);
      }

      const input: AccountInput = {
        id: body.id,
        email: body.email,
        imapHost: body.imapHost,
        imapPort: body.imapPort,
        imapUser: body.imapUser,
        imapPass: body.imapPass,
        smtpHost: body.smtpHost || '',
        smtpPort: body.smtpPort,
        smtpUser: body.smtpUser || '',
        smtpPass: body.smtpPass || '',
        smtpSecure: body.smtpSecure,
        localPassword: body.localPassword,
        inboundEnabled: body.inboundEnabled,
        outboundEnabled: body.outboundEnabled,
        mcpReceiveEnabled: body.mcpReceiveEnabled,
        mcpSendEnabled: body.mcpSendEnabled,
        mcpToken: body.mcpToken,
      };

      // Validate connectivity before saving
      const imapCreds = (input.imapHost && input.imapPass)
        ? { host: input.imapHost, port: input.imapPort || 993, user: input.imapUser, pass: input.imapPass }
        : undefined;
      const smtpCreds = (input.smtpHost && input.smtpPass)
        ? { host: input.smtpHost, port: input.smtpPort || 587, user: input.smtpUser, pass: input.smtpPass, secure: input.smtpSecure }
        : undefined;
      const test = await testCredentials({ imap: imapCreds, smtp: smtpCreds });
      if (imapCreds && !test.imap) {
        return json(res, { error: test.error || 'IMAP connection failed — check host, port, and credentials' }, 422);
      }
      if (smtpCreds && !test.smtp) {
        return json(res, { error: test.error || 'SMTP connection failed — check host, port, and credentials' }, 422);
      }

      const account = await addAccount(input);
      json(res, { id: account.id, email: account.email, smtp: test.smtp }, 201);
    },
  },
  {
    method: 'PUT',
    pattern: /^\/api\/accounts\/(?<id>[^/]+)$/,
    handler: async (req, res, params) => {
      const auth = req.carapamailAuth!;
      if (auth.type === 'user' && auth.accountId !== params.id) {
        return json(res, { error: 'You can only edit your own account' }, 403);
      }
      if (auth.type !== 'admin' && auth.type !== 'user') {
        return json(res, { error: 'Unauthorized' }, 401);
      }
      const body = await safeJsonParse(req, res);
      if (body === null) return;
      const updated = await updateAccount(params.id, body);
      if (!updated) return json(res, { error: 'Account not found' }, 404);
      json(res, { id: updated.id, email: updated.email });
    },
  },
  {
    method: 'DELETE',
    pattern: /^\/api\/accounts\/(?<id>[^/]+)$/,
    handler: async (req, res, params) => {
      const auth = req.carapamailAuth!;
      if (auth.type === 'user') {
        // Users can only delete their own account, with password confirmation
        if (auth.accountId !== params.id) {
          return json(res, { error: 'You can only delete your own account' }, 403);
        }
        const body = await safeJsonParse(req, res);
        if (body === null) return;
        if (!body.password) {
          return json(res, { error: 'Password required to delete account' }, 400);
        }
        const account = authenticateAccount(
          getAccountById(params.id)?.email || '',
          body.password,
        );
        if (!account) {
          return json(res, { error: 'Incorrect password' }, 403);
        }
      } else if (!requireAdmin(req, res)) {
        return;
      }
      const ok = await removeAccount(params.id);
      if (!ok) return json(res, { error: 'Account not found' }, 404);
      json(res, { deleted: true });
    },
  },
  {
    method: 'POST',
    pattern: /^\/api\/accounts\/(?<id>[^/]+)\/test$/,
    handler: async (req, res, params) => {
      const auth = req.carapamailAuth!;
      if (auth.type === 'user' && auth.accountId !== params.id) {
        return json(res, { error: 'You can only test your own account' }, 403);
      }
      if (auth.type !== 'admin' && auth.type !== 'user') {
        return json(res, { error: 'Unauthorized' }, 401);
      }
      const result = await testAccount(params.id);
      json(res, result);
    },
  },
  {
    method: 'POST',
    pattern: /^\/api\/accounts\/(?<id>[^/]+)\/test-mail$/,
    handler: async (req, res, params) => {
      const auth = req.carapamailAuth!;
      if (auth.type === 'user' && auth.accountId !== params.id) {
        return json(res, { error: 'You can only test your own account' }, 403);
      }
      if (auth.type !== 'admin' && auth.type !== 'user') {
        return json(res, { error: 'Unauthorized' }, 401);
      }
      const account = getAccountById(params.id);
      if (!account) return json(res, { error: 'Account not found' }, 404);

      const body = await safeJsonParse(req, res);
      if (body === null) return;
      if (!body.to) {
        return json(res, { error: 'Destination "to" email is required' }, 400);
      }

      try {
        const rawEml = Buffer.from(
          `From: ${account.email}\r\n` +
          `To: ${body.to}\r\n` +
          `Subject: CarapaMail Test Email\r\n` +
          `Date: ${new Date().toUTCString()}\r\n` +
          `\r\n` +
          `This is a test email sent from the CarapaMail dashboard.\r\n`
        );

        const parsed = await simpleParser(rawEml);
        const emailSummary = toEmailSummary(parsed, 'outbound');

        const startTime = Date.now();
        const decision = await inspectEmail(emailSummary, undefined, account.id);
        const latencyMs = Date.now() - startTime;

        await logAudit({
          direction: 'outbound',
          from_addr: account.email,
          to_addr: body.to,
          subject: 'CarapaMail Test Email',
          decision,
          latency_ms: latencyMs,
          accountId: account.id,
        });

        if (decision.unavailable) {
          return json(res, { error: 'LLM filter was unavailable / failed: ' + decision.reason }, 502);
        }

        if (decision.action === 'pass') {
          try {
            await relayRawMessage(rawEml, { from: account.email, to: [body.to] }, account);
          } catch (err) {
            return json(res, { decision: decision.action, error: String(err) }, 500);
          }
        } else if (decision.action === 'quarantine') {
          await quarantineMessage(parsed, rawEml, 'outbound', decision, account.id);
        }

        json(res, { decision: decision.action, reason: decision.reason });
      } catch (err: any) {
        console.error('[test-mail] Error:', err);
        console.error('[test-mail] Stack:', err.stack);
        return json(res, { error: 'Test mail failed: ' + (err.message || String(err)), stack: err.stack }, 500);
      }
    },
  },

  // Quarantine
  {
    method: 'GET',
    pattern: /^\/quarantine$/,
    handler: async (req, res) => {
      const url = new URL(req.url || '/', `http://${req.headers.host}`);
      const status = url.searchParams.get('status') || undefined;
      const requestedId = url.searchParams.get('account') || undefined;
      const accountId = getEffectiveAccountId(req, res, requestedId);
      if (accountId === null) return;
      json(res, await listQuarantine(status, accountId));
    },
  },
  {
    method: 'GET',
    pattern: /^\/quarantine\/(?<id>[^/]+)$/,
    handler: async (req, res, params) => {
      const entry = await getQuarantineEntry(params.id);
      if (!entry) return json(res, { error: 'Not found' }, 404);
      const accountId = getEffectiveAccountId(req, res, entry.account_id);
      if (accountId === null) return;
      // Don't send raw_eml in JSON response
      const { raw_eml, ...rest } = entry;
      json(res, rest);
    },
  },
  {
    method: 'POST',
    pattern: /^\/quarantine\/(?<id>[^/]+)\/release$/,
    handler: async (req, res, params) => {
      const entry = await getQuarantineEntry(params.id);
      if (!entry) return json(res, { error: 'Not found' }, 404);
      const accountId = getEffectiveAccountId(req, res, entry.account_id);
      if (accountId === null) return;

      const rawEml = await releaseFromQuarantine(params.id);
      if (!rawEml) return json(res, { error: 'Not found or already processed' }, 404);

      // Re-parse to get envelope info for relay
      const { simpleParser } = await import('mailparser');
      const parsed = await simpleParser(rawEml);
      const from = parsed.from?.value?.[0]?.address || '';
      const to = parsed.to
        ? (Array.isArray(parsed.to) ? parsed.to.flatMap(a => a.value.map(v => v.address || '')) : parsed.to.value.map(v => v.address || ''))
        : [];

      // Find account for this sender to relay through correct upstream
      const account = getAccountByEmail(from);

      // Auto-whitelist this sender when message is manually released
      if (from) {
        await autoWhitelistSender(from);
      }

      try {
        await relayRawMessage(rawEml, { from, to }, account);
        json(res, { released: true, relayed: true, whitelisted: !!from });
      } catch (err) {
        json(res, { released: true, relayed: false, error: String(err), whitelisted: !!from });
      }
    },
  },
  {
    method: 'DELETE',
    pattern: /^\/quarantine\/(?<id>[^/]+)$/,
    handler: async (req, res, params) => {
      const entry = await getQuarantineEntry(params.id);
      if (!entry) return json(res, { error: 'Not found' }, 404);
      const accountId = getEffectiveAccountId(req, res, entry.account_id);
      if (accountId === null) return;

      const ok = await deleteFromQuarantine(params.id);
      if (!ok) return json(res, { error: 'Not found' }, 404);
      json(res, { deleted: true });
    },
  },

  // Audit log
  {
    method: 'GET',
    pattern: /^\/audit$/,
    handler: async (req, res) => {
      const url = new URL(req.url || '/', `http://${req.headers.host}`);
      const limit = parseInt(url.searchParams.get('limit') || '100', 10);
      const offset = parseInt(url.searchParams.get('offset') || '0', 10);
      const requestedId = url.searchParams.get('account') || undefined;
      const accountId = getEffectiveAccountId(req, res, requestedId);
      if (accountId === null) return;
      json(res, await listAuditLog(limit, offset, accountId));
    },
  },

  // Rules
  {
    method: 'GET',
    pattern: /^\/rules$/,
    handler: async (req, res) => {
      if (!requireAdmin(req, res)) return;
      json(res, await listRules());
    },
  },
  {
    method: 'POST',
    pattern: /^\/rules$/,
    handler: async (req, res) => {
      if (!requireAdmin(req, res)) return;
      const body = await safeJsonParse(req, res);
      if (body === null) return;

      // Validate type
      const VALID_TYPES = ['allow', 'block', 'quarantine'];
      if (!body.type || !VALID_TYPES.includes(body.type)) {
        return json(res, { error: `Invalid type. Must be one of: ${VALID_TYPES.join(', ')}` }, 400);
      }

      // Validate match_field — whitelist prevents arbitrary property access on email objects
      const VALID_FIELDS = ['from', 'to', 'subject', 'body'];
      if (!body.match_field || !VALID_FIELDS.includes(body.match_field)) {
        return json(res, { error: `Invalid match_field. Must be one of: ${VALID_FIELDS.join(', ')}` }, 400);
      }

      // Validate match_pattern
      if (!body.match_pattern || typeof body.match_pattern !== 'string') {
        return json(res, { error: 'match_pattern is required and must be a string' }, 400);
      }
      if (body.match_pattern.length > 500) {
        return json(res, { error: 'match_pattern must be 500 characters or fewer' }, 400);
      }

      // Verify it compiles as a valid regex
      try {
        new RegExp(body.match_pattern, 'i');
      } catch {
        return json(res, { error: 'match_pattern is not a valid regular expression' }, 400);
      }

      const id = randomUUID();
      await insertRule({
        id,
        type: body.type,
        match_field: body.match_field,
        match_pattern: body.match_pattern,
        priority: typeof body.priority === 'number' ? body.priority : 0,
      });
      json(res, { id }, 201);
    },
  },
  {
    method: 'DELETE',
    pattern: /^\/rules\/(?<id>[^/]+)$/,
    handler: async (req, res, params) => {
      if (!requireAdmin(req, res)) return;
      await deleteRule(params.id);
      json(res, { deleted: true });
    },
  },

  // Whitelist
  {
    method: 'GET',
    pattern: /^\/whitelist$/,
    handler: async (req, res) => {
      const url = new URL(req.url || '/', `http://${req.headers.host}`);
      const requestedId = url.searchParams.get('account') || undefined;
      const accountId = getEffectiveAccountId(req, res, requestedId);
      if (accountId === null) return;
      json(res, await listWhitelist(accountId));
    },
  },
  {
    method: 'POST',
    pattern: /^\/whitelist$/,
    handler: async (req, res) => {
      const body = await safeJsonParse(req, res);
      if (body === null) return;

      const accountId = getEffectiveAccountId(req, res, body.account_id);
      if (accountId === null) return;

      if (!body.type || !['email', 'domain'].includes(body.type)) {
        return json(res, { error: 'Invalid type. Must be email or domain' }, 400);
      }

      if (!body.pattern || typeof body.pattern !== 'string') {
        return json(res, { error: 'Pattern is required' }, 400);
      }

      try {
        await addToWhitelist(accountId || 'default', body.type, body.pattern, 'manual');
        json(res, { success: true }, 201);
      } catch (err: any) {
        if (err.message && err.message.includes('UNIQUE constraint failed')) {
          return json(res, { error: 'Entry already exists in whitelist' }, 409);
        }
        return json(res, { error: 'Database error: ' + err.message }, 500);
      }
    },
  },
  {
    method: 'DELETE',
    pattern: /^\/whitelist$/,
    handler: async (req, res) => {
      const body = await safeJsonParse(req, res);
      if (body === null) return;

      const accountId = getEffectiveAccountId(req, res, body.account_id);
      if (accountId === null) return;

      if (!body.type || !body.pattern) {
        return json(res, { error: 'Type and pattern are required' }, 400);
      }

      await removeFromWhitelist(accountId || 'default', body.type, body.pattern);
      json(res, { deleted: true });
    },
  },
];

export function matchRoute(method: string, pathname: string): { handler: RouteHandler; params: Record<string, string> } | null {
  for (const route of routes) {
    if (route.method !== method) continue;
    const match = pathname.match(route.pattern);
    if (match) {
      return { handler: route.handler, params: match.groups || {} };
    }
  }
  return null;
}
