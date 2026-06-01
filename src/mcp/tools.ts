// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import crypto from 'crypto';
import { z } from 'zod';
import { simpleParser } from 'mailparser';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getStats, getScan, recordScan, logAudit, getMatchingRules, createAttachmentToken } from '../db/index.js';
import { inspectEmail } from '../agent/filter.js';
import { scanAttachments } from '../email/attachment-scanner.js';
import { relayRawMessage } from '../smtp/relay.js';
import { getAllAccounts } from '../accounts.js';
import { AUTO_QUARANTINE, FILTER_CONFIDENCE_THRESHOLD, ATTACHMENT_LINK_TTL_MS } from '../config.js';
import type { EmailSummary as FilterEmailSummary } from '../types.js';
import {
  listFolders,
  listMessages,
  getMessage,
  searchMessages,
  deleteMessages,
  moveMessages,
  resolveAccount,
  sanitizeMessageBody,
  type McpMode,
  type EmailDetail,
} from './imap-client.js';

/**
 * A list of email UIDs that tolerates clients (esp. local LLMs) sending the array
 * as a JSON-encoded string or a comma-separated string instead of a real array.
 * The published JSON Schema is still `array<number>`; this only loosens input parsing.
 */
const uidList = z.preprocess((v) => {
  if (typeof v === 'string') {
    const t = v.trim();
    if (t.startsWith('[')) {
      try {
        const parsed = JSON.parse(t);
        if (Array.isArray(parsed)) return parsed;
      } catch { /* fall through */ }
    }
    if (t === '') return [];
    return t.includes(',') ? t.split(',').map((x) => x.trim()).filter(Boolean) : [t];
  }
  return v;
}, z.array(z.coerce.number()));

function text(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

function error(msg: string) {
  return { content: [{ type: 'text' as const, text: msg }], isError: true };
}

function makeRequireAccount(allowedAccountIds: string[]) {
  return function requireAccount(accountParam: string | undefined, mode: McpMode) {
    const acc = resolveAccount(accountParam, mode);
    if (!acc) {
      const label = mode === 'send' ? 'MCP send' : mode === 'delete' ? 'MCP delete' : 'MCP receive';
      const msg = accountParam
        ? `${label} access disabled for account '${accountParam}'. Enable it in the setup UI.`
        : `No accounts with ${label} enabled.`;
      return { account: undefined as never, err: error(msg) };
    }
    if (!allowedAccountIds.includes(acc.id)) {
      return { account: undefined as never, err: error(`Account '${acc.id}' is not accessible with this token.`) };
    }
    return { account: acc, err: undefined };
  };
}

type GateResult =
  | { ok: true; message: EmailDetail; rawSource: Buffer; uidValidity: number }
  | { ok: false; error: ReturnType<typeof error> };

/**
 * Run the full inbound security gate for an agent-facing email read.
 * Mirrors the pipeline that protects `carapamail_read_email`: scan cache → attachment
 * scan → AI/rule decision (recorded + audited) → block on non-pass. Returns the raw,
 * unsanitized message + RFC822 source on pass; the caller is responsible for sanitizing
 * the body before returning it to an agent.
 */
async function gateInboundMessage(folder: string, uid: number, accountId: string): Promise<GateResult> {
  const result = await getMessage(folder, uid, accountId);
  if (!result) return { ok: false, error: error('Email not found') };
  const { message, uidValidity, rawSource } = result;

  // Reuse a prior agent-context scan decision when available.
  const existing = await getScan(folder, uid, uidValidity, 'inbound-agent', accountId);
  if (existing) {
    if (existing.action !== 'pass') {
      return { ok: false, error: error(`Email blocked by security filter: ${existing.reason}`) };
    }
    return { ok: true, message, rawSource, uidValidity };
  }

  // Attachment scanning (MIME-level, independent of AI filter)
  const attachmentScan = await scanAttachments(rawSource);
  let attachmentWarning = '';
  if (!attachmentScan.safe) {
    attachmentWarning = `\n\n[ATTACHMENT THREATS DETECTED: ${attachmentScan.threats.join(', ')}]`;
  }

  // Build email summary for AI filter — uses raw (unsanitized) body so AI sees injection patterns
  const emailSummary: FilterEmailSummary = {
    direction: 'inbound',
    from: message.from,
    to: message.to,
    subject: message.subject,
    body: message.body_text.slice(0, 2000) + attachmentWarning,
    attachments: message.attachments.map(a => ({
      filename: a.name,
      contentType: a.type,
      size: a.size,
    })),
    headers: message.rawHeaders,
  };

  const rule = await getMatchingRules({
    from: message.from,
    to: message.to,
    subject: message.subject,
    body: message.body_text,
  }, 'inbound');

  const startTime = Date.now();
  let decision;
  const isInbox = /^inbox$/i.test(folder);

  if (rule) {
    decision = {
      action: rule.type === 'allow' ? 'pass' as const : rule.type === 'block' ? 'reject' as const : rule.type as 'quarantine',
      reason: `Matched rule: ${rule.match_field} ~ ${rule.match_pattern}`,
      confidence: 1,
      categories: [] as string[],
    };
  } else if (!AUTO_QUARANTINE && !isInbox) {
    // Log-only mode — but INBOX always gets AI-filtered for MCP agents
    decision = { action: 'pass' as const, reason: 'Log-only mode', confidence: 1, categories: [] as string[] };
  } else {
    decision = await inspectEmail(emailSummary, 'inbound-agent', accountId);
    if (decision.unavailable) {
      return { ok: false, error: error('Email content withheld: AI security filter is temporarily unavailable. Try again later.') };
    }
    if (decision.action === 'reject' && decision.confidence < FILTER_CONFIDENCE_THRESHOLD) {
      decision.action = 'quarantine';
      decision.reason += ' (low confidence, quarantined for review)';
    }
  }

  const latencyMs = Date.now() - startTime;
  await recordScan(folder, uid, uidValidity, decision.action, decision.reason, 'inbound-agent', accountId);
  await logAudit({
    direction: 'inbound',
    from_addr: message.from,
    to_addr: message.to,
    subject: message.subject,
    decision,
    latency_ms: latencyMs,
    accountId,
  });

  if (decision.action !== 'pass') {
    return { ok: false, error: error(`Email blocked by security filter: ${decision.reason}`) };
  }

  return { ok: true, message, rawSource, uidValidity };
}

/**
 * @param attachmentBase Base URL (no trailing slash) for attachment download links,
 *   resolved per-request from the calling ingress so links point back through the same
 *   path the caller used. `/attachments/<token>` is appended to it.
 */
export function registerTools(s: McpServer, allowedAccountIds: string[], attachmentBase: string) {
  const requireAccount = makeRequireAccount(allowedAccountIds);
  const tool = s.tool.bind(s) as (
    name: string,
    description: string,
    schema: Record<string, z.ZodType>,
    cb: (args: any) => Promise<any>,
  ) => any;

  tool(
    'carapamail_list_accounts',
    'List configured email accounts (IDs and emails, no passwords).',
    {},
    async () => {
      try {
        const accounts = getAllAccounts()
          .filter(a => allowedAccountIds.includes(a.id) && (a.mcpReceiveEnabled || a.mcpSendEnabled || a.mcpDeleteEnabled))
          .map(a => ({
            id: a.id,
            email: a.email,
            imap_host: a.imap.host,
            smtp_host: a.smtp.host,
            mcp_receive: a.mcpReceiveEnabled,
            mcp_send: a.mcpSendEnabled,
            mcp_delete: a.mcpDeleteEnabled,
          }));
        return text(accounts);
      } catch (e: any) {
        return error(`Failed to list accounts: ${e.message}`);
      }
    },
  );

  tool(
    'carapamail_list_folders',
    'List available IMAP folders with message counts.',
    {
      account: z.string().optional().describe('Account ID or email (default: first account)'),
    },
    async (args: { account?: string }) => {
      try {
        const { account: acc, err } = requireAccount(args.account, 'receive');
        if (err) return err;
        return text(await listFolders(acc.id));
      } catch (e: any) {
        return error(`Failed to list folders: ${e.message}`);
      }
    },
  );

  tool(
    'carapamail_list_emails',
    'List emails in a folder (newest first). Returns paginated results with items (uid, from, to, subject, date, seen, attachment_count), total, page, totalPages, hasMore.',
    {
      folder: z.string().optional().describe('IMAP folder path (default: INBOX)'),
      limit: z.coerce.number().optional().describe('Max emails to return (default: 20, max: 50)'),
      page: z.coerce.number().optional().describe('Page number for pagination (default: 1)'),
      account: z.string().optional().describe('Account ID or email (default: first account)'),
    },
    async (args: { folder?: string; limit?: number; page?: number; account?: string }) => {
      try {
        const { account: acc, err } = requireAccount(args.account, 'receive');
        if (err) return err;
        const folder = args.folder || 'INBOX';
        const limit = Math.min(args.limit || 20, 50);
        const page = args.page || 1;
        return text(await listMessages(folder, limit, page, acc.id));
      } catch (e: any) {
        return error(`Failed to list emails: ${e.message}`);
      }
    },
  );

  tool(
    'carapamail_read_email',
    'Read a specific email by UID. Returns full headers, text body, and attachment metadata.',
    {
      uid: z.coerce.number().describe('Email UID number'),
      folder: z.string().optional().describe('IMAP folder path (default: INBOX)'),
      account: z.string().optional().describe('Account ID or email (default: first account)'),
    },
    async (args: { uid: number; folder?: string; account?: string }) => {
      try {
        const { account: acc, err } = requireAccount(args.account, 'receive');
        if (err) return err;
        const folder = args.folder || 'INBOX';

        const gate = await gateInboundMessage(folder, args.uid, acc.id);
        if (!gate.ok) return gate.error;

        // Sanitize body AFTER AI inspection (so AI sees raw injection patterns)
        gate.message.body_text = sanitizeMessageBody(gate.message.body_text);
        return text(gate.message);
      } catch (e: any) {
        return error(`Failed to read email: ${e.message}`);
      }
    },
  );

  tool(
    'carapamail_download_attachment',
    'Get a short-lived download link for an attachment of an email. Runs the same security gate as carapamail_read_email (blocked/quarantined emails and dangerous attachments are refused). Returns { url, filename, content_type, size, expires_at }; fetch the URL to retrieve the bytes before it expires.',
    {
      uid: z.coerce.number().describe('Email UID number'),
      filename: z.string().describe('Attachment filename (as shown in carapamail_read_email)'),
      index: z.coerce.number().optional().describe('1-based index to disambiguate multiple attachments with the same filename'),
      folder: z.string().optional().describe('IMAP folder path (default: INBOX)'),
      account: z.string().optional().describe('Account ID or email (default: first account)'),
    },
    async (args: { uid: number; filename: string; index?: number; folder?: string; account?: string }) => {
      try {
        const { account: acc, err } = requireAccount(args.account, 'receive');
        if (err) return err;
        const folder = args.folder || 'INBOX';

        const gate = await gateInboundMessage(folder, args.uid, acc.id);
        if (!gate.ok) return gate.error;

        // Re-check attachment safety explicitly (covers the cached-AI-pass path too).
        const attachmentScan = await scanAttachments(gate.rawSource);
        if (!attachmentScan.safe) {
          return error(`Attachment download blocked: ${attachmentScan.threats.join(', ')}`);
        }

        // Resolve the requested attachment from the decoded MIME tree.
        const parsed = await simpleParser(gate.rawSource);
        const atts = parsed.attachments || [];
        const wanted = args.filename.trim();
        const matches = atts.map((a, i) => ({ a, i })).filter(({ a }) => (a.filename || '').trim() === wanted);
        if (matches.length === 0) {
          const names = atts.map(a => a.filename || '(unnamed)');
          return error(`Attachment '${wanted}' not found. Available: ${names.length ? names.join(', ') : '(none)'}`);
        }
        let chosen = matches[0];
        if (matches.length > 1) {
          if (!args.index) return error(`Multiple attachments named '${wanted}' (${matches.length}). Specify 'index' (1-${matches.length}).`);
          if (args.index < 1 || args.index > matches.length) return error(`index out of range (1-${matches.length}).`);
          chosen = matches[args.index - 1];
        }
        const att = chosen.a;

        const token = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expiresAt = new Date(Date.now() + ATTACHMENT_LINK_TTL_MS).toISOString();
        await createAttachmentToken(tokenHash, {
          accountId: acc.id,
          folder,
          uid: args.uid,
          filename: att.filename || wanted,
          attachmentIndex: chosen.i,
          expiresAt,
        });

        return text({
          url: `${attachmentBase}/attachments/${token}`,
          filename: att.filename || wanted,
          content_type: att.contentType || 'application/octet-stream',
          size: att.size ?? 0,
          expires_at: expiresAt,
        });
      } catch (e: any) {
        return error(`Failed to prepare attachment download: ${e.message}`);
      }
    },
  );

  tool(
    'carapamail_search',
    'Search emails in a folder. Returns paginated results with items (uid, from, to, subject, date, seen), total, page, totalPages, hasMore.',
    {
      query: z.string().describe('Search query string'),
      field: z.enum(['from', 'to', 'subject', 'body', 'all']).optional().describe('Field to search (default: all)'),
      folder: z.string().optional().describe('IMAP folder path (default: INBOX)'),
      since: z.string().optional().describe('Only return emails after this ISO date'),
      before: z.string().optional().describe('Only return emails before this ISO date'),
      limit: z.coerce.number().optional().describe('Max results per page (default: 20, max: 50)'),
      page: z.coerce.number().optional().describe('Page number for pagination (default: 1)'),
      account: z.string().optional().describe('Account ID or email (default: first account)'),
    },
    async (args: { query: string; field?: string; folder?: string; since?: string; before?: string; limit?: number; page?: number; account?: string }) => {
      try {
        const { account: acc, err } = requireAccount(args.account, 'receive');
        if (err) return err;
        const field = (args.field || 'all') as 'from' | 'to' | 'subject' | 'body' | 'all';
        const results = await searchMessages(
          args.folder || 'INBOX',
          args.query,
          field,
          args.since,
          args.before,
          Math.min(args.limit || 20, 50),
          args.page || 1,
          acc.id,
        );
        return text(results);
      } catch (e: any) {
        return error(`Search failed: ${e.message}`);
      }
    },
  );

  tool(
    'carapamail_send',
    'Compose and send an email. The email goes through the outbound AI filter before delivery.',
    {
      to: z.string().describe('Recipient email address'),
      subject: z.string().describe('Email subject line'),
      body: z.string().describe('Plain text email body'),
      html: z.string().optional().describe('Optional HTML email body'),
      account: z.string().optional().describe('Account ID or email to send from (default: first account)'),
    },
    async (args: { to: string; subject: string; body: string; html?: string; account?: string }) => {
      try {
        const { account: acc, err } = requireAccount(args.account, 'send');
        if (err) return err;
        const from = acc.smtp.user || acc.email;
        if (!acc.smtp.host) return error(`No SMTP host configured for account '${acc.id}'`);

        // Prevent email header injection via CRLF in to/subject fields
        if (/[\r\n]/.test(args.to) || /[\r\n]/.test(args.subject)) {
          return error('Invalid input: to and subject must not contain newline characters');
        }
        // Basic email address format validation
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(args.to)) {
          return error('Invalid recipient email address format');
        }

        const domain = from.split('@')[1] || 'localhost';
        const messageId = `<${Date.now()}.${crypto.randomUUID()}@${domain}>`;
        const boundary = `----=_Part_${Date.now().toString(36)}`;

        let rawParts = [
          `From: ${from}`,
          `To: ${args.to}`,
          `Subject: ${args.subject}`,
          `Date: ${new Date().toUTCString()}`,
          `Message-ID: ${messageId}`,
          `MIME-Version: 1.0`,
        ];

        if (args.html) {
          rawParts.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
          rawParts.push('');
          rawParts.push(`--${boundary}`);
          rawParts.push('Content-Type: text/plain; charset=utf-8');
          rawParts.push('Content-Transfer-Encoding: quoted-printable');
          rawParts.push('');
          rawParts.push(args.body);
          rawParts.push(`--${boundary}`);
          rawParts.push('Content-Type: text/html; charset=utf-8');
          rawParts.push('Content-Transfer-Encoding: quoted-printable');
          rawParts.push('');
          rawParts.push(args.html);
          rawParts.push(`--${boundary}--`);
        } else {
          rawParts.push('Content-Type: text/plain; charset=utf-8');
          rawParts.push('Content-Transfer-Encoding: quoted-printable');
          rawParts.push('');
          rawParts.push(args.body);
        }

        const rawEml = Buffer.from(rawParts.join('\r\n'));

        // Outbound AI filter (same as SMTP handler)
        const emailSummary: FilterEmailSummary = {
          direction: 'outbound',
          from,
          to: args.to,
          subject: args.subject,
          body: args.body.slice(0, 2000),
          attachments: [],
          headers: {},
        };

        const rule = await getMatchingRules({
          from,
          to: args.to,
          subject: args.subject,
          body: args.body,
        }, 'outbound');

        let decision;
        const startTime = Date.now();

        if (rule) {
          decision = {
            action: rule.type === 'allow' ? 'pass' as const : rule.type === 'block' ? 'reject' as const : rule.type as 'quarantine',
            reason: `Matched rule: ${rule.match_field} ~ ${rule.match_pattern}`,
            confidence: 1,
            categories: [] as string[],
          };
        } else if (!AUTO_QUARANTINE) {
          decision = { action: 'pass' as const, reason: 'Log-only mode', confidence: 1, categories: [] as string[] };
        } else {
          decision = await inspectEmail(emailSummary, undefined, acc.id);
          if (decision.unavailable) {
            return error('Outbound filter is temporarily unavailable. Try again later.');
          }
          if (decision.action === 'reject' && decision.confidence < FILTER_CONFIDENCE_THRESHOLD) {
            decision.action = 'quarantine';
            decision.reason += ' (low confidence, quarantined for review)';
          }
        }

        const latencyMs = Date.now() - startTime;
        await logAudit({
          direction: 'outbound',
          from_addr: from,
          to_addr: args.to,
          subject: args.subject,
          decision,
          latency_ms: latencyMs,
          accountId: acc.id,
        });

        if (decision.action !== 'pass') {
          return error(`Email blocked by outbound filter: ${decision.reason}`);
        }

        await relayRawMessage(rawEml, { from, to: [args.to] }, acc);

        return text({ sent: true, message_id: messageId, to: args.to, from });
      } catch (e: any) {
        return error(`Failed to send: ${e.message}`);
      }
    },
  );

  tool(
    'carapamail_delete',
    'Delete emails by UID. Supports bulk deletion with multiple UIDs.',
    {
      uids: uidList.describe('Array of email UIDs to delete'),
      folder: z.string().optional().describe('IMAP folder path (default: INBOX)'),
      account: z.string().optional().describe('Account ID or email (default: first account)'),
    },
    async (args: { uids: number[]; folder?: string; account?: string }) => {
      try {
        if (args.uids.length === 0) return error('No UIDs provided');
        const { account: acc, err } = requireAccount(args.account, 'delete');
        if (err) return err;
        const count = await deleteMessages(args.folder || 'INBOX', args.uids, acc.id);
        return text({ deleted: count, folder: args.folder || 'INBOX' });
      } catch (e: any) {
        return error(`Failed to delete: ${e.message}`);
      }
    },
  );

  tool(
    'carapamail_move',
    'Move emails to another folder by UID. Supports bulk moves with multiple UIDs.',
    {
      uids: uidList.describe('Array of email UIDs to move'),
      destination: z.string().describe('Destination IMAP folder path'),
      folder: z.string().optional().describe('Source IMAP folder path (default: INBOX)'),
      account: z.string().optional().describe('Account ID or email (default: first account)'),
    },
    async (args: { uids: number[]; destination: string; folder?: string; account?: string }) => {
      try {
        if (args.uids.length === 0) return error('No UIDs provided');
        const { account: acc, err } = requireAccount(args.account, 'receive');
        if (err) return err;
        const count = await moveMessages(args.folder || 'INBOX', args.uids, args.destination, acc.id);
        return text({ moved: count, from: args.folder || 'INBOX', to: args.destination });
      } catch (e: any) {
        return error(`Failed to move: ${e.message}`);
      }
    },
  );

  tool(
    'carapamail_stats',
    'Get email filtering statistics: total processed, passed, rejected, and quarantined counts.',
    {
      account: z.string().optional().describe('Account ID to filter stats (default: all accounts)'),
    },
    async (args: { account?: string }) => {
      try {
        return text(await getStats(args.account));
      } catch (e: any) {
        return error(`Failed to get stats: ${e.message}`);
      }
    },
  );
}
