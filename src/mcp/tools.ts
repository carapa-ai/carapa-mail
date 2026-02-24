// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import crypto from 'crypto';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getStats, getScan, recordScan, logAudit, getMatchingRules } from '../db/index.js';
import { inspectEmail } from '../agent/filter.js';
import { scanAttachments } from '../email/attachment-scanner.js';
import { relayRawMessage } from '../smtp/relay.js';
import { getAllAccounts } from '../accounts.js';
import { AUTO_QUARANTINE, FILTER_CONFIDENCE_THRESHOLD } from '../config.js';
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
} from './imap-client.js';

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

export function registerTools(s: McpServer, allowedAccountIds: string[]) {
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
    'List emails in a folder (newest first). Returns paginated results with items (uid, from, to, subject, date, seen), total, page, totalPages, hasMore.',
    {
      folder: z.string().optional().describe('IMAP folder path (default: INBOX)'),
      limit: z.number().optional().describe('Max emails to return (default: 20, max: 50)'),
      page: z.number().optional().describe('Page number for pagination (default: 1)'),
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
      uid: z.number().describe('Email UID number'),
      folder: z.string().optional().describe('IMAP folder path (default: INBOX)'),
      account: z.string().optional().describe('Account ID or email (default: first account)'),
    },
    async (args: { uid: number; folder?: string; account?: string }) => {
      try {
        const { account: acc, err } = requireAccount(args.account, 'receive');
        if (err) return err;
        const accountId = acc.id;
        const folder = args.folder || 'INBOX';
        const result = await getMessage(folder, args.uid, accountId);
        if (!result) return error('Email not found');

        const { message, uidValidity, rawSource } = result;

        // Check if already scanned (agent context)
        const existing = await getScan(folder, args.uid, uidValidity, 'inbound-agent', accountId);
        if (existing) {
          if (existing.action !== 'pass') {
            return error(`Email blocked by security filter: ${existing.reason}`);
          }
          // Sanitize before returning cached-pass results
          message.body_text = sanitizeMessageBody(message.body_text);
          return text(message);
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
        });

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
            return error('Email content withheld: AI security filter is temporarily unavailable. Try again later.');
          }
          if (decision.action === 'reject' && decision.confidence < FILTER_CONFIDENCE_THRESHOLD) {
            decision.action = 'quarantine';
            decision.reason += ' (low confidence, quarantined for review)';
          }
        }

        const latencyMs = Date.now() - startTime;
        await recordScan(folder, args.uid, uidValidity, decision.action, decision.reason, 'inbound-agent', accountId);
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
          return error(`Email blocked by security filter: ${decision.reason}`);
        }

        // Sanitize body AFTER AI inspection (so AI sees raw injection patterns)
        message.body_text = sanitizeMessageBody(message.body_text);
        return text(message);
      } catch (e: any) {
        return error(`Failed to read email: ${e.message}`);
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
      limit: z.number().optional().describe('Max results per page (default: 20, max: 50)'),
      page: z.number().optional().describe('Page number for pagination (default: 1)'),
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
        });

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
      uids: z.array(z.number()).describe('Array of email UIDs to delete'),
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
      uids: z.array(z.number()).describe('Array of email UIDs to move'),
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
