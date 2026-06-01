// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import type { IncomingMessage, ServerResponse } from 'http';
import { createHash } from 'crypto';
import { simpleParser } from 'mailparser';
import { MCP_PUBLIC_URL, PUBLIC_HOSTNAME, MCP_PORT } from '../config.js';
import { getAttachmentToken, deleteExpiredAttachmentTokens } from '../db/index.js';
import { getRawMessage } from './imap-client.js';

/** Header an ingress (api-relay, carapa-board) can set to declare the base URL it
 *  is reachable at, so attachment links point back through the SAME path the caller
 *  used. Value is a prefix; `/attachments/<token>` is appended to it. */
export const PUBLIC_BASE_HEADER = 'x-carapamail-public-base';

function stripTrailing(u: string): string {
  return u.replace(/\/+$/, '');
}

/**
 * Resolve the base URL to advertise in attachment download links for THIS request.
 * carapa-mail cannot infer which consumer is calling (the relay rewrites Host to the
 * upstream), so the ingress declares its base via PUBLIC_BASE_HEADER. Fallbacks cover
 * direct/external callers that don't set it.
 */
export function resolveAttachmentBase(req: IncomingMessage): string {
  const declared = req.headers[PUBLIC_BASE_HEADER];
  if (typeof declared === 'string' && declared.trim()) return stripTrailing(declared.trim());
  // External consumers reaching a public MCP ingress: derive from the advertised MCP URL.
  if (MCP_PUBLIC_URL) return stripTrailing(MCP_PUBLIC_URL).replace(/\/mcp$/, '');
  if (PUBLIC_HOSTNAME) return `https://${PUBLIC_HOSTNAME}`;
  // Last resort: how the caller addressed us (works only when reached directly).
  if (req.headers.host) return `http://${req.headers.host}`;
  return `http://127.0.0.1:${MCP_PORT}`;
}

function sendError(res: ServerResponse, status: number, message: string): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: message }));
}

/**
 * Redeem an attachment download token and stream the bytes. Shared by the MCP server
 * (primary ingress for agents) and the HTTP admin server. The URL token is the only
 * credential — no Authorization header required.
 */
export async function streamAttachment(res: ServerResponse, token: string): Promise<void> {
  deleteExpiredAttachmentTokens().catch(() => { });
  const tokenHash = createHash('sha256').update(token).digest('hex');
  const row = await getAttachmentToken(tokenHash);
  if (!row) return sendError(res, 404, 'Not found');
  if (new Date(row.expires_at).getTime() < Date.now()) return sendError(res, 410, 'Link expired');

  const raw = await getRawMessage(row.folder, row.uid, row.account_id);
  if (!raw) return sendError(res, 404, 'Message no longer available');

  const parsed = await simpleParser(raw);
  const att = (parsed.attachments || [])[row.attachment_index];
  if (!att || !att.content) return sendError(res, 404, 'Attachment no longer available');

  const filename = (att.filename || row.filename || 'attachment').replace(/["\r\n]/g, '');
  res.writeHead(200, {
    'Content-Type': att.contentType || 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${filename}"`,
    'Content-Length': att.content.length,
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(att.content);
}
