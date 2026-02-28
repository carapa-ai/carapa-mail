// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { simpleParser, type ParsedMail } from 'mailparser';
import type { EmailSummary } from '../types.js';

export { type ParsedMail };

export const SECURITY_HEADERS = [
  'authentication-results',
  'received-spf',
  'reply-to',
  'return-path',
  'dkim-signature',
  'x-php-originating-script',
  'x-mailer',
  'x-sender-ip',
  'received',
];

/**
 * Parse RFC822 headers from raw email text or buffer.
 * Handles line unfolding and multi-value headers.
 */
export function parseHeaders(raw: string | Buffer): Record<string, string> {
  const text = typeof raw === 'string' ? raw : raw.toString('utf-8');
  const headers: Record<string, string> = {};

  const headerEnd = text.indexOf('\r\n\r\n');
  const headerBlock = headerEnd > 0 ? text.slice(0, headerEnd) : text.slice(0, 8192);

  // Unfold continuation lines (RFC 2822: CRLF followed by WSP)
  const unfolded = headerBlock.replace(/\r\n[ \t]+/g, ' ');

  for (const line of unfolded.split('\r\n')) {
    const colon = line.indexOf(':');
    if (colon > 0) {
      const name = line.slice(0, colon).trim().toLowerCase();
      const value = line.slice(colon + 1).trim();
      if (name) {
        // Append multi-value headers (e.g. Received, Authentication-Results)
        headers[name] = headers[name] ? `${headers[name]}\n${value}` : value;
      }
    }
  }
  return headers;
}

export async function parseFromStream(stream: NodeJS.ReadableStream): Promise<{ parsed: ParsedMail; rawBuffer: Buffer }> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const rawBuffer = Buffer.concat(chunks);
  const parsed = await simpleParser(rawBuffer);
  return { parsed, rawBuffer };
}

export function toEmailSummary(parsed: ParsedMail, direction: 'inbound' | 'outbound'): EmailSummary {
  const from = parsed.from?.text || '';
  const to = parsed.to ? (Array.isArray(parsed.to) ? parsed.to.map(a => a.text).join(', ') : parsed.to.text) : '';

  const headers: Record<string, string> = {};
  if (parsed.headers) {
    for (const [key, value] of parsed.headers) {
      if (typeof value === 'string') {
        headers[key] = value;
      } else if (value && typeof value === 'object' && 'text' in value) {
        headers[key] = (value as { text: string }).text;
      }
    }
  }

  // Detect encryption/signing at the top level
  const contentType = (headers['content-type'] || '').toLowerCase();
  const isEncrypted =
    contentType.includes('application/pkcs7-mime') ||
    contentType.includes('multipart/encrypted') ||
    contentType.includes('application/pgp-encrypted') ||
    (parsed.text && (parsed.text.includes('-----BEGIN PGP MESSAGE-----') || parsed.text.includes('-----BEGIN PGP SIGNED MESSAGE-----')));

  const isSigned =
    contentType.includes('multipart/signed') ||
    contentType.includes('application/pkcs7-signature') ||
    contentType.includes('application/pgp-signature') ||
    (parsed.text && (parsed.text.includes('-----BEGIN PGP SIGNED MESSAGE-----') || parsed.text.includes('-----BEGIN PGP SIGNATURE-----')));

  const attachments = (parsed.attachments || []).map(att => ({
    filename: att.filename || 'unnamed',
    contentType: att.contentType || 'application/octet-stream',
    size: att.size || 0,
    isEncrypted: att.contentType.includes('pkcs7') || att.filename?.endsWith('.pgp') || att.filename?.endsWith('.gpg') || att.filename?.endsWith('.p7m') || att.filename?.endsWith('.p7s'),
  }));

  return {
    direction,
    from,
    to,
    subject: parsed.subject || '(no subject)',
    body: parsed.text || parsed.html || '',
    attachments,
    headers,
    isEncrypted: !!isEncrypted,
    isSigned: !!isSigned,
  };
}
