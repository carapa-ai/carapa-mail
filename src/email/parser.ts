// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { simpleParser, type ParsedMail } from 'mailparser';
import type { EmailSummary } from '../types.js';

export { type ParsedMail };

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
