// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { getAllAccounts, type Account } from '../accounts.js';

// Per-account transporter pool
const transporters = new Map<string, nodemailer.Transporter>();

function getTransporter(account: Account): nodemailer.Transporter {
  let t = transporters.get(account.id);
  if (!t) {
    t = nodemailer.createTransport({
      host: account.smtp.host,
      port: account.smtp.port,
      secure: account.smtp.secure === 'tls',
      ...(account.smtp.secure === 'starttls' ? { requireTLS: true } : {}),
      auth: account.smtp.user
        ? { user: account.smtp.user, pass: account.smtp.pass }
        : undefined,
      tls: {
        rejectUnauthorized: false,
        checkServerIdentity: () => undefined,
      },
    });
    transporters.set(account.id, t);
  }
  return t;
}

export function clearTransporter(accountId: string): void {
  transporters.delete(accountId);
}

/**
 * Ensure RFC 5322 required headers (Date, Message-ID) exist in the raw message.
 * Prepends missing headers so strict upstream servers don't bounce.
 */
function ensureRequiredHeaders(rawEml: Buffer, from: string): Buffer {
  const headerEnd = rawEml.indexOf('\r\n\r\n');
  const headSection = (headerEnd >= 0 ? rawEml.subarray(0, headerEnd) : rawEml).toString('utf-8');
  const headersLower = headSection.toLowerCase();

  const missing: string[] = [];

  if (!headersLower.includes('\ndate:') && !headersLower.startsWith('date:')) {
    missing.push(`Date: ${new Date().toUTCString()}`);
  }

  if (!headersLower.includes('\nmessage-id:') && !headersLower.startsWith('message-id:')) {
    const domain = from.split('@')[1] || 'localhost';
    const id = `<${Date.now()}.${crypto.randomUUID()}@${domain}>`;
    missing.push(`Message-ID: ${id}`);
  }

  if (missing.length === 0) return rawEml;

  const prefix = Buffer.from(missing.join('\r\n') + '\r\n');
  return Buffer.concat([prefix, rawEml]);
}

/**
 * Relay a raw email through the correct account's upstream SMTP.
 * If no account is provided, uses the first configured account.
 */
export async function relayRawMessage(
  rawEml: Buffer,
  envelope: { from: string; to: string[] },
  account?: Account,
): Promise<void> {
  const acc = account || getAllAccounts()[0];
  if (!acc) throw new Error('No accounts configured');
  if (!acc.smtp.host) throw new Error(`No SMTP host configured for account '${acc.id}'`);

  const patched = ensureRequiredHeaders(rawEml, envelope.from);

  await getTransporter(acc).sendMail({
    envelope: {
      from: envelope.from,
      to: envelope.to,
    },
    raw: patched,
  });
}
