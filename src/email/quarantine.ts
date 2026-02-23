// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { randomUUID } from 'crypto';
import { insertQuarantine, getQuarantineEntry, updateQuarantineStatus } from '../db/index.js';
import type { ParsedMail } from './parser.js';
import type { FilterDecision } from '../types.js';

export async function quarantineMessage(
  parsed: ParsedMail,
  rawEml: Buffer,
  direction: 'inbound' | 'outbound',
  decision: FilterDecision,
  accountId?: string,
): Promise<string> {
  const id = randomUUID();
  const from = parsed.from?.text || '';
  const to = parsed.to ? (Array.isArray(parsed.to) ? parsed.to.map(a => a.text).join(', ') : parsed.to.text) : '';
  const bodyPreview = (parsed.text || parsed.html || '').slice(0, 500);

  await insertQuarantine({
    id,
    direction,
    from_addr: from,
    to_addr: to,
    subject: parsed.subject || '(no subject)',
    body_preview: bodyPreview,
    raw_eml: rawEml,
    reason: decision.reason,
    categories: decision.categories,
    confidence: decision.confidence,
    accountId,
  });

  return id;
}

export async function releaseFromQuarantine(id: string): Promise<Buffer | null> {
  const entry = await getQuarantineEntry(id);
  if (!entry || entry.status !== 'pending') return null;
  await updateQuarantineStatus(id, 'released');
  return Buffer.from(entry.raw_eml);
}

export async function deleteFromQuarantine(id: string): Promise<boolean> {
  const entry = await getQuarantineEntry(id);
  if (!entry) return false;
  await updateQuarantineStatus(id, 'deleted');
  return true;
}
