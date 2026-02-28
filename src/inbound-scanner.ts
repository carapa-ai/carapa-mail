// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { ImapFlow, CopyResponseObject } from 'imapflow';
import {
  AUTO_QUARANTINE,
  FILTER_CONFIDENCE_THRESHOLD,
  INBOUND_SCAN_INTERVAL,
  INCOMING_FOLDER,
} from './config.js';
import { getScannerState, setScannerState, logAudit, getMatchingRules, insertQuarantine, recordScan, getScan, pruneScans, isWhitelisted } from './db/index.js';
import { inspectEmail } from './agent/filter.js';
import { getAllAccounts, type Account } from './accounts.js';
import { parseHeaders, SECURITY_HEADERS } from './email/parser.js';
import type { FilterDecision, EmailSummary } from './types.js';
import { randomUUID } from 'crypto';
import { logger } from './logger.js';

const FOLDER = 'INBOX';
const SPAM_FOLDER = 'Junk';

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

function findAttachments(structure: any): { filename: string; contentType: string; size: number }[] {
  const result: { filename: string; contentType: string; size: number }[] = [];
  if (!structure) return result;
  if (structure.disposition === 'attachment' || structure.dispositionParameters?.filename) {
    result.push({
      filename: structure.dispositionParameters?.filename || structure.parameters?.name || 'unknown',
      contentType: structure.type || 'application/octet-stream',
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

/**
 * Per-account scanner loop state
 */
interface ScannerLoop {
  account: Account;
  client: ImapFlow | null;
  pollTimer: ReturnType<typeof setTimeout> | null;
  stopped: boolean;
  knownFolders: Set<string>;
}

function createClient(account: Account): ImapFlow {
  const client = new ImapFlow({
    host: account.imap.host,
    port: account.imap.port,
    secure: true,
    auth: { user: account.imap.user, pass: account.imap.pass },
    logger: false,
  });
  client.on('error', (err: Error) => {
    logger.error('scanner', `[${account.id}] IMAP error: ${err.message}`);
  });
  return client;
}

async function ensureFolder(c: ImapFlow, folder: string, knownFolders: Set<string>): Promise<void> {
  if (knownFolders.has(folder)) return;
  try {
    await c.mailboxCreate(folder);
  } catch (e: any) {
    if (!e.message?.includes('ALREADYEXISTS') && !e.responseStatus) {
      logger.warn('scanner', `Could not create folder "${folder}": ${e.message}`);
    }
  }
  try {
    await c.mailboxSubscribe(folder);
  } catch {
    // Not critical
  }
  knownFolders.add(folder);
}

/**
 * Scan a message in INBOX. Returns 'bounce' if the message passed and stays
 * in INBOX (needs a UID refresh bounce), or null otherwise.
 */
async function processMessage(loop: ScannerLoop, uid: number, uidValidity: number): Promise<'bounce' | null> {
  const { client: c, account } = loop;
  if (!c) return null;

  // Skip if already scanned (e.g. bounced back from Incoming with a new UID)
  const existing = await getScan(FOLDER, uid, uidValidity, 'inbound', account.id);
  if (existing) return null;

  const msg = await c.fetchOne(String(uid), {
    envelope: true,
    flags: true,
    bodyStructure: true,
    uid: true,
    headers: SECURITY_HEADERS,
  }, { uid: true });

  if (!msg) return null;

  const from = formatAddress(msg.envelope?.from);
  const to = formatAddress(msg.envelope?.to);
  const subject = msg.envelope?.subject || '(no subject)';

  let bodyText = '';
  const textPart = findTextPart(msg.bodyStructure);
  if (textPart) {
    try {
      const { content } = await c.download(String(uid), textPart, { uid: true });
      const chunks: Buffer[] = [];
      for await (const chunk of content) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      bodyText = Buffer.concat(chunks).toString('utf-8');
    } catch {
      // If body download fails, filter with headers only
    }
  }

  const emailSummary: EmailSummary = {
    direction: 'inbound',
    from,
    to,
    subject,
    body: bodyText.slice(0, 2000),
    attachments: findAttachments(msg.bodyStructure),
    headers: msg.headers ? parseHeaders(msg.headers) : {},
  };

  const rule = await getMatchingRules({
    from: emailSummary.from,
    to: emailSummary.to,
    subject: emailSummary.subject,
    body: emailSummary.body,
  }, 'inbound');

  let decision: FilterDecision;
  const startTime = Date.now();

  const isSenderWhitelisted = await isWhitelisted(account.id, from);

  if (rule) {
    // Explicit rules always take precedence over auto-whitelisting
    decision = {
      action: rule.type === 'allow' ? 'pass' : rule.type === 'block' ? 'reject' : rule.type,
      reason: `Matched rule: ${rule.match_field} ~ ${rule.match_pattern}`,
      confidence: 1,
      categories: [],
    };
  } else if (isSenderWhitelisted) {
    decision = {
      action: 'pass',
      reason: `Sender ${from} is whitelisted (previous outbound contact or manual whitelist)`,
      confidence: 1,
      categories: ['whitelisted'],
    };
  } else if (!AUTO_QUARANTINE) {
    decision = { action: 'pass', reason: 'Log-only mode', confidence: 1, categories: [] };
  } else {
    decision = await inspectEmail(emailSummary, undefined, account.id);
    if (decision.action === 'reject' && decision.confidence < FILTER_CONFIDENCE_THRESHOLD) {
      decision.action = 'quarantine';
      decision.reason += ' (low confidence, quarantined for review)';
    }
  }

  const latencyMs = Date.now() - startTime;

  await logAudit({
    direction: 'inbound',
    from_addr: from,
    to_addr: to,
    subject,
    decision,
    latency_ms: latencyMs,
    accountId: account.id,
  });

  const moveTarget = decision.move_to || undefined;

  logger.info('scanner',
    `[${account.id}] ${decision.action.toUpperCase()} uid=${uid} from=${from} subject="${subject}"${moveTarget ? ` → ${moveTarget}` : ''} (${latencyMs}ms)`,
  );

  if (decision.action === 'reject' || decision.action === 'quarantine') {
    const target = moveTarget || SPAM_FOLDER;
    try {
      await ensureFolder(c, target, loop.knownFolders);
      await c.messageMove(String(uid), target, { uid: true });
    } catch (e: any) {
      logger.error('scanner', `[${account.id}] Failed to move uid=${uid} to ${target}: ${e.message}`);
    }
    await recordScan(FOLDER, uid, uidValidity, decision.action, decision.reason, 'inbound', account.id);

    if (decision.action === 'quarantine') {
      await insertQuarantine({
        id: randomUUID(),
        direction: 'inbound',
        from_addr: from,
        to_addr: to,
        subject,
        body_preview: bodyText.slice(0, 500),
        raw_eml: Buffer.from(''),
        reason: decision.reason,
        categories: decision.categories,
        confidence: decision.confidence,
        accountId: account.id,
      });
    }
    return null;
  }

  if (decision.action === 'pass' && moveTarget) {
    try {
      await ensureFolder(c, moveTarget, loop.knownFolders);
      await c.messageMove(String(uid), moveTarget, { uid: true });
    } catch (e: any) {
      logger.error('scanner', `[${account.id}] Failed to move uid=${uid} to ${moveTarget}: ${e.message}`);
    }
    await recordScan(FOLDER, uid, uidValidity, decision.action, decision.reason, 'inbound', account.id);
    return null;
  }

  // Message passes and stays in INBOX — needs a UID bounce so clients refetch the body
  await recordScan(FOLDER, uid, uidValidity, decision.action, decision.reason, 'inbound', account.id);
  return 'bounce';
}

async function scanNewMessages(loop: ScannerLoop): Promise<void> {
  const { client, account } = loop;
  if (!client?.usable) return;

  // Collect UIDs that need a bounce (passed, staying in INBOX)
  const bouncePending: number[] = [];

  const lock = await client.getMailboxLock(FOLDER);
  try {
    const mailbox = client.mailbox;
    if (!mailbox) return;

    const uidValidity = Number(mailbox.uidValidity);
    const state = await getScannerState(FOLDER, account.id);

    let startUid: number;
    if (!state || state.uid_validity !== uidValidity) {
      if (mailbox.exists === 0) {
        await setScannerState(FOLDER, uidValidity, 0, account.id);
        return;
      }
      const searchResult = await client.search({ all: true }, { uid: true });
      const uids = Array.isArray(searchResult) ? searchResult : [];
      const lastUid = uids.length > 0 ? uids[uids.length - 1] : 0;
      await setScannerState(FOLDER, uidValidity, lastUid, account.id);
      logger.info('scanner', `[${account.id}] Initialized baseline: uidValidity=${uidValidity} lastUid=${lastUid}`);
      return;
    }

    startUid = state.last_uid;

    const searchResult = await client.search({ uid: `${startUid + 1}:*` }, { uid: true });
    const uids = Array.isArray(searchResult) ? searchResult : [];
    const newUids = uids.filter((u: number) => u > startUid);

    if (newUids.length === 0) return;

    logger.info('scanner', `[${account.id}] Found ${newUids.length} new message(s) to scan`);

    let lastProcessed = startUid;
    for (const uid of newUids) {
      if (loop.stopped) break;
      try {
        const result = await processMessage(loop, uid, uidValidity);
        if (result === 'bounce') bouncePending.push(uid);
        lastProcessed = uid;
      } catch (e: any) {
        logger.error('scanner', `[${account.id}] Error processing uid=${uid}: ${e.message}`);
        lastProcessed = uid;
      }
    }

    if (lastProcessed > startUid) {
      await setScannerState(FOLDER, uidValidity, lastProcessed, account.id);
      // Prune old scan records for UIDs below the previous baseline
      await pruneScans(FOLDER, startUid, uidValidity, 'inbound', account.id);
    }

    // Bounce: move passed messages to Incoming (still under INBOX lock)
    if (bouncePending.length > 0) {
      for (const uid of bouncePending) {
        try {
          await client.messageMove(String(uid), INCOMING_FOLDER, { uid: true });
        } catch (e: any) {
          logger.error('scanner', `[${account.id}] Bounce-out failed uid=${uid}: ${e.message}`);
        }
      }
    }
  } finally {
    lock.release();
  }

  // Bounce back: move everything from Incoming → INBOX to get fresh UIDs
  if (bouncePending.length > 0) {
    let incomingLock;
    try {
      incomingLock = await client.getMailboxLock(INCOMING_FOLDER);
    } catch {
      return;
    }
    try {
      const searchResult = await client.search({ all: true }, { uid: true });
      const incomingUids = Array.isArray(searchResult) ? searchResult : [];
      for (const uid of incomingUids) {
        try {
          const moveResult = await client.messageMove(String(uid), FOLDER, { uid: true }) as CopyResponseObject | false;

          // Record scan with the new INBOX UID so the interceptor and scanner skip it
          if (moveResult && moveResult.uidMap) {
            const newUid = moveResult.uidMap.get(uid);
            const destUv = moveResult.uidValidity ? Number(moveResult.uidValidity) : 0;
            if (newUid && destUv) {
              await recordScan(FOLDER, newUid, destUv, 'pass', 'UID refresh after scan', 'inbound', account.id);
            }
          }
        } catch (e: any) {
          logger.error('scanner', `[${account.id}] Bounce-back failed uid=${uid}: ${e.message}`);
        }
      }

      if (incomingUids.length > 0) {
        logger.info('scanner', `[${account.id}] Bounced ${incomingUids.length} message(s) back to INBOX with fresh UIDs`);
      }
    } finally {
      incomingLock.release();
    }
  }
}

async function runLoop(loop: ScannerLoop): Promise<void> {
  while (!loop.stopped) {
    try {
      if (!loop.client?.usable) {
        loop.client = createClient(loop.account);
        await loop.client.connect();
        logger.info('scanner', `[${loop.account.id}] Connected to IMAP`);
        await ensureFolder(loop.client, INCOMING_FOLDER, loop.knownFolders);
      }

      await scanNewMessages(loop);

      try {
        const lock = await loop.client.getMailboxLock(FOLDER);
        try {
          await Promise.race([
            loop.client.idle(),
            new Promise(resolve => {
              loop.pollTimer = setTimeout(resolve, INBOUND_SCAN_INTERVAL);
            }),
          ]);
        } finally {
          lock.release();
        }
      } catch {
        // IDLE interrupted or failed
      }
    } catch (e: any) {
      logger.error('scanner', `[${loop.account.id}] Error: ${e.message}`);
      if (loop.client) {
        try { loop.client.close(); } catch { }
        loop.client = null;
      }
      if (!loop.stopped) {
        await new Promise(resolve => {
          loop.pollTimer = setTimeout(resolve, INBOUND_SCAN_INTERVAL);
        });
      }
    }
  }
}

export async function startInboundScanner(): Promise<{ stop: () => void }> {
  const accounts = getAllAccounts().filter(a => a.imap.host && a.imap.user);

  if (accounts.length === 0) {
    logger.info('scanner', 'Skipped: no accounts with IMAP configured');
    return { stop: () => { } };
  }

  const loops: ScannerLoop[] = [];

  for (const account of accounts) {
    const loop: ScannerLoop = {
      account,
      client: null,
      pollTimer: null,
      stopped: false,
      knownFolders: new Set(),
    };
    loops.push(loop);

    logger.info('scanner', `[${account.id}] Starting inbound scanner (interval=${INBOUND_SCAN_INTERVAL}ms)`);
    runLoop(loop).catch(e => logger.error('scanner', `[${account.id}] Fatal:`, e));
  }

  return {
    stop: () => {
      for (const loop of loops) {
        loop.stopped = true;
        if (loop.pollTimer) clearTimeout(loop.pollTimer);
        if (loop.client) {
          try { loop.client.close(); } catch { }
          loop.client = null;
        }
      }
      logger.info('scanner', 'All scanner loops stopped');
    },
  };
}
