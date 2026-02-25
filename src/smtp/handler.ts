// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import type { SMTPServerDataStream, SMTPServerSession } from 'smtp-server';
import { parseFromStream, toEmailSummary } from '../email/parser.js';
import { inspectEmail } from '../agent/filter.js';
import { relayRawMessage } from './relay.js';
import { quarantineMessage } from '../email/quarantine.js';
import { logAudit, getMatchingRules, addToWhitelist } from '../db/index.js';
import { getAccountById } from '../accounts.js';
import { scanEmailForSecrets } from '../email/secret-scanner.js';
import { FILTER_CONFIDENCE_THRESHOLD, AUTO_QUARANTINE } from '../config.js';
import type { FilterDecision } from '../types.js';

export async function handleMessage(
  stream: SMTPServerDataStream,
  session: SMTPServerSession,
  callback: (err?: Error | null) => void,
): Promise<void> {
  try {
    const { parsed, rawBuffer } = await parseFromStream(stream);

    const from = session.envelope.mailFrom ? session.envelope.mailFrom.address : '';
    const to = session.envelope.rcptTo.map(r => r.address);

    // Get account from session (stored by onAuth as user field)
    const accountId = session.user || 'default';
    const account = getAccountById(accountId);

    // 0. Sender Authenticity Check: Ensure authenticated user is sending from their own address
    if (account && session.envelope.mailFrom && session.envelope.mailFrom.address) {
      const authenticatedEmail = account.email.toLowerCase();
      const envelopeFrom = session.envelope.mailFrom.address.toLowerCase();

      if (envelopeFrom !== authenticatedEmail) {
        const errorMsg = `Sender address mismatch: authenticated as ${authenticatedEmail} but tried to send as ${envelopeFrom}`;
        console.warn(`[smtp] REJECT: ${errorMsg}`);
        return callback(new Error(`550 ${errorMsg}`));
      }
    }

    const emailSummary = toEmailSummary(parsed, 'outbound');

    // 1. Data Loss Prevention (DLP): Scan for secrets in outbound mail
    const outboundSecrets = scanEmailForSecrets(parsed);
    let dlpDecision: FilterDecision | null = null;

    if (outboundSecrets.length > 0) {
      dlpDecision = {
        action: 'quarantine',
        reason: `DLP: Detected potential secrets: ${outboundSecrets.map(s => `${s.name} in ${s.location}`).join(', ')}`,
        confidence: 1,
        categories: ['dlp', 'secrets'],
      };
    }

    // Check user-defined rules first
    const rule = await getMatchingRules({
      from: emailSummary.from,
      to: emailSummary.to,
      subject: emailSummary.subject,
      body: emailSummary.body,
    });

    let decision: FilterDecision;
    const startTime = Date.now();

    if (dlpDecision) {
      decision = dlpDecision;
    } else if (rule) {
      decision = {
        action: rule.type === 'allow' ? 'pass' : rule.type === 'block' ? 'reject' : rule.type,
        reason: `Matched rule: ${rule.match_field} ~ ${rule.match_pattern}`,
        confidence: 1,
        categories: [],
      };
    } else if (!AUTO_QUARANTINE) {
      // Log-only mode: pass everything
      decision = { action: 'pass', reason: 'Log-only mode', confidence: 1, categories: [] };
    } else {
      // AI inspection
      decision = await inspectEmail(emailSummary, undefined, accountId);

      // If confidence is below threshold, quarantine instead of reject
      if (decision.action === 'reject' && decision.confidence < FILTER_CONFIDENCE_THRESHOLD) {
        decision.action = 'quarantine';
        decision.reason += ' (low confidence, quarantined for review)';
      }
    }

    const latencyMs = Date.now() - startTime;

    await logAudit({
      direction: 'outbound',
      from_addr: emailSummary.from,
      to_addr: emailSummary.to,
      subject: emailSummary.subject,
      decision,
      latency_ms: latencyMs,
      accountId,
    });

    console.log(
      `[smtp] ${decision.action.toUpperCase()} from=${from} to=${to.join(',')} subject="${emailSummary.subject}" (${latencyMs}ms)`,
    );

    switch (decision.action) {
      case 'pass':
        // Auto-whitelist recipients of outbound mail
        // Accept immediately so the client doesn't time out waiting for relay
        callback();
        // Relay and whitelist in the background
        (async () => {
          try {
            for (const recipient of session.envelope.rcptTo) {
              await addToWhitelist(accountId, 'email', recipient.address, 'outbound');
              // Also whitelist the domain of the recipient
              const domain = recipient.address.split('@')[1];
              if (domain) {
                await addToWhitelist(accountId, 'domain', domain, 'outbound');
              }
            }
            await relayRawMessage(rawBuffer, { from, to }, account);
          } catch (relayErr) {
            console.error(`[smtp] Background relay failed: ${relayErr instanceof Error ? relayErr.message : relayErr}`);
          }
        })();
        break;

      case 'quarantine': {
        const qId = await quarantineMessage(parsed, rawBuffer, 'outbound', decision, accountId);
        console.log(`[smtp] Quarantined as ${qId}: ${decision.reason}`);
        // Accept the message (250) but hold it
        callback();
        break;
      }

      case 'reject':
        callback(new Error(`550 Message rejected: ${decision.reason}`));
        break;
    }
  } catch (err) {
    console.error('[smtp] Handler error:', err);
    // On error, accept to avoid losing mail
    callback();
  }
}
