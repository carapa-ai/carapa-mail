// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { sanitizeBody, sanitizeHtml } from './sanitizer.js';
import { scanAttachments } from '../email/attachment-scanner.js';
import { scanAuthenticity } from '../email/authenticity.js';
import { toEmailSummary } from '../email/parser.js';
import { inspectEmail } from '../agent/filter.js';
import { getScan, getScannerState, recordScan, logAudit, getMatchingRules } from '../db/index.js';
import { FILTER_CONFIDENCE_THRESHOLD, INCOMING_FOLDER } from '../config.js';
import type { EmailSummary, FolderPolicy, FolderContext } from '../types.js';
import { simpleParser } from 'mailparser';

/**
 * Determine the security policy for a given folder.
 */
function getFolderPolicy(folder: string): FolderPolicy {
  const name = folder.toLowerCase();

  // Junk/Spam: Skip AI (already flagged), minimal sanitization
  if (name.includes('junk') || name.includes('spam')) {
    return { level: 'minimal', skipAi: true, skipSanitization: false, autoQuarantine: false };
  }

  // Sent/Drafts: Trust the user, but maybe audit?
  if (name.includes('sent') || name.includes('draft')) {
    return { level: 'audit-only', skipAi: true, skipSanitization: true, autoQuarantine: false };
  }

  // Trash: Minimal
  if (name.includes('trash') || name.includes('bin')) {
    return { level: 'minimal', skipAi: true, skipSanitization: true, autoQuarantine: false };
  }

  // Incoming: Messages awaiting scan — block all body content.
  // The inbound scanner moves new mail here before scanning, then routes
  // to INBOX (or other folders) once cleared.  Clients should never see
  // raw content from this folder.
  if (name === INCOMING_FOLDER.toLowerCase()) {
    return { level: 'strict', skipAi: false, skipSanitization: false, autoQuarantine: false };
  }

  // INBOX: Strict AI and sanitization
  return { level: 'strict', skipAi: false, skipSanitization: false, autoQuarantine: true };
}

/**
 * IMAP FETCH response interceptor.
 *
 * Handles three layers of protection:
 * 1. UID-level gate — blocks ALL FETCH data (including envelopes/headers) for
 *    messages that haven't been scanned yet or were rejected/quarantined
 * 2. AI filtering — checks each fetched message against the LLM filter (with DB cache)
 * 3. Body sanitization — strips tracking pixels, hidden content, prompt injection
 *
 * IMAP literals look like: {1234}\r\n<1234 bytes of content>
 * When we modify the content, the byte count changes, so we must rewrite
 * the literal prefix.
 */

// Maximum literal size we'll buffer for sanitization (50 MB).
const MAX_LITERAL_SIZE = 50 * 1024 * 1024;

// Scan cache TTL — re-check DB after this many ms
const SCAN_CACHE_TTL = 5_000;

type ScanStatus = { action: string; reason: string | null } | null; // null = not scanned

interface CacheEntry {
  status: ScanStatus;
  ts: number;
}

interface BufferState {
  pending: Buffer;
  inLiteral: boolean;
  literalRemaining: number;
  literalPrefix: string;
  literalData: Buffer;
  currentUid: number | null;
  currentSection: string; // e.g. 'BODY[]', 'BODY[TEXT]', 'RFC822'
  // When true, discard all output for the current FETCH response (including its literal)
  suppressFetch: boolean;
}

interface MailboxContext {
  folder: string;
  uidValidity: number;
  accountId: string;
}

/**
 * Parse RFC822 headers from raw email text.
 * Returns a map of lowercase header name → value.
 */
function parseHeaders(raw: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const headerEnd = raw.indexOf('\r\n\r\n');
  const headerBlock = headerEnd > 0 ? raw.slice(0, headerEnd) : raw.slice(0, 4096);

  // Unfold continuation lines (lines starting with whitespace)
  const unfolded = headerBlock.replace(/\r\n[ \t]+/g, ' ');
  for (const line of unfolded.split('\r\n')) {
    const colon = line.indexOf(':');
    if (colon > 0) {
      const name = line.slice(0, colon).trim().toLowerCase();
      const value = line.slice(colon + 1).trim();
      headers[name] = value;
    }
  }
  return headers;
}

/**
 * Extract body text from raw RFC822 message.
 */
function extractBody(raw: string): string {
  const headerEnd = raw.indexOf('\r\n\r\n');
  if (headerEnd < 0) return '';
  return raw.slice(headerEnd + 4);
}

/**
 * Build a warning body to replace flagged email content.
 */
function buildWarningBody(reason: string, section: string): Buffer {
  const warningText = `[EMAIL BLOCKED BY AI FILTER]\r\n\r\nReason: ${reason}\r\n\r\nThis message was flagged as potentially harmful and its content has been hidden.\r\nCheck the quarantine via the admin API to review or release it.\r\n`;

  const isFull = section === 'BODY[]' || section === 'RFC822';
  const isHeader = section.includes('HEADER');

  if (isFull || isHeader) {
    // Return a minimal valid RFC822 message or header block
    const msg = `From: carapamail-filter@local\r\nSubject: [BLOCKED] Message flagged by AI filter\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${isFull ? warningText : ''}`;
    return Buffer.from(msg, 'utf-8');
  }
  // BODY[TEXT] or other text section
  return Buffer.from(warningText, 'utf-8');
}

/**
 * Build a placeholder body for messages still being scanned.
 * Preserves original headers when available to prevent clients (e.g. Thunderbird)
 * from caching fake placeholder headers permanently.
 */
function buildPendingScanBody(section: string, originalRaw?: string): Buffer {
  const text = `[CarapaMail: Message pending security scan]\r\n\r\nThis message has not been scanned yet. Please refresh in a moment.\r\n`;

  const isFull = section === 'BODY[]' || section === 'RFC822';

  if (isFull && originalRaw) {
    // Preserve original headers, replace only the body
    const headerEnd = originalRaw.indexOf('\r\n\r\n');
    const originalHeaders = headerEnd > 0 ? originalRaw.slice(0, headerEnd) : originalRaw.slice(0, 4096);
    const msg = `${originalHeaders}\r\n\r\n${text}`;
    return Buffer.from(msg, 'utf-8');
  }

  if (isFull) {
    // No original available — fallback to synthetic headers
    const msg = `From: carapamail-filter@local\r\nSubject: [PENDING SCAN] Message awaiting security check\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${text}`;
    return Buffer.from(msg, 'utf-8');
  }

  // BODY[TEXT] or other text section — just the placeholder body
  return Buffer.from(text, 'utf-8');
}

export function createInterceptor() {
  const state: BufferState = {
    pending: Buffer.alloc(0),
    inLiteral: false,
    literalRemaining: 0,
    literalPrefix: '',
    literalData: Buffer.alloc(0),
    currentUid: null,
    currentSection: '',
    suppressFetch: false,
  };

  let context: FolderContext = {
    folder: '',
    uidValidity: 0,
    accountId: 'default',
    policy: getFolderPolicy(''),
  };

  // In-memory scan status cache: uid → {status, timestamp}
  // Cleared on folder context change
  const scanCache = new Map<number, CacheEntry>();

  // Scanner baseline: UIDs at or below this were present before carapa-mail started scanning.
  // They are implicitly trusted (no scan record needed).
  let scannerBaseline: { lastUid: number; ts: number } | null = null;

  /**
   * Get the inbound scanner's baseline last_uid for the current folder.
   * Cached with TTL to avoid repeated DB lookups.
   */
  async function getScannerBaseline(): Promise<number> {
    if (scannerBaseline && (Date.now() - scannerBaseline.ts) < SCAN_CACHE_TTL) {
      return scannerBaseline.lastUid;
    }
    const state = await getScannerState(context.folder, context.accountId);
    const lastUid = state?.last_uid ?? 0;
    scannerBaseline = { lastUid, ts: Date.now() };
    return lastUid;
  }

  /**
   * Check scan status for a UID. Uses in-memory cache with TTL.
   * Returns the scan result or null if not scanned.
   */
  async function getUidScanStatus(uid: number): Promise<ScanStatus> {
    const cached = scanCache.get(uid);
    if (cached && (Date.now() - cached.ts) < SCAN_CACHE_TTL) {
      return cached.status;
    }

    if (!context.folder || !context.uidValidity) return null;

    const result = await getScan(context.folder, uid, context.uidValidity, 'inbound', context.accountId);
    scanCache.set(uid, { status: result, ts: Date.now() });
    return result;
  }

  /**
   * Determine if a UID should be gated.
   * Returns: 'pass' | 'block' | 'pending'
   * - 'pass': forward normally
   * - 'block': replace with warning (rejected/quarantined)
   * - 'pending': replace with placeholder (not yet scanned)
   */
  async function gateUid(uid: number | null): Promise<'pass' | 'block' | 'pending'> {
    if (!uid || context.policy.skipAi) return 'pass';
    if (!context.folder || !context.uidValidity) return 'pass';

    const scan = await getUidScanStatus(uid);
    if (scan) {
      if (scan.action === 'reject' || scan.action === 'quarantine') return 'block';
      return 'pass';
    }

    // No scan record — check if this message predates carapa-mail's scanner baseline.
    // Messages at or below the baseline existed before scanning started and are implicitly trusted.
    const baseline = await getScannerBaseline();
    if (baseline > 0 && uid <= baseline) return 'pass';

    return 'pending'; // Newer than baseline but not yet scanned
  }

  return {
    /**
     * Update the current mailbox context (folder + UIDVALIDITY + account).
     * Called by the proxy when SELECT/EXAMINE responses are seen.
     */
    setContext(folder: string, uidValidity: number, accountId?: string) {
      const folderChanged = folder !== context.folder || uidValidity !== context.uidValidity;
      context = {
        folder,
        uidValidity,
        accountId: accountId || context.accountId,
        policy: getFolderPolicy(folder),
      };
      // Clear caches on folder change
      if (folderChanged) {
        scanCache.clear();
        scannerBaseline = null;
      }
    },

    /**
     * Process a chunk of data from the upstream IMAP server.
     * Returns the (possibly modified) data to send to the client.
     * Now async to support AI filtering on FETCH bodies.
     */
    async process(data: Buffer): Promise<Buffer> {
      // Fast path: if not in a literal, no pending buffered data, and no FETCH in sight, pass through
      if (!state.inLiteral && state.pending.length === 0
        && !data.includes('FETCH') && !data.includes('BODY[')) {
        return data;
      }

      // Accumulate data
      state.pending = Buffer.concat([state.pending, data]);
      const output: Buffer[] = [];

      while (state.pending.length > 0) {
        if (state.inLiteral) {
          // Collecting literal data
          const needed = state.literalRemaining;
          const available = state.pending.length;
          const take = Math.min(needed, available);

          state.literalData = Buffer.concat([state.literalData, state.pending.subarray(0, take)]);
          state.pending = state.pending.subarray(take);
          state.literalRemaining -= take;

          if (state.literalRemaining === 0) {
            if (!state.literalPrefix) {
              // Passthrough mode (oversized literal) — data already flushed
              state.inLiteral = false;
              state.suppressFetch = false;
            } else if (state.suppressFetch) {
              // Suppressed/blocked literal — discard
              state.inLiteral = false;
              state.literalData = Buffer.alloc(0);
              state.literalPrefix = '';
              state.currentUid = null;
              state.currentSection = '';
              state.suppressFetch = false;
            } else {
              // Only filter/sanitize full message bodies; pass other sections through
              const isFilterable = state.currentSection === 'BODY[]'
                || state.currentSection === 'BODY[TEXT]'
                || state.currentSection === 'RFC822'
                || state.currentSection === 'RFC822.TEXT';

              if (isFilterable) {
                const processed = await filterAndSanitizeLiteral(
                  state.literalData,
                  state.currentUid,
                  state.currentSection,
                  context,
                  scanCache,
                );
                const prefix = state.literalPrefix.replace(
                  /\{(\d+)\}/,
                  `{${processed.length}}`,
                );
                output.push(Buffer.from(prefix));
                output.push(processed);
              } else {
                // Non-filterable section — pass through unmodified
                output.push(Buffer.from(state.literalPrefix));
                output.push(state.literalData);
              }

              state.inLiteral = false;
              state.literalData = Buffer.alloc(0);
              state.literalPrefix = '';
              state.currentUid = null;
              state.currentSection = '';
            }
          } else if (!state.literalPrefix && !state.suppressFetch) {
            // Passthrough mode — flush accumulated data immediately instead of buffering
            output.push(state.literalData);
            state.literalData = Buffer.alloc(0);
          } else if (state.suppressFetch) {
            // Suppressed literal — discard accumulated data
            state.literalData = Buffer.alloc(0);
          }
        } else {
          // Look for a literal start in the pending text (regex match on string for pattern extraction)
          const pendingStr = state.pending.toString('utf-8');
          // Match all IMAP BODY[...] section specs (including HEADER.FIELDS, part numbers, etc.)
          // and RFC822 variants, followed by a literal size marker {N}\r\n
          const match = pendingStr.match(/^([\s\S]*?)((?:(BODY\[[^\]]*\](?:<\d+>)?|RFC822(?:\.(?:TEXT|HEADER))?) )\{(\d+)\}\r\n)/);

          if (match) {
            const [, before, literalHeader, section, sizeStr] = match;
            const literalSize = parseInt(sizeStr, 10);

            // Extract UID from the text before the literal (e.g. "* 1 FETCH (UID 123 ...")
            const uidMatch = before.match(/\bUID\s+(\d+)/i);
            state.currentUid = uidMatch ? parseInt(uidMatch[1], 10) : null;
            state.currentSection = section;

            // --- UID-level gate for body literals ---
            const gate = await gateUid(state.currentUid);
            const isFullMessage = section === 'BODY[]' || section === 'RFC822';

            const isHeaderOnly = section.includes('HEADER');
            if (gate === 'block' || (gate === 'pending' && !isFullMessage && !isHeaderOnly)) {
              // Replace body literal with warning/placeholder, skip original literal data
              const label = gate === 'pending' ? 'not yet scanned' : 'rejected/quarantined';
              console.log(`[imap:gate] ${gate.toUpperCase()} uid=${state.currentUid} body literal (${label})`);
              const literalHeaderBuf = Buffer.from(literalHeader);
              const headerPos = state.pending.indexOf(literalHeaderBuf);

              // Output the "before" text (FETCH response prefix) to keep response structure valid
              if (headerPos > 0) output.push(state.pending.subarray(0, headerPos));
              state.pending = state.pending.subarray(headerPos + literalHeaderBuf.length);

              // Build replacement body and output it with correct literal size
              const replacement = gate === 'block'
                ? buildWarningBody((await getUidScanStatus(state.currentUid!))?.reason || 'Blocked by AI filter', section)
                : buildPendingScanBody(section);
              const newPrefix = literalHeader.replace(/\{(\d+)\}/, `{${replacement.length}}`);
              output.push(Buffer.from(newPrefix));
              output.push(replacement);

              // Skip the original literal data
              state.inLiteral = true;
              state.literalRemaining = literalSize;
              state.literalPrefix = '';
              state.literalData = Buffer.alloc(0);
              state.suppressFetch = true;
              continue;
            }

            // gate === 'pass' — proceed with normal literal handling
            // Find the literal header position in the raw buffer to avoid UTF-8 round-trip corruption.
            // The literal header (e.g. "BODY[] {1234}\r\n") is always ASCII, so Buffer.indexOf is safe.
            const literalHeaderBuf = Buffer.from(literalHeader);
            const headerPos = state.pending.indexOf(literalHeaderBuf);

            // Output everything before the literal as raw bytes (preserves original encoding)
            if (headerPos > 0) output.push(state.pending.subarray(0, headerPos));

            // Advance past the literal header
            state.pending = state.pending.subarray(headerPos + literalHeaderBuf.length);

            if (literalSize > MAX_LITERAL_SIZE) {
              // Oversized literal — pass through unsanitized to prevent OOM
              console.warn(`[imap] Literal too large (${literalSize} bytes), passing through unsanitized`);
              output.push(literalHeaderBuf);
              const take = Math.min(literalSize, state.pending.length);
              output.push(state.pending.subarray(0, take));
              state.pending = state.pending.subarray(take);
              state.inLiteral = true;
              state.literalRemaining = literalSize - take;
              state.literalPrefix = ''; // empty prefix signals passthrough mode
              state.literalData = Buffer.alloc(0);
            } else {
              state.inLiteral = true;
              state.literalRemaining = literalSize;
              state.literalPrefix = literalHeader;
              state.literalData = Buffer.alloc(0);
            }
          } else {
            // No literal found in current buffer — process line by line for FETCH gating
            // Keep the last partial line in case a literal header is split across chunks.
            const lastNewlineIdx = state.pending.lastIndexOf(0x0A); // '\n'
            let flushEnd: number;
            let keepFrom: number;

            if (lastNewlineIdx >= 0 && lastNewlineIdx < state.pending.length - 1) {
              flushEnd = lastNewlineIdx + 1;
              keepFrom = lastNewlineIdx + 1;
            } else {
              flushEnd = state.pending.length;
              keepFrom = state.pending.length;
            }

            // No body literal — pass through non-literal data as-is.
            // Envelope/flags FETCH responses are forwarded without gating to preserve
            // IMAP protocol integrity. Body content is gated at the literal level.
            const flushData = state.pending.subarray(0, flushEnd);
            state.pending = state.pending.subarray(keepFrom);
            output.push(flushData);

            break;
          }
        }
      }

      return Buffer.concat(output);
    },

    /** Flush any remaining buffered data */
    flush(): Buffer {
      const remaining = state.pending;
      state.pending = Buffer.alloc(0);
      return remaining;
    },
  };
}

/**
 * Filter a collected FETCH literal through:
 * 1. UID-level gate — block if rejected/quarantined or not yet scanned (non-full-message sections)
 * 2. AI filter (with DB cache) — blocks spam/malicious content
 * 3. Body sanitization — strips tracking, hidden content, prompt injection
 */
async function filterAndSanitizeLiteral(
  data: Buffer,
  uid: number | null,
  section: string,
  ctx: FolderContext,
  scanCache: Map<number, CacheEntry>,
): Promise<Buffer> {
  const text = data.toString('utf-8');

  // AI filtering — only for full messages (BODY[] / RFC822) where we have headers
  const isFullMessage = section === 'BODY[]' || section === 'RFC822';
  let filterUnavailable = false;

  if (uid && ctx.folder && ctx.uidValidity && !ctx.policy.skipAi) {
    // Check DB cache first
    const existing = await getScan(ctx.folder, uid, ctx.uidValidity, 'inbound', ctx.accountId);

    if (existing) {
      // Update the in-memory cache
      scanCache.set(uid, { status: existing, ts: Date.now() });

      if (existing.action === 'reject' || existing.action === 'quarantine') {
        return buildWarningBody(existing.reason || 'Flagged by AI filter', section);
      }
      // Already scanned and passed — skip to sanitization
    } else if (isFullMessage) {
      // Not yet scanned, but we have the full message — run AI filter inline
      const headers = parseHeaders(text);
      const body = extractBody(text);
      const from = headers['from'] || '';
      const to = headers['to'] || '';
      const subject = headers['subject'] || '(no subject)';

      const emailSummary: EmailSummary = {
        direction: 'inbound',
        from,
        to,
        subject,
        body,
        attachments: [],
        headers,
      };

      // Check user-defined rules first
      const rule = await getMatchingRules({ from, to, subject, body });

      const startTime = Date.now();
      let decision;

      if (rule) {
        decision = {
          action: rule.type === 'allow' ? 'pass' as const : rule.type === 'block' ? 'reject' as const : rule.type as 'quarantine',
          reason: `Matched rule: ${rule.match_field} ~ ${rule.match_pattern}`,
          confidence: 1,
          categories: [] as string[],
        };
      } else {
        decision = await inspectEmail(emailSummary, undefined, ctx.accountId);

        if (decision.unavailable) {
          filterUnavailable = true;
          // Don't record scan — so next read will re-trigger the filter
        } else if (decision.action === 'reject' && decision.confidence < FILTER_CONFIDENCE_THRESHOLD) {
          decision.action = 'quarantine';
          decision.reason += ' (low confidence, quarantined for review)';
        }
      }

      const latencyMs = Date.now() - startTime;

      if (!filterUnavailable) {
        await recordScan(ctx.folder, uid, ctx.uidValidity, decision.action, decision.reason, 'inbound', ctx.accountId);
        scanCache.set(uid, { status: { action: decision.action, reason: decision.reason }, ts: Date.now() });
        await logAudit({
          direction: 'inbound',
          from_addr: from,
          to_addr: to,
          subject,
          decision,
          latency_ms: latencyMs,
          accountId: ctx.accountId,
        });

        console.log(
          `[imap:filter] ${decision.action.toUpperCase()} uid=${uid} from=${from} subject="${subject}" (${latencyMs}ms)`,
        );

        if (decision.action === 'reject' || decision.action === 'quarantine') {
          return buildWarningBody(decision.reason, section);
        }
      } else {
        console.log(
          `[imap:filter] UNAVAILABLE uid=${uid} from=${from} subject="${subject}" — prepending warning`,
        );
      }
    } else if (!isFullMessage && !existing) {
      // Partial body fetch (BODY[TEXT], BODY[1], etc.) for an unscanned message.
      // We don't have the full message to run AI filter — block with placeholder.
      console.log(`[imap:gate] BLOCK uid=${uid} partial fetch ${section} (not yet scanned)`);
      return buildPendingScanBody(section, text);
    }
  }

  // Scan for dangerous attachments (only if we have the full message)
  let attachmentWarning = '';
  let authenticityWarning = '';
  let foundThreats: string[] = [];

  if (isFullMessage) {
    // 1. Attachment Scanning
    const { safe, threats } = await scanAttachments(data);
    if (!safe) {
      foundThreats = threats;
      attachmentWarning = `[⚠️ SECURITY WARNING: DANGEROUS ATTACHMENTS DETECTED]\r\nPotential malware or phishing vectors: ${threats.join(', ')}\r\nExercise extreme caution and DO NOT open these files unless you are 100% certain they are safe.\r\n\r\n`;
    }

    // 2. Authenticity Scanning (Spoofing, Encryption, Signatures)
    try {
      const parsed = await simpleParser(data);
      const emailSummary = toEmailSummary(parsed, 'inbound');
      const authenticity = scanAuthenticity(emailSummary);

      if (authenticity.findings.length > 0) {
        const severity = authenticity.isSpoofed || emailSummary.isEncrypted ? 'HIGH' : 'LOW';
        authenticityWarning = `[🛡️ CARAPAMAIL SECURITY ANALYSIS - ${severity} SEVERITY]\r\n${authenticity.findings.map(f => `- ${f}`).join('\r\n')}\r\n\r\n`;
      }
    } catch (err) {
      console.warn('[imap:filter] Authenticity scan failed:', err);
    }
  }

  // Sanitize
  if (ctx.policy.skipSanitization) {
    if (attachmentWarning || authenticityWarning) {
      return Buffer.from(authenticityWarning + attachmentWarning + text, 'utf-8');
    }
    return data;
  }

  const isHtml = /<html|<body|<div|<p\b/i.test(text);
  const { sanitized, flags: sanitizerFlags } = isHtml ? sanitizeHtml(text) : sanitizeBody(text);

  // Build prepend warnings
  let prependText = '';
  let prependHtml = '';

  if (filterUnavailable) {
    prependText += '[⚠️ CARAPAMAIL: AI security filter temporarily unavailable. This message was NOT inspected.]\r\n\r\n';
    prependHtml += '<div style="background-color:#fff3cd; border:2px solid #ffc107; color:#856404; padding:15px; margin-bottom:20px; font-family:sans-serif; border-radius:8px; font-weight:bold;">⚠️ AI security filter temporarily unavailable. This message was NOT inspected.</div>';
  }

  if (authenticityWarning) {
    prependText += authenticityWarning;
    prependHtml += `<div style="background-color:#f0f4f8; border:2px solid #1a73e8; color:#1e3a8a; padding:15px; margin-bottom:20px; font-family:sans-serif; border-radius:8px; font-weight:bold;">🛡️ CARAPAMAIL SECURITY ANALYSIS<br/><div style="font-weight:normal; font-size:14px; margin-top:8px;">${authenticityWarning.replace(/\r\n/g, '<br/>')}</div></div>`;
  }

  if (attachmentWarning) {
    prependText += attachmentWarning;
    prependHtml += `<div style="background-color:#ffcccc; border:2px solid red; color:#990000; padding:15px; margin-bottom:20px; font-family:sans-serif; border-radius:8px; font-weight:bold;">⚠️ SECURITY WARNING: DANGEROUS ATTACHMENTS<br/><span style="font-weight:normal; font-size:14px;">This email contains potentially harmful files: ${foundThreats.join(', ')}. Avoid downloading or opening them.</span></div>`;
  }

  if (sanitizerFlags.length > 0) {
    const importantFlags = sanitizerFlags.filter(f => f === 'dangerous_tag' || f === 'zero_width_chars' || f === 'event_handler');
    if (importantFlags.length > 0) {
      const severity = importantFlags.includes('dangerous_tag') ? 'HIGH' : 'LOW';
      const flagWarning = `[🛡️ CARAPAMAIL CONTENT ANALYSIS - ${severity} SEVERITY]\r\n${importantFlags.map(f => `- Detected and blocked: ${f.replace(/_/g, ' ')}`).join('\r\n')}\r\n\r\n`;
      prependText += flagWarning;
      prependHtml += `<div style="background-color:#fff3cd; border:2px solid #ffc107; color:#856404; padding:15px; margin-bottom:20px; font-family:sans-serif; border-radius:8px;">🛡️ Content Analysis<br/><div style="font-weight:normal; font-size:14px; margin-top:8px;">${flagWarning.replace(/\r\n/g, '<br/>')}</div></div>`;
    }
  }

  if (prependText || prependHtml) {
    if (isHtml) {
      const bodyMatch = sanitized.match(/<body[^>]*>/i);
      if (bodyMatch) {
        const insertAt = (bodyMatch.index || 0) + bodyMatch[0].length;
        return Buffer.from(sanitized.slice(0, insertAt) + prependHtml + sanitized.slice(insertAt), 'utf-8');
      }
      return Buffer.from(prependHtml + sanitized, 'utf-8');
    }
    return Buffer.from(prependText + sanitized, 'utf-8');
  }

  return Buffer.from(sanitized, 'utf-8');
}
