// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import Anthropic from '@anthropic-ai/sdk';
import * as config from '../config.js';
import { getFilterPrompt, type FilterContext } from './prompts.js';
import type { FilterDecision, EmailSummary } from '../types.js';
import { scanUrls } from '../email/url-scanner.js';
import { scanAuthenticity } from '../email/authenticity.js';
import { scanDlp } from '../email/dlp-scanner.js';
import { redact } from '../email/redactor.js';
import { logger } from '../logger.js';

let client: Anthropic | null = null;

function getClient(): Anthropic {
  if (!client) {
    client = new Anthropic({
      apiKey: config.ANTHROPIC_AUTH_TOKEN,
      baseURL: config.ANTHROPIC_BASE_URL,
    });
  }
  return client;
}

/** Approximate token count (1 token ≈ 4 chars). */
function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Build the metadata header that prefixes every chunk.
 * This includes direction, addresses, subject, headers, DLP, authenticity,
 * URL analysis and attachments — everything except the body.
 */
function buildMeta(email: EmailSummary): string {
  const redactedSubject = redact(email.subject);

  const parts = [
    `Direction: ${email.direction}`,
    `From: ${email.from}`,
    `To: ${email.to}`,
    `Subject: ${redactedSubject}`,
    '',
    'Headers:',
    ...Object.entries(email.headers).slice(0, 10).map(([k, v]) => `  ${k}: ${v}`),
  ];

  // DLP (Data Loss Prevention) Analysis
  const dlpScan = scanDlp(`${email.subject}\n${email.body}`);
  if (dlpScan.score > 0) {
    parts.push('', 'DLP (Data Loss Prevention) Analysis:');
    parts.push(`  - Total Data Exposure Risk Score: ${dlpScan.score}`);
    for (const res of dlpScan.findings) {
      parts.push(`  - Found: ${res.type} (Score: ${res.score})`);
    }
  }

  // Authenticity & Spoofing Analysis
  const authenticity = scanAuthenticity(email);
  if (authenticity.isSpoofed || authenticity.score > 0) {
    parts.push('', 'Sender Authenticity Analysis:');
    parts.push(`  - Spoofing Risk Score: ${authenticity.score}`);
    for (const finding of authenticity.findings) {
      parts.push(`  - Issue: ${finding}`);
    }
    parts.push(`  - SPF: ${authenticity.spf}, DKIM: ${authenticity.dkim}, DMARC: ${authenticity.dmarc}`);
  }

  // URL Analysis
  const urlScan = scanUrls(email.body);
  if (urlScan.length > 0) {
    parts.push('', 'URL Security Analysis:');
    for (const res of urlScan) {
      if (res.riskScore > 0.4) {
        parts.push(`  - High Risk: ${res.url} (Score: ${res.riskScore}, Issues: ${res.risks.join(', ')})`);
      } else {
        parts.push(`  - Low Risk: ${res.url} (Score: ${res.riskScore})`);
      }
    }
  }

  // Attachment Analysis
  if (email.attachments.length > 0) {
    parts.push('', 'Attachments:');
    const suspiciousExts = ['.exe', '.scr', '.vbs', '.js', '.vbe', '.jse', '.wsf', '.wsh', '.ps1', '.bat', '.cmd', '.zip', '.iso', '.msi', '.hta', '.cpl', '.scr'];
    for (const att of email.attachments) {
      const filename = att.filename;
      const lowerName = filename.toLowerCase();
      const ext = lowerName.slice(lowerName.lastIndexOf('.'));
      const isSuspicious = suspiciousExts.includes(ext);

      const issues: string[] = [];
      if (isSuspicious) issues.push('SUSPICIOUS EXTENSION');

      const doubleExtMatch = lowerName.match(/\.(pdf|doc|docx|xls|xlsx|txt|jpg|png|zip)\.(exe|scr|vbs|js|bat|cmd|ps1|msi)$/);
      if (doubleExtMatch) issues.push('HIDDEN/DOUBLE EXTENSION');

      if (filename.includes('\u202E')) issues.push('RLO CHARACTER (SPOOFED FILENAME)');
      if (filename.includes('    ')) issues.push('EXCESSIVE WHITESPACE (EXTENSION HIDING)');

      const issueStr = issues.length > 0 ? ` [${issues.join(', ')}]` : '';
      parts.push(`  - ${filename} (${att.contentType}, ${att.size} bytes)${issueStr}`);
    }
  }

  return parts.join('\n');
}

function buildSummary(email: EmailSummary): string {
  const meta = buildMeta(email);
  // When chunking is disabled, truncate body to 2000 chars as before
  const bodyLimit = config.AGENT_CHUNK_TOKENS > 0 ? email.body.length : 2000;
  const redactedBody = redact(email.body.slice(0, bodyLimit));

  const parts = [
    meta,
    '',
    bodyLimit < email.body.length ? 'Body (truncated, redacted):' : 'Body (redacted):',
    redactedBody,
  ];

  return parts.join('\n');
}

/**
 * Split a full summary into chunks that fit within the token budget.
 * Each chunk includes the metadata header + a portion of the body.
 * Returns a single-element array when chunking is unnecessary.
 */
function splitIntoChunks(email: EmailSummary): string[] {
  if (config.AGENT_CHUNK_TOKENS <= 0) {
    return [buildSummary(email)];
  }

  const meta = buildMeta(email);
  const charsPerToken = 3.5;
  // Body budget = total token limit expressed in chars.
  // Meta is always prepended to every chunk for context but doesn't reduce the body slice size.
  const bodyBudget = config.AGENT_CHUNK_TOKENS * charsPerToken;

  const redactedBody = redact(email.body);

  if (redactedBody.length <= bodyBudget) {
    // Entire body fits in one chunk
    logger.info('filter', `Email fits in 1 chunk (AGENT_CHUNK_TOKENS=${config.AGENT_CHUNK_TOKENS}, body=${redactedBody.length} chars)`);
    return [meta + '\n\nBody (redacted):\n' + redactedBody];
  }

  // Split body into chunks with 10% overlap for context continuity at boundaries.
  // The overlap means each chunk (after the first) rewinds ~10% from the previous
  // chunk's end, so the AI sees a bit of the previous context before the new material.
  const OVERLAP_RATIO = 0.10;
  const overlapSize = Math.floor(bodyBudget * OVERLAP_RATIO);

  const chunks: string[] = [];
  let offset = 0;
  // Effective advance per chunk accounts for the overlap
  const effectiveAdvance = bodyBudget - overlapSize;
  const totalChunks = Math.ceil(redactedBody.length / effectiveAdvance);

  while (offset < redactedBody.length) {
    let sliceEnd = offset + bodyBudget;

    // Don't cut in the middle of a word if possible. Find the last whitespace.
    if (sliceEnd < redactedBody.length) {
      const lastSpace = redactedBody.lastIndexOf(' ', sliceEnd);
      const lastNewline = redactedBody.lastIndexOf('\n', sliceEnd);
      const breakPoint = Math.max(lastSpace, lastNewline);

      // Only adjust if the whitespace is within a reasonable distance (e.g., within the current chunk)
      if (breakPoint > offset) {
        sliceEnd = breakPoint;
      }
    }

    const slice = redactedBody.slice(offset, sliceEnd);
    const chunkNum = chunks.length + 1;
    chunks.push(
      meta +
      `\n\nBody chunk ${chunkNum}/${totalChunks} (redacted):\n` +
      slice,
    );

    // Advance by effectiveAdvance (not the full sliceEnd), creating the overlap.
    // Find a natural word boundary for the next chunk's start too.
    const rawNextOffset = offset + effectiveAdvance;
    const nextNewline = redactedBody.indexOf('\n', rawNextOffset);
    const nextSpace = redactedBody.indexOf(' ', rawNextOffset);
    const nextBreak = Math.min(
      nextNewline > rawNextOffset ? nextNewline : redactedBody.length,
      nextSpace > rawNextOffset ? nextSpace : redactedBody.length,
    );
    offset = nextBreak < redactedBody.length ? nextBreak + 1 : sliceEnd;

    if (offset >= sliceEnd) {
      // Safety: don't get stuck — if overlap logic didn't advance us at all, move forward
      offset = sliceEnd;
      if (sliceEnd < redactedBody.length && (redactedBody[sliceEnd] === ' ' || redactedBody[sliceEnd] === '\n')) {
        offset = sliceEnd + 1;
      }
    }
  }

  logger.info('filter', `Email split into ${chunks.length} chunks (AGENT_CHUNK_TOKENS=${config.AGENT_CHUNK_TOKENS}, body=${redactedBody.length} chars, budget=${bodyBudget} chars/chunk, overlap=${overlapSize} chars)`);
  return chunks;
}

/** Severity ranking for merging decisions (higher = more restrictive). */
const ACTION_SEVERITY: Record<string, number> = { pass: 0, quarantine: 1, reject: 2 };

/**
 * Merge multiple chunk decisions into one.
 * Most restrictive action wins; highest confidence kept; all categories & reasons aggregated.
 */
function mergeDecisions(decisions: FilterDecision[]): FilterDecision {
  if (decisions.length === 1) return decisions[0];

  let merged: FilterDecision = decisions[0];
  const allCategories = new Set<string>(merged.categories);
  const reasons: string[] = [merged.reason];

  for (let i = 1; i < decisions.length; i++) {
    const d = decisions[i];
    const currentSev = ACTION_SEVERITY[merged.action] ?? 0;
    const newSev = ACTION_SEVERITY[d.action] ?? 0;

    if (newSev > currentSev || (newSev === currentSev && d.confidence > merged.confidence)) {
      merged = { ...d, categories: merged.categories };
    }
    for (const c of d.categories) allCategories.add(c);
    if (d.reason && !reasons.includes(d.reason)) reasons.push(d.reason);
  }

  return {
    ...merged,
    categories: Array.from(allCategories),
    reason: reasons.join(' | '),
    confidence: Math.max(...decisions.map(d => d.confidence)),
  };
}

const PASSTHROUGH: FilterDecision = {
  action: 'pass',
  reason: 'Filter unavailable, passing through',
  confidence: 0,
  categories: [],
  unavailable: true,
};

/** Verify connection to the model. */
export async function checkModelConnection(): Promise<{ ok: boolean; message: string }> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000); // 5s timeout for healthcheck

    await getClient().messages.create(
      {
        model: config.ANTHROPIC_MODEL,
        max_tokens: 1,
        messages: [{ role: 'user', content: 'test' }],
      },
      { signal: controller.signal },
    );

    clearTimeout(timeout);
    return { ok: true, message: 'Connection successful' };
  } catch (err: any) {
    return { ok: false, message: err.message };
  }
}

/** Analyze a single content chunk and return a FilterDecision. */
async function analyzeChunk(content: string, filterContext: FilterContext, accountId?: string): Promise<FilterDecision> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.FILTER_TIMEOUT);

  const response = await getClient().messages.create(
    {
      model: config.ANTHROPIC_MODEL,
      max_tokens: 256,
      system: getFilterPrompt(filterContext, accountId),
      messages: [{ role: 'user', content }],
    },
    { signal: controller.signal },
  );

  clearTimeout(timeout);

  const text = response.content[0];
  if (text.type !== 'text') throw new Error('AI returned non-text response');

  // Parse JSON from response, tolerating markdown fences
  let json = text.text.trim();
  if (json.startsWith('```')) {
    json = json.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '');
  }

  const parsed = JSON.parse(json);
  return {
    action: parsed.action || 'quarantine',
    reason: parsed.reason || 'Unknown',
    confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.5,
    categories: Array.isArray(parsed.categories) ? parsed.categories : [],
    move_to: typeof parsed.move_to === 'string' ? parsed.move_to : undefined,
  };
}

export async function inspectEmail(email: EmailSummary, contextOverride?: FilterContext, accountId?: string): Promise<FilterDecision> {
  if (!config.AI_FEATURES_ENABLED) {
    return PASSTHROUGH;
  }

  if (!config.ANTHROPIC_AUTH_TOKEN && !config.ANTHROPIC_BASE_URL.includes('localhost')) {
    if (!config.AUTO_QUARANTINE) return PASSTHROUGH;
    return { action: 'quarantine', reason: 'No API key configured', confidence: 0, categories: [] };
  }

  const filterContext: FilterContext = contextOverride ?? email.direction;
  const chunks = splitIntoChunks(email);

  try {
    // Analyze all chunks (sequentially to respect rate limits)
    const decisions: FilterDecision[] = [];
    for (const chunk of chunks) {
      const decision = await analyzeChunk(chunk, filterContext, accountId);
      decisions.push(decision);

      // Early exit: if any chunk triggers reject, no need to continue
      if (decision.action === 'reject') {
        logger.info('filter', `Chunk ${decisions.length}/${chunks.length} triggered reject — skipping remaining chunks`);
        break;
      }
    }

    return mergeDecisions(decisions);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error('filter', `Agent call failed: ${message}`);

    // Respect configured failure action
    const { AI_FAIL_ACTION } = await import('../config.js');
    if (AI_FAIL_ACTION === 'quarantine') {
      return { action: 'quarantine', reason: `AI unavailable: ${message}`, confidence: 0, categories: [] };
    }
    if (AI_FAIL_ACTION === 'reject') {
      return { action: 'reject', reason: `AI unavailable: ${message}`, confidence: 0, categories: [] };
    }

    return PASSTHROUGH;
  }
}
