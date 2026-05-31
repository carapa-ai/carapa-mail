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

/**
 * Concurrency limiter for AI requests.
 * Local models (Ollama, llama.cpp) crash under concurrent requests.
 * Controlled via MAX_PARALLEL_AI_CALLS (default 1 = serial).
 */
let aiRunning = 0;
const aiWaiters: (() => void)[] = [];

function enqueue<T>(fn: () => Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const run = () => {
      aiRunning++;
      fn().then(resolve, reject).finally(() => {
        aiRunning--;
        if (aiWaiters.length > 0) aiWaiters.shift()!();
      });
    };

    if (aiRunning < config.MAX_PARALLEL_AI_CALLS) {
      run();
    } else {
      aiWaiters.push(run);
    }
  });
}

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
 * Yield every top-level, brace-balanced `{...}` object in a string, in order,
 * respecting strings/escapes so braces inside quoted values don't confuse it.
 * Used to recover the real verdict even when a model emits extra objects
 * (e.g. an echoed schema template) before or after it.
 */
function* balancedObjects(s: string): Generator<string> {
  let i = 0;
  while (i < s.length) {
    const start = s.indexOf('{', i);
    if (start === -1) return;
    let depth = 0;
    let inStr = false;
    let esc = false;
    let end = -1;
    for (let j = start; j < s.length; j++) {
      const ch = s[j];
      if (inStr) {
        if (esc) esc = false;
        else if (ch === '\\') esc = true;
        else if (ch === '"') inStr = false;
      } else if (ch === '"') {
        inStr = true;
      } else if (ch === '{') {
        depth++;
      } else if (ch === '}') {
        depth--;
        if (depth === 0) { end = j; break; }
      }
    }
    if (end === -1) return; // unterminated object — nothing more to find
    yield s.slice(start, end + 1);
    i = end + 1;
  }
}

/**
 * Extract a JSON object from an LLM response. Reasoning/instruct models routinely
 * surround the answer with prose ("I'll set action to pass."), markdown fences,
 * or even emit a *second* JSON block while second-guessing themselves. We must
 * take the FIRST complete object, not everything between the first `{` and last
 * `}` (which would span multiple blocks). Strategy, in order:
 *   1. the first fenced ```json block, if any;
 *   2. the whole string (already-clean JSON);
 *   3. each brace-balanced object in the text, in order, until one parses.
 * Throws if none parse.
 */
function extractJsonObject(raw: string): any {
  const s = raw.trim();
  const candidates: string[] = [];

  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) candidates.push(fence[1].trim());

  candidates.push(s);

  for (const obj of balancedObjects(s)) candidates.push(obj);

  for (const c of candidates) {
    try {
      const parsed = JSON.parse(c);
      if (parsed && typeof parsed === 'object') return parsed;
    } catch {
      // try next candidate
    }
  }
  throw new SyntaxError(`No JSON object in model response: ${s.slice(0, 80)}`);
}

interface HeaderAnalysisReport {
  is_authentic: boolean;
  risk_score: number;
  findings: string[];
  summary: string;
}

/**
 * Perform a technical audit of email headers to detect spoofing and relay anomalies.
 */
async function analyzeHeaders(email: EmailSummary, accountId?: string): Promise<HeaderAnalysisReport | null> {
  const headerContent = Object.entries(email.headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');

  if (!headerContent) return null;

  return enqueue(async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.FILTER_TIMEOUT);

    try {
      const response = await getClient().messages.create(
        {
          model: config.ANTHROPIC_MODEL,
          max_tokens: 1024,
          system: getFilterPrompt('header-analysis', accountId),
          messages: [{ role: 'user', content: `Analyze these email headers:\n\n${headerContent}` }],
        },
        { signal: controller.signal },
      );

      clearTimeout(timeout);

      const text = response.content.find(block => block.type === 'text');
      if (!text || text.type !== 'text') return null;

      return extractJsonObject(text.text) as HeaderAnalysisReport;
    } catch (err) {
      logger.warn('filter', `Header analysis failed: ${err instanceof Error ? err.message : String(err)}`);
      return null;
    } finally {
      clearTimeout(timeout);
    }
  });
}

/**
 * Build the metadata header that prefixes every chunk.
 */
function buildMeta(email: EmailSummary, headerReport?: HeaderAnalysisReport | null): string {
  const redactedSubject = redact(email.subject);

  const parts = [
    `Direction: ${email.direction}`,
    `From: ${email.from}`,
    `To: ${email.to}`,
    `Subject: ${redactedSubject}`,
    '',
    'Headers (Audit-relevant):',
    ...Object.entries(email.headers)
      .filter(([k]) => k !== 'received') // Exclude raw Received chains from the main prompt to save tokens
      .slice(0, 15)
      .map(([k, v]) => `  ${k}: ${v}`),
  ];

  if (headerReport) {
    parts.push('', '--- TECHNICAL HEADER AUDIT REPORT ---');
    parts.push(`Authentic: ${headerReport.is_authentic ? 'YES' : 'NO'}`);
    parts.push(`Technical Risk Score: ${headerReport.risk_score}`);
    parts.push(`Auditor Summary: ${headerReport.summary}`);
    if (headerReport.findings.length > 0) {
      parts.push('Forensic Findings:');
      for (const f of headerReport.findings) parts.push(`  - ${f}`);
    }
    parts.push('-------------------------------------');
  }

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

function buildSummary(email: EmailSummary, headerReport?: HeaderAnalysisReport | null): string {
  const meta = buildMeta(email, headerReport);
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
function splitIntoChunks(email: EmailSummary, headerReport?: HeaderAnalysisReport | null): string[] {
  if (config.AGENT_CHUNK_TOKENS <= 0) {
    return [buildSummary(email, headerReport)];
  }

  const meta = buildMeta(email, headerReport);
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

/** Correction sent when the first response can't be parsed into a verdict. */
const STRICT_JSON_RETRY =
  'Your previous reply could not be parsed. Respond with ONLY the single JSON object described in the ' +
  'system prompt — no preamble, no explanation, no markdown code fences, and do not output more than one object.';

/** Call the filter model once and return its text block + stop reason. */
async function callFilterModel(
  systemPrompt: string,
  messages: Anthropic.MessageParam[],
): Promise<{ text: string; stopReason: string | null }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.FILTER_TIMEOUT);
  try {
    const isAnthropicApi = config.ANTHROPIC_BASE_URL.includes('anthropic.com');
    const response = await getClient().messages.create(
      {
        model: config.ANTHROPIC_MODEL,
        max_tokens: 1024,
        ...(isAnthropicApi ? { thinking: { type: 'disabled' as const } } : {}),
        system: systemPrompt,
        messages,
      },
      { signal: controller.signal },
    );
    const text = response.content.find(block => block.type === 'text');
    if (!text || text.type !== 'text') {
      throw new Error(`AI returned no text block (got ${response.content.length} blocks: ${response.content.map(b => b.type).join(', ') || 'empty'})`);
    }
    return { text: text.text, stopReason: response.stop_reason };
  } finally {
    clearTimeout(timeout);
  }
}

function toDecision(parsed: any): FilterDecision {
  return {
    action: parsed.action || 'quarantine',
    reason: parsed.reason || 'Unknown',
    confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.5,
    categories: Array.isArray(parsed.categories) ? parsed.categories : [],
    move_to: typeof parsed.move_to === 'string' ? parsed.move_to : undefined,
  };
}

/** Analyze a single content chunk and return a FilterDecision. */
function analyzeChunk(content: string, filterContext: FilterContext, accountId?: string): Promise<FilterDecision> {
  return enqueue(async () => {
    const systemPrompt = getFilterPrompt(filterContext, accountId);
    logger.debug('filter', `LLM request: model=${config.ANTHROPIC_MODEL} base=${config.ANTHROPIC_BASE_URL} context=${filterContext} sysPromptChars=${systemPrompt.length} contentChars=${content.length}`);
    if (!systemPrompt) logger.warn('filter', `Empty system prompt for context=${filterContext} account=${accountId ?? 'none'} — model will not know to emit JSON`);

    const messages: Anthropic.MessageParam[] = [{ role: 'user', content }];
    const first = await callFilterModel(systemPrompt, messages);
    try {
      return toDecision(extractJsonObject(first.text));
    } catch {
      // The model rambled or emitted multiple/garbled objects. Feed its own reply
      // back with a strict instruction and retry once before giving up.
      logger.warn('filter', `Unparseable LLM response (context=${filterContext}, ${first.text.length} chars, stop=${first.stopReason}) — retrying with strict-JSON instruction: ${JSON.stringify(first.text.slice(0, 300))}`);
      const retry = await callFilterModel(systemPrompt, [
        ...messages,
        { role: 'assistant', content: first.text },
        { role: 'user', content: STRICT_JSON_RETRY },
      ]);
      try {
        return toDecision(extractJsonObject(retry.text));
      } catch (parseErr) {
        logger.warn('filter', `Retry still unparseable (context=${filterContext}, ${retry.text.length} chars, stop=${retry.stopReason}): ${JSON.stringify(retry.text.slice(0, 300))}`);
        throw parseErr;
      }
    }
  });
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

  // 1. Header Analysis pass (inbound only, if not already bypassed by rules/whitelist)
  let headerReport: HeaderAnalysisReport | null = null;
  if (config.HEADER_ANALYSIS_ENABLED && filterContext === 'inbound' && Object.keys(email.headers).length > 0) {
    headerReport = await analyzeHeaders(email, accountId);
  }

  const chunks = splitIntoChunks(email, headerReport);

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

    // Respect configured failure action. Mark the decision `unavailable` so callers
    // treat it as a TRANSIENT failure (withhold/quarantine for this read) and do NOT
    // persist it to the scan cache — otherwise a one-off parse error / timeout / empty
    // body would block the email permanently on every subsequent read.
    const { AI_FAIL_ACTION } = await import('../config.js');
    if (AI_FAIL_ACTION === 'quarantine') {
      return { action: 'quarantine', reason: `AI unavailable: ${message}`, confidence: 0, categories: [], unavailable: true };
    }
    if (AI_FAIL_ACTION === 'reject') {
      return { action: 'reject', reason: `AI unavailable: ${message}`, confidence: 0, categories: [], unavailable: true };
    }

    return PASSTHROUGH;
  }
}
