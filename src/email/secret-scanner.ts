// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import type { ParsedMail } from 'mailparser';

/**
 * Common patterns for sensitive information (API keys, secrets, tokens).
 */
export const SECRET_PATTERNS = [
  { name: 'AWS Access Key', regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'AWS Secret Key', regex: /\b[a-zA-Z0-9+/]{40}\b/g, entropy: 4.5 }, // High entropy string of length 40
  { name: 'GitHub Personal Access Token', regex: /\bghp_[a-zA-Z0-9]{36,255}\b/g },
  { name: 'GitHub OAuth Token', regex: /\bgho_[a-zA-Z0-9]{36,255}\b/g },
  { name: 'Slack Token', regex: /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/g },
  { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+\b/g },
  { name: 'Stripe Secret Key', regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g },
  { name: 'Stripe Restricted Key', regex: /\brk_live_[0-9a-zA-Z]{24,}\b/g },
  { name: 'OpenAI API Key', regex: /\bsk-[a-zA-Z0-9]{20,T3BlbkFJ}[a-zA-Z0-9]{20,}\b/g },
  { name: 'Google API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: 'Discord Webhook', regex: /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+\b/g },
  { name: 'Discord Bot Token', regex: /\b[MN][a-zA-Z0-9_]{23}\.[a-zA-Z0-9_]{6}\.[a-zA-Z0-9_]{27}\b/g },
  { name: 'Private Key (PEM)', regex: /-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/g },
  { name: 'Credit Card', regex: /\b(?:\d[ -]*?){13,16}\b/g },
];

export interface SecretFinding {
  name: string;
  match: string;
  index: number;
  location: string; // 'body', 'subject', or filename
}

/**
 * Scan text for common secret patterns.
 */
export function scanSecrets(text: string, location = 'text'): SecretFinding[] {
  const findings: SecretFinding[] = [];

  if (!text) return findings;

  for (const pattern of SECRET_PATTERNS) {
    let match;
    // Reset regex index for global matches
    pattern.regex.lastIndex = 0;
    while ((match = pattern.regex.exec(text)) !== null) {
      const matchStr = match[0];

      // If entropy is specified, check it
      if (pattern.entropy) {
        if (calculateEntropy(matchStr) < pattern.entropy) {
          continue; // Skip if entropy is too low (might be a false positive)
        }
      }

      findings.push({
        name: pattern.name,
        match: matchStr,
        index: match.index,
        location,
      });
    }
  }

  // Also look for generic high-entropy strings that might be secrets
  // (e.g., long strings of random-looking characters)
  const genericLongStrings = text.match(/\b[a-zA-Z0-9+/]{32,}\b/g) || [];
  for (const str of genericLongStrings) {
    if (calculateEntropy(str) > 4.5 && !findings.some(f => f.match === str)) {
      findings.push({
        name: 'High-Entropy Secret',
        match: str,
        index: text.indexOf(str),
        location,
      });
    }
  }

  return findings;
}

/**
 * Scan an entire email (ParsedMail) for secrets.
 */
export function scanEmailForSecrets(parsed: ParsedMail): SecretFinding[] {
  const findings: SecretFinding[] = [];

  // Scan subject
  findings.push(...scanSecrets(parsed.subject || '', 'subject'));

  // Scan body
  findings.push(...scanSecrets(parsed.text || '', 'body'));
  if (parsed.html && typeof parsed.html === 'string') {
    // Basic HTML tag stripping for scanning
    const textFromHtml = parsed.html.replace(/<[^>]*>?/gm, ' ');
    findings.push(...scanSecrets(textFromHtml, 'body (html)'));
  }

  // Scan attachments (only text-based ones)
  for (const att of parsed.attachments || []) {
    const isText = att.contentType.startsWith('text/') ||
      att.contentType === 'application/json' ||
      att.contentType === 'application/javascript' ||
      att.contentType === 'application/xml' ||
      att.filename?.endsWith('.yml') ||
      att.filename?.endsWith('.yaml') ||
      att.filename?.endsWith('.env') ||
      att.filename?.endsWith('.py') ||
      att.filename?.endsWith('.js') ||
      att.filename?.endsWith('.ts');

    if (isText && att.content) {
      const content = att.content.toString('utf-8');
      findings.push(...scanSecrets(content, `attachment:${att.filename || 'unnamed'}`));
    }
  }

  // Deduplicate findings by match string
  const uniqueFindings = new Map<string, SecretFinding>();
  for (const f of findings) {
    if (!uniqueFindings.has(f.match)) {
      uniqueFindings.set(f.match, f);
    }
  }

  return Array.from(uniqueFindings.values());
}


/**
 * Redact secrets from text.
 */
export function redactSecrets(text: string): string {
  let redacted = text;
  const findings = scanSecrets(text);

  // Sort findings by index descending to avoid changing positions of upcoming matches
  findings.sort((a, b) => b.index - a.index);

  for (const finding of findings) {
    const start = finding.index;
    const end = start + finding.match.length;
    redacted = redacted.substring(0, start) + `[${finding.name.toUpperCase()}_REDACTED]` + redacted.substring(end);
  }

  return redacted;
}

/**
 * Calculate Shannon entropy.
 */
function calculateEntropy(str: string): number {
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
