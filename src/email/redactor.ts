// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { DLP_RULES } from './dlp-rules.js';
import { redactSecrets } from './secret-scanner.js';

/**
 * Simple redactor to mask sensitive information from email summaries before sending to AI.
 * This is a best-effort implementation to improve privacy.
 */
export function redact(text: string): string {
  if (!text) return '';

  let redacted = text;

  // Mask Secrets (API keys, tokens, etc.) via entropy-based scanner
  redacted = redactSecrets(redacted);

  // Mask PII via DLP rules
  for (const { pattern, piiType } of DLP_RULES) {
    // Avoid masking common date formats like 2024-02-22 when scanning for phone numbers
    if (piiType === 'PHONE') {
      redacted = redacted.replace(pattern, (match) => {
        if (/^\d{4}-\d{2}-\d{2}$/.test(match)) return match;
        return `[REDACTED:${piiType}]`;
      });
    } else {
      redacted = redacted.replace(pattern, `[REDACTED:${piiType}]`);
    }
  }

  return redacted;
}

export function redactObject<T extends Record<string, any>>(obj: T, fieldsToRedact: string[]): T {
  const result = { ...obj } as any;
  for (const field of fieldsToRedact) {
    if (typeof result[field] === 'string') {
      result[field] = redact(result[field]);
    }
  }
  return result as T;
}
