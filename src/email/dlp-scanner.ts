// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { DLP_RULES } from './dlp-rules.js';

export interface DlpFinding {
  type: string;
  match: string;
  score: number;
}

/**
 * Scan text for potential sensitive data exposure (DLP).
 */
export function scanDlp(text: string): { score: number; findings: DlpFinding[] } {
  if (!text) return { score: 0, findings: [] };

  const findings: DlpFinding[] = [];
  let totalScore = 0;

  for (const { name, pattern, score } of DLP_RULES) {
    const matches = text.match(pattern);
    if (matches) {
      for (const match of matches) {
        // Simple deduplication of same type/match
        if (!findings.some(f => f.type === name && f.match === match)) {
          findings.push({ type: name, match: match.trim(), score });
          totalScore += score;
        }
      }
    }
  }

  return {
    score: Math.min(totalScore, 1.0),
    findings,
  };
}
