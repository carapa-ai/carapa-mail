// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import fs from 'fs';
import path from 'path';
import { PROJECT_ROOT } from '../config.js';
import { getAccountById } from '../accounts.js';

import { DLP_RULES } from '../email/dlp-rules.js';

const PROMPTS_DIR = path.join(PROJECT_ROOT, 'prompts');

function loadPrompt(filename: string): string {
  const filePath = path.join(PROMPTS_DIR, filename);
  return fs.readFileSync(filePath, 'utf-8').trim();
}

let inboundPrompt: string | null = null;
let inboundAgentPrompt: string | null = null;
let outboundPrompt: string | null = null;

export type FilterContext = 'inbound' | 'outbound' | 'inbound-agent';

function getDefaultPrompt(context: FilterContext): string {
  switch (context) {
    case 'inbound':
      if (!inboundPrompt) inboundPrompt = loadPrompt('inbound-filter.md');
      return inboundPrompt;
    case 'inbound-agent':
      if (!inboundAgentPrompt) inboundAgentPrompt = loadPrompt('inbound-agent-filter.md');
      return inboundAgentPrompt;
    case 'outbound':
      if (!outboundPrompt) outboundPrompt = loadPrompt('outbound-filter.md');
      return outboundPrompt;
  }
}

export function getFilterPrompt(context: FilterContext, accountId?: string): string {
  const defaultPrompt = getDefaultPrompt(context);

  if (accountId) {
    const account = getAccountById(accountId);
    if (account) {
      const modeMap = {
        'inbound': { mode: account.customInboundPromptMode, text: account.customInboundPrompt },
        'outbound': { mode: account.customOutboundPromptMode, text: account.customOutboundPrompt },
        'inbound-agent': { mode: account.customAgentPromptMode, text: account.customAgentPrompt },
      } as const;
      const { mode, text } = modeMap[context];
      if (mode === 'replace' && text) return text;
      if (mode === 'append' && text) return defaultPrompt + '\n\n' + text;
    }
  }

  return defaultPrompt;
}

export const SANITIZER_PATTERNS = {
  // Patterns that indicate prompt injection attempts
  prompt_injection: [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /you\s+are\s+now\s+(a|an)\s+/i,
    /system\s*:\s*/i,
    /\[INST\]/i,
    /\[\/INST\]/i,
    /<\|im_start\|>/i,
    /<\|im_end\|>/i,
    /\bhuman\s*:\s*/i,
    /\bassistant\s*:\s*/i,
    /do\s+not\s+follow\s+(the\s+)?(previous|above|original)/i,
    /override\s+(your\s+)?(instructions|programming|rules)/i,
    /disregard\s+(all\s+)?(previous|prior|above)/i,
  ],

  // PII patterns for redaction (derived from DLP rules)
  pii: DLP_RULES.reduce((acc, rule) => {
    acc[rule.piiType.toLowerCase()] = rule.pattern;
    return acc;
  }, {} as Record<string, RegExp>),
};
