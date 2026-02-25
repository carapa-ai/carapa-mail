// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

export interface FilterDecision {
  action: 'pass' | 'reject' | 'quarantine';
  reason: string;
  confidence: number;
  categories: string[];
  move_to?: string; // Target IMAP folder (e.g. "Spam", "Work"). Omit to leave in place.
  unavailable?: boolean; // True when AI filter was unreachable (timeout, API error, etc.)
}

export interface QuarantineEntry {
  id: string;
  direction: 'inbound' | 'outbound';
  from_addr: string;
  to_addr: string;
  subject: string;
  body_preview: string;
  raw_eml: Buffer;
  reason: string;
  categories: string;
  confidence: number;
  status: 'pending' | 'released' | 'deleted';
  account_id: string;
  created_at: string;
  reviewed_at: string | null;
}

export interface AuditEntry {
  id: number;
  direction: 'inbound' | 'outbound';
  from_addr: string;
  to_addr: string;
  subject: string;
  action: 'pass' | 'reject' | 'quarantine';
  reason: string;
  categories: string;
  confidence: number;
  latency_ms: number;
  account_id: string;
  created_at: string;
}

export interface FilterRule {
  id: string;
  type: 'allow' | 'block' | 'quarantine';
  match_field: 'from' | 'to' | 'subject' | 'body';
  match_pattern: string;
  priority: number;
  direction: 'inbound' | 'outbound' | 'both';
  created_at: string;
}

export interface EmailSummary {
  direction: 'inbound' | 'outbound';
  from: string;
  to: string;
  subject: string;
  body: string;
  attachments: { filename: string; contentType: string; size: number; isEncrypted?: boolean }[];
  headers: Record<string, string>;
  isEncrypted?: boolean;
  isSigned?: boolean;
}

export type SecurityLevel = 'strict' | 'standard' | 'minimal' | 'audit-only';

export interface FolderPolicy {
  level: SecurityLevel;
  skipAi?: boolean;
  skipSanitization?: boolean;
  autoQuarantine?: boolean;
}

export interface FolderContext {
  folder: string;
  uidValidity: number;
  accountId: string;
  policy: FolderPolicy;
}
