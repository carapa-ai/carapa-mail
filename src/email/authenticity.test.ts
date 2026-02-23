// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe } from 'bun:test';
import { scanAuthenticity } from './authenticity.js';
import type { EmailSummary } from '../types.js';

function makeEmail(overrides: Partial<EmailSummary> = {}): EmailSummary {
  return {
    direction: 'inbound',
    from: 'sender@example.com',
    to: 'recipient@test.com',
    subject: 'Test',
    body: 'Hello',
    attachments: [],
    headers: {},
    ...overrides,
  };
}

describe('Authenticity Scanner', () => {
  test('clean email from unknown domain has no findings', () => {
    const result = scanAuthenticity(makeEmail());
    expect(result.isSpoofed).toBe(false);
    expect(result.findings).toHaveLength(0);
    expect(result.score).toBe(0);
  });

  test('detects Reply-To domain mismatch', () => {
    const result = scanAuthenticity(makeEmail({
      from: 'ceo@company.com',
      headers: { 'reply-to': 'attacker@evil.com' },
    }));
    expect(result.isSpoofed).toBe(true);
    expect(result.findings.some(f => f.includes('Reply-To'))).toBe(true);
    expect(result.score).toBeGreaterThan(0);
  });

  test('Reply-To same domain is not flagged', () => {
    const result = scanAuthenticity(makeEmail({
      from: 'alice@company.com',
      headers: { 'reply-to': 'noreply@company.com' },
    }));
    // Same domain, different address — not a mismatch
    expect(result.findings.some(f => f.includes('Reply-To'))).toBe(false);
  });

  test('detects display name spoofing with security keywords', () => {
    const result = scanAuthenticity(makeEmail({
      from: '"Security Alert" <phisher@sketchy.xyz>',
      headers: { from: '"Security Alert" <phisher@sketchy.xyz>' },
    }));
    expect(result.findings.some(f => f.includes('security keywords'))).toBe(true);
    expect(result.score).toBeGreaterThan(0);
  });

  test('security keywords from major provider are not flagged', () => {
    const result = scanAuthenticity(makeEmail({
      from: '"Google Security" <noreply@google.com>',
      headers: { from: '"Google Security" <noreply@google.com>' },
    }));
    expect(result.findings.some(f => f.includes('security keywords'))).toBe(false);
  });

  test('detects non-ASCII in display name', () => {
    const result = scanAuthenticity(makeEmail({
      from: '"Gооgle" <fake@evil.com>',  // Cyrillic 'о' characters
      headers: { from: '"Gооgle" <fake@evil.com>' },
    }));
    expect(result.findings.some(f => f.includes('non-ASCII'))).toBe(true);
  });

  test('detects lookalike domain for major provider', () => {
    const result = scanAuthenticity(makeEmail({
      from: 'noreply@gogle.com',  // missing one 'o'
      headers: { from: 'noreply@gogle.com' },
    }));
    expect(result.isSpoofed).toBe(true);
    expect(result.findings.some(f => f.includes('lookalike'))).toBe(true);
    expect(result.score).toBeGreaterThan(0.5);
  });

  test('parses SPF/DKIM/DMARC from authentication-results', () => {
    const result = scanAuthenticity(makeEmail({
      headers: {
        'authentication-results': 'mx.google.com; spf=pass; dkim=pass; dmarc=pass',
      },
    }));
    expect(result.spf).toBe('pass');
    expect(result.dkim).toBe('pass');
    expect(result.dmarc).toBe('pass');
    expect(result.score).toBe(0);
  });

  test('SPF fail increases score', () => {
    const result = scanAuthenticity(makeEmail({
      headers: {
        'authentication-results': 'mx.google.com; spf=fail; dkim=pass; dmarc=pass',
      },
    }));
    expect(result.spf).toBe('fail');
    expect(result.isSpoofed).toBe(true);
    expect(result.score).toBeGreaterThan(0);
    expect(result.findings.some(f => f.includes('SPF'))).toBe(true);
  });

  test('DKIM fail increases score', () => {
    const result = scanAuthenticity(makeEmail({
      headers: {
        'authentication-results': 'mx.google.com; spf=pass; dkim=fail; dmarc=pass',
      },
    }));
    expect(result.dkim).toBe('fail');
    expect(result.isSpoofed).toBe(true);
    expect(result.findings.some(f => f.includes('DKIM'))).toBe(true);
  });

  test('DMARC fail is high severity', () => {
    const result = scanAuthenticity(makeEmail({
      headers: {
        'authentication-results': 'mx.google.com; spf=pass; dkim=pass; dmarc=fail',
      },
    }));
    expect(result.dmarc).toBe('fail');
    expect(result.isSpoofed).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(0.7);
  });

  test('falls back to Received-SPF header', () => {
    const result = scanAuthenticity(makeEmail({
      headers: {
        'received-spf': 'pass (google.com: domain of sender@example.com designates...)',
      },
    }));
    expect(result.spf).toBe('pass');
  });

  test('Received-SPF fail detected', () => {
    const result = scanAuthenticity(makeEmail({
      headers: {
        'received-spf': 'fail (google.com: domain of sender@example.com does not designate...)',
      },
    }));
    expect(result.spf).toBe('fail');
    expect(result.isSpoofed).toBe(true);
  });

  test('well-known provider with no SPF/DKIM is suspicious', () => {
    const result = scanAuthenticity(makeEmail({
      from: 'user@gmail.com',
      headers: {
        'authentication-results': 'mx.example.com; spf=none; dkim=none',
      },
    }));
    expect(result.findings.some(f => f.includes('no SPF/DKIM'))).toBe(true);
    expect(result.score).toBeGreaterThan(0);
  });

  test('no headers returns all unknown', () => {
    const result = scanAuthenticity(makeEmail({ headers: {} }));
    expect(result.spf).toBe('unknown');
    expect(result.dkim).toBe('unknown');
    expect(result.dmarc).toBe('unknown');
  });

  test('score is capped at 1.0', () => {
    // Combine multiple risk factors
    const result = scanAuthenticity(makeEmail({
      from: '"Support" <phisher@gogle.com>',
      headers: {
        from: '"Support" <phisher@gogle.com>',
        'reply-to': 'attacker@evil.com',
        'authentication-results': 'spf=fail; dkim=fail; dmarc=fail',
      },
    }));
    expect(result.score).toBeLessThanOrEqual(1);
  });
});
