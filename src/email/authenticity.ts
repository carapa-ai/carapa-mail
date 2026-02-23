// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import type { EmailSummary } from '../types.js';
import { getLevenshteinDistance } from './url-scanner.js';
import { DKIM_VERIFY } from '../config.js';

export interface AuthenticityScan {
  isSpoofed: boolean;
  score: number; // 0 to 1
  findings: string[];
  spf?: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unknown';
  dkim?: 'pass' | 'fail' | 'neutral' | 'none' | 'unknown';
  dmarc?: 'pass' | 'fail' | 'neutral' | 'none' | 'unknown';
}

const MAJOR_PROVIDERS = ['google.com', 'gmail.com', 'microsoft.com', 'outlook.com', 'hotmail.com', 'apple.com', 'icloud.com', 'amazon.com', 'paypal.com', 'github.com', 'facebook.com', 'netflix.com', 'stripe.com', 'circleci.com'];

// Second-level domain names of brands that legitimately operate across many country TLDs.
// e.g. "amazon" matches amazon.fr, amazon.de, amazon.co.uk, etc.
const TRUSTED_BRAND_SLDS = new Set([
  'amazon', 'google', 'microsoft', 'apple', 'paypal', 'netflix', 'adobe',
  'spotify', 'linkedin', 'facebook', 'instagram', 'twitter', 'github',
  'stripe', 'dropbox', 'slack', 'zoom', 'salesforce',
  // Developer / infrastructure services
  'circleci', 'atlassian', 'bitbucket', 'gitlab', 'datadog', 'sentry',
  'pagerduty', 'cloudflare', 'vercel', 'heroku', 'render', 'railway',
]);

/** Returns the second-level domain portion (part immediately before the TLD). */
function getSld(domain: string): string {
  const parts = domain.split('.');
  return parts.length >= 2 ? parts[parts.length - 2] : domain;
}

/**
 * Perform authenticity and spoofing checks on an email summary.
 */
export function scanAuthenticity(email: EmailSummary): AuthenticityScan {
  const findings: string[] = [];
  let score = 0;
  let isSpoofed = false;

  const headers = email.headers;
  const fromStr = (headers['from'] || email.from || '').toLowerCase();
  const replyToStr = (headers['reply-to'] || '').toLowerCase();
  const returnPath = (headers['return-path'] || '').toLowerCase();

  // 1. Sender Consistency Checks
  const fromEmailMatch = fromStr.match(/<([^>]+)>/);
  const fromEmail = fromEmailMatch ? fromEmailMatch[1] : fromStr.trim();
  const fromName = fromStr.replace(/<[^>]+>/, '').replace(/"/g, '').trim();

  const fromDomain = fromEmail.split('@')[1] || '';

  // 1a. Reply-To mismatch
  if (replyToStr) {
    const replyToEmailMatch = replyToStr.match(/<([^>]+)>/);
    const replyToEmail = replyToEmailMatch ? replyToEmailMatch[1] : replyToStr.trim();

    if (replyToEmail && fromEmail && replyToEmail !== fromEmail) {
      const replyToDomain = replyToEmail.split('@')[1];

      if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
        score += 0.4;
        findings.push(`Reply-To address (${replyToEmail}) domain mismatch with From address (${fromEmail})`);
        isSpoofed = true;
      }
    }
  }

  // 1b. Display name spoofing (e.g., "From: Security <attacker@mail.com>")
  const suspiciousNames = ['security', 'support', 'billing', 'admin', 'service', 'account', 'verify', 'update', 'login', 'official', 'it desk', 'help desk'];
  if (fromName && fromEmail) {
    const nameLower = fromName.toLowerCase();

    // If the name contains a suspicious keyword but the domain is not associated with it
    if (suspiciousNames.some(name => nameLower.includes(name))) {
      const isTrusted = MAJOR_PROVIDERS.some(service => fromDomain === service || fromDomain.endsWith('.' + service))
        || TRUSTED_BRAND_SLDS.has(getSld(fromDomain));
      if (!isTrusted) {
        score += 0.2;
        findings.push(`Display name "${fromName}" contains security keywords from an untrusted domain (${fromDomain})`);
      }
    }

    // Check for lookalike characters in display name (homograph)
    if (/[^\x00-\x7F]/.test(fromName)) {
      score += 0.3;
      findings.push('Display name contains non-ASCII characters (potential homograph attack)');
    }
  }

  // 1c. Lookalike domain detection for major providers
  if (fromDomain) {
    // Skip check for domains whose SLD is a known trusted brand (e.g. amazon.fr, google.co.uk)
    if (!TRUSTED_BRAND_SLDS.has(getSld(fromDomain))) {
      for (const provider of MAJOR_PROVIDERS) {
        if (fromDomain === provider) break;
        const distance = getLevenshteinDistance(fromDomain, provider);
        if (distance > 0 && distance <= (provider.length > 10 ? 2 : 1)) {
          score += 0.7;
          findings.push(`Sender domain ${fromDomain} is a potential lookalike of ${provider}`);
          isSpoofed = true;
          break;
        }
      }
    }
  }

  // 1d. Header Consistency Checks
  const messageId = (headers['message-id'] || '').toLowerCase();
  if (messageId && fromDomain) {
    const idDomainMatch = messageId.match(/@([^>]+)>?/);
    if (idDomainMatch) {
      const idDomain = idDomainMatch[1];
      // If the Message-ID domain is completely different from the From domain, and it's not a common mailing list/relay
      const commonRelays = ['amazonses.com', 'sendgrid.net', 'mailgun.org', 'mandrillapp.com', 'postal.io', 'outlook.com', 'google.com', 'gmail.com'];
      if (idDomain !== fromDomain && !fromDomain.endsWith('.' + idDomain) && !idDomain.endsWith('.' + fromDomain)) {
        if (!commonRelays.some(relay => idDomain.includes(relay))) {
          score += 0.2;
          findings.push(`Message-ID domain (${idDomain}) does not match From domain (${fromDomain})`);
        }
      }
    }
  }

  if (returnPath && fromDomain) {
    const rpEmailMatch = returnPath.match(/<([^>]+)>/);
    const rpEmail = rpEmailMatch ? rpEmailMatch[1] : returnPath.trim();
    const rpDomain = rpEmail.split('@')[1];

    if (rpDomain && rpDomain !== fromDomain && !fromDomain.endsWith('.' + rpDomain) && !rpDomain.endsWith('.' + fromDomain)) {
      score += 0.3;
      findings.push(`Return-Path domain (${rpDomain}) does not match From domain (${fromDomain})`);
    }
  }

  // 2. Authentication Header Review
  // Analysis of Authentication-Results (added by upstream SMTP)
  const authResults = headers['authentication-results'] || '';
  let spfStatus: AuthenticityScan['spf'] = 'unknown';
  let dkimStatus: AuthenticityScan['dkim'] = 'unknown';
  let dmarcStatus: AuthenticityScan['dmarc'] = 'unknown';

  if (authResults) {
    // Basic regex-based parsing of authentication results
    if (authResults.includes('spf=pass')) spfStatus = 'pass';
    else if (authResults.includes('spf=fail')) spfStatus = 'fail';
    else if (authResults.includes('spf=softfail')) spfStatus = 'softfail';
    else if (authResults.includes('spf=none')) spfStatus = 'none';

    if (authResults.includes('dkim=pass')) dkimStatus = 'pass';
    else if (authResults.includes('dkim=fail')) dkimStatus = 'fail';
    else if (authResults.includes('dkim=none')) dkimStatus = 'none';

    if (authResults.includes('dmarc=pass')) dmarcStatus = 'pass';
    else if (authResults.includes('dmarc=fail')) dmarcStatus = 'fail';
    else if (authResults.includes('dmarc=none')) dmarcStatus = 'none';
  }

  // Fallback to Received-SPF
  if (spfStatus === 'unknown' && headers['received-spf']) {
    const receivedSpf = headers['received-spf'].toLowerCase();
    if (receivedSpf.startsWith('pass')) spfStatus = 'pass';
    else if (receivedSpf.startsWith('fail')) spfStatus = 'fail';
    else if (receivedSpf.startsWith('softfail')) spfStatus = 'softfail';
  }

  // Impact on score
  if (spfStatus === 'fail') {
    score += 0.5;
    findings.push('SPF authentication failed (Unauthorized sender server)');
    isSpoofed = true;
  }
  if (dkimStatus === 'fail') {
    score += 0.5;
    findings.push('DKIM signature failed (Message may have been tampered with or sender is unauthorized)');
    isSpoofed = true;
  }
  if (dmarcStatus === 'fail') {
    score += 0.7;
    findings.push('DMARC authentication failed (High certainty of spoofing/impersonation)');
    isSpoofed = true;
  }

  // Stricter verification mode: penalize missing authentication data
  if (DKIM_VERIFY) {
    if (!authResults && !headers['received-spf']) {
      score += 0.4;
      findings.push('DKIM_VERIFY enabled but no Authentication-Results header found — cannot verify sender');
      isSpoofed = true;
    }
    if (dkimStatus === 'none' || dkimStatus === 'unknown') {
      score += 0.3;
      findings.push('DKIM_VERIFY enabled: DKIM signature missing or unverifiable');
    }
  }

  // 3. Sensitive Header Scanning
  const suspiciousHeaders = [
    { name: 'x-php-originating-script', reason: 'Sent via PHP script (often associated with bulk mail or automated exploits)' },
    { name: 'x-mailer', reason: 'Custom X-Mailer header (common in bulk mail tools)' },
    { name: 'x-get-message-it-from', reason: 'Unusual X-Get-Message-It-From header (often spoofed)' },
    { name: 'x-sender-ip', reason: 'Specific sender IP exposed (can be checked against blacklists)' },
  ];

  for (const { name, reason } of suspiciousHeaders) {
    if (headers[name]) {
      score += 0.1;
      findings.push(`Suspicious header detected: ${name} (${reason})`);
    }
  }

  // 4. If both SPF and DKIM are none/unknown for a message from a well-known service, it's suspicious
  const wellKnownDomains = ['gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com', 'icloud.com'];
  if (fromEmail) {
    const fromDomain = fromEmail.split('@')[1];
    if (wellKnownDomains.includes(fromDomain)) {
      if (spfStatus === 'none' && dkimStatus === 'none') {
        score += 0.3;
        findings.push(`Message from major provider ${fromDomain} has no SPF/DKIM authentication`);
      }
    }
  }

  if (email.isEncrypted) {
    findings.push('Encrypted message detected (Content could not be scanned for threats)');
  }
  if (email.isSigned) {
    findings.push('Digitally signed message detected');
  }

  return {
    isSpoofed,
    score: Math.min(score, 1),
    findings,
    spf: spfStatus,
    dkim: dkimStatus,
    dmarc: dmarcStatus,
  };
}
