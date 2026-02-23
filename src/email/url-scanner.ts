// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

export interface ScannedUrl {
  url: string;
  domain: string;
  riskScore: number; // 0 to 1
  risks: string[];
}

/**
 * Extract URLs from a text body.
 */
export function extractUrls(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s<>"']+/g;
  const matches = text.match(urlRegex) || [];
  // Clean trailing punctuation that might be part of the sentence but not the URL
  return [...new Set(matches.map(url => url.replace(/[.,;!)]+$/, '')))];
}

/**
 * Basic risk analysis of a URL.
 */
export function analyzeUrl(url: string): ScannedUrl {
  let domain = '';
  try {
    const parsed = new URL(url);
    domain = parsed.hostname.toLowerCase();
  } catch {
    domain = 'invalid';
  }

  // 0. Whitelist for common trusted domains
  const safeDomains = [
    'google.com', 'microsoft.com', 'apple.com', 'github.com', 'slack.com',
    'zoom.us', 'dropbox.com', 'notion.so', 'amazon.com', 'aws.amazon.com',
    'facebook.com', 'linkedin.com', 'twitter.com', 'x.com', 'instagram.com',
    'paypal.com', 'netflix.com', 'adobe.com', 'spotify.com', 'salesforce.com',
    'stripe.com', 'circleci.com', 'atlassian.com', 'jira.com', 'confluence.com',
  ];
  if (safeDomains.some(safe => domain === safe || domain.endsWith('.' + safe))) {
    return { url, domain, riskScore: 0, risks: [] };
  }

  // 0b. Multi-TLD brand whitelist: well-known brands that operate across many country TLDs.
  // Match on the second-level domain name (e.g. "amazon" covers amazon.fr, amazon.de, amazon.co.uk …).
  const safeDomainBases = [
    'amazon', 'google', 'microsoft', 'apple', 'paypal', 'netflix', 'adobe',
    'spotify', 'linkedin', 'facebook', 'instagram', 'twitter', 'github',
    'stripe', 'dropbox', 'slack', 'zoom', 'salesforce',
    // Developer / infrastructure services
    'circleci', 'atlassian', 'bitbucket', 'gitlab', 'datadog', 'sentry',
    'pagerduty', 'cloudflare', 'vercel', 'heroku', 'render', 'railway',
  ];
  // Extract the second-level domain (part just before the TLD).
  // For "mail.amazon.fr" → ["mail","amazon","fr"] → sld = "amazon"
  // For "amazon.fr"      → ["amazon","fr"]         → sld = "amazon"
  const domainParts = domain.split('.');
  const sld = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : domain;
  if (safeDomainBases.includes(sld)) {
    return { url, domain, riskScore: 0, risks: [] };
  }

  const risks: string[] = [];
  let riskScore = 0;

  // 1. Typosquatting/Homograph Detection
  for (const safe of safeDomains) {
    const distance = getLevenshteinDistance(domain, safe);
    // If distance is 1-2 (one or two chars off), it's likely typosquatting
    if (distance > 0 && distance <= 2) {
      riskScore += 0.6;
      risks.push(`Potential typosquatting for ${safe}`);
      break;
    }
  }

  // 2. Entropy Analysis (DGA detection)
  const entropy = calculateEntropy(domain.split('.')[0]); // Check the main domain part
  if (entropy > 3.5 && domain.length > 10) {
    riskScore += 0.3;
    risks.push('High domain entropy (potential DGA or random domain)');
  }

  // 3. IP address as hostname
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
    riskScore += 0.5;
    risks.push('IP address used as hostname');
  }

  // 4. Suspicious TLDs (basic list)
  const suspiciousTlds = ['.zip', '.mov', '.top', '.xyz', '.loan', '.win', '.bid'];
  if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
    riskScore += 0.3;
    risks.push('Suspicious TLD');
  }

  // 5. Excessively long URL
  if (url.length > 200) {
    riskScore += 0.2;
    risks.push('Excessively long URL');
  }

  // 6. Multiple subdomains (common in phishing)
  const dots = domain.split('.').length;
  if (dots > 4) {
    riskScore += 0.2;
    risks.push('High number of subdomains');
  }

  // 7. Encoded characters in domain (homograph attack mitigation)
  if (domain.includes('xn--')) {
    riskScore += 0.4;
    risks.push('Punycode domain (potential homograph attack)');
  }

  // 8. URL Shortener detection
  const shorteners = ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly'];
  if (shorteners.some(s => domain === s || domain.endsWith('.' + s))) {
    riskScore += 0.3;
    risks.push('URL shortener (obscures final destination)');
  }

  // 9. Suspicious path components
  const suspiciousPaths = ['/login', '/signin', '/verify', '/confirm', '/account', '/update'];
  if (suspiciousPaths.some(path => url.toLowerCase().includes(path))) {
    riskScore += 0.1;
  }

  return {
    url,
    domain,
    riskScore: Math.min(riskScore, 1),
    risks,
  };
}

/**
 * Calculate the Levenshtein distance between two strings.
 */
export function getLevenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];

  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Calculate the Shannon entropy of a string.
 */
export function calculateEntropy(str: string): number {
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

/**
 * Inject security warnings for high-risk URLs in the text or HTML body.
 */
export function injectUrlWarnings(text: string, isHtml: boolean): string {
  const urls = extractUrls(text);
  let result = text;

  for (const url of urls) {
    const analysis = analyzeUrl(url);
    if (analysis.riskScore >= 0.5) {
      const escapedUrl = url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      if (isHtml) {
        // Defang: rewrite href to #blocked so the link is no longer clickable
        result = result.replace(
          new RegExp(`href\\s*=\\s*["']${escapedUrl}["']`, 'gi'),
          `href="#blocked" data-original-url="${url.replace(/"/g, '&quot;')}" title="Blocked: ${analysis.risks.join(', ')}"`,
        );
        // Inject visible warning badge after the URL text
        result = result.replace(
          new RegExp(`(${escapedUrl})`, 'g'),
          `$1 <span style="color:red; font-weight:bold; background:#ffebeb; border:1px solid red; padding:0 4px; border-radius:3px; font-size:12px;" title="Security Warning: ${analysis.risks.join(', ')}">⚠️ BLOCKED</span>`,
        );
      } else {
        // Defang: bracket dots and replace protocol to prevent accidental clicks
        const defanged = url.replace(/\./g, '[.]').replace(/^https?:\/\//, 'hxxps://');
        result = result.replace(url, `${defanged} [⚠️ UNSAFE: ${analysis.risks.join(', ')}]`);
      }
    }
  }

  return result;
}

/**
 * Scan all URLs in a text and return high-risk ones.
 */
export function scanUrls(text: string): ScannedUrl[] {
  const urls = extractUrls(text);
  return urls.map(analyzeUrl).filter(res => res.riskScore > 0);
}
