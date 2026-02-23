// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { SANITIZER_PATTERNS } from '../agent/prompts.js';
import { PII_REDACTION, STRIP_REMOTE_IMAGES } from '../config.js';
import { scanUrls, injectUrlWarnings } from '../email/url-scanner.js';

/**
 * Sanitize email body text for safe consumption by humans and AI agents.
 * Uses fast regex patterns — no AI call (too slow for interactive IMAP).
 */
export function sanitizeBody(text: string): { sanitized: string; flags: string[] } {
  const flags: string[] = [];
  let result = text;

  // Remove zero-width characters and other non-printing characters
  const zeroWidthRegex = /[\u200B-\u200D\uFEFF]/g;
  if (zeroWidthRegex.test(result)) {
    result = result.replace(zeroWidthRegex, '');
    flags.push('zero_width_chars');
  }

  // URL safety warnings
  const scanned = scanUrls(result);
  const unsafeUrls = scanned.filter(s => s.riskScore >= 0.5);
  if (scanned.length > 0) {
    result = injectUrlWarnings(result, false);
    if (unsafeUrls.length > 0) flags.push('unsafe_urls');
  }

  // Check for prompt injection patterns
  for (const pattern of SANITIZER_PATTERNS.prompt_injection) {
    if (pattern.test(result)) {
      flags.push('prompt_injection');
      // Replace the injection attempt with a visible warning
      result = result.replace(pattern, (match) => `[🛑 BLOCKED: potential prompt injection ("${match.substring(0, 50)}...")]`);
    }
  }

  // If any high-risk flags are present, add a "Secure View" header
  if (flags.includes('unsafe_urls') || flags.includes('prompt_injection')) {
    const warningText = `[⚠️ CARAPAMAIL SECURE VIEW: This message contains ${flags.join(' and ')}. Exercise extreme caution.]\n\n`;
    result = warningText + result;
  }

  // PII redaction (if enabled)
  if (PII_REDACTION) {
    for (const [type, pattern] of Object.entries(SANITIZER_PATTERNS.pii)) {
      const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
      const replaced = result.replace(globalPattern, `[REDACTED:${type}]`);
      if (replaced !== result) {
        flags.push(`pii_${type}`);
        result = replaced;
      }
    }
  }

  return { sanitized: result, flags };
}

/**
 * Sanitize HTML email content.
 * Note: Uses regex for speed in streaming. For a more robust solution, a proper parser
 * should be used if the content is fully buffered.
 */
export function sanitizeHtml(html: string): { sanitized: string; flags: string[] } {
  const flags: string[] = [];
  let result = html;

  // 1. Invisible Content & Obfuscation
  const invisiblePatterns = [
    // Display:none elements
    { pattern: /<[^>]+style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>[\s\S]*?<\/[^>]+>/gi, tag: 'hidden_content' },
    // Zero-size font elements
    { pattern: /<[^>]+style\s*=\s*["'][^"']*font-size\s*:\s*0[^"']*["'][^>]*>[\s\S]*?<\/[^>]+>/gi, tag: 'hidden_content' },
    // White text on white background
    { pattern: /<[^>]+style\s*=\s*["'][^"']*color\s*:\s*(?:white|#fff(?:fff)?|rgb\(255\s*,\s*255\s*,\s*255\))[^"']*["'][^>]*>[\s\S]*?<\/[^>]+>/gi, tag: 'hidden_content' },
  ];

  for (const { pattern, tag } of invisiblePatterns) {
    const replaced = result.replace(pattern, '<!-- [BLOCKED: hidden content removed] -->');
    if (replaced !== result) {
      if (!flags.includes(tag)) flags.push(tag);
      result = replaced;
    }
  }

  // Remove tracking pixels (1x1 or 0x0 images)
  const trackingPixelPattern = /<img\b[^>]*(?:width\s*=\s*["']?[01](?:px)?["']?[^>]*height\s*=\s*["']?[01](?:px)?["']?|height\s*=\s*["']?[01](?:px)?["']?[^>]*width\s*=\s*["']?[01](?:px)?["']?)[^>]*\/?>/gi;
  const pixelStripped = result.replace(trackingPixelPattern, '<!-- [tracking pixel removed] -->');
  if (pixelStripped !== result) {
    flags.push('tracking_pixels');
    result = pixelStripped;
  }

  // Optionally strip ALL remote images
  if (STRIP_REMOTE_IMAGES) {
    const beforeStrip = result;
    result = result.replace(
      /<img\b[^>]*\bsrc\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*\/?>/gi,
      (_, src) => `<!-- [remote image blocked: ${src}] -->`,
    );
    if (result !== beforeStrip) {
      flags.push('remote_images_stripped');
    }
  }

  // 2. High-Risk HTML Tags (Phishing, XSS, Tracking)
  const dangerousTags = [
    { pattern: /<script[\s\S]*?>[\s\S]*?<\/script>/gi, tag: 'scripts' },
    { pattern: /<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi, tag: 'iframes' },
    { pattern: /<object[\s\S]*?>[\s\S]*?<\/object>/gi, tag: 'objects' },
    { pattern: /<embed[\s\S]*?>[\s\S]*?<\/embed>/gi, tag: 'embeds' },
    { pattern: /<form[\s\S]*?>[\s\S]*?<\/form>/gi, tag: 'forms' },
    { pattern: /<meta\s+http-equiv\s*=\s*["']refresh["'][\s\S]*?>/gi, tag: 'meta_refresh' },
    { pattern: /<base\s+href[\s\S]*?>/gi, tag: 'base_href' },
    { pattern: /<link\s+rel\s*=\s*["'](?:import|prefetch|prerender)["'][\s\S]*?>/gi, tag: 'dangerous_link' },
  ];

  for (const { pattern, tag } of dangerousTags) {
    const replaced = result.replace(pattern, (match) => `<!-- [BLOCKED: ${tag} removed] -->`);
    if (replaced !== result) {
      if (!flags.includes(tag)) flags.push(tag);
      result = replaced;
    }
  }

  // 3. Dangerous Attributes (on*, formaction, data-uris)
  const dangerousAttributes = [
    { pattern: /\son\w+\s*=\s*["'][^"']*["']/gi, tag: 'event_handlers' },
    { pattern: /\sformaction\s*=\s*["'][^"']*["']/gi, tag: 'form_actions' },
    { pattern: /href\s*=\s*["']data:[^"']+["']/gi, tag: 'data_uris' },
    { pattern: /src\s*=\s*["']data:[^"']+["']/gi, tag: 'data_uris' },
  ];

  for (const { pattern, tag } of dangerousAttributes) {
    const replaced = result.replace(pattern, (match) => ` ${tag}-blocked="removed"`);
    if (replaced !== result) {
      if (!flags.includes(tag)) flags.push(tag);
      result = replaced;
    }
  }

  // 4. Apply text sanitization to visible content
  const textResult = sanitizeBody(result);
  flags.push(...textResult.flags);
  result = textResult.sanitized;

  // 5. Apply HTML-specific URL warnings
  const scanned = scanUrls(result);
  if (scanned.length > 0) {
    result = injectUrlWarnings(result, true);
    if (!flags.includes('unsafe_urls_html')) flags.push('unsafe_urls_html');
  }

  return { sanitized: result, flags: [...new Set(flags)] };
}
