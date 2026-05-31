// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

/**
 * Locate the best body part to fetch from an IMAP bodyStructure.
 * Prefers `text/plain`; falls back to `text/html` so HTML-only emails
 * (most marketing / newsletter / transactional mail) still yield a body
 * instead of an empty string. Returns the IMAP part id and whether it is HTML.
 */
export function findBodyPart(structure: any): { part: string; isHtml: boolean } | null {
  const plain = findPartByType(structure, 'text/plain');
  if (plain) return { part: plain, isHtml: false };
  const html = findPartByType(structure, 'text/html');
  if (html) return { part: html, isHtml: true };
  return null;
}

function findPartByType(structure: any, type: string): string | null {
  if (!structure) return null;
  if (structure.type === type) return structure.part || '1';
  if (structure.childNodes) {
    for (const child of structure.childNodes) {
      const found = findPartByType(child, type);
      if (found) return found;
    }
  }
  return null;
}

/**
 * Convert an HTML email body into readable plain text for the AI filter and
 * for agents reading the message. Strips scripts/styles, turns block-level tags
 * into line breaks, removes the remaining tags, and decodes common entities.
 * This is deliberately lightweight (no DOM) — good enough to give the filter
 * meaningful content, not a faithful render.
 */
export function htmlToText(html: string): string {
  return html
    .replace(/<\s*(script|style|head)\b[\s\S]*?<\/\s*\1\s*>/gi, ' ')
    // Preserve link targets so URL security scanning still sees them: "text (url)"
    .replace(/<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, '$2 ($1)')
    .replace(/<\s*br\s*\/?\s*>/gi, '\n')
    .replace(/<\s*\/\s*(p|div|tr|li|h[1-6]|table|ul|ol)\s*>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_, n) => {
      const code = parseInt(n, 10);
      return Number.isFinite(code) ? String.fromCharCode(code) : '';
    })
    .replace(/[ \t]+/g, ' ')
    .replace(/\n[ \t]*\n[ \t]*\n+/g, '\n\n')
    .trim();
}
