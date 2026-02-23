// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { simpleParser } from 'mailparser';
import { scanWithAv } from './av-scanner.js';

/**
 * High-risk attachment extensions often used in phishing/malware.
 */
export const DANGEROUS_EXTENSIONS = [
  // Executables and Scripts
  /\.exe$/i, /\.scr$/i, /\.bat$/i, /\.cmd$/i, /\.ps1$/i, /\.vbs$/i,
  /\.js$/i, /\.jse$/i, /\.wsf$/i, /\.wsh$/i, /\.msc$/i, /\.msi$/i,
  /\.reg$/i, /\.inf$/i, /\.sh$/i, /\.pl$/i, /\.py$/i, /\.jar$/i,
  /\.com$/i, /\.pif$/i, /\.gadget$/i, /\.hta$/i, /\.cpl$/i, /\.msc$/i,
  /\.vbe$/i, /\.vba$/i,

  // Macro-enabled documents (often contain malware)
  /\.docm$/i, /\.dotm$/i, /\.xlsm$/i, /\.xltm$/i, /\.xlam$/i, /\.pptm$/i, /\.potm$/i, /\.ppsm$/i, /\.sldm$/i,

  // Disk Images (used to bypass some scanners)
  /\.iso$/i, /\.vhd$/i, /\.vhdx$/i, /\.img$/i, /\.dmg$/i,

  // Compressed archives (can contain malware, but common, so we treat as suspicious if they contain the above)
  // Note: we don't block them all, but we might flag them if we could look inside.
  // For now, we focus on the top level.
];

const DANGEROUS_CONTENT_TYPES = [
  'application/x-msdownload',
  'application/x-ms-installer',
  'application/x-sh',
  'application/x-shellscript',
  'application/x-python-code',
  'application/x-java-archive',
  'application/x-ms-dos-executable',
  'application/x-vhd',
  'application/x-iso9660-image',
];

const COMMON_DOC_EXTENSIONS = [
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.jpg', '.jpeg', '.png', '.gif', '.zip', '.tar', '.gz',
];

export interface AttachmentInfo {
  filename?: string | null;
  contentType?: string;
  content: Buffer;
}

/**
 * Core scanner logic that works on a list of pre-parsed attachments.
 * Exported for direct use in tests to avoid the overhead of mailparser.
 */
export function scanAttachmentList(attachments: AttachmentInfo[]): { safe: boolean; threats: string[] } {
  const threats: string[] = [];

  for (const attachment of attachments) {
    let filename = attachment.filename || 'unnamed';

    // Check for RTL-O (Right-To-Left Override) character \u202e
    // This is used to spoof extensions, e.g. "invoice\u202egepj.exe" looks like "invoiceexe.jpeg"
    if (filename.includes('\u202e')) {
      threats.push(`${filename.replace('\u202e', '[RTL-O]')} (Extension Spoofing Attempt)`);
      filename = filename.replace('\u202e', '');
    }

    // 1. Check for dangerous extensions
    if (DANGEROUS_EXTENSIONS.some(ext => ext.test(filename))) {
      threats.push(filename);
    }

    // 2. Check for double extensions (e.g. invoice.pdf.exe)
    if (/\.[a-z0-9]{2,4}\.[a-z0-9]{2,4}$/i.test(filename)) {
      const parts = filename.split('.');
      if (parts.length >= 3) {
        const lastExt = '.' + parts[parts.length - 1].toLowerCase();
        const secondLastExt = '.' + parts[parts.length - 2].toLowerCase();

        if (COMMON_DOC_EXTENSIONS.includes(secondLastExt) && DANGEROUS_EXTENSIONS.some(ext => ext.test(lastExt))) {
          if (!threats.includes(filename)) {
            threats.push(`${filename} (potential double extension trick)`);
          }
        }
      }
    }

    // 3. Check content type (even if filename looks safe)
    if (attachment.contentType && DANGEROUS_CONTENT_TYPES.includes(attachment.contentType)) {
      const threat = `${filename} (dangerous content type: ${attachment.contentType})`;
      if (!threats.some(t => t.includes(filename))) {
        threats.push(threat);
      }
    }
  }

  return { safe: threats.length === 0, threats };
}

/**
 * Scan for dangerous attachment extensions in a raw email buffer.
 * Uses a proper MIME parser to decode headers and filenames correctly.
 */
export async function scanAttachments(rawEml: Buffer): Promise<{ safe: boolean; threats: string[] }> {
  try {
    const parsed = await simpleParser(rawEml);

    if (!parsed.attachments || parsed.attachments.length === 0) {
      return { safe: true, threats: [] };
    }

    // Run synchronous extension/content-type checks
    const { threats } = scanAttachmentList(parsed.attachments);

    // 4. External antivirus scan (if configured)
    const avResult = await scanWithAv(
      parsed.attachments.map(a => ({ filename: a.filename || 'unnamed', content: a.content })),
    );
    for (const t of avResult.threats) {
      threats.push(t);
    }

    return { safe: threats.length === 0, threats };
  } catch (err) {
    console.error('[attachment-scanner] Failed to parse email for attachment scanning:', err);
    // On parse error, we can't be sure it's safe.
    return { safe: true, threats: [] };
  }
}
