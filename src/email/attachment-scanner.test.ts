// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe, mock, beforeAll } from 'bun:test';

// Mock av-scanner so no real clamscan is invoked
mock.module('./av-scanner.js', () => ({
  scanWithAv: mock(async () => ({ safe: true, threats: [] })),
}));

import type { scanAttachmentList as ScanAttachmentList, DANGEROUS_EXTENSIONS as DangerousExtensions } from './attachment-scanner.js';

let scanAttachmentList: typeof ScanAttachmentList;
let DANGEROUS_EXTENSIONS: typeof DangerousExtensions;

beforeAll(async () => {
  const mod = await import('./attachment-scanner.js');
  scanAttachmentList = mod.scanAttachmentList;
  DANGEROUS_EXTENSIONS = mod.DANGEROUS_EXTENSIONS;
});

// Helper — build a minimal attachment descriptor without parsing any MIME
function att(filename: string, contentType = 'application/octet-stream'): { filename: string; contentType: string; content: Buffer } {
  return { filename, contentType, content: Buffer.from('test content') };
}

describe('Attachment Scanner', () => {
  test('DANGEROUS_EXTENSIONS list is non-empty', () => {
    expect(DANGEROUS_EXTENSIONS.length).toBeGreaterThan(0);
  }, 30_000);

  test('safe attachment passes', () => {
    const result = scanAttachmentList([att('report.pdf', 'application/pdf')]);
    expect(result.safe).toBe(true);
    expect(result.threats).toHaveLength(0);
  }, 30_000);

  test('detects dangerous .exe extension', () => {
    const result = scanAttachmentList([att('setup.exe')]);
    expect(result.safe).toBe(false);
    expect(result.threats.some(t => t.includes('setup.exe'))).toBe(true);
  }, 30_000);

  test('detects dangerous .ps1 extension', () => {
    const result = scanAttachmentList([att('script.ps1')]);
    expect(result.safe).toBe(false);
  }, 30_000);

  test('detects dangerous .bat extension', () => {
    const result = scanAttachmentList([att('run.bat')]);
    expect(result.safe).toBe(false);
  }, 30_000);

  test('detects dangerous .vbs extension', () => {
    const result = scanAttachmentList([att('macro.vbs')]);
    expect(result.safe).toBe(false);
  }, 30_000);

  test('detects dangerous .jar extension', () => {
    const result = scanAttachmentList([att('payload.jar')]);
    expect(result.safe).toBe(false);
  }, 30_000);

  test('detects double extension trick (pdf.exe)', () => {
    const result = scanAttachmentList([att('invoice.pdf.exe')]);
    expect(result.safe).toBe(false);
    expect(result.threats.length).toBeGreaterThan(0);
  }, 30_000);

  test('detects double extension trick (doc.vbs)', () => {
    const result = scanAttachmentList([att('resume.doc.vbs')]);
    expect(result.safe).toBe(false);
  }, 30_000);

  test('double extension with safe final ext is not flagged', () => {
    const result = scanAttachmentList([att('file.backup.pdf', 'application/pdf')]);
    expect(result.safe).toBe(true);
  }, 30_000);

  test('detects dangerous content type', () => {
    const result = scanAttachmentList([att('file.bin', 'application/x-msdownload')]);
    expect(result.safe).toBe(false);
    expect(result.threats.some(t => t.includes('dangerous content type'))).toBe(true);
  }, 30_000);

  test('safe email with no attachments', () => {
    const result = scanAttachmentList([]);
    expect(result.safe).toBe(true);
    expect(result.threats).toHaveLength(0);
  }, 30_000);

  test('multiple attachments — one dangerous', () => {
    const result = scanAttachmentList([
      att('photo.jpg', 'image/jpeg'),
      att('malware.scr'),
      att('notes.txt', 'text/plain'),
    ]);
    expect(result.safe).toBe(false);
    expect(result.threats).toHaveLength(1);
    expect(result.threats[0]).toContain('malware.scr');
  }, 30_000);

  test('RTL-O extension spoofing detected', () => {
    // filename visually looks like "invoiceexe.jpeg" but contains RTL-O
    const result = scanAttachmentList([att('invoice\u202egepj.exe')]);
    expect(result.safe).toBe(false);
    expect(result.threats.some(t => t.includes('[RTL-O]'))).toBe(true);
  }, 30_000);

  test('macro-enabled Office document is flagged', () => {
    const result = scanAttachmentList([att('report.xlsm', 'application/vnd.ms-excel')]);
    expect(result.safe).toBe(false);
  }, 30_000);

  test('disk image (.iso) is flagged', () => {
    const result = scanAttachmentList([att('installer.iso', 'application/x-iso9660-image')]);
    expect(result.safe).toBe(false);
  }, 30_000);
});
