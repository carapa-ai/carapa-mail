// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

/**
 * AV Scanner Unit Tests
 *
 * These tests verify the scanner logic WITHOUT requiring ClamAV.
 * They pass an empty avCommand to force the no-op code path.
 */

import { expect, test, describe } from 'bun:test';
import { scanWithAv } from './av-scanner.js';

// Pass an empty command to every call — this tests the disabled-AV code path
// without relying on mock.module or env var manipulation.
const scan = (attachments: { filename: string; content: Buffer }[]) =>
  scanWithAv(attachments, '');

describe('av-scanner', () => {
  test('returns safe with no threats when AV_COMMAND is empty (default)', async () => {
    const result = await scan([
      { filename: 'test.txt', content: Buffer.from('hello') },
    ]);
    expect(result.safe).toBe(true);
    expect(result.threats).toHaveLength(0);
  });

  test('returns safe with empty attachments list', async () => {
    const result = await scan([]);
    expect(result.safe).toBe(true);
    expect(result.threats).toHaveLength(0);
  });

  test('returns safe with multiple attachments when AV disabled', async () => {
    const result = await scan([
      { filename: 'a.pdf', content: Buffer.from('pdf content') },
      { filename: 'b.docx', content: Buffer.from('docx content') },
    ]);
    expect(result.safe).toBe(true);
    expect(result.threats).toHaveLength(0);
  });

  test('AvScanResult has correct shape', async () => {
    const result = await scan([]);
    expect(result).toHaveProperty('safe');
    expect(result).toHaveProperty('threats');
    expect(typeof result.safe).toBe('boolean');
    expect(Array.isArray(result.threats)).toBe(true);
  });
});
