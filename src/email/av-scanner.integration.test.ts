// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

/**
 * AV Scanner Integration Tests
 *
 * These tests require ClamAV installed on the system and are SKIPPED by
 * default during `bun test`. Set TEST_INTEGRATION=true to run them.
 *
 * Install ClamAV:
 *   sudo apt install clamav        # Debian/Ubuntu
 *   brew install clamav             # macOS
 *   sudo freshclam                  # download/update virus signatures
 *
 * Run:
 *   TEST_INTEGRATION=true bun test src/email/av-scanner.integration.test.ts
 *   # or via npm script:
 *   bun run test:integration
 */

import { expect, test, describe, beforeAll } from 'bun:test';
import { spawnSync } from 'child_process';

const RUN_INTEGRATION = process.env.TEST_INTEGRATION === 'true';

// Only probe for clamscan if we actually intend to run integration tests
const hasClamscan = RUN_INTEGRATION
  ? spawnSync('clamscan', ['--version'], { timeout: 5000 }).status === 0
  : false;

// EICAR test string — harmless signature recognized by all AV engines
// See: https://en.wikipedia.org/wiki/EICAR_test_file
// The backslash at position 13 is built via charCode to avoid escaping pitfalls.
const EICAR = 'X5O!P%@AP[4' + String.fromCharCode(92) + 'PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

import type { AvScanResult } from './av-scanner.js';

const AV_CMD = 'clamscan --no-summary -';

let scanWithAv: (attachments: { filename: string; content: Buffer }[]) => Promise<AvScanResult>;

beforeAll(async () => {
  if (!hasClamscan) return;
  const mod = await import('./av-scanner.js');
  scanWithAv = (attachments) => mod.scanWithAv(attachments, AV_CMD);
});

describe.skipIf(!hasClamscan)('av-scanner integration (ClamAV)', () => {
  test('detects EICAR test virus in attachment', async () => {
    const result = await scanWithAv([
      { filename: 'eicar.txt', content: Buffer.from(EICAR) },
    ]);
    if (result.safe) {
      console.log('DIAGNOSTIC: EICAR not detected. Result:', JSON.stringify(result, null, 2));
      console.log('DIAGNOSTIC: EICAR length:', EICAR.length, '(expected 68)');
      console.log('DIAGNOSTIC: EICAR hex:', Buffer.from(EICAR).toString('hex'));
    }
    expect(result.safe).toBe(false);
    expect(result.threats.length).toBeGreaterThanOrEqual(1);
    expect(result.threats[0]).toContain('eicar.txt');
  }, 15_000);

  test('passes clean attachment', async () => {
    const result = await scanWithAv([
      { filename: 'clean.txt', content: Buffer.from('This is a perfectly normal file.') },
    ]);
    expect(result.safe).toBe(true);
    expect(result.threats).toHaveLength(0);
  }, 15_000);

  test('scans multiple attachments — mixed clean and infected', async () => {
    const result = await scanWithAv([
      { filename: 'readme.txt', content: Buffer.from('Hello world') },
      { filename: 'virus.dat', content: Buffer.from(EICAR) },
      { filename: 'notes.txt', content: Buffer.from('Meeting notes for Monday') },
    ]);
    expect(result.safe).toBe(false);
    expect(result.threats.length).toBe(1);
    expect(result.threats[0]).toContain('virus.dat');
  }, 15_000);

  test('passes multiple clean attachments', async () => {
    const result = await scanWithAv([
      { filename: 'doc.pdf', content: Buffer.from('%PDF-1.4 fake pdf content') },
      { filename: 'image.png', content: Buffer.from('fake png content') },
      { filename: 'data.csv', content: Buffer.from('name,email\nAlice,alice@example.com') },
    ]);
    expect(result.safe).toBe(true);
    expect(result.threats).toHaveLength(0);
  }, 15_000);

  test('returns safe with empty attachments list', async () => {
    const result = await scanWithAv([]);
    expect(result.safe).toBe(true);
    expect(result.threats).toHaveLength(0);
  });

  test('returns safe with multiple attachments when AV disabled', async () => {
    const mod = await import('./av-scanner.js');
    const result = await mod.scanWithAv([
      { filename: 'a.pdf', content: Buffer.from('pdf content') },
      { filename: 'b.docx', content: Buffer.from('docx content') },
    ], '');
    expect(result.safe).toBe(true);
    expect(result.threats).toHaveLength(0);
  });

  test('AvScanResult has correct shape', async () => {
    const result = await scanWithAv([]);
    expect(result).toHaveProperty('safe');
    expect(result).toHaveProperty('threats');
    expect(typeof result.safe).toBe('boolean');
    expect(Array.isArray(result.threats)).toBe(true);
  });

  test('detects multiple infected attachments', async () => {
    const result = await scanWithAv([
      { filename: 'virus1.com', content: Buffer.from(EICAR) },
      { filename: 'virus2.bat', content: Buffer.from(EICAR) },
    ]);
    expect(result.safe).toBe(false);
    expect(result.threats.length).toBe(2);
    expect(result.threats[0]).toContain('virus1.com');
    expect(result.threats[1]).toContain('virus2.bat');
  }, 15_000);
});
