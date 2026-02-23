// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe } from 'bun:test';
import { parseFromStream, toEmailSummary } from './parser.js';
import { Readable } from 'stream';

function bufferToStream(buf: Buffer): NodeJS.ReadableStream {
  return Readable.from(buf);
}

function buildRawEmail(opts: {
  from?: string;
  to?: string;
  subject?: string;
  body?: string;
  html?: string;
  headers?: Record<string, string>;
  attachments?: { filename: string; contentType: string; content: string }[];
} = {}): Buffer {
  const boundary = '----=_TestBoundary';
  const hasAttachments = opts.attachments && opts.attachments.length > 0;
  const isMultipart = hasAttachments || opts.html;

  const lines: string[] = [];
  lines.push(`From: ${opts.from || 'sender@example.com'}`);
  lines.push(`To: ${opts.to || 'recipient@example.com'}`);
  lines.push(`Subject: ${opts.subject || 'Test Subject'}`);
  lines.push('MIME-Version: 1.0');

  if (opts.headers) {
    for (const [k, v] of Object.entries(opts.headers)) {
      lines.push(`${k}: ${v}`);
    }
  }

  if (isMultipart) {
    lines.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
    lines.push('');
    lines.push(`--${boundary}`);
    lines.push('Content-Type: text/plain; charset=utf-8');
    lines.push('');
    lines.push(opts.body || '');

    if (opts.html) {
      lines.push(`--${boundary}`);
      lines.push('Content-Type: text/html; charset=utf-8');
      lines.push('');
      lines.push(opts.html);
    }

    for (const att of opts.attachments || []) {
      lines.push(`--${boundary}`);
      lines.push(`Content-Type: ${att.contentType}`);
      lines.push(`Content-Disposition: attachment; filename="${att.filename}"`);
      lines.push('Content-Transfer-Encoding: base64');
      lines.push('');
      lines.push(Buffer.from(att.content).toString('base64'));
    }

    lines.push(`--${boundary}--`);
  } else {
    lines.push('Content-Type: text/plain; charset=utf-8');
    lines.push('');
    lines.push(opts.body || 'Hello world');
  }

  return Buffer.from(lines.join('\r\n'));
}

describe('parseFromStream', () => {
  test('parses a simple email and returns rawBuffer', async () => {
    const raw = buildRawEmail({ body: 'Test body' });
    const stream = bufferToStream(raw);
    const { parsed, rawBuffer } = await parseFromStream(stream);

    expect(rawBuffer).toBeInstanceOf(Buffer);
    expect(rawBuffer.length).toBe(raw.length);
    expect(parsed.subject).toBe('Test Subject');
    expect(parsed.text).toContain('Test body');
  });

  test('preserves full raw buffer for MIME emails', async () => {
    const raw = buildRawEmail({
      body: 'Text part',
      attachments: [{ filename: 'doc.pdf', contentType: 'application/pdf', content: 'pdf data' }],
    });
    const { rawBuffer, parsed } = await parseFromStream(bufferToStream(raw));
    expect(rawBuffer.length).toBe(raw.length);
    expect(parsed.attachments).toHaveLength(1);
    expect(parsed.attachments[0].filename).toBe('doc.pdf');
  });

  test('handles empty stream', async () => {
    const { parsed, rawBuffer } = await parseFromStream(bufferToStream(Buffer.from('')));
    expect(rawBuffer.length).toBe(0);
    // simpleParser should not throw on empty input
    expect(parsed).toBeDefined();
  });
});

describe('toEmailSummary', () => {
  test('extracts from, to, subject, body', async () => {
    const raw = buildRawEmail({
      from: 'alice@test.com',
      to: 'bob@test.com',
      subject: 'Hello Bob',
      body: 'How are you?',
    });
    const { parsed } = await parseFromStream(bufferToStream(raw));
    const summary = toEmailSummary(parsed, 'inbound');

    expect(summary.direction).toBe('inbound');
    expect(summary.from).toContain('alice@test.com');
    expect(summary.to).toContain('bob@test.com');
    expect(summary.subject).toBe('Hello Bob');
    expect(summary.body).toContain('How are you?');
  });

  test('sets direction to outbound when specified', async () => {
    const raw = buildRawEmail();
    const { parsed } = await parseFromStream(bufferToStream(raw));
    const summary = toEmailSummary(parsed, 'outbound');
    expect(summary.direction).toBe('outbound');
  });

  test('falls back to (no subject) when missing', async () => {
    const raw = Buffer.from([
      'From: a@b.com',
      'To: c@d.com',
      'Content-Type: text/plain',
      '',
      'body text',
    ].join('\r\n'));
    const { parsed } = await parseFromStream(bufferToStream(raw));
    const summary = toEmailSummary(parsed, 'inbound');
    expect(summary.subject).toBe('(no subject)');
  });

  test('extracts headers as Record<string, string>', async () => {
    const raw = buildRawEmail({
      headers: { 'X-Custom-Header': 'custom-value' },
    });
    const { parsed } = await parseFromStream(bufferToStream(raw));
    const summary = toEmailSummary(parsed, 'inbound');
    expect(summary.headers['x-custom-header']).toBe('custom-value');
  });

  test('extracts attachments metadata', async () => {
    const raw = buildRawEmail({
      attachments: [
        { filename: 'report.pdf', contentType: 'application/pdf', content: 'abc' },
        { filename: 'image.png', contentType: 'image/png', content: 'xyz' },
      ],
    });
    const { parsed } = await parseFromStream(bufferToStream(raw));
    const summary = toEmailSummary(parsed, 'inbound');
    expect(summary.attachments).toHaveLength(2);
    expect(summary.attachments[0].filename).toBe('report.pdf');
    expect(summary.attachments[0].contentType).toBe('application/pdf');
    expect(summary.attachments[1].filename).toBe('image.png');
  });

  test('uses html as body fallback when text is empty', async () => {
    const raw = buildRawEmail({ html: '<p>HTML only</p>', body: '' });
    const { parsed } = await parseFromStream(bufferToStream(raw));
    const summary = toEmailSummary(parsed, 'inbound');
    // The body should contain something (either parsed text from html or the html itself)
    expect(summary.body.length).toBeGreaterThan(0);
  });

  test('handles email with no from/to gracefully', async () => {
    const raw = Buffer.from([
      'Subject: Orphan',
      'Content-Type: text/plain',
      '',
      'No from or to',
    ].join('\r\n'));
    const { parsed } = await parseFromStream(bufferToStream(raw));
    const summary = toEmailSummary(parsed, 'inbound');
    expect(summary.from).toBe('');
    expect(summary.to).toBe('');
    expect(summary.subject).toBe('Orphan');
  });
});
