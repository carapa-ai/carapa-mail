/**
 * Debug script: fetch the last email from Junk/Spam and run it through the AI filter.
 *
 * Usage:
 *   npx tsx scripts/test-filter.ts [folder] [accountId]
 *
 * Examples:
 *   npx tsx scripts/test-filter.ts              # defaults to Junk, first account
 *   npx tsx scripts/test-filter.ts Spam
 *   npx tsx scripts/test-filter.ts INBOX test
 */

import { ImapFlow } from 'imapflow';
import { loadAccounts, getAllAccounts } from '../src/accounts.js';
import { inspectEmail } from '../src/agent/filter.js';
import { initDatabase } from '../src/db/index.js';
import type { EmailSummary } from '../src/types.js';

function findTextPart(structure: any): string | null {
  if (!structure) return null;
  if (structure.type === 'text/plain') return structure.part || '1';
  if (structure.childNodes) {
    for (const child of structure.childNodes) {
      const found = findTextPart(child);
      if (found) return found;
    }
  }
  return null;
}

function formatAddress(addrs?: { name?: string; address?: string }[]): string {
  if (!addrs?.length) return '';
  return addrs.map(a => a.name ? `${a.name} <${a.address}>` : a.address || '').join(', ');
}

async function main() {
  const folder = process.argv[2] || 'Junk';
  const accountIdArg = process.argv[3];

  // Init DB & accounts
  await initDatabase();
  await loadAccounts();

  const accounts = getAllAccounts();
  if (accounts.length === 0) {
    console.error('No accounts configured.');
    process.exit(1);
  }

  const account = accountIdArg
    ? accounts.find(a => a.id === accountIdArg)
    : accounts[0];

  if (!account) {
    console.error(`Account not found: ${accountIdArg}`);
    console.error('Available:', accounts.map(a => `${a.id} (${a.email})`).join(', '));
    process.exit(1);
  }

  console.log(`Account: ${account.id} (${account.email})`);
  console.log(`Folder:  ${folder}\n`);

  // Connect via IMAP
  const client = new ImapFlow({
    host: account.imap.host,
    port: account.imap.port,
    secure: true,
    auth: { user: account.imap.user, pass: account.imap.pass },
    logger: false,
  });

  await client.connect();
  console.log('IMAP connected.');

  const lock = await client.getMailboxLock(folder);
  try {
    const status = client.mailbox;
    if (!status || !status.exists || status.exists === 0) {
      console.log(`Folder "${folder}" is empty.`);
      return;
    }

    console.log(`${status.exists} message(s) in ${folder}`);

    // Fetch the last message by sequence number
    const seqNo = String(status.exists);
    const msg = await client.fetchOne(seqNo, {
      envelope: true,
      bodyStructure: true,
      uid: true,
      headers: true,
    });

    if (!msg) {
      console.error('Failed to fetch last message.');
      return;
    }

    const from = formatAddress(msg.envelope?.from);
    const to = formatAddress(msg.envelope?.to);
    const subject = msg.envelope?.subject || '(no subject)';

    console.log(`\n--- Message ---`);
    console.log(`UID:     ${msg.uid}`);
    console.log(`From:    ${from}`);
    console.log(`To:      ${to}`);
    console.log(`Subject: ${subject}`);

    // Parse headers
    const headers: Record<string, string> = {};
    if (msg.headers) {
      const headerText = msg.headers.toString();
      const unfolded = headerText.replace(/\r\n[ \t]+/g, ' ');
      for (const line of unfolded.split('\r\n')) {
        const colon = line.indexOf(':');
        if (colon > 0) {
          headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
        }
      }
    }

    // Download body text
    let bodyText = '';
    const textPart = findTextPart(msg.bodyStructure);
    if (textPart) {
      const { content } = await client.download(String(msg.uid), textPart, { uid: true });
      const chunks: Buffer[] = [];
      for await (const chunk of content) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      bodyText = Buffer.concat(chunks).toString('utf-8');
    }

    console.log(`Body:    ${bodyText.length} chars`);
    if (bodyText.length > 0) {
      console.log(`Preview: ${bodyText.slice(0, 200)}${bodyText.length > 200 ? '...' : ''}`);
    }

    // Build email summary
    const emailSummary: EmailSummary = {
      direction: 'inbound',
      from,
      to,
      subject,
      body: bodyText.slice(0, 2000),
      attachments: [],
      headers,
    };

    // Run AI filter
    console.log(`\n--- Running AI filter ---`);
    const startTime = Date.now();
    const decision = await inspectEmail(emailSummary, undefined, account.id);
    const latencyMs = Date.now() - startTime;

    console.log(`\n--- Result (${latencyMs}ms) ---`);
    console.log(`Action:     ${decision.action}`);
    console.log(`Reason:     ${decision.reason}`);
    console.log(`Confidence: ${decision.confidence}`);
    console.log(`Categories: ${decision.categories?.join(', ') || '(none)'}`);
    if (decision.move_to) console.log(`Move to:    ${decision.move_to}`);
    if (decision.unavailable) console.log(`⚠️  Filter was unavailable`);
  } finally {
    lock.release();
    await client.logout();
    console.log('\nDone.');
  }
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
