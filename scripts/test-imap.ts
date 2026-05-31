// Quick standalone IMAP probe: bun scripts/test-imap.ts <host> <port> <user> <pass>
import { ImapFlow } from 'imapflow';

const [host, portStr, user, pass] = process.argv.slice(2);
if (!host || !portStr || !user || !pass) {
  console.error('Usage: bun scripts/test-imap.ts <host> <port> <user> <pass>');
  process.exit(1);
}
const port = Number(portStr);

const client = new ImapFlow({
  host,
  port,
  secure: port === 993,
  auth: { user, pass },
  logger: false, // set to undefined for full protocol trace
});

try {
  await client.connect();
  console.log('✅ Connected & authenticated OK');
  const mailboxes = await client.list();
  console.log('Folders:', mailboxes.map(m => m.path).join(', '));
  await client.logout();
} catch (e: any) {
  console.error('❌ IMAP failed');
  console.error('  message:            ', e.message);
  console.error('  authenticationFailed:', e.authenticationFailed);
  console.error('  serverResponseCode: ', e.serverResponseCode);
  console.error('  responseText:       ', e.responseText);
  process.exit(1);
}
