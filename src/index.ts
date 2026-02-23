// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import './config.js'; // Load env first
import { initDatabase } from './db/index.js';
import { initRateLimiter } from './rate-limiter.js';
import { loadAccounts, getAllAccounts } from './accounts.js';
import { startSmtpServer } from './smtp/server.js';
import { startImapProxy } from './imap/proxy.js';
import { startHttpServer } from './http/server.js';
import {
  ANTHROPIC_AUTH_TOKEN,
  ANTHROPIC_MODEL,
  AUTO_QUARANTINE,
  MCP_ENABLED,
  INBOUND_SCAN,
  HTTP_PORT,
} from './config.js';

import { logger } from './logger.js';

// Graceful shutdown
const cleanup: (() => void)[] = [];
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    logger.info('system', `Received ${signal}, shutting down...`);
    for (const fn of cleanup) fn();
    process.exit(0);
  });
}

// Bootstrap
logger.info('system', 'Starting CarapaMail...');

await initDatabase();
await initRateLimiter();
await loadAccounts();

const accounts = getAllAccounts();
if (accounts.length === 0) {
  logger.info('system', `No accounts configured. Open http://localhost:${HTTP_PORT}/setup to add accounts.`);
} else {
  logger.info('system', `Accounts: ${accounts.length} (${accounts.map(a => a.id).join(', ')})`);
}
logger.info('system', `AI model: ${ANTHROPIC_AUTH_TOKEN ? ANTHROPIC_MODEL : '(no API key)'}`);
logger.info('system', `Mode: ${AUTO_QUARANTINE ? 'active filtering' : 'log-only (passthrough)'}`);

const smtp = startSmtpServer();
cleanup.push(() => smtp.close());

const imap = startImapProxy();
cleanup.push(() => imap.close());

const http = startHttpServer();
cleanup.push(() => http.close());

if (MCP_ENABLED) {
  const { startMcpServer } = await import('./mcp/server.js');
  const mcp = await startMcpServer();
  cleanup.push(() => mcp.close());
}

if (INBOUND_SCAN) {
  const { startInboundScanner } = await import('./inbound-scanner.js');
  const scanner = await startInboundScanner();
  cleanup.push(() => scanner.stop());
}
