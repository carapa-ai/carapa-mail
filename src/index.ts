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
  AI_FEATURES_ENABLED,
  ANTHROPIC_BASE_URL,
} from './config.js';

import { logger } from './logger.js';
import { checkModelConnection } from './agent/filter.js';
import { checkTlsRequirements } from './crypto.js';

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

const tlsCheck = checkTlsRequirements();
if (!tlsCheck.ok) {
  logger.warn('system', `TLS encryption: UNAVAILABLE — ${tlsCheck.message}`);
  logger.warn('system', 'STARTTLS will be disabled. Connections will be plaintext ONLY.');
} else {
  logger.info('system', 'TLS encryption: AVAILABLE');
}

const accounts = getAllAccounts();
if (accounts.length === 0) {
  logger.info('system', `No accounts configured. Open http://localhost:${HTTP_PORT}/setup to add accounts.`);
} else {
  logger.info('system', `Accounts: ${accounts.length} (${accounts.map(a => a.id).join(', ')})`);
}

if (AI_FEATURES_ENABLED) {
  const hasLocalBackend = ANTHROPIC_BASE_URL.includes('localhost') || ANTHROPIC_BASE_URL.includes('127.0.0.1');
  if (!ANTHROPIC_AUTH_TOKEN && !hasLocalBackend) {
    logger.error('system', 'AI_FEATURES_ENABLED is true, but no model configuration found!');
    logger.error('system', 'Please set ANTHROPIC_AUTH_TOKEN (for Claude) or ANTHROPIC_BASE_URL (for local models).');
    logger.error('system', 'To run without AI, explicitly set AI_FEATURES_ENABLED=false in your .env file.');
  } else {
    logger.info('system', `AI features: ENABLED (${ANTHROPIC_MODEL}) — testing connection...`);
    const test = await checkModelConnection();
    if (test.ok) {
      logger.info('system', 'AI connection: SUCCESS');
    } else {
      logger.error('system', `AI connection: FAILED — ${test.message}`);
      logger.warn('system', 'Filtering may fall back to failure action or passthrough until connection is fixed.');
    }
  }
} else {
  logger.info('system', 'AI features: DISABLED (manual override)');
}

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
