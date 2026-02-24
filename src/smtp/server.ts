// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { SMTPServer } from 'smtp-server';
import { SMTP_PORT, LOG_LEVEL } from '../config.js';
import { authenticateAccount, getAllAccounts } from '../accounts.js';
import { handleMessage } from './handler.js';
import { logger } from '../logger.js';
import { checkRateLimit, recordAttempt } from '../rate-limiter.js';
import { getTlsCertificate } from '../crypto.js';

export function startSmtpServer(): SMTPServer {
  const accounts = getAllAccounts();
  const certs = getTlsCertificate();

  const server = new SMTPServer({
    secure: true,
    key: certs?.key,
    cert: certs?.cert,
    authOptional: false,
    allowInsecureAuth: true,
    size: 25 * 1024 * 1024,
    logger: LOG_LEVEL === 'debug',
    onConnect(session, callback) {
      logger.debug('smtp', `Client connected: ${session.remoteAddress}`);
      callback();
    },
    onData(stream, session, callback) {
      handleMessage(stream, session, callback);
    },
    onAuth(auth, session, callback) {
      const clientIp = session.remoteAddress || 'unknown';
      const rateLimit = checkRateLimit(clientIp, 'smtp-auth');
      if (!rateLimit.allowed) {
        return callback(new Error(`Too many failed attempts. Try again in ${rateLimit.retryAfter} seconds.`));
      }
      const account = authenticateAccount(auth.username || '', auth.password || '');
      if (!account) {
        recordAttempt(clientIp, 'smtp-auth', false);
        callback(new Error('Invalid credentials'));
        return;
      }
      recordAttempt(clientIp, 'smtp-auth', true);
      callback(null, { user: account.id });
    },
  });

  server.on('error', (err) => {
    logger.error('smtp', `Server error: ${err}`);
  });

  server.listen(SMTP_PORT, () => {
    logger.info('smtp', `Server listening on port ${SMTP_PORT} (plain + STARTTLS)`);
  });

  return server;
}
