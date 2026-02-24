// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { SMTPServer } from 'smtp-server';
import { SMTP_PORT } from '../config.js';
import { authenticateAccount, getAllAccounts } from '../accounts.js';
import { handleMessage } from './handler.js';
import { logger } from '../logger.js';
import { checkRateLimit, recordAttempt } from '../rate-limiter.js';
import { getTlsCertificate } from '../crypto.js';

export function startSmtpServer(): SMTPServer {
  const accounts = getAllAccounts();
  const certs = getTlsCertificate();

  const baseOptions: any = {
    secure: false,
    key: certs?.key,
    cert: certs?.cert,
    disabledCommands: certs ? [] : ['STARTTLS']
  };

  if (accounts.length === 0) {
    logger.info('smtp', 'No accounts configured, SMTP proxy disabled');
    const server = new SMTPServer(baseOptions);
    return server;
  }

  const server = new SMTPServer({
    ...baseOptions,
    authOptional: false,
    allowInsecureAuth: true,
    size: 25 * 1024 * 1024,
    onData(stream, session, callback) {
      handleMessage(stream, session, callback);
    },
    onAuth(auth, session, callback) {
      const clientIp = session.remoteAddress || 'unknown';
      const rateLimit = checkRateLimit(clientIp, 'smtp-auth');

      if (!rateLimit.allowed) {
        logger.warn('smtp', `Rate limit exceeded for IP ${clientIp}`);
        return callback(new Error(`Too many failed attempts. Try again in ${rateLimit.retryAfter} seconds.`));
      }

      const account = authenticateAccount(auth.username || '', auth.password || '');
      if (!account) {
        recordAttempt(clientIp, 'smtp-auth', false);
        callback(new Error('Invalid credentials'));
        return;
      }

      recordAttempt(clientIp, 'smtp-auth', true);
      // Store account ID in the user field so handler can retrieve it
      callback(null, { user: account.id });
    },
  });

  server.on('error', (err) => {
    logger.error('smtp', `Server error: ${err}`);
  });

  server.listen(SMTP_PORT, () => {
    logger.info('smtp', `Proxy listening on port ${SMTP_PORT}`);
  });

  return server;
}
