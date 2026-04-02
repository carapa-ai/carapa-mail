// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import net from 'net';
import tls from 'tls';
import { SMTPServer } from 'smtp-server';
import { SMTP_PORT, SMTP_INSECURE_PORT, LOG_LEVEL, BIND_HOST, ALLOW_INSECURE_AUTH } from '../config.js';
import { authenticateAccount } from '../accounts.js';
import { handleMessage } from './handler.js';
import { logger } from '../logger.js';
import { checkRateLimit, recordAttempt } from '../rate-limiter.js';
import { getTlsCertificate } from '../crypto.js';

function smtpOptions(certs: { key: string; cert: string } | null) {
  return {
    authOptional: false,
    allowInsecureAuth: ALLOW_INSECURE_AUTH,
    size: 25 * 1024 * 1024,
    logger: LOG_LEVEL === 'debug',
    key: certs?.key,
    cert: certs?.cert,
    onConnect(session: any, callback: any) {
      logger.debug('smtp', `SMTP session from ${session.remoteAddress}`);
      callback();
    },
    onData(stream: any, session: any, callback: any) {
      handleMessage(stream, session, callback);
    },
    onAuth(auth: any, session: any, callback: any) {
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
  };
}

export function startSmtpServer(): net.Server {
  const certs = getTlsCertificate();

  // STARTTLS server: plaintext clients connect here and upgrade via STARTTLS
  // Has certs so it can offer STARTTLS, allowInsecureAuth must stay false
  const starttlsServer = new SMTPServer({ ...smtpOptions(certs), secure: false });
  starttlsServer.on('error', (err) => logger.error('smtp', `SMTP STARTTLS server error: ${err}`));
  starttlsServer.listen(0, '127.0.0.1');

  // Post-TLS server: receives already-decrypted connections from tls.createServer
  // No certs needed (TLS handled by outer layer), allowInsecureAuth: true is safe
  // because this server only listens on 127.0.0.1 and is unreachable from outside
  const postTlsServer = new SMTPServer({ ...smtpOptions(null), secure: false, allowInsecureAuth: true });
  postTlsServer.on('error', (err) => logger.error('smtp', `SMTP post-TLS server error: ${err}`));
  postTlsServer.listen(0, '127.0.0.1');

  // Internal TLS server for implicit SSL connections (same pattern as IMAP proxy)
  const implicitTlsServer = certs ? tls.createServer({
    key: certs.key,
    cert: certs.cert,
    requestCert: false,
    minVersion: 'TLSv1.2' as any,
  }) : null;

  if (implicitTlsServer) {
    implicitTlsServer.on('secureConnection', (tlsSocket: tls.TLSSocket) => {
      const clientAddr = `${tlsSocket.remoteAddress}:${tlsSocket.remotePort}`;
      logger.info('smtp', `Implicit TLS secured for ${clientAddr}`);
      // Pipe decrypted TLS socket to the post-TLS SMTP server (no STARTTLS needed)
      pipeToSmtp(tlsSocket, postTlsServer, clientAddr);
    });
    implicitTlsServer.on('tlsClientError', (err: any) => {
      logger.error('smtp', `TLS client error: ${err.message}`);
    });
    implicitTlsServer.listen(0, '127.0.0.1');
  }

  // Outer server: sniff first byte to detect TLS vs plaintext
  const server = net.createServer(socket => {
    const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
    logger.debug('smtp', `Client connected: ${clientAddr}`);

    let sniffed = false;
    const sniffTimeout = setTimeout(() => {
      if (!sniffed && !socket.destroyed) {
        sniffed = true;
        logger.debug('smtp', `Plaintext (timeout) from ${clientAddr}`);
        pipeToSmtp(socket, starttlsServer, clientAddr);
      }
    }, 150);

    socket.once('data', (data) => {
      if (sniffed || socket.destroyed) return;
      clearTimeout(sniffTimeout);
      sniffed = true;

      if (data[0] === 0x16 && implicitTlsServer) {
        // TLS ClientHello → pipe raw bytes to internal TLS server
        const port = (implicitTlsServer.address() as net.AddressInfo).port;
        logger.debug('smtp', `Implicit TLS detected from ${clientAddr}, forwarding to port ${port}`);

        const internal = net.connect({ port, host: '127.0.0.1' });
        internal.on('connect', () => {
          internal.write(data);
          internal.on('data', (chunk) => socket.writable && socket.write(chunk));
          socket.on('data', (chunk) => internal.writable && internal.write(chunk));
          internal.on('end', () => socket.end());
          socket.on('end', () => internal.end());
        });
        internal.on('error', (err) => {
          logger.error('smtp', `Internal TLS error for ${clientAddr}: ${err.message}`);
          socket.destroy();
        });
        socket.on('error', () => internal.destroy());
      } else if (data[0] === 0x16) {
        logger.error('smtp', `TLS detected but no certs for ${clientAddr}`);
        socket.destroy();
      } else {
        logger.debug('smtp', `Plaintext detected from ${clientAddr}`);
        socket.unshift(data);
        pipeToSmtp(socket, starttlsServer, clientAddr);
      }
    });

    socket.on('error', (err) => {
      logger.debug('smtp', `Client error (${clientAddr}): ${err.message}`);
    });
  });

  server.on('error', (err) => logger.error('smtp', `Proxy error: ${err}`));

  // Plaintext-only server on a separate port (no TLS, no STARTTLS)
  let insecureServer: net.Server | null = null;
  if (ALLOW_INSECURE_AUTH && SMTP_INSECURE_PORT) {
    const plaintextSmtp = new SMTPServer({
      ...smtpOptions(null),
      secure: false,
      hideSTARTTLS: true,
      allowInsecureAuth: true,
    });
    plaintextSmtp.on('error', (err) => logger.error('smtp', `SMTP insecure server error: ${err}`));

    insecureServer = plaintextSmtp.server as net.Server;
    plaintextSmtp.listen(SMTP_INSECURE_PORT, BIND_HOST, () => {
      logger.info('smtp', `Insecure server listening on ${BIND_HOST}:${SMTP_INSECURE_PORT} (plaintext only, no STARTTLS)`);
    });
  }

  // Start outer server once all internal servers are ready
  let readyCount = 0;
  const needed = 2 + (implicitTlsServer ? 1 : 0);
  const onReady = () => {
    if (++readyCount === needed) {
      server.listen(SMTP_PORT, BIND_HOST, () => {
        logger.info('smtp', `Server listening on ${BIND_HOST}:${SMTP_PORT} (auto-detecting SSL/TLS and STARTTLS)`);
      });
    }
  };
  starttlsServer.server.on('listening', onReady);
  postTlsServer.server.on('listening', onReady);
  if (implicitTlsServer) implicitTlsServer.on('listening', onReady);


  return server;
}

// Pipe a socket (raw or TLS-decrypted) to the internal plaintext SMTP server
function pipeToSmtp(socket: net.Socket | tls.TLSSocket, smtpServer: SMTPServer, clientAddr: string) {
  const port = (smtpServer.server as net.Server).address() as net.AddressInfo;
  const internal = net.connect({ port: port.port, host: '127.0.0.1' });

  internal.on('connect', () => {
    internal.on('data', (chunk) => socket.writable && socket.write(chunk));
    socket.on('data', (chunk) => internal.writable && internal.write(chunk));
    internal.on('end', () => socket.end());
    socket.on('end', () => internal.end());
  });

  internal.on('error', (err) => {
    logger.error('smtp', `SMTP pipe error for ${clientAddr}: ${err.message}`);
    socket.destroy();
  });
  socket.on('error', () => internal.destroy());
}
