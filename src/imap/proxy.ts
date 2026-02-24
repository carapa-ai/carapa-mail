// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import net from 'net';
import tls from 'tls';
import { IMAP_PROXY_PORT, BIND_HOST } from '../config.js';
import { authenticateAccount, getAllAccounts, type Account } from '../accounts.js';
import { createInterceptor } from './interceptor.js';
import { logger } from '../logger.js';
import { checkRateLimit, recordAttempt } from '../rate-limiter.js';
import { getTlsCertificate } from '../crypto.js';

export function startImapProxy(): net.Server {
  const accounts = getAllAccounts();
  const certs = getTlsCertificate();

  if (accounts.length === 0) {
    logger.info('imap', 'No accounts configured, IMAP proxy disabled');
    return net.createServer();
  }

  // --- Internal TLS server for Implicit SSL connections ---
  // Same proven pattern as the SMTP proxy: pipe raw bytes to an internal
  // tls.Server that handles the TLS handshake natively.
  const implicitTlsServer = certs ? tls.createServer({
    key: certs.key,
    cert: certs.cert,
    requestCert: false,
    minVersion: 'TLSv1.2' as any,
  }) : null;

  if (implicitTlsServer) {
    implicitTlsServer.on('secureConnection', (tlsSocket: tls.TLSSocket) => {
      const clientIp = tlsSocket.remoteAddress || 'unknown';
      const clientAddr = `${clientIp}:${tlsSocket.remotePort}`;
      const cipher = tlsSocket.getCipher();
      const protocol = tlsSocket.getProtocol();
      logger.info('imap', `Implicit TLS secured for ${clientAddr} (${protocol}, ${cipher?.name})`);
      setupImapSession(tlsSocket, clientIp, clientAddr, true);
    });
    implicitTlsServer.on('tlsClientError', (err: any, tlsSocket) => {
      logger.error('imap', `Implicit TLS client error: ${err.message} (code: ${err.code || 'unknown'})`);
      logger.debug('imap', `TLS error details: ${JSON.stringify({ code: err.code, reason: err.reason, library: err.library })}`);
      tlsSocket.destroy();
    });
    implicitTlsServer.listen(0, '127.0.0.1');
  }

  // --- Main outer server ---
  const server = net.createServer(socket => {
    const clientIp = socket.remoteAddress || 'unknown';
    const clientAddr = `${clientIp}:${socket.remotePort}`;
    logger.debug('imap', `Client connected: ${clientAddr}`);

    // Sniff first byte to detect TLS vs plaintext
    let sniffed = false;
    const sniffTimeout = setTimeout(() => {
      if (!sniffed && !socket.destroyed) {
        sniffed = true;
        logger.debug('imap', 'Sniff timeout: assuming standard IMAP');
        setupImapSession(socket, clientIp, clientAddr, false);
      }
    }, 150);

    socket.once('data', (data) => {
      if (sniffed || socket.destroyed) return;
      clearTimeout(sniffTimeout);
      sniffed = true;

      if (data[0] === 0x16 && implicitTlsServer) {
        // TLS Handshake -> pipe to internal TLS server
        const port = (implicitTlsServer as any).address().port;
        logger.debug('imap', `Implicit TLS detected from ${clientAddr}, forwarding to internal port ${port}`);

        const internal = net.connect({ port, host: '127.0.0.1' });
        internal.on('connect', () => {
          logger.debug('imap', `Internal TLS connection established for ${clientAddr}`);
          internal.write(data);

          // Explicit bidirectional forwarding (instead of pipe) for debugging
          internal.on('data', (chunk) => {
            logger.debug('imap', `[internal→client] ${chunk.length} bytes for ${clientAddr}`);
            socket.write(chunk);
          });
          socket.on('data', (chunk) => {
            logger.debug('imap', `[client→internal] ${chunk.length} bytes for ${clientAddr}`);
            internal.write(chunk);
          });

          internal.on('end', () => socket.end());
          socket.on('end', () => internal.end());
        });
        internal.on('error', (err) => {
          logger.error('imap', `Internal TLS proxy error for ${clientAddr}: ${err.message}`);
          socket.destroy();
        });
        socket.on('error', (err) => {
          logger.debug('imap', `Client socket error during TLS pipe for ${clientAddr}: ${err.message}`);
          internal.destroy();
        });
      } else if (data[0] === 0x16) {
        logger.error('imap', `Implicit TLS detected but no certificates available for ${clientAddr}`);
        socket.destroy();
      } else {
        // Plaintext
        logger.debug('imap', `Plaintext detected from ${clientAddr}`);
        socket.unshift(data);
        setupImapSession(socket, clientIp, clientAddr, false);
      }
    });
  });

  server.on('error', (err) => {
    logger.error('imap', `Proxy server error: ${err}`);
  });

  // Wait for internal server to be ready before listening
  if (implicitTlsServer) {
    implicitTlsServer.on('listening', () => {
      const port = (implicitTlsServer as any).address().port;
      server.listen(IMAP_PROXY_PORT, BIND_HOST, () => {
        logger.info('imap', `Proxy listening on ${BIND_HOST}:${IMAP_PROXY_PORT} (auto-detecting TLS/Plain, internal TLS port ${port})`);
      });
    });
  } else {
    server.listen(IMAP_PROXY_PORT, BIND_HOST, () => {
      logger.info('imap', `Proxy listening on ${BIND_HOST}:${IMAP_PROXY_PORT} (plaintext only, no certs available)`);
    });
  }

  return server;
}

// ─── IMAP Session Handler ────────────────────────────────────────────────────
// Handles a single IMAP client session on a socket (raw or already-TLS).

function setupImapSession(
  initialSocket: net.Socket | tls.TLSSocket,
  clientIp: string,
  clientAddr: string,
  isSecure: boolean,
) {
  let clientSocket: net.Socket | tls.TLSSocket = initialSocket;
  const certs = getTlsCertificate();

  const interceptor = createInterceptor();
  let currentFolder = '';
  let currentUidValidity = 0;
  let upstreamSocket: tls.TLSSocket | null = null;
  let account: Account | null = null;
  let authenticated = false;
  let upgrading = false;

  // Track AUTHENTICATE PLAIN continuation
  let awaitingPlainContinuation = false;
  let authenticateTag = '';

  // Delay greeting slightly — TLSv1.3 needs a tick to finish post-handshake
  // processing (session tickets) before application data can flow
  function getCapabilities(): string[] {
    const caps = ['IMAP4rev1'];
    if (!isSecure && certs) {
      // RFC 3501: MUST advertise LOGINDISABLED when not encrypted
      caps.push('STARTTLS', 'LOGINDISABLED');
    } else {
      // Only advertise auth methods over a secure connection
      caps.push('AUTH=PLAIN', 'SASL-IR');
    }
    caps.push('ID', 'IDLE', 'NAMESPACE');
    return caps;
  }

  setImmediate(() => {
    const greeting = '* OK CarapaMail IMAP proxy ready';
    logger.debug('imap', `[P->C]: ${greeting}`);
    clientSocket.write(greeting + '\r\n', (err) => {
      if (err) {
        logger.error('imap', `Greeting write error for ${clientAddr}: ${err.message}`);
      } else {
        logger.debug('imap', `Greeting flushed OK for ${clientAddr}`);
      }
    });

    // Attach the IMAP command handler
    attachDataListener(clientSocket);
  });

  function connectUpstream(acc: Account): Promise<tls.TLSSocket> {
    return new Promise((resolve, reject) => {
      const sock = tls.connect(
        { host: acc.imap.host, port: acc.imap.port, rejectUnauthorized: acc.strictTls },
        () => {
          logger.info('imap', `Connected to upstream ${acc.imap.host}:${acc.imap.port} for ${acc.email}`);
          resolve(sock);
        },
      );
      sock.on('error', (err: Error) => reject(err));
    });
  }

  function setupUpstreamPipe(sock: tls.TLSSocket) {
    upstreamSocket = sock;
    let processing = Promise.resolve();

    sock.on('data', (data: Buffer) => {
      const str = data.toString('utf-8');
      logger.debug('imap', `[S]: ${str.trim()}`);

      // Track UIDVALIDITY from server SELECT/EXAMINE responses
      const validityMatch = str.match(/\[UIDVALIDITY\s+(\d+)\]/);
      if (validityMatch) {
        currentUidValidity = parseInt(validityMatch[1], 10);
        interceptor.setContext(currentFolder, currentUidValidity, account?.id || 'default');
      }

      processing = processing.then(async () => {
        try {
          const processed = await interceptor.process(data);
          if (processed.length > 0 && !clientSocket.destroyed) {
            clientSocket.write(processed);
          }
        } catch (err) {
          logger.error('imap', `Processing error: ${err instanceof Error ? err.message : err}`);
          if (!clientSocket.destroyed) clientSocket.write(data);
        }
      });
    });

    sock.on('end', () => clientSocket.end());
    sock.on('error', (err: Error) => {
      logger.error('imap', `Upstream error: ${err.message}`);
      clientSocket.destroy();
    });
  }

  async function handleAuth(tag: string, email: string, password: string) {
    const rateLimit = checkRateLimit(clientIp, 'imap-auth');
    if (!rateLimit.allowed) {
      logger.warn('imap', `Rate limit exceeded for IP ${clientIp}`);
      clientSocket.write(`${tag} NO [UNAVAILABLE] Too many failed attempts. Try again in ${rateLimit.retryAfter} seconds.\r\n`);
      return;
    }

    const acc = authenticateAccount(email, password);
    if (!acc) {
      recordAttempt(clientIp, 'imap-auth', false);
      clientSocket.write(`${tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n`);
      return;
    }

    recordAttempt(clientIp, 'imap-auth', true);
    account = acc;

    try {
      const sock = await connectUpstream(acc);

      // Consume upstream greeting (wait for "* OK")
      await new Promise<void>((resolve) => {
        const onData = (data: Buffer) => {
          const str = data.toString('utf-8');
          if (str.includes('* OK')) {
            sock.removeListener('data', onData);
            resolve();
          }
        };
        sock.on('data', onData);
      });

      // Login to upstream with real credentials
      const loginTag = 'A0';
      const loginCmd = `${loginTag} LOGIN "${escapeImapString(acc.imap.user)}" "${escapeImapString(acc.imap.pass)}"\r\n`;

      const loginResult = await new Promise<string>((resolve) => {
        let buf = '';
        const onData = (data: Buffer) => {
          buf += data.toString('utf-8');
          if (buf.includes(`${loginTag} OK`) || buf.includes(`${loginTag} NO`) || buf.includes(`${loginTag} BAD`)) {
            sock.removeListener('data', onData);
            resolve(buf);
          }
        };
        sock.on('data', onData);
        sock.write(loginCmd);
      });

      if (!loginResult.includes(`${loginTag} OK`)) {
        logger.warn('imap', `Upstream auth failed for ${acc.email} — response: ${loginResult.trim()}`);
        let msg = 'Upstream auth failed';
        if (loginResult.includes('INTERACTIONREQUIRED')) {
          msg = 'Upstream requires interaction (MFA). Please use an App Password.';
        } else {
          const match = loginResult.match(/(?:NO|BAD)\s+(.+)/i);
          if (match) msg = `Upstream: ${match[1]}`;
        }
        clientSocket.write(`${tag} NO [AUTHENTICATIONFAILED] ${msg}\r\n`);
        sock.destroy();
        return;
      }

      authenticated = true;
      setupUpstreamPipe(sock);

      // Tell client auth succeeded
      clientSocket.write(`${tag} OK LOGIN completed\r\n`);
    } catch (err: any) {
      let msg = err.message;
      if (msg.includes('INTERACTIONREQUIRED')) {
        msg = 'Upstream requires interaction (MFA). Please use an App Password.';
      }
      logger.error('imap', `Auth error for ${email}: ${err.message}`);
      clientSocket.write(`${tag} NO [UNAVAILABLE] ${msg}\r\n`);
    }
  }

  async function handleStartTls(tag: string, rawSocket: net.Socket) {
    if (upgrading || isSecure || clientSocket instanceof tls.TLSSocket) {
      clientSocket.write(`${tag} BAD Already in TLS mode\r\n`);
      return;
    }
    if (!certs) {
      clientSocket.write(`${tag} BAD STARTTLS unavailable\r\n`);
      return;
    }

    logger.debug('imap', `STARTTLS for ${clientAddr}`);
    upgrading = true;

    // Remove data listeners BEFORE sending OK
    rawSocket.removeAllListeners('data');

    // Flush the OK response, THEN upgrade — this ensures the client
    // receives "OK" in plaintext before we switch to TLS
    clientSocket.write(`${tag} OK Begin TLS negotiation now\r\n`, () => {
      try {
        logger.debug('imap', `STARTTLS OK flushed, creating TLSSocket for ${clientAddr}`);

        const tlsSocket = new tls.TLSSocket(rawSocket, {
          isServer: true,
          key: certs!.key,
          cert: certs!.cert,
        });

        tlsSocket.on('secure', () => {
          logger.info('imap', `STARTTLS secured for ${clientAddr}`);
          clientSocket = tlsSocket;
          upgrading = false;
          isSecure = true;
          attachDataListener(tlsSocket);
        });

        tlsSocket.on('error', (err) => {
          logger.error('imap', `STARTTLS error for ${clientAddr}: ${err.message}`);
          upgrading = false;
          rawSocket.destroy();
        });
      } catch (err: any) {
        logger.error('imap', `Failed STARTTLS: ${err.message}`);
        upgrading = false;
        rawSocket.destroy();
      }
    });
  }

  let commandBuffer = '';

  function attachDataListener(sock: net.Socket | tls.TLSSocket) {
    sock.on('data', (data) => {
      // Post-auth: forward raw bytes to upstream (no line splitting needed)
      if (authenticated) {
        const str = data.toString('utf-8');
        logger.debug('imap', `[C->P]: ${str.trim()}`);

        if (!upstreamSocket || upstreamSocket.destroyed) {
          const tag = str.split(' ')[0];
          if (tag) clientSocket.write(`${tag} NO Connection lost\r\n`);
          return;
        }

        // Track SELECT/EXAMINE to know the current folder
        const selectMatch = str.match(/^\S+ (?:SELECT|EXAMINE)\s+"?([^"\r\n]+?)"?\s*\r\n/i);
        if (selectMatch) {
          currentFolder = selectMatch[1].replace(/"/g, '');
        }

        upstreamSocket.write(data);
        return;
      }

      // Pre-auth: split by CRLF and process each command individually
      commandBuffer += data.toString('utf-8');
      const lines = commandBuffer.split('\r\n');
      // Keep the last (potentially incomplete) line in the buffer
      commandBuffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.trim()) continue;
        logger.debug('imap', `[C->P]: ${line.trim()}`);
        processPreAuthCommand(line + '\r\n', sock);
      }
    });
  }

  function processPreAuthCommand(str: string, sock: net.Socket | tls.TLSSocket) {
    // Before auth: handle CAPABILITY, LOGIN, AUTHENTICATE locally
    // Handle AUTHENTICATE PLAIN continuation (base64 credentials line)
    if (awaitingPlainContinuation) {
      awaitingPlainContinuation = false;
      const decoded = Buffer.from(str.trim(), 'base64').toString('utf-8');
      const parts = decoded.split('\0');
      const email = parts[1] || '';
      const password = parts[2] || '';
      handleAuth(authenticateTag, email, password);
      return;
    }

    // CAPABILITY
    if (/^\S+ CAPABILITY/i.test(str)) {
      const tag = str.split(' ')[0];
      const response = `* CAPABILITY ${getCapabilities().join(' ')}\r\n${tag} OK CAPABILITY completed\r\n`;
      logger.debug('imap', `[P->C]: ${response.trim()}`);
      clientSocket.write(response);
      return;
    }

    // STARTTLS
    if (/^\S+ STARTTLS/i.test(str)) {
      const tag = str.split(' ')[0];
      // STARTTLS only works on the original raw socket, not on a piped TLS socket
      if (initialSocket instanceof net.Socket && !(initialSocket instanceof tls.TLSSocket)) {
        handleStartTls(tag, initialSocket);
      } else {
        clientSocket.write(`${tag} BAD STARTTLS not available\r\n`);
      }
      return;
    }

    // NOOP
    if (/^\S+ NOOP/i.test(str)) {
      const tag = str.split(' ')[0];
      clientSocket.write(`${tag} OK NOOP completed\r\n`);
      return;
    }

    // ID (RFC 2971) — Thunderbird sends this during autoconfig
    if (/^\S+ ID /i.test(str)) {
      const tag = str.split(' ')[0];
      clientSocket.write(`* ID ("name" "CarapaMail" "version" "1.0")\r\n${tag} OK ID completed\r\n`);
      return;
    }

    // LOGIN: TAG LOGIN "user" "pass"
    if (/^\S+ LOGIN /i.test(str)) {
      const tag = str.split(' ')[0];
      if (!isSecure && certs) {
        clientSocket.write(`${tag} NO [PRIVACYREQUIRED] STARTTLS required before login\r\n`);
        return;
      }
      const loginMatch = str.match(/^\S+ LOGIN\s+(?:"((?:[^"\\]|\\.)*)"|(\S+))\s+(?:"((?:[^"\\]|\\.)*)"|(\S+))/i);
      const email = loginMatch ? (loginMatch[1] ?? loginMatch[2] ?? '').replace(/\\(.)/g, '$1') : '';
      const password = loginMatch ? (loginMatch[3] ?? loginMatch[4] ?? '').replace(/\\(.)/g, '$1') : '';
      handleAuth(tag, email, password);
      return;
    }

    // AUTHENTICATE PLAIN
    if (/^\S+ AUTHENTICATE PLAIN/i.test(str)) {
      const parts = str.trim().split(/\s+/);
      authenticateTag = parts[0];
      if (!isSecure && certs) {
        clientSocket.write(`${authenticateTag} NO [PRIVACYREQUIRED] STARTTLS required before authentication\r\n`);
        return;
      }
      if (parts.length > 3) {
        // Inline: TAG AUTHENTICATE PLAIN <base64>
        const decoded = Buffer.from(parts[3], 'base64').toString('utf-8');
        const authParts = decoded.split('\0');
        handleAuth(authenticateTag, authParts[1] || '', authParts[2] || '');
      } else {
        awaitingPlainContinuation = true;
        clientSocket.write('+ \r\n');
      }
      return;
    }

    // LOGOUT before auth
    if (/^\S+ LOGOUT/i.test(str)) {
      const tag = str.split(' ')[0];
      logger.debug('imap', `[P->C]: * BYE CarapaMail proxy closing / ${tag} OK LOGOUT completed`);
      clientSocket.write(`* BYE CarapaMail proxy closing\r\n${tag} OK LOGOUT completed\r\n`);
      clientSocket.end();
      return;
    }

    // Unknown pre-auth command
    const tag = str.split(' ')[0];
    if (tag && tag !== '*') {
      clientSocket.write(`${tag} BAD Please authenticate first\r\n`);
    }
  }

  // Cleanup
  initialSocket.on('end', () => {
    if (upstreamSocket) {
      const remaining = interceptor.flush();
      if (remaining.length > 0 && !clientSocket.destroyed) {
        clientSocket.write(remaining);
      }
      upstreamSocket.end();
    }
  });

  initialSocket.on('error', (err) => {
    logger.error('imap', `Client error (${clientAddr}): ${err.message}`);
    if (upstreamSocket) upstreamSocket.destroy();
  });
}

function escapeImapString(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}
