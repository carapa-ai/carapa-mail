// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import http from 'http';
import { HTTP_PORT, HTTP_API_TOKEN, ALLOW_SIGNUP, PUBLIC_HOSTNAME, BIND_HOST } from '../config.js';
import { authenticateAccount } from '../accounts.js';
import { matchRoute } from './routes.js';

import { logger } from '../logger.js';
import { checkRateLimit, recordAttempt } from '../rate-limiter.js';

// Auth role attached to each request
export type AuthRole = { type: 'admin' } | { type: 'user'; accountId: string } | { type: 'guest' } | { type: 'none' };

// Extend IncomingMessage to carry auth info
declare module 'http' {
  interface IncomingMessage {
    carapamailAuth?: AuthRole;
  }
}

export function startHttpServer(): http.Server {
  const server = http.createServer(async (req, res) => {
    // CORS & Security Headers
    const origin = req.headers.origin || '';
    const allowedOrigin = PUBLIC_HOSTNAME ? (origin.includes(PUBLIC_HOSTNAME) ? origin : `https://${PUBLIC_HOSTNAME}`) : '*';

    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Security Best Practices
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self';");
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');

    // Strict-Transport-Security (only if on HTTPS or known public hostname)
    if (PUBLIC_HOSTNAME || req.headers['x-forwarded-proto'] === 'https') {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const clientIp = req.socket.remoteAddress || 'unknown';
    const isLocal = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1' ||
      clientIp.startsWith('192.168.') ||
      clientIp.startsWith('10.') ||
      clientIp.startsWith('::ffff:192.168.') ||
      clientIp.startsWith('::ffff:10.') ||
      (clientIp.startsWith('172.') && (() => {
        const parts = clientIp.split('.');
        if (parts.length < 2) return false;
        const second = parseInt(parts[1], 10);
        return second >= 16 && second <= 31;
      })());

    const pathname = (req.url || '/').split('?')[0];
    const isPublic = pathname === '/' || pathname === '/setup' || pathname === '/health'
      || pathname === '/api/auth'
      || (ALLOW_SIGNUP && req.method === 'POST' && pathname === '/api/accounts');

    // Determine auth role
    const authHeader = req.headers.authorization || '';
    if (authHeader === `Bearer ${HTTP_API_TOKEN}` && HTTP_API_TOKEN) {
      req.carapamailAuth = { type: 'admin' };
    } else if (authHeader.startsWith('Basic ')) {
      // Rate limit check for Basic auth
      const rateLimit = checkRateLimit(clientIp, 'http-basic-auth');
      if (!rateLimit.allowed) {
        logger.warn('http', `Rate limit exceeded for IP ${clientIp}`);
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': rateLimit.retryAfter?.toString() || '60' });
        res.end(JSON.stringify({ error: 'Too many failed attempts. Try again later.' }));
        return;
      }

      // User login: Basic base64(email:password)
      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString();
      const colonIdx = decoded.indexOf(':');
      if (colonIdx > 0) {
        const email = decoded.slice(0, colonIdx);
        const password = decoded.slice(colonIdx + 1);
        const account = authenticateAccount(email, password);
        if (account) {
          recordAttempt(clientIp, 'http-basic-auth', true);
          req.carapamailAuth = { type: 'user', accountId: account.id };
        } else {
          recordAttempt(clientIp, 'http-basic-auth', false);
        }
      }
    }

    if (!req.carapamailAuth) {
      if (!HTTP_API_TOKEN && isLocal) {
        // No token configured — only allow local admin access
        req.carapamailAuth = { type: 'admin' };
      } else if (isPublic) {
        req.carapamailAuth = (ALLOW_SIGNUP || pathname === '/setup') ? { type: 'guest' } : { type: 'none' };
      }
    }

    if (!req.carapamailAuth || req.carapamailAuth.type === 'none') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    const url = new URL(req.url || '/', `http://${req.headers.host}`);
    const match = matchRoute(req.method || 'GET', url.pathname);

    if (!match) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    try {
      await match.handler(req, res, match.params);
    } catch (err) {
      logger.error('http', `Route error: ${err}`);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  });

  server.listen(HTTP_PORT, BIND_HOST, () => {
    logger.info('http', `Admin API listening on ${BIND_HOST}:${HTTP_PORT}`);
  });

  return server;
}
