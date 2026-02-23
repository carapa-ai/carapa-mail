// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import http from 'http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { MCP_PORT } from '../config.js';
import { getAccountIdsByMcpToken } from '../accounts.js';
import { checkRateLimit, recordAttempt } from '../rate-limiter.js';
import { registerTools } from './tools.js';
import { disconnect as disconnectImap } from './imap-client.js';

function extractBearerToken(req: http.IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return null;
  return auth.slice(7).trim() || null;
}

function sendJson(res: http.ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

export async function startMcpServer(): Promise<http.Server> {
  const httpServer = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host}`);

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (url.pathname === '/health') {
      sendJson(res, 200, { status: 'ok' });
      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404);
      res.end('Not found');
      return;
    }

    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'Method not allowed. Use POST.' });
      return;
    }

    // Read and parse body
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    let body: any;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
    } catch {
      sendJson(res, 400, { error: 'Invalid JSON' });
      return;
    }

    // Authenticate via Bearer token
    const clientIp = req.socket.remoteAddress || 'unknown';

    const rateLimit = checkRateLimit(clientIp, 'mcp-auth');
    if (!rateLimit.allowed) {
      res.writeHead(429, { 'Retry-After': String(Math.ceil((rateLimit.retryAfter ?? 0) / 1000)) });
      res.end(JSON.stringify({ error: 'Too many authentication attempts. Try again later.' }));
      return;
    }

    const rawToken = extractBearerToken(req);
    if (!rawToken) {
      recordAttempt(clientIp, 'mcp-auth', false);
      sendJson(res, 401, { error: 'Authorization: Bearer <token> required' });
      return;
    }

    const allowedAccountIds = await getAccountIdsByMcpToken(rawToken);
    if (allowedAccountIds.length === 0) {
      recordAttempt(clientIp, 'mcp-auth', false);
      sendJson(res, 401, { error: 'Invalid token or no accounts linked to this token' });
      return;
    }

    recordAttempt(clientIp, 'mcp-auth', true);

    // Stateless: create a fresh server+transport per request, no session tracking
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    const server = new McpServer({
      name: 'carapamail',
      version: '0.1.0',
    });
    registerTools(server, allowedAccountIds);

    await server.connect(transport);
    await transport.handleRequest(req, res, body);
    await transport.close();
    await server.close();
  });

  httpServer.listen(MCP_PORT, () => {
    console.log(`[mcp] Server listening on port ${MCP_PORT}`);
  });

  httpServer.on('close', () => {
    disconnectImap();
  });

  return httpServer;
}
