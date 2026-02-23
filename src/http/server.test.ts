// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe, mock, beforeEach } from 'bun:test';
import type { IncomingMessage, ServerResponse } from 'http';

// Mocks MUST be set up before importing the module that uses them
mock.module('../config.js', () => ({
    HTTP_PORT: 0,
    HTTP_API_TOKEN: 'secret',
    ALLOW_SIGNUP: true,
    PUBLIC_HOSTNAME: 'localhost',
}));

mock.module('../accounts.js', () => ({
    authenticateAccount: mock((email: string, pass: string) => email === 'test@test.com' && pass === 'good' ? { id: 'acc1', email } : null),
}));

mock.module('./routes.js', () => ({
    matchRoute: mock((method: string, path: string) => {
        if (path === '/found') {
            return {
                handler: async (req: any, res: any) => {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ ok: true }));
                },
                params: {}
            };
        }
        if (path === '/error') {
            return {
                handler: async () => { throw new Error('Crash'); },
                params: {}
            };
        }
        return null;
    }),
}));

mock.module('../logger.js', () => ({
    logger: { info: mock(), error: mock(), warn: mock(), debug: mock() },
}));

mock.module('../rate-limiter.js', () => ({
    checkRateLimit: mock(() => ({ allowed: true, retryAfter: 0 })),
    recordAttempt: mock(),
}));

let requestHandler: any;
mock.module('http', () => ({
    default: {
        createServer: (handler: any) => {
            requestHandler = handler;
            return { listen: mock() };
        }
    }
}));

import { startHttpServer } from './server.js';

class MockResponse {
    statusCode: number = 200;
    headers: Record<string, string> = {};
    body: string = '';
    setHeader(name: string, value: string) {
        this.headers[name] = value;
    }
    writeHead(status: number, headers?: Record<string, string>) {
        this.statusCode = status;
        if (headers) Object.assign(this.headers, headers);
    }
    end(data?: string) {
        if (data) this.body += data;
    }
    json() {
        try { return JSON.parse(this.body); } catch { return this.body; }
    }
}

class MockRequest {
    method: string;
    url: string;
    socket = { remoteAddress: '127.0.0.1' };
    headers: Record<string, string> = { host: 'localhost' };
    carapamailAuth?: any;

    constructor(method: string, url: string, extraHeaders: Record<string, string> = {}) {
        this.method = method;
        this.url = url;
        Object.assign(this.headers, extraHeaders);
    }
}

describe('HTTP Server', () => {
    beforeEach(() => {
        startHttpServer();
    });

    test('CORS and Security headers are set', async () => {
        const req = new MockRequest('OPTIONS', '/');
        const res = new MockResponse();
        await requestHandler(req, res);

        expect(res.statusCode).toBe(204);
        expect(res.headers['Access-Control-Allow-Origin']).toBeDefined();
        expect(res.headers['X-Content-Type-Options']).toBe('nosniff');
    });

    test('Public routes allow access without auth', async () => {
        // '/setup' is considered a public route, so it doesn't instantly 401
        const req = new MockRequest('GET', '/setup');
        const res = new MockResponse();
        await requestHandler(req, res);
        expect(res.statusCode).not.toBe(401);
    });

    test('Admin token auth works', async () => {
        const req = new MockRequest('GET', '/found', { authorization: 'Bearer secret' });
        const res = new MockResponse();
        await requestHandler(req, res);
        expect(req.carapamailAuth).toEqual({ type: 'admin' });
        expect(res.statusCode).toBe(200);
        expect(res.json().ok).toBe(true);
    });

    test('Basic auth works', async () => {
        const token = Buffer.from('test@test.com:good').toString('base64');
        const req = new MockRequest('GET', '/found', { authorization: `Basic ${token}` });
        const res = new MockResponse();
        await requestHandler(req, res);
        expect(req.carapamailAuth).toEqual({ type: 'user', accountId: 'acc1' });
        expect(res.statusCode).toBe(200);
    });

    test('Invalid Basic auth blocked', async () => {
        const token = Buffer.from('test@test.com:bad').toString('base64');
        const req = new MockRequest('GET', '/found', { authorization: `Basic ${token}` });
        const res = new MockResponse();
        await requestHandler(req, res);
        // Because auth failed and the route is not public => 401
        expect(res.statusCode).toBe(401);
    });

    test('404 for unknown route', async () => {
        const req = new MockRequest('GET', '/unknown', { authorization: 'Bearer secret' });
        const res = new MockResponse();
        await requestHandler(req, res);
        expect(res.statusCode).toBe(404);
    });

    test('500 on handler error', async () => {
        const req = new MockRequest('GET', '/error', { authorization: 'Bearer secret' });
        const res = new MockResponse();
        await requestHandler(req, res);
        expect(res.statusCode).toBe(500);
    });
});
