// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe, mock, beforeEach } from 'bun:test';
import type { IncomingMessage, ServerResponse } from 'http';

// Mocks MUST be set up before importing the module that uses them
mock.module('../db/index.js', () => ({
    getStats: mock(async () => ({ total: 10, passed: 5 })),
    listAccounts: mock(async () => []),
    listQuarantine: mock(async () => []),
    getQuarantineEntry: mock(async (id: string) => id === 'q1' ? { id: 'q1', account_id: 'acc1', raw_eml: Buffer.from('') } : null),
    listAuditLog: mock(async () => []),
    listRules: mock(async () => []),
    insertRule: mock(async () => { }),
    deleteRule: mock(async () => { }),
    autoWhitelistSender: mock(async () => { }),
    logAudit: mock(async () => { }),
}));

mock.module('../accounts.js', () => ({
    getAllAccounts: mock(() => []),
    getAccountById: mock((id: string) => id === 'acc1' ? { id: 'acc1', email: 'test@test.com', imap: {}, smtp: {} } : null),
    getAccountByEmail: mock((email: string) => email === 'test@test.com' ? { id: 'acc1' } : null),
    authenticateAccount: mock((email: string, pass: string) => email === 'test@test.com' && pass === 'good' ? { id: 'acc1', email } : null),
    addAccount: mock(async () => ({ id: 'new-acc', email: 'new@test.com' })),
    updateAccount: mock(async (id: string) => ({ id, email: 'updated@test.com' })),
    removeAccount: mock(async (id: string) => id === 'acc1'),
    testAccount: mock(async () => ({ imap: true, smtp: true })),
    testCredentials: mock(async () => ({ imap: true, smtp: true })),
}));

mock.module('../rate-limiter.js', () => ({
    checkRateLimit: mock(() => ({ allowed: true, retryAfter: 0 })),
    recordAttempt: mock(),
}));

mock.module('../email/quarantine.js', () => ({
    releaseFromQuarantine: mock(async (id: string) => id === 'q1' ? Buffer.from('test') : null),
    deleteFromQuarantine: mock(async (id: string) => id === 'q1'),
    quarantineMessage: mock(async () => { }),
}));

mock.module('../smtp/relay.js', () => ({
    relayRawMessage: mock(async () => { }),
}));

mock.module('../agent/filter.js', () => ({
    inspectEmail: mock(async () => ({ action: 'pass', reason: 'ok' })),
}));

// Import after mocks are set up
import { matchRoute } from './routes.js';

class MockResponse {
    statusCode: number = 200;
    headers: Record<string, string> = {};
    body: string = '';
    writeHead(status: number, headers: Record<string, string>) {
        this.statusCode = status;
        this.headers = headers;
    }
    end(data: string) {
        this.body += data;
    }
    json() {
        try {
            return JSON.parse(this.body);
        } catch {
            return this.body;
        }
    }
}

class MockRequest {
    method: string;
    url: string;
    socket = { remoteAddress: '127.0.0.1' };
    headers = { host: 'localhost' };
    carapamailAuth?: { type: string; accountId?: string };
    _body: string;

    constructor({ method, url, body, auth }: { method: string, url: string, body?: string, auth?: { type: string; accountId?: string } }) {
        this.method = method;
        this.url = url;
        this._body = body || '';
        this.carapamailAuth = auth;
    }

    async *[Symbol.asyncIterator]() {
        yield Buffer.from(this._body);
    }
}

describe('API Routes', () => {
    test('Health endpoint', async () => {
        const route = matchRoute('GET', '/health');
        expect(route).not.toBeNull();
        const req = new MockRequest({ method: 'GET', url: '/health' });
        const res = new MockResponse();
        await route!.handler(req as unknown as IncomingMessage, res as unknown as ServerResponse, route!.params);
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({ status: 'ok' });
    });

    test('Auth endpoint - success', async () => {
        const route = matchRoute('POST', '/api/auth');
        expect(route).not.toBeNull();
        const req = new MockRequest({
            method: 'POST',
            url: '/api/auth',
            body: JSON.stringify({ email: 'test@test.com', password: 'good' })
        });
        const res = new MockResponse();
        await route!.handler(req as unknown as IncomingMessage, res as unknown as ServerResponse, route!.params);
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({ accountId: 'acc1', email: 'test@test.com' });
    });

    test('Auth endpoint - failure', async () => {
        const route = matchRoute('POST', '/api/auth');
        const req = new MockRequest({
            method: 'POST',
            url: '/api/auth',
            body: JSON.stringify({ email: 'test@test.com', password: 'bad' })
        });
        const res = new MockResponse();
        await route!.handler(req as unknown as IncomingMessage, res as unknown as ServerResponse, route!.params);
        expect(res.statusCode).toBe(401);
        expect(res.json()).toEqual({ error: 'Invalid email or password' });
    });

    test('Stats endpoint - user access', async () => {
        const route = matchRoute('GET', '/stats');
        const req = new MockRequest({ method: 'GET', url: '/stats', auth: { type: 'user', accountId: 'acc1' } });
        const res = new MockResponse();
        await route!.handler(req as unknown as IncomingMessage, res as unknown as ServerResponse, route!.params);
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({ total: 10, passed: 5 });
    });

    test('Stats endpoint - unauthorized without auth', async () => {
        const route = matchRoute('GET', '/stats');
        const req = new MockRequest({ method: 'GET', url: '/stats', auth: { type: 'none' } });
        const res = new MockResponse();
        await route!.handler(req as unknown as IncomingMessage, res as unknown as ServerResponse, route!.params);
        expect(res.statusCode).toBe(401);
    });

    test('Create account - missing fields', async () => {
        const route = matchRoute('POST', '/api/accounts');
        const req = new MockRequest({ method: 'POST', url: '/api/accounts', body: '{}' });
        const res = new MockResponse();
        await route!.handler(req as unknown as IncomingMessage, res as unknown as ServerResponse, route!.params);
        expect(res.statusCode).toBe(400);
        expect(res.json().error).toContain('Missing required fields');
    });

    test('Create account - success', async () => {
        const route = matchRoute('POST', '/api/accounts');
        const validBody = {
            id: 'new-acc', email: 'new@test.com', imapHost: 'imap.tld', imapUser: 'u', imapPass: 'p', localPassword: 'lp'
        };
        const req = new MockRequest({ method: 'POST', url: '/api/accounts', body: JSON.stringify(validBody) });
        const res = new MockResponse();
        await route!.handler(req as unknown as IncomingMessage, res as unknown as ServerResponse, route!.params);
        expect(res.statusCode).toBe(201);
        expect(res.json().id).toBe('new-acc');
    });

    test('Quarantine endpoints', async () => {
        const route = matchRoute('GET', '/quarantine/q1');
        const req = new MockRequest({ method: 'GET', url: '/quarantine/q1', auth: { type: 'admin' } });
        const res = new MockResponse();
        await route!.handler(req as unknown as IncomingMessage, res as unknown as ServerResponse, route!.params);
        expect(res.statusCode).toBe(200);
        expect(res.json().id).toBe('q1');

        // Test release
        const releaseRoute = matchRoute('POST', '/quarantine/q1/release');
        const releaseReq = new MockRequest({ method: 'POST', url: '/quarantine/q1/release', auth: { type: 'admin' } });
        const releaseRes = new MockResponse();
        await releaseRoute!.handler(releaseReq as unknown as IncomingMessage, releaseRes as unknown as ServerResponse, releaseRoute!.params);
        expect(releaseRes.statusCode).toBe(200);
        expect(releaseRes.json().released).toBe(true);
    });

    test('Rules endpoint - Admin restricted', async () => {
        const getRoute = matchRoute('GET', '/rules');
        const req1 = new MockRequest({ method: 'GET', url: '/rules', auth: { type: 'user', accountId: 'acc1' } });
        const res1 = new MockResponse();
        await getRoute!.handler(req1 as unknown as IncomingMessage, res1 as unknown as ServerResponse, getRoute!.params);
        expect(res1.statusCode).toBe(403);

        const req2 = new MockRequest({ method: 'GET', url: '/rules', auth: { type: 'admin' } });
        const res2 = new MockResponse();
        await getRoute!.handler(req2 as unknown as IncomingMessage, res2 as unknown as ServerResponse, getRoute!.params);
        expect(res2.statusCode).toBe(200);
    });

    test('Rules endpoint - POST validation', async () => {
        const route = matchRoute('POST', '/rules');
        // valid
        const reqValid = new MockRequest({ method: 'POST', url: '/rules', body: JSON.stringify({ type: 'allow', match_field: 'from', match_pattern: '.*' }), auth: { type: 'admin' } });
        const resValid = new MockResponse();
        await route!.handler(reqValid as unknown as IncomingMessage, resValid as unknown as ServerResponse, route!.params);
        expect(resValid.statusCode).toBe(201);

        // invalid regex
        const reqInvalidReg = new MockRequest({ method: 'POST', url: '/rules', body: JSON.stringify({ type: 'allow', match_field: 'from', match_pattern: '[unclosed' }), auth: { type: 'admin' } });
        const resInvalidReg = new MockResponse();
        await route!.handler(reqInvalidReg as unknown as IncomingMessage, resInvalidReg as unknown as ServerResponse, route!.params);
        expect(resInvalidReg.statusCode).toBe(400);
        expect(resInvalidReg.json().error).toContain('not a valid regular expression');
    });

    test('Delete account endpoint', async () => {
        const route = matchRoute('DELETE', '/api/accounts/acc1');
        const params = route!.params;

        // user deleting their own account (needs valid password)
        const reqGoodBody = new MockRequest({ method: 'DELETE', url: '/api/accounts/acc1', body: JSON.stringify({ password: 'good' }), auth: { type: 'user', accountId: 'acc1' } });
        const resGoodBody = new MockResponse();
        await route!.handler(reqGoodBody as unknown as IncomingMessage, resGoodBody as unknown as ServerResponse, params);
        expect(resGoodBody.statusCode).toBe(200);
        expect(resGoodBody.json()).toEqual({ deleted: true });

        // admin deleting bypasses password
        const reqAdmin = new MockRequest({ method: 'DELETE', url: '/api/accounts/acc1', body: '', auth: { type: 'admin' } });
        const resAdmin = new MockResponse();
        await route!.handler(reqAdmin as unknown as IncomingMessage, resAdmin as unknown as ServerResponse, params);
        expect(resAdmin.statusCode).toBe(200);
        expect(resAdmin.json()).toEqual({ deleted: true });
    });
});
