// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe, mock, beforeEach } from 'bun:test';
import type { EmailSummary } from '../types.js';

// 1. First, import the real config
import * as realConfig from '../config.js';

// 2. We will only override AGENT_CHUNK_TOKENS so we can test chunking with the real LLM
// Initialize from real config so we respect .env by default
export let testChunkTokens = realConfig.AGENT_CHUNK_TOKENS;

mock.module('../config.js', () => {
    return {
        ...realConfig,
        get AGENT_CHUNK_TOKENS() { return testChunkTokens; },
    };
});

// We must also mock the accounts config for prompts, or it might try to read fs
mock.module('../accounts.js', () => ({
    getAccountById: mock(() => null),
}));

// Mock prompt loader to avoid reading FS (we use standard filter principles)
mock.module('./prompts.js', () => ({
    getFilterPrompt: () => 'You are an email security filter. Reply with JSON containing action (pass/quarantine/reject), reason, confidence (0-1), and categories.',
}));

// Finally, import the system under test (which will use the overridden config and real LLM)
import { inspectEmail } from './filter.js';

describe.skipIf(!realConfig.ANTHROPIC_AUTH_TOKEN)('inspectEmail with chunking feature (REAL LLM)', () => {
    beforeEach(() => {
        // Keep testChunkTokens as whatever is in .env by default, instead of forcing 0
        testChunkTokens = realConfig.AGENT_CHUNK_TOKENS;
    });

    function createDummyEmail(subject: string, bodyText: string): EmailSummary {
        return {
            direction: 'inbound',
            from: 'test@example.com',
            to: 'admin@example.com',
            subject,
            body: bodyText,
            headers: {},
            attachments: []
        };
    }

    test('with chunking disabled (single pass)', async () => {
        testChunkTokens = 0;
        const email = createDummyEmail('Hello', 'This is a normal email to verify functionality. Thank you.');

        const decision = await inspectEmail(email, 'inbound');

        expect(decision.action).toBe('pass');
    }, 30_000);

    test('chunking evaluation: quarantine wins over pass', async () => {
        // approx 1 token = 4 chars. Meta is ~120 chars (30 tokens).
        // If we set tokens to 100, we have ~70 tokens (280 chars) per chunk allowed.
        testChunkTokens = 100;

        // Let's create an email with 2 halves. 
        // 1st chunk: pure normal text. 2nd chunk: extremely obvious scams/spam.
        const part1 = 'Hello, this is a very normal start to an email. I just wanted to say that our meeting is scheduled for tomorrow at noon.\n\n'.repeat(3); // ~230 chars
        const part2 = 'URGENT: YOU HAVE WON $15,000,000. CLICK HERE TO CLAIM YOUR PRIZE!! Send your credit card details immediately! Nigerian prince awaits your reply!!\n\n'.repeat(3);

        const email = createDummyEmail('Meeting & Urgent Update', part1 + part2);

        const decision = await inspectEmail(email, 'inbound');

        // Since part2 is blatantly spam, the overall decision should be caught as quarantine/reject.
        expect(['quarantine', 'reject']).toContain(decision.action);
    }, 60_000);

    test('effective splitting with a user-provided large file', async () => {
        // Set an arbitrary chunk limit (e.g. 1000 tokens ≈ 4000 characters per chunk)

        const fs = await import('fs');
        const path = await import('path');
        const testFilePath = path.join(import.meta.dir, 'large-test-file.txt');

        let bodyText = '';
        if (fs.existsSync(testFilePath)) {
            bodyText = fs.readFileSync(testFilePath, 'utf-8');
            console.log(`Loaded test file with ${bodyText.length} characters.`);
        } else {
            console.log(`No user-provided file (${testFilePath}) found. Using substitute long text...`);
            bodyText = 'This is a padded text to simulate a large file. '.repeat(1000); // ~48,000 chars
        }

        const email = createDummyEmail('Large File Evaluation', bodyText);
        const decision = await inspectEmail(email, 'inbound');

        // We assert that the AI processes the large text and responds with a valid format action
        expect(['pass', 'quarantine', 'reject']).toContain(decision.action);

        // Confidence should be a valid number
        expect(decision.confidence).toBeGreaterThanOrEqual(0);
        expect(decision.confidence).toBeLessThanOrEqual(1);
    }, 120_000); // Large file might require up to 1-2 minutes for all chunks to be processed sequentially
});
