// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe } from 'bun:test';
import { checkRateLimit, recordAttempt } from './rate-limiter.js';

// Use unique action names per test to avoid cross-test state pollution
let testCounter = 0;
function uniqueAction() {
  return `test-action-${++testCounter}-${Date.now()}`;
}

describe('Rate Limiter', () => {
  test('allows requests under threshold', () => {
    const action = uniqueAction();
    const ip = '10.0.0.1';

    // First attempt should be allowed
    expect(checkRateLimit(ip, action).allowed).toBe(true);

    // Record 4 failures (under default limit of 5)
    for (let i = 0; i < 4; i++) {
      recordAttempt(ip, action, false);
    }

    // Should still be allowed
    expect(checkRateLimit(ip, action).allowed).toBe(true);
  });

  test('blocks after exceeding threshold', () => {
    const action = uniqueAction();
    const ip = '10.0.0.2';

    // Record 5 failures (hits the default limit)
    for (let i = 0; i < 5; i++) {
      recordAttempt(ip, action, false);
    }

    const result = checkRateLimit(ip, action);
    expect(result.allowed).toBe(false);
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  test('successful attempt resets counter', () => {
    const action = uniqueAction();
    const ip = '10.0.0.3';

    // Record 4 failures
    for (let i = 0; i < 4; i++) {
      recordAttempt(ip, action, false);
    }

    // Successful attempt resets
    recordAttempt(ip, action, true);

    // Record 4 more failures — should still be under limit
    for (let i = 0; i < 4; i++) {
      recordAttempt(ip, action, false);
    }

    expect(checkRateLimit(ip, action).allowed).toBe(true);
  });

  test('different IPs are tracked independently', () => {
    const action = uniqueAction();

    // Block IP A
    for (let i = 0; i < 5; i++) {
      recordAttempt('10.0.0.10', action, false);
    }

    // IP A blocked
    expect(checkRateLimit('10.0.0.10', action).allowed).toBe(false);
    // IP B still allowed
    expect(checkRateLimit('10.0.0.11', action).allowed).toBe(true);
  });

  test('different actions are tracked independently', () => {
    const action1 = uniqueAction();
    const action2 = uniqueAction();
    const ip = '10.0.0.20';

    // Block action1
    for (let i = 0; i < 5; i++) {
      recordAttempt(ip, action1, false);
    }

    // action1 blocked
    expect(checkRateLimit(ip, action1).allowed).toBe(false);
    // action2 still allowed
    expect(checkRateLimit(ip, action2).allowed).toBe(true);
  });

  test('custom config with lower threshold', () => {
    const action = uniqueAction();
    const ip = '10.0.0.30';
    const config = { windowMs: 60_000, maxAttempts: 2, blockDurationMs: 60_000 };

    recordAttempt(ip, action, false, config);
    expect(checkRateLimit(ip, action, config).allowed).toBe(true);

    recordAttempt(ip, action, false, config);
    expect(checkRateLimit(ip, action, config).allowed).toBe(false);
  });

  test('retryAfter is a positive number in seconds', () => {
    const action = uniqueAction();
    const ip = '10.0.0.40';

    for (let i = 0; i < 5; i++) {
      recordAttempt(ip, action, false);
    }

    const result = checkRateLimit(ip, action);
    expect(result.allowed).toBe(false);
    // retryAfter should be roughly blockDurationMs/1000 (30 minutes = 1800 seconds)
    expect(result.retryAfter).toBeGreaterThan(1700);
    expect(result.retryAfter).toBeLessThanOrEqual(1800);
  });
});
