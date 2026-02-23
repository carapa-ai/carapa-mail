// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { logger } from './logger.js';
import { loadRateLimits, upsertRateLimit, deleteRateLimit, pruneRateLimits } from './db/index.js';

interface RateLimitConfig {
  windowMs: number;
  maxAttempts: number;
  blockDurationMs: number;
}

interface AttemptRecord {
  count: number;
  lastAttempt: number;
  blockedUntil?: number;
}

const defaultAuthLimit: RateLimitConfig = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxAttempts: 5,
  blockDurationMs: 30 * 60 * 1000, // 30 minutes
};

const attempts = new Map<string, AttemptRecord>();

/**
 * Load persisted rate limit records from DB into memory.
 * Call after initDatabase() on startup.
 */
export async function initRateLimiter(): Promise<void> {
  try {
    const rows = await loadRateLimits();
    for (const row of rows) {
      attempts.set(row.key, {
        count: row.count,
        lastAttempt: row.last_attempt,
        blockedUntil: row.blocked_until ?? undefined,
      });
    }
    if (rows.length > 0) {
      logger.info('rate-limit', `Loaded ${rows.length} rate limit records from DB`);
    }
  } catch (err) {
    logger.warn('rate-limit', `Failed to load rate limits from DB (table may not exist yet): ${err}`);
  }
}

export function checkRateLimit(ip: string, action: string, config: RateLimitConfig = defaultAuthLimit): { allowed: boolean; retryAfter?: number } {
  const key = `${action}:${ip}`;
  const now = Date.now();
  const record = attempts.get(key);

  if (record) {
    // Check if currently blocked
    if (record.blockedUntil && record.blockedUntil > now) {
      return { allowed: false, retryAfter: Math.ceil((record.blockedUntil - now) / 1000) };
    }

    // Reset if window has passed
    if (now - record.lastAttempt > config.windowMs) {
      record.count = 0;
      record.blockedUntil = undefined;
    }
  }

  return { allowed: true };
}

export function recordAttempt(ip: string, action: string, success: boolean, config: RateLimitConfig = defaultAuthLimit) {
  const key = `${action}:${ip}`;
  const now = Date.now();
  let record = attempts.get(key);

  if (!record) {
    record = { count: 0, lastAttempt: now };
    attempts.set(key, record);
  }

  if (success) {
    // Reset on success
    attempts.delete(key);
    deleteRateLimit(key).catch(() => { });
    return;
  }

  record.count++;
  record.lastAttempt = now;

  if (record.count >= config.maxAttempts) {
    record.blockedUntil = now + config.blockDurationMs;
    logger.warn('rate-limit', `IP ${ip} blocked from ${action} for ${config.blockDurationMs / 60000} minutes after ${record.count} failures`);
  }

  // Fire-and-forget DB persistence
  upsertRateLimit(key, record.count, record.lastAttempt, record.blockedUntil).catch(() => { });
}

// Cleanup old records periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of attempts.entries()) {
    if (now - record.lastAttempt > 24 * 60 * 60 * 1000) { // 24 hours
      attempts.delete(key);
    }
  }
  pruneRateLimits(24 * 60 * 60 * 1000).catch(() => { });
}, 60 * 60 * 1000); // Hourly
