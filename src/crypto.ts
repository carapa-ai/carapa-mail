// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { STORE_DIR, TLS_CERT_PATH, TLS_KEY_PATH, PUBLIC_HOSTNAME } from './config.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_FILE = '.encryption-key';

let encryptionKey: Buffer | null = null;

/**
 * Get or generate the master encryption key.
 * Priority: CARAPA_MAIL_ENCRYPTION_KEY env var → persisted file in store/ → auto-generate and persist.
 */
export function getEncryptionKey(): Buffer {
  if (encryptionKey) return encryptionKey;

  const envKey = process.env.CARAPA_MAIL_ENCRYPTION_KEY;
  if (envKey) {
    encryptionKey = Buffer.from(envKey, 'hex');
    if (encryptionKey.length !== 32) {
      throw new Error('CARAPA_MAIL_ENCRYPTION_KEY must be 64 hex characters (32 bytes)');
    }
    return encryptionKey;
  }

  const keyPath = path.join(STORE_DIR, KEY_FILE);
  if (fs.existsSync(keyPath)) {
    encryptionKey = Buffer.from(fs.readFileSync(keyPath, 'utf-8').trim(), 'hex');
    if (encryptionKey.length !== 32) {
      throw new Error(`Invalid encryption key in ${keyPath}`);
    }
    return encryptionKey;
  }

  // Auto-generate and persist
  fs.mkdirSync(STORE_DIR, { recursive: true });
  encryptionKey = crypto.randomBytes(32);
  fs.writeFileSync(keyPath, encryptionKey.toString('hex') + '\n', { mode: 0o600 });
  console.log(`[crypto] Generated encryption key → ${keyPath}`);
  return encryptionKey;
}

/**
 * Encrypt a plaintext string using AES-256-GCM.
 * Returns "iv:authTag:ciphertext" in hex encoding.
 */
export function encrypt(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypt an "iv:authTag:ciphertext" hex string back to plaintext.
 */
export function decrypt(encoded: string): string {
  const key = getEncryptionKey();
  const parts = encoded.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted value format');
  }
  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const ciphertext = Buffer.from(parts[2], 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);
  return decipher.update(ciphertext).toString('utf-8') + decipher.final('utf-8');
}

/**
 * Hash a password using scrypt.
 * Returns "salt:hash" in hex.
 */
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

/**
 * Verify a password against a hash.
 */
export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split(':');
  if (parts.length !== 2) return false;
  const [salt, hash] = parts;
  const key = crypto.scryptSync(password, salt, 64).toString('hex');
  return key === hash;
}

/**
 * Checks if TLS requirements are met. Returns ok:true if certs exist or can be generated.
 */
export function checkTlsRequirements(): { ok: boolean; message?: string } {
  const keyPath = TLS_KEY_PATH || path.join(STORE_DIR, 'server.key');
  const certPath = TLS_CERT_PATH || path.join(STORE_DIR, 'server.cert');

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    return { ok: true };
  }

  if (TLS_CERT_PATH || TLS_KEY_PATH) {
    return { ok: false, message: `Configured TLS paths not found: ${keyPath} or ${certPath}` };
  }

  try {
    execSync('openssl version', { stdio: 'ignore' });
    return { ok: true };
  } catch {
    return {
      ok: false,
      message: 'OpenSSL not found in PATH. Required to generate self-signed certificates for STARTTLS. Please install OpenSSL or provide your own certificates via TLS_CERT_PATH and TLS_KEY_PATH.'
    };
  }
}

/**
 * Ensures self-signed TLS certificates exist for STARTTLS.
 * Returns { key: string, cert: string } or null if unavailable.
 */
export function getTlsCertificate(): { key: string; cert: string } | null {
  const keyPath = TLS_KEY_PATH || path.join(STORE_DIR, 'server.key');
  const certPath = TLS_CERT_PATH || path.join(STORE_DIR, 'server.cert');

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    try {
      return {
        key: fs.readFileSync(keyPath, 'utf-8'),
        cert: fs.readFileSync(certPath, 'utf-8'),
      };
    } catch {
      return null;
    }
  }

  if (TLS_CERT_PATH || TLS_KEY_PATH) {
    return null;
  }

  try {
    const hostname = PUBLIC_HOSTNAME || 'localhost';
    const subj = `/CN=${hostname}`;
    const san = `subjectAltName=DNS:${hostname},IP:127.0.0.1`;
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 3650 -nodes -subj "${subj}" -addext "${san}"`,
      { stdio: 'pipe' }
    );
    return {
      key: fs.readFileSync(keyPath, 'utf-8'),
      cert: fs.readFileSync(certPath, 'utf-8'),
    };
  } catch (err) {
    return null;
  }
}
