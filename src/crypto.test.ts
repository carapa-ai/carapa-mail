// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe, beforeAll } from 'bun:test';
import { encrypt, decrypt, hashPassword, verifyPassword, getEncryptionKey } from './crypto.js';

describe('Crypto', () => {
  beforeAll(() => {
    // Ensure a key is available (auto-generates if needed)
    getEncryptionKey();
  });

  describe('encrypt / decrypt', () => {
    test('roundtrip preserves plaintext', () => {
      const plaintext = 'my-secret-password-123!';
      const encrypted = encrypt(plaintext);
      const decrypted = decrypt(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    test('encrypted format is iv:tag:ciphertext', () => {
      const encrypted = encrypt('test');
      const parts = encrypted.split(':');
      expect(parts).toHaveLength(3);
      // IV is 12 bytes = 24 hex chars
      expect(parts[0]).toHaveLength(24);
      // Auth tag is 16 bytes = 32 hex chars
      expect(parts[1]).toHaveLength(32);
      // Ciphertext is non-empty
      expect(parts[2].length).toBeGreaterThan(0);
    });

    test('same plaintext produces different ciphertexts (random IV)', () => {
      const a = encrypt('same-input');
      const b = encrypt('same-input');
      expect(a).not.toBe(b);
      // But both decrypt to the same value
      expect(decrypt(a)).toBe(decrypt(b));
    });

    test('handles empty string', () => {
      const encrypted = encrypt('');
      expect(decrypt(encrypted)).toBe('');
    });

    test('handles unicode', () => {
      const plaintext = 'пароль 密码 🔑';
      expect(decrypt(encrypt(plaintext))).toBe(plaintext);
    });

    test('tampered ciphertext throws', () => {
      const encrypted = encrypt('secret');
      const parts = encrypted.split(':');
      // Flip a byte in the ciphertext
      const tampered = parts[0] + ':' + parts[1] + ':' + 'ff' + parts[2].slice(2);
      expect(() => decrypt(tampered)).toThrow();
    });

    test('invalid format throws', () => {
      expect(() => decrypt('not:valid')).toThrow('Invalid encrypted value format');
      expect(() => decrypt('only-one-part')).toThrow('Invalid encrypted value format');
    });
  });

  describe('hashPassword / verifyPassword', () => {
    test('correct password verifies', () => {
      const hash = hashPassword('mypassword');
      expect(verifyPassword('mypassword', hash)).toBe(true);
    });

    test('wrong password does not verify', () => {
      const hash = hashPassword('mypassword');
      expect(verifyPassword('wrongpassword', hash)).toBe(false);
    });

    test('hash format is salt:hash', () => {
      const hash = hashPassword('test');
      const parts = hash.split(':');
      expect(parts).toHaveLength(2);
      // Salt is 16 bytes = 32 hex chars
      expect(parts[0]).toHaveLength(32);
      // Hash is 64 bytes = 128 hex chars
      expect(parts[1]).toHaveLength(128);
    });

    test('same password produces different hashes (random salt)', () => {
      const a = hashPassword('same');
      const b = hashPassword('same');
      expect(a).not.toBe(b);
      // But both verify
      expect(verifyPassword('same', a)).toBe(true);
      expect(verifyPassword('same', b)).toBe(true);
    });

    test('handles empty password', () => {
      const hash = hashPassword('');
      expect(verifyPassword('', hash)).toBe(true);
      expect(verifyPassword('notempty', hash)).toBe(false);
    });

    test('invalid hash format returns false', () => {
      expect(verifyPassword('test', 'no-colon-here')).toBe(false);
      expect(verifyPassword('test', '')).toBe(false);
    });
  });
});
