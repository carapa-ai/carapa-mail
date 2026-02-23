// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe } from "bun:test";
import { redact } from "./redactor.js";

// NOTE: redact() runs secret-scanner (redactSecrets) FIRST, then DLP rules.
// secret-scanner covers: API keys, tokens, private keys, credit cards → format: [NAME_REDACTED]
// dlp-rules covers: SSN, phone, email addresses, PII → format: [REDACTED:PIITYPE]
// SSN and Phone are ONLY in dlp-rules, so they always produce [REDACTED:SSN] / [REDACTED:PHONE].

describe("Email Redactor", () => {
  test("redacts credit card numbers", () => {
    const text = "My card is 1234-5678-9012-3456";
    const result = redact(text);
    // secret-scanner matches first with "Credit Card" pattern
    expect(result).toContain("REDACTED");
    expect(result).not.toBe(text);
  });

  test("redacts SSNs", () => {
    const text = "The SSN is 000-00-0000";
    const result = redact(text);
    // SSN matched by dlp-rules (no SSN pattern in secret-scanner)
    expect(result).toContain("[REDACTED:SSN]");
  });

  test("redacts phone numbers", () => {
    const text = "Call me at 123-456-7890 or +1 (555) 123-4567";
    const redacted = redact(text);
    // Phone matched by dlp-rules (no phone pattern in secret-scanner)
    expect(redacted).toContain("[REDACTED:PHONE]");
  });

  test("does not redact dates", () => {
    const text = "The date is 2024-02-22";
    expect(redact(text)).toBe("The date is 2024-02-22");
  });

  test("redacts mixed content", () => {
    const text = "SSN: 123-45-6789, Phone: 555.555.5555";
    const redacted = redact(text);
    expect(redacted).toContain("[REDACTED:SSN]");
    expect(redacted).toContain("[REDACTED:PHONE]");
  });

  test("handles empty string", () => {
    expect(redact("")).toBe("");
  });

  test("redacts AWS access keys", () => {
    // Standard AWS access key format: AKIA + exactly 16 uppercase alphanumeric chars
    const text = "Key: AKIAIOSFODNN7EXAMPLE";
    const redacted = redact(text);
    expect(redacted).toContain("REDACTED");
    expect(redacted).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  test("redacts private SSH keys", () => {
    const text = "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekeybody\n-----END OPENSSH PRIVATE KEY-----";
    const redacted = redact(text);
    expect(redacted).toContain("REDACTED");
  });
});
