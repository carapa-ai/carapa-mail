# Security

## Reporting vulnerabilities

If you discover a security vulnerability in CarapaMail, please report it responsibly:

- **Email:** hello@carapa.ai
- **Subject prefix:** `[SECURITY]`
- **Expected response:** within 72 hours

Do not open a public issue for security vulnerabilities. We will coordinate disclosure with you once a fix is available.

## Threat model

CarapaMail is a passive email guard. It protects against:

| Threat | Protection |
|--------|-----------|
| Spam / unsolicited bulk email | AI classification, user-defined rules |
| Phishing (credential harvesting) | URL risk analysis, sender authenticity checks, AI classification |
| Prompt injection targeting AI agents | Regex-based pattern stripping, AI classification with strict agent prompt |
| Sender spoofing | SPF/DKIM/DMARC header parsing, Reply-To/Return-Path/Message-ID consistency checks, display name analysis, lookalike domain detection |
| Malicious attachments | Extension/MIME scanning (40+ types including macro-enabled docs, disk images), double-extension detection, RTL-O character spoofing detection |
| HTML-based attacks (XSS, clickjacking) | Dangerous tag removal (script, iframe, object, embed, form, applet), event handler stripping, data URI blocking, zero-width character removal |
| Data exfiltration via outbound email | Outbound AI filter, DLP rules engine (28 patterns), entropy-based secret scanner |
| Credential/secret leaks in outgoing mail | DLP scanner detects API keys, tokens, private keys, cloud credentials, crypto wallet addresses |
| Brute-force authentication | Rate limiting on all auth surfaces |
| PII exposure to AI provider | DLP-based redaction (credit cards, SSNs, phones, emails, crypto addresses) + entropy-based secret masking before API calls |
| MITM on local connections | STARTTLS support on IMAP proxy, TLS certificates on SMTP proxy |
| Encrypted/signed email evasion | Detection and flagging of PGP/S/MIME encrypted and signed messages |

### Out of scope

CarapaMail does **not** protect against:

- **Encrypted/password-protected attachments** — content is opaque; only filename and MIME type are inspected
- **Zero-day exploits in attachment file formats** — no sandboxed execution or detonation
- **Compromised upstream mail server** — CarapaMail trusts the IMAP/SMTP upstream for transport
- **AI model failures** — if the LLM is unavailable, the MCP path withholds email content; the IMAP proxy path prepends a warning and delivers the email
- **Network-level attacks** — certificate pinning and network segmentation are outside CarapaMail's scope (though STARTTLS is now supported for local connections)

## Security architecture

CarapaMail has two independent email consumption paths. Both apply the full security pipeline:

```
                    ┌──────────────────────────────────┐
                    │        Upstream IMAP Server      │
                    └──────┬───────────────────┬───────┘
                           │                   │
              ┌────────────▼──────┐   ┌────────▼──────────┐
              │   IMAP Proxy      │   │  MCP IMAP Client  │
              │   (port 1993)     │   │  (direct connect) │
              └────────┬──────────┘   └────────┬──────────┘
                       │                       │
              ┌────────▼──────────┐   ┌────────▼──────────┐
              │   Interceptor     │   │   MCP Tools       │
              │   (FETCH filter)  │   │   (read_email)    │
              └────────┬──────────┘   └────────┬──────────┘
                       │                       │
                       ▼                       ▼
              ┌──────────────────────────────────────────┐
              │         Shared Security Pipeline         │
              │                                          │
              │  1. Rate limiting (per-IP, DB-backed)    │
              │  2. DB scan cache check                  │
              │  3. User-defined rule matching           │
              │  4. Attachment scanning (MIME-level)     │
              │     - 40+ dangerous extensions           │
              │     - Macro-enabled docs, disk images    │
              │     - RTL-O filename spoofing detection  │
              │  5. Sender authenticity                  │
              │     - SPF/DKIM/DMARC verification        │
              │     - Message-ID/Return-Path consistency │
              │     - Suspicious header scanning         │
              │     - Encryption/signature detection     │
              │  6. AI filter (LLM)                      │
              │     - URL risk analysis                  │
              │     - DLP + secret scanning (pre-API)    │
              │     - PII redaction (before API call)    │
              │     - Attachment metadata analysis       │
              │  7. Body sanitization (post-filter)      │
              │     - Dangerous HTML tag removal         │
              │     - Event handler stripping            │
              │     - Zero-width character removal       │
              │     - Prompt injection stripping         │
              │     - Hidden content removal             │
              │     - Tracking pixel removal             │
              │     - URL defanging + safety warnings    │
              └──────────────────────────────────────────┘
```

### Path differences

| | IMAP Proxy | MCP Tools |
|---|---|---|
| **Prompt** | `inbound-filter.md` (standard) | `inbound-agent-filter.md` (stricter) |
| **INBOX AI filter** | Always on | Always on (even in log-only mode) |
| **Sanitization** | Post-filter | Post-filter |
| **Moves spam** | Scanner moves to Spam folder | Returns error to agent |
| **Connection** | Client → proxy → upstream | Direct to upstream |

The MCP path uses a stricter AI prompt because AI agents are more vulnerable than humans to prompt injection, social engineering, and data exfiltration vectors embedded in email content.

## Credential security

| Asset | Protection | Details |
|-------|-----------|---------|
| IMAP/SMTP passwords | AES-256-GCM encryption at rest | Key from `ENCRYPTION_KEY` env var or auto-generated at `store/.encryption-key` (mode 0600) |
| CarapaMail local passwords | scrypt hash | Salt + hash stored; plaintext never persisted |
| MCP bearer tokens | SHA-256 hash | Raw token shown once at generation; only the hash is stored |
| Encryption key | File-system permissions | Auto-generated key is written with mode 0600; should be backed up separately |

### Key management

If `ENCRYPTION_KEY` is not set, CarapaMail generates a random 32-byte key on first startup and persists it to `store/.encryption-key`. **If this file is lost, all stored IMAP/SMTP passwords become unrecoverable.** For production deployments:

1. Set `ENCRYPTION_KEY` explicitly via environment variable
2. Back up the key separately from the database
3. Rotate by: setting a new key, then re-saving each account (triggers re-encryption)

## Rate limiting

All authentication surfaces are protected by an in-memory rate limiter:

| Surface | Key | Threshold | Block duration |
|---------|-----|-----------|---------------|
| SMTP AUTH | Client IP | 5 attempts / 15 min | 30 min |
| IMAP LOGIN | Client IP | 5 attempts / 15 min | 30 min |
| HTTP Basic Auth | Client IP | 5 attempts / 15 min | 30 min |
| REST `/api/auth` | Client IP | 5 attempts / 15 min | 30 min |
| MCP Bearer Auth | Client IP | 5 attempts / 15 min | 30 min |

Rate limiter state is persisted to the database and restored on restart. For multi-instance deployments, each instance maintains its own in-memory state with DB write-through — an external rate limiter (e.g., reverse proxy) is recommended for shared state.

## Email scanning pipeline

### URL risk analysis (`email/url-scanner.ts`)

Extracts URLs from email bodies and scores them against multiple heuristics:

- **Typosquatting** — Levenshtein distance against trusted domains (Google, Microsoft, Apple, GitHub, PayPal, etc.)
- **DGA detection** — Shannon entropy analysis to identify algorithmically generated domains
- **Suspicious TLDs** — `.zip`, `.top`, `.xyz`, `.loan`, `.click`, etc.
- **IP-as-hostname** — URLs using raw IP addresses
- **Punycode/homograph** — Internationalized domain names that visually mimic trusted domains
- **URL shorteners** — `bit.ly`, `t.co`, `tinyurl.com`, etc.
- **Suspicious paths** — `/login`, `/verify`, `/account`, `/password`, etc.

High-risk URLs (score >= 0.5) are **defanged** — in HTML, `href` is rewritten to `#blocked`; in plain text, dots are bracketed (e.g., `evil[.]com`) and protocol changed to `hxxps://`. Visible warning badges are also injected.

### Sender authenticity (`email/authenticity.ts`)

Analyzes email headers to detect spoofing:

- **SPF/DKIM/DMARC** — parsed from `Authentication-Results` and `Received-SPF` headers; with `DKIM_VERIFY=true`, missing authentication data incurs additional score penalties
- **Reply-To mismatch** — flags when Reply-To domain differs from From domain
- **Message-ID consistency** — flags when the Message-ID domain doesn't match the From domain (excludes common relays like SES, SendGrid, Mailgun)
- **Return-Path consistency** — flags when the Return-Path domain doesn't match the From domain
- **Display name spoofing** — suspicious keywords ("security", "support", "billing") from non-major-provider domains
- **Lookalike domains** — Levenshtein distance against major email providers
- **Suspicious headers** — detects `X-PHP-Originating-Script`, custom `X-Mailer`, and other headers associated with bulk mail tools
- **Encryption/signature detection** — flags PGP and S/MIME encrypted messages (content cannot be scanned) and digitally signed messages

### Attachment scanning (`email/attachment-scanner.ts`)

MIME-level analysis using `mailparser`:

- **Dangerous extensions** — 40+ types including executables (`.exe`, `.ps1`, `.vbs`, `.jar`, `.scr`, `.bat`), macro-enabled documents (`.docm`, `.xlsm`, `.pptm`), and disk images (`.iso`, `.vhd`, `.img`)
- **Double-extension tricks** — e.g., `invoice.pdf.exe`
- **RTL-O character spoofing** — detects Right-to-Left Override characters used to disguise file extensions (e.g., `file\u202Etxt.exe` appears as `fileexe.txt`)
- **Dangerous MIME types** — `application/x-msdownload`, `application/x-executable`, etc.
- **External antivirus** — optional `AV_COMMAND` config (e.g., `clamscan --no-summary -`); each attachment is piped to the command via stdin, exit code 0 = clean

### DLP and PII redaction (`email/dlp-rules.ts`, `email/secret-scanner.ts`, `email/redactor.ts`)

Before sending email content to the LLM, two layers of redaction are applied:

**Entropy-based secret scanner** — detects high-entropy strings that look like API keys, tokens, and credentials using Shannon entropy analysis. Secrets are masked as `[SECRET_REDACTED]`.

**DLP rules engine** — 28 regex patterns covering:

| Category | Examples | Redaction label |
|----------|---------|-----------------|
| API keys | AWS, Google, Stripe, GitHub, Slack tokens | `[REDACTED:AWS_KEY]`, etc. |
| PII | Credit cards, SSNs, phone numbers, email addresses | `[REDACTED:CREDIT_CARD]`, etc. |
| Crypto | Bitcoin, Ethereum addresses | `[REDACTED:CRYPTO_ADDRESS]` |
| Credentials | Private keys, connection strings | `[REDACTED:PRIVATE_KEY]`, etc. |

Redaction only applies to the AI API call. The original email content is preserved for the end consumer (after sanitization).

### HTML sanitization (`imap/sanitizer.ts`)

HTML email content is sanitized through multiple passes:

- **Invisible content removal** — `display:none`, zero-size fonts, white-on-white text
- **Tracking pixel removal** — 1x1 and 0x0 images
- **Remote image blocking** — optional (`STRIP_REMOTE_IMAGES=true`)
- **Dangerous tag removal** — `<script>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, `<meta http-equiv="refresh">`, `<base>`, dangerous `<link>` types
- **Dangerous attribute removal** — `on*` event handlers, `formaction`, `data:` URIs in `href`/`src`
- **Zero-width character removal** — strips Unicode zero-width spaces and similar non-printing characters used for fingerprinting or obfuscation

### STARTTLS support

The IMAP and SMTP proxies support STARTTLS for local client connections:

- **Self-signed TLS certificates** are automatically generated on first startup (stored at `store/server.key` and `store/server.cert`)
- **IMAP proxy** advertises `STARTTLS` capability and handles TLS upgrade before authentication
- **SMTP proxy** provides TLS certificates for client STARTTLS negotiation
- **Per-account `strict_tls`** — controls whether upstream IMAP connections verify server certificates (default: enabled)

## Docker hardening

See the [Docker section in README.md](README.md#docker) for container security details:

- Read-only filesystem
- All capabilities dropped
- No privilege escalation
- Localhost-only port binding
- Resource limits (memory + PIDs)
- PostgreSQL isolated on internal network

## HTTP security headers

The admin HTTP server sets the following headers on every response:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy` (restrictive policy)
- `Permissions-Policy` (disables camera, microphone, geolocation, etc.)
- `Strict-Transport-Security` (when served over HTTPS)

CORS `Access-Control-Allow-Origin` is restricted to `PUBLIC_HOSTNAME` when configured.

## AV Scan

1. Install ClamAV:


sudo apt install clamav clamav-daemon
# sudo freshclam          # download virus signatures
# clamscan --version

2. Configure CarapaMail in your .env:

AV_COMMAND=clamscan --no-summary -
3. Quick manual test — you can test directly with the EICAR test file (a harmless AV test signature recognized by all antivirus engines):

# Should exit 1 (infected)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | clamscan --no-summary -

# Should exit 0 (clean)
echo 'Hello, this is a normal file' | clamscan --no-summary -

# Run the integration tests
bun test src/email/av-scanner.integration.test.ts

4. Test via CarapaMail — send an email with the EICAR string as an attachment. The scanner pipes each attachment's content to clamscan --no-summary - via stdin. Exit code 0 = clean, non-zero = threat detected


## Known limitations

1. **No encrypted attachment inspection** — password-protected ZIP/RAR/7z files cannot be scanned; encrypted emails (PGP/S/MIME) are detected and flagged but content cannot be inspected
2. **No cryptographic DKIM verification** — CarapaMail reads DKIM results from upstream `Authentication-Results` headers; enable `DKIM_VERIFY=true` for stricter scoring when headers are missing, but full signature verification requires a future `mailauth` integration
3. **Multi-instance rate limiting** — rate limiter state is persisted to DB and survives restarts, but each instance maintains its own in-memory copy; not suitable for distributed deployments without an external limiter
4. **Regex-based HTML sanitization** — HTML processing uses regex patterns, not a DOM parser; sophisticated obfuscation (multi-line tags, unusual attribute quoting) may bypass hidden content detection
5. **Self-signed TLS certificates** — the auto-generated STARTTLS certificates are self-signed; mail clients will show a certificate warning unless you replace them with proper certificates or add an exception
