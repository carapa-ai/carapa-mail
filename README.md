# CarapaMail

AI-powered SMTP + IMAP proxy that filters and sanitizes email using LLMs.

**[Documentation](https://mail.carapa.ai/docs)** | **[Website](https://carapa.ai)**

CarapaMail is a **passive guard** — it sits between your mail server and everything that reads email (humans and AI agents alike). It does not reply to emails or execute autonomous tasks on your behalf.
Its only job is to classify, block, sanitize, and route messages (e.g. to Quarantine or Spam) so that downstream consumers (your mail client, your AI agents) never see unfiltered content.

**For humans** — blocks spam, phishing, and malware before it reaches your inbox.

**For AI agents** — strips prompt injections, redacts PII, and quarantines suspicious content.
Agents that read email through CarapaMail's MCP tools get clean, safe data without needing their own filtering logic.

**Lite Mode** — Run without an AI model by setting `AI_FEATURES_ENABLED=false`. Useful for basic mail security (tracking pixel removal, HTML sanitization, and manual rules) without an LLM backend.

## How it works

```
Mail Client                       Upstream Server
     │                                  │
     ├─ SMTP ─→ [LLM] ─→ relay/reject/quarantine
     │                                  │
     └─ IMAP ←─ [sanitize] ←─ FETCH responses
        ↕ STARTTLS                      │
                       [scanner] ─→ IDLE/poll INBOX
                                 ─→ inspect new mail
                                 ─→ move spam to Spam
```

**Outbound SMTP proxy** accepts outgoing mail, sends a compact summary to the LLM for classification, then either relays, rejects, or quarantines the message.

### Inbound: two-layer protection

Inbound email is protected by two independent mechanisms that complement each other:

**Layer 1 — Background scanner** (`inbound-scanner.ts`): a persistent process that connects directly to the upstream IMAP server and proactively scans new messages.

- Maintains a long-lived IMAP connection using IDLE (instant notification) with a polling fallback
- Tracks the last processed UID per folder so it only scans new arrivals
- On first startup, sets the current highest UID as baseline — existing mail is not retroactively scanned
- Per message: checks user-defined rules first (instant, no AI call), then runs the AI filter if `AUTO_QUARANTINE` is on
- **Takes action on the mailbox** — moves spam/phishing to Spam, optionally routes passed messages to AI-suggested folders (e.g. "Receipts", "Work")
- Creates folders automatically if the move target doesn't exist yet
- Records every scan result in the `message_scans` DB table for the interceptor to use

**Layer 2 — IMAP proxy interceptor** (`imap/interceptor.ts`): a transparent filter that sits between the email client and the upstream server, intercepting FETCH responses as they stream through.

- Parses raw IMAP wire protocol, buffering `BODY[]`/`RFC822` literals as they arrive
- On each literal: checks the DB scan cache first (populated by the scanner) — if already scanned and rejected, replaces the body with a `[EMAIL BLOCKED]` warning
- If not yet cached (scanner hasn't reached it, was down, or race condition): runs the full filter pipeline inline before returning the response
- Rewrites the IMAP literal byte count `{N}` when content changes size
- **Always sanitizes** passed messages — strips tracking pixels, hidden content, dangerous HTML tags (script, iframe, object, embed, form), event handlers, zero-width characters, and prompt injection patterns regardless of filter decision
- **Never moves messages** — only modifies content in-flight; the original stays on the server
- Oversized literals (>50 MB) skip sanitization to prevent OOM

| | Scanner | Interceptor |
|---|---|---|
| When | Background, continuously | On every IMAP FETCH |
| Action on spam | Moves to Spam folder | Replaces body with warning |
| Caches results | Writes to DB | Reads from DB (+ writes on cache miss) |
| Sanitizes body | No | Yes (tracking, XSS, injection, PII) |
| Catches missed mail | No (new UIDs only) | Yes (any fetched message) |

The scanner is the first line of defense — it catches spam before the client polls. The interceptor is the safety net — if a message wasn't scanned yet, it filters on read. Together they ensure no unfiltered email reaches the client.

## Requirements

### Host Setup (Bun)
- **Bun Runtime**: v1.1.0 or higher
- **OpenSSL**: Required for auto-generating TLS certificates (STARTTLS).
- **OS**: Linux, macOS, or Windows (v1.1+).

### Container (Docker)
- **Docker Engine**: v20.10.x+
- **Docker Compose**: v2.0+

## Quick start

```bash
# Install dependencies
bun install

# Run
bun run dev
```

CarapaMail works with **Anthropic Claude** or any **local model** (Ollama, vLLM, LM Studio, llama.cpp).

**Cloud (Anthropic Claude):**
```bash
echo 'ANTHROPIC_AUTH_TOKEN=sk-ant-...' > .env
```

**Local model — no API key needed, data stays on your machine:**
```bash
echo 'ANTHROPIC_BASE_URL=http://localhost:11434/v1' > .env
echo 'ANTHROPIC_MODEL=qwen2.5:14b' >> .env
```

Open **http://localhost:3200/setup** to manage accounts. Then point your mail client at:
- **SMTP:** `localhost:2525` (authenticate with your email + CarapaMail password)
- **IMAP:** `localhost:1993` (authenticate with your email + CarapaMail password)

Multiple accounts are supported — CarapaMail routes to the correct upstream based on which account you authenticate as.

## Testing

CarapaMail uses [Bun's native test runner](https://bun.sh/docs/test/runner). Tests are divided into two categories to prevent accidental API costs and long wait times during development:

### 1. Code Tests
Standard unit and integration tests that verify application logic, parsing, and infrastructure. These are fast and use mocks for LLM calls.

```bash
# Run all core code tests
bun test
```

### 2. AI Filter Evaluations
A comprehensive benchmarking suite that evaluates the AI filter's accuracy against realistic datasets (spam, phishing, prompt injection, etc.) across multiple languages. These tests make real API calls to your configured model.

```bash
# Run LLM evaluation benchmarks (all languages)
bun run test:llm

# Run benchmarks for a specific language (e.g. German)
bun run test:llm -de
```

The evaluation suite will automatically skip if `ANTHROPIC_AUTH_TOKEN` is not set or if you run it via the standard `bun test` command without the `TEST_LLM=true` flag.

## Setup UI

The setup UI at `/setup` is how users and admins manage accounts and configure filtering.

### Authentication

The UI supports three access modes:

- **Admin** — authenticates with the `HTTP_API_TOKEN` bearer token. Can see, create, edit, and delete all accounts.
- **User** — authenticates with their email + CarapaMail password. Can edit and delete only their own account (including all settings, permissions, and prompts).
- **Guest** — when `ALLOW_SIGNUP=true` and an API token is set, unauthenticated visitors can create a new account directly. After signup, they're automatically logged in as a user.

### Account settings

Each account card shows IMAP/SMTP server info, permission badges, and action buttons. The **Edit** modal lets you configure:

- **Email address** and **CarapaMail password** — credentials for mail client authentication
- **IMAP / SMTP** — upstream server host, port, username, and password (encrypted at rest)
- **Security** — STARTTLS, TLS, or None for the SMTP connection; **Strict TLS** toggle for upstream certificate verification
- **Permissions** — toggle Inbound (IMAP scanning), Outbound (SMTP relay), MCP read, and MCP send independently
- **MCP Token** — generate or set a bearer token for MCP client access

**Test Connection** checks connectivity to the upstream IMAP and SMTP servers, but only tests services that are currently enabled for the account.

After login, users see a **mail client settings** card with the hostname and ports to configure in their email client.

### Custom filter prompts

The **Prompts** button opens a separate modal with tabs for the three filter contexts (Inbound, Outbound, Agent). Each tab offers three modes:

| Mode | Behavior |
|------|----------|
| **Default** | Uses the system prompt from `prompts/`. The textarea is disabled — any saved text is preserved but not used. |
| **Append** | Uses the system prompt with your custom text appended after it. Useful for adding account-specific rules without losing the base filtering. |
| **Replace** | Uses only your custom text, completely replacing the system prompt. |

Custom prompt text is stored per-account in the database and survives mode changes — switching to Default doesn't delete your text.

## Configuration

Accounts are managed through the setup UI at `/setup` (or via the `/api/accounts` REST API). Environment variables control proxy behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_PORT` | `2525` | Local SMTP proxy port (binds to localhost only in Docker) |
| `IMAP_PROXY_PORT` | `1993` | Local IMAP proxy port (binds to localhost only in Docker) |
| `HTTP_PORT` | `3200` | Admin API + setup UI port |
| `AI_FEATURES_ENABLED` | `true` | Master toggle for all AI filtering. If `false`, all AI logic is bypassed (lite/non-AI mode) |
| `ANTHROPIC_AUTH_TOKEN` | — | LLM API key (required for AI filtering) |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` | API base URL. Override to use a local proxy or alternative endpoint |
| `ANTHROPIC_MODEL` | `claude-haiku-4-5-20251001` | Model for filtering. Haiku is recommended for low latency and cost |
| `ENCRYPTION_KEY` | (auto-generated) | 32-byte hex key for AES-256-GCM password encryption. If not set, a key is generated at `store/.encryption-key` (mode 0600). **Back this up** — if lost, all stored passwords are unrecoverable |
| `FILTER_CONFIDENCE_THRESHOLD` | `0.7` | Below this confidence score, quarantine instead of hard-reject |
| `FILTER_TIMEOUT` | `5000` | AI API call timeout (ms) |
| `AGENT_CHUNK_TOKENS` | `0` | If > 0, large emails are split into chunks of ~N tokens for independent analysis (e.g. `4000`) |
| `AI_FAIL_ACTION` | `reject` | Action if AI call fails. `reject` (block, default), `passthrough` (allow), or `quarantine` (move to Spam) |
| `AUTO_QUARANTINE` | `true` | `false` = log-only passthrough mode (sanitizes but does not block) |
| `TLS_CERT_PATH` | — | Path to custom PEM certificate. If set, `TLS_KEY_PATH` is also required |
| `TLS_KEY_PATH` | — | Path to custom PEM private key |
| `INBOUND_SCAN` | `true` | `false` = disable background IMAP IDLE scanner (Layer 1) |
| `INBOUND_SCAN_INTERVAL` | `60000` | Polling fallback interval (ms) when IMAP IDLE is unavailable |
| `DKIM_VERIFY` | `false` | `true` = penalize emails missing DKIM/SPF authentication headers |
| `STRIP_REMOTE_IMAGES` | `false` | `true` = block all remote images in HTML emails. Tracking pixel removal is always on |
| `PII_REDACTION` | `false` | `true` = redact SSNs, credit cards, and API keys in IMAP email content delivered to clients |
| `MCP_ENABLED` | `false` | Enable MCP server for agent access |
| `MCP_PORT` | `3466` | MCP server port |
| `MCP_PUBLIC_URL` | — | Full public URL for the MCP endpoint shown in the setup UI (e.g. `https://mail.example.com:3466/mcp`). Falls back to `https://<PUBLIC_HOSTNAME>:<MCP_PORT>/mcp` |
| `HTTP_API_TOKEN` | — | Bearer token for admin API (empty = no auth). Set this in production |
| `ALLOW_SIGNUP` | `false` | `true` = guests can create accounts via `/setup` without the admin API token |
| `ALLOW_PROMPT_OVERRIDE` | `true` | `false` = prevent accounts from replacing the system filter prompt with a custom one |
| `ALLOW_PROMPT_APPEND` | `true` | `false` = prevent accounts from appending custom text to the system filter prompt |
| `PUBLIC_HOSTNAME` | (auto-detect) | Hostname shown in mail client setup instructions. Falls back to `window.location.hostname` |
| `DB_TYPE` | `sqlite` | `sqlite` or `postgres` |
| `DATABASE_URL` | — | PostgreSQL connection string (required when `DB_TYPE=postgres`). Example: `postgres://user:pass@localhost:5432/carapamail` |
| `AV_COMMAND` | — | CLI antivirus command. Each attachment is piped via stdin; exit code 0 = clean. Example: `clamscan --no-summary -` |
| `AV_TIMEOUT` | `30000` | Antivirus scan timeout (ms). If exceeded, the attachment is treated as suspicious |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

### Database

By default, CarapaMail uses SQLite (zero-config, stored at `store/carapamail.db`). For larger deployments with many accounts, PostgreSQL is supported:

```bash
# .env
DB_TYPE=postgres
DATABASE_URL=postgres://user:pass@localhost:5432/carapamail
```

Both backends use the same schema and migration system. SQLite databases are stored at `store/carapamail.db` and automatically migrated to the versioned schema on upgrade.

## Filter prompts

Filter prompts are stored as markdown files in `prompts/`. There are three distinct filtering contexts, each with its own prompt:

| File | Context | Used by |
|------|---------|---------|
| `prompts/outbound-filter.md` | Outbound emails | SMTP proxy — catches credential leaks, data exfiltration, secrets in outgoing mail |
| `prompts/inbound-filter.md` | Inbound emails (humans) | IMAP proxy FETCH filter, inbound scanner — catches spam, phishing, malware for webmail users |
| `prompts/inbound-agent-filter.md` | Inbound emails (AI agents) | MCP `carapamail_read_email` tool — stricter filter that also catches prompt injection, social engineering targeting AI, data exfiltration vectors, and marketing/newsletters agents don't need |

**Why separate inbound prompts?** AI agents are more vulnerable than humans to prompt injection embedded in email content — they'll execute instructions. The agent prompt is stricter: it rejects prompt injection with high confidence, quarantines marketing/newsletters, and flags emails that try to trick agents into leaking data via reply or tool use.

Edit these files to customize the default filtering behavior. Changes take effect on restart (prompts are loaded once on first use). When running in Docker, you can volume-mount `prompts/` to iterate without rebuilding.

Individual accounts can override these defaults via the setup UI — see [Custom filter prompts](#custom-filter-prompts) above.

## MCP tools

When `MCP_ENABLED=true`, carapamail exposes MCP tools on port `MCP_PORT` for AI agents.

### Authentication

MCP clients must authenticate with `Authorization: Bearer <token>`. The token is set per account in the setup UI — accounts sharing the same token are accessible in a single MCP session.

1. Open `/setup`, edit an account, and click **Generate** in the MCP Token section
2. Copy the generated token (it won't be shown again)
3. To give the same MCP client access to multiple accounts, paste the same token into each account
4. Configure your MCP client with the bearer token

### Access control

Each account has two MCP permission flags (configurable in the setup UI):

- **MCP read** — allows listing folders, reading emails, searching, deleting, and moving messages
- **MCP send** — allows composing and sending emails through the account

A token grants access only to accounts where it is set. Within those accounts, operations are further gated by the read/send flags.

### Available tools

| Tool | Description |
|------|-------------|
| `carapamail_list_accounts` | List accessible accounts (IDs and emails, no passwords) |
| `carapamail_list_folders` | List IMAP folders with message counts |
| `carapamail_list_emails` | List emails in a folder (paginated, newest first) |
| `carapamail_read_email` | Read a specific email by UID (on-demand AI filter on first read) |
| `carapamail_search` | Search emails with field/date filters (paginated) |
| `carapamail_send` | Compose and send an email (goes through outbound filter) |
| `carapamail_delete` | Delete emails by UID (bulk) |
| `carapamail_move` | Move emails to another folder (bulk) |
| `carapamail_stats` | Get filtering statistics |

All tools accept an optional `account` parameter (account ID or email) to target a specific mailbox. Defaults to the first accessible account.

All list/search tools return paginated results with `{ items, total, page, totalPages, hasMore }`.

**On-demand filtering:** When an agent reads an email via `carapamail_read_email`, carapamail checks if that message has already been AI-scanned. If not, it runs the full filter pipeline (rules → AI inspection) before returning the content. Flagged emails are moved to Spam and blocked from the agent. Results are cached in `message_scans` so subsequent reads are instant. The inbound scanner also populates this cache for new arriving emails.

## Admin API

All endpoints return JSON. If `HTTP_API_TOKEN` is set, include `Authorization: Bearer <token>`.

```
GET  /setup                       — account management UI

GET  /api/accounts                — list accounts (no passwords)
POST /api/accounts                — add account
PUT  /api/accounts/:id            — update account
DELETE /api/accounts/:id          — remove account
POST /api/accounts/:id/test       — test IMAP + SMTP connectivity

GET  /health                      — health check
GET  /stats                       — filtering statistics (?account=)
GET  /quarantine                  — list quarantined messages (?status=pending&account=)
GET  /quarantine/:id              — get quarantine entry details
POST /quarantine/:id/release      — release and relay to upstream
DELETE /quarantine/:id            — permanently delete

GET  /audit                       — audit log (?limit=100&offset=0&account=)

GET  /rules                       — list filter rules
POST /rules                       — create rule (body: {type, match_field, match_pattern, priority})
DELETE /rules/:id                 — delete rule
```

### Filter rules

Rules are evaluated before the AI agent, in priority order. Rule types:

| `type` | `match_field` | Effect |
|--------|---------------|--------|
| `allow` | `from`, `to`, `subject`, `body` | Skip AI, pass through |
| `block` | same | Reject immediately |
| `quarantine` | same | Quarantine without AI call |

`match_pattern` is a regex (case-insensitive).

Example — always allow from your domain:
```bash
curl -X POST http://localhost:3200/rules \
  -H "Content-Type: application/json" \
  -d '{"type":"allow","match_field":"from","match_pattern":"@yourdomain\\.com$","priority":10}'
```

## Docker

Two Docker Compose files are provided — pick the one that matches your needs.

### SQLite (default)

Zero-config, single-container setup. Good for personal use and small deployments.

```bash
# Set your API key
echo 'ANTHROPIC_AUTH_TOKEN=sk-ant-...' > .env

# Start
docker compose up -d
```

### PostgreSQL

For larger deployments with many accounts or when you want a proper database.

```bash
# Set your API key and a Postgres password
cat > .env <<EOF
ANTHROPIC_AUTH_TOKEN=sk-ant-...
POSTGRES_PASSWORD=change-me-to-something-strong
EOF

# Start
docker compose -f docker-compose.postgres.yml up -d
```

CarapaMail waits for PostgreSQL to pass its healthcheck before starting. The database, user, and schema are created automatically.

### Security hardening

Both compose files apply the same hardening:

- **Read-only filesystem** — only the `store` volume and `/tmp` (tmpfs) are writable
- **All capabilities dropped** — `cap_drop: ALL` (PostgreSQL gets the 4 it needs: `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`)
- **No privilege escalation** — `no-new-privileges:true`
- **Localhost-only ports** — all ports bind to `127.0.0.1`; use a reverse proxy (Caddy, nginx) for remote access
- **Resource limits** — memory and PID caps prevent runaway processes
- **PostgreSQL not exposed** — only reachable by carapamail over the internal Docker network

### Ports

| Port | Service | Compose variable |
|------|---------|-----------------|
| 2525 | SMTP proxy | `SMTP_PORT` |
| 1993 | IMAP proxy | `IMAP_PROXY_PORT` |
| 3200 | Admin UI + API | `HTTP_PORT` |
| 3466 | MCP server | `MCP_PORT` (disabled by default — uncomment in compose file) |

### Customizing filter prompts

The `prompts/` directory is volume-mounted read-only. Edit the files on the host and restart:

```bash
docker compose restart carapamail
```

### Connecting to host services

If `ANTHROPIC_BASE_URL` points to a service running on the host machine:

```bash
ANTHROPIC_BASE_URL=http://host.docker.internal:8080
```

### Sandbox stack

CarapaMail can also run as a sandbox stack via `carapa-box`:

```bash
# From carapa-box
./sandbox start carapamail
```

## Project structure

```
src/
  index.ts              — bootstrap
  config.ts             — env-derived config
  crypto.ts             — AES-256-GCM encryption + TLS certificate generation
  accounts.ts           — account registry (CRUD, auth, in-memory cache)
  db/
    index.ts            — async database API (accounts, quarantine, audit, rules, scanner state, scans)
    adapter.ts          — DbAdapter interface
    sqlite-adapter.ts   — SQLite adapter (bun:sqlite)
    pg-adapter.ts       — PostgreSQL adapter (pg)
    schema.ts           — dialect-aware DDL
    migrations.ts       — version-based migration runner
  types.ts              — shared types
  inbound-scanner.ts    — per-account IMAP IDLE + poll scanner
  smtp/
    server.ts           — SMTP server (auth-based account routing)
    handler.ts          — parse → inspect → relay/quarantine
    relay.ts            — per-account transporter pool
  imap/
    proxy.ts            — IMAP proxy (deferred auth, per-account upstream routing)
    interceptor.ts      — FETCH response interception
    sanitizer.ts        — HTML sanitization, PII redaction, prompt injection stripping
  agent/
    filter.ts           — Claude API integration
    prompts.ts          — prompt loader + regex patterns
  email/
    parser.ts           — mailparser wrapper (encryption/signature detection)
    quarantine.ts       — quarantine storage
    dlp-rules.ts        — DLP pattern definitions (28 rules for API keys, tokens, PII, crypto)
    dlp-scanner.ts      — DLP scoring engine
    secret-scanner.ts   — entropy-based secret/API key detection
    redactor.ts         — PII + secret masking before AI calls
  http/
    server.ts           — admin HTTP server
    routes.ts           — REST endpoints + account CRUD API
    setup-ui.ts         — embedded setup page (inline HTML + JS)
  mcp/
    server.ts           — MCP server (agent tool access)
    tools.ts            — MCP tool definitions (multi-account)
    imap-client.ts      — per-account IMAP client pool
prompts/
  inbound-filter.md       — inbound filter prompt (humans via webmail/IMAP)
  inbound-agent-filter.md — inbound filter prompt (AI agents via MCP, stricter)
  outbound-filter.md      — outbound filter prompt (SMTP)
```

## Support & Bugs

- **Reporting Bugs**: Please use [GitHub Issues](https://github.com/carapa-ai/carapa-mail/issues) exclusively to report bugs or request features.
- **Support**: During the Beta phase, formal support is not provided for non-commercial users. We do our best to monitor issues, but cannot guarantee response times.
- **Commercial Support**: Priority support is available to commercial license holders. See [COMMERCIAL.md](COMMERCIAL.md) for details.

## Contributing

We welcome contributions to CarapaMail! Whether it's fixing bugs, improving documentation, or suggesting new features, your help is appreciated.

By submitting a Pull Request, you agree to the following:
1. Your contribution is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).
2. You grant **Regun Software SRL** a non-exclusive, perpetual, irrevocable, royalty-free, worldwide license to use, modify, and distribute your contribution as part of both the non-commercial and commercial versions of CarapaMail.

## License

Copyright (c) 2026 Regun Software SRL

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).

**Personal / self-hosted use** — free and unrestricted. Run it on your own server for yourself, your family, or your homelab.

**Enterprise / commercial use** — requires a separate commercial license. Contact **hello@carapa.ai** for pricing and terms.

