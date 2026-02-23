# CarapaMail

AI-powered SMTP + IMAP proxy for comprehensive email filtering, security scanning, and sanitization.

## What this is

An email proxy tailored for both human users and embedded LLM agents. It features a robust, multi-layered security pipeline:
1. **Traditional Security Layer** — Analyzes attachments, checks anti-virus, scans URLs, checks sender authenticity (SPF/DKIM/DMARC), and detects data/secret leaks.
2. **AI Semantic Filtering** — Uses an embedded LLM agent to make higher-level judgements about spam, phishing, and context.
3. **Agent Protection** — Strips out PII, neutralizes tracking pixels, and sanitizes prompt injection attempts via the IMAP proxy.

## Architecture

- **SMTP proxy** (`src/smtp/`): Accepts mail on port `SMTP_PORT` (default 2525), inspects outbound emails via LLM prompts, relays or quarantines them.
- **IMAP proxy** (`src/imap/`): TCP proxy on port `IMAP_PROXY_PORT` (default 1993), intercepts FETCH responses for reactive, on-the-fly AI filtering and body sanitization (tracking pixels, prompt injections).
- **Inbound scanner** (`src/inbound-scanner.ts`): Background IMAP IDLE + poll loop that proactively processes new incoming mail, running security modules and the AI-filter. Moves spam out of the inbox and updates the cache.
- **Security Scanners** (`src/email/`): Synchronous and asynchronous scanners that run before the LLM, including:
  - Antivirus (`av-scanner.ts`) relying on external binaries (e.g. ClamAV).
  - Attachment risk analysis (`attachment-scanner.ts`).
  - Authenticity validation (`authenticity.ts`).
  - Data Loss Prevention / Secrets (`dlp-scanner.ts` / `secret-scanner.ts`).
  - URL scanning (`url-scanner.ts`) and PII redaction (`redactor.ts`).
- **AI Agent Filter** (`src/agent/`): Executes LLM prompts for nuanced filtering decisions based on different contexts.
- **MCP Server** (`src/mcp/`): Exposes safe email tools to external AI agents via the Model Context Protocol (giving agents an on-demand, strictly sanitized path).
- **Admin API** (`src/http/`): REST API on port `HTTP_PORT` (default 3200) for quarantine management, multi-account setup, and statistics.
- **Database Layer** (`src/db/`): An abstracted database layer supporting both `postgres` and `sqlite` based on the `DB_TYPE` env variable, storing accounts, quarantine, audit logs, rules, and scan cache.

## Multi-Account Setup

CarapaMail supports maintaining multiple accounts (IMAP/SMTP credentials) simultaneously. 
Credentials, routing profiles, custom AI prompts, and feature flags (inbound vs outbound scanning) are stored per account in the `accounts` table within the database, configured initially via the Setup UI.

## Three-Prompt Filtering Architecture

The logic defines 3 distinct AI filtering contexts, each with its own system prompt:

| Prompt file | Context | Code path |
|-------------|---------|-----------|
| `prompts/outbound-filter.md` | Outbound SMTP | `src/smtp/handler.ts` → `inspectEmail(summary)` |
| `prompts/inbound-filter.md` | Inbound for humans | `src/imap/interceptor.ts`, `src/inbound-scanner.ts` |
| `prompts/inbound-agent-filter.md` | Inbound for AI agents | `src/mcp/tools.ts` (`carapamail_read_email`) |

**Why separate inbound prompts?** AI agents executing autonomous tasks are vulnerable to prompt injection, whereas humans might just want fewer newsletters. The agent prompt (`inbound-agent`) is stricter:
- Rejects prompt injection with high confidence.
- Quarantines marketing/newsletters (agents don't need them).
- Flags potential data exfiltration vectors.

*(Accounts can also override these defaults with their own custom system prompts.)*

## Database Details

The application abstracts DB interactions (mutations in `src/db/index.ts`) through `DbAdapter`.
- **Postgres mode** defaults to connection via `DATABASE_URL`.
- **SQLite mode** puts the DB file in `store/carapamail.db`.

## Commands

- `bun run dev` — run with watch mode
- `bun run start` — run in production
- `bun run typecheck` — TypeScript check
- `bun test` — run standard unit tests without hitting LLM endpoints
- `bun test:llm` — run tests that engage the LLM API
- `bun test:integration` — run integration tests (e.g., AV scanner tests) requiring specific setups

## Key env vars

Configured systematically in `src/config.ts`.
- **Database**: `DB_TYPE` (`sqlite` or `postgres`), `DATABASE_URL`
- **Application Ports**: `SMTP_PORT`, `IMAP_PROXY_PORT`, `HTTP_PORT`, `MCP_PORT`
- **AI Details**: `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_MODEL`
- **Filtering Thresholds**: `FILTER_CONFIDENCE_THRESHOLD`, `AGENT_CHUNK_TOKENS`
- **Security Binaries**: `AV_COMMAND` (e.g., `"clamscan --no-summary -"`)
- **Toggles**: `AUTO_QUARANTINE` (false for log-only), `INBOUND_SCAN`, `MCP_ENABLED`, `DKIM_VERIFY`, `PII_REDACTION`, `STRIP_REMOTE_IMAGES`

## Code conventions

- **Runtime**: Bun (TypeScript, no build step).
- **Architecture**: Keep route handlers thin (`src/http/`), keep logic in domain modules (`src/email/`, `src/imap/`).
- **Dependencies**: Uses `imapflow` for upstream connection and standard `nodemailer` for outgoing relaying. 

## Key code locations

- **Bootstrap**: `src/index.ts` (Graceful shutdowns, database init, service startup).
- **Filter logic**: `src/agent/filter.ts` (`inspectEmail()`) and `prompts/*.md`.
- **Security Checkers**: `src/email/` (av-scanner, attachment-scanner, url-scanner, dlp-scanner, redactor).
- **IMAP proxy**: `src/imap/proxy.ts` (connection pooling, capabilities spoofing) and `src/imap/interceptor.ts` (async rewriting/filtering of FETCH literals).
- **Body sanitizer**: `src/imap/sanitizer.ts` (offline regex-based stripping logic).
- **SMTP logic**: `src/smtp/handler.ts` (transaction handling and outbound filtering).
- **Inbound background scanner**: `src/inbound-scanner.ts` (idle processing without intercepting on read).
- **MCP tools**: `src/mcp/tools.ts` (on-demand agent filtering and folder operations).
