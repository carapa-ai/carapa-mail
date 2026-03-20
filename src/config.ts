// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import path from 'path';
import fs from 'fs';

// ── Docker Compose file-based secrets ──────────────────────────────────
// Reads from /run/secrets/<name> first, falls back to process.env.
const SECRETS_DIR = process.env.SECRETS_DIR || '/run/secrets';
function readSecret(envName: string): string {
  try {
    const val = fs.readFileSync(path.join(SECRETS_DIR, envName.toLowerCase()), 'utf8').trim();
    if (val) return val;
  } catch { /* ignore */ }
  return process.env[envName] || '';
}

// Load .env file into process.env
const projectRoot = process.cwd();
const envFile = path.join(projectRoot, '.env');
if (fs.existsSync(envFile)) {
  const envContent = fs.readFileSync(envFile, 'utf-8');
  envContent.split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 1) return;
    const key = trimmed.slice(0, eqIdx).trim();
    let v = trimmed.slice(eqIdx + 1).trim();
    // Strip unquoted inline comments (e.g. VALUE=foo  # comment)
    // Only strip if the # is preceded by whitespace and the value is not quoted
    if (!v.startsWith('"') && !v.startsWith("'")) {
      const commentIdx = v.search(/\s+#/);
      if (commentIdx >= 0) {
        v = v.slice(0, commentIdx).trim();
      }
    }
    if (key && !process.env[key]) {
      process.env[key] = v;
    }
  });
}

// Local proxy ports
export const SMTP_PORT = parseInt(process.env.SMTP_PORT || '2525', 10);
export const IMAP_PROXY_PORT = parseInt(process.env.IMAP_PROXY_PORT || '1993', 10);
export const HTTP_PORT = parseInt(process.env.HTTP_PORT || '3200', 10);
export const BIND_HOST = process.env.BIND_HOST || '127.0.0.1';
export const ALLOW_INSECURE_AUTH = process.env.ALLOW_INSECURE_AUTH === 'true';

// AI filtering
export const ANTHROPIC_AUTH_TOKEN = readSecret('ANTHROPIC_AUTH_TOKEN');
export const AI_FEATURES_ENABLED = process.env.AI_FEATURES_ENABLED !== 'false';
export const ANTHROPIC_BASE_URL = process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com';
export const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-haiku-4-5-20251001';
export const FILTER_CONFIDENCE_THRESHOLD = parseFloat(process.env.FILTER_CONFIDENCE_THRESHOLD || '0.7');

// Admin
export const HTTP_API_TOKEN = readSecret('HTTP_API_TOKEN');
export const ALLOW_SIGNUP = process.env.ALLOW_SIGNUP === 'true';
export const PUBLIC_HOSTNAME = process.env.PUBLIC_HOSTNAME || '';
export const ALLOW_PROMPT_OVERRIDE = process.env.ALLOW_PROMPT_OVERRIDE !== 'false';
export const ALLOW_PROMPT_APPEND = process.env.ALLOW_PROMPT_APPEND !== 'false';

// Encryption (optional — auto-generated if not set)
export const ENCRYPTION_KEY = readSecret('ENCRYPTION_KEY');

// TLS Certificates (optional — auto-generated if not set)
export const TLS_CERT_PATH = process.env.TLS_CERT_PATH || '';
export const TLS_KEY_PATH = process.env.TLS_KEY_PATH || '';

// MCP server (agent access)
export const MCP_ENABLED = process.env.MCP_ENABLED === 'true';
export const MCP_PORT = parseInt(process.env.MCP_PORT || '3466', 10);
export const MCP_PUBLIC_URL = process.env.MCP_PUBLIC_URL || '';

// Behavior
export const AUTO_QUARANTINE = process.env.AUTO_QUARANTINE !== 'false';
export const PII_REDACTION = process.env.PII_REDACTION === 'true';
export const LOG_LEVEL = (process.env.LOG_LEVEL || 'info') as 'debug' | 'info' | 'warn' | 'error';
export const AI_FAIL_ACTION = (process.env.AI_FAIL_ACTION || 'reject') as 'passthrough' | 'quarantine' | 'reject';

// Paths
export const PROJECT_ROOT = projectRoot;
export const STORE_DIR = path.resolve(PROJECT_ROOT, 'store');

// Agent call timeout (ms)
export const FILTER_TIMEOUT = parseInt(process.env.FILTER_TIMEOUT || '30000', 10);

// Max parallel AI requests (1 = serial queue, safe for local models; higher for Anthropic API)
export const MAX_PARALLEL_AI_CALLS = parseInt(process.env.MAX_PARALLEL_AI_CALLS || '1', 10);

// Maximum tokens per AI chunk (0 = no chunking, send full content)
// Approximate: 1 token ≈ 4 characters. e.g. 4000 tokens ≈ 16000 chars.
export const AGENT_CHUNK_TOKENS = parseInt(process.env.AGENT_CHUNK_TOKENS || '0', 10);

// Inbound scanner
export const INBOUND_SCAN = process.env.INBOUND_SCAN !== 'false';
export const INBOUND_SCAN_INTERVAL = parseInt(process.env.INBOUND_SCAN_INTERVAL || '60000', 10);
export const INCOMING_FOLDER = process.env.INCOMING_FOLDER || 'Incoming';

// External antivirus (e.g. "clamscan --no-summary -")
export const AV_COMMAND = process.env.AV_COMMAND || '';
export const AV_TIMEOUT = parseInt(process.env.AV_TIMEOUT || '30000', 10);

// DKIM verification — when true, penalizes emails with missing/unverifiable authentication
export const DKIM_VERIFY = process.env.DKIM_VERIFY === 'true';

// AI-powered header forensic analysis (extra API call per inbound email)
export const HEADER_ANALYSIS_ENABLED = process.env.HEADER_ANALYSIS_ENABLED !== 'false';

// Strip all remote images from HTML emails (tracking pixel removal is always on)
export const STRIP_REMOTE_IMAGES = process.env.STRIP_REMOTE_IMAGES === 'true';
