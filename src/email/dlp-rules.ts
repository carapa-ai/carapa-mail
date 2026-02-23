// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

/**
 * Sensitive data patterns for Data Loss Prevention (DLP) and Redaction.
 * Matches common API keys, secrets, and PII.
 */
export const DLP_RULES = [
  // Cloud Providers & Infrastructure
  { name: 'AWS Access Key', pattern: /\bAKIA[0-9A-Z]{16}\b/g, score: 0.7, piiType: 'AWS_ACCESS_KEY' },
  { name: 'AWS Secret Key', pattern: /\b[a-zA-Z0-9/+=]{40}\b/g, score: 0.5, piiType: 'AWS_SECRET_KEY' },
  { name: 'Azure Secret', pattern: /\b[a-zA-Z0-9]{32,40}\b[a-zA-Z0-9]{8,12}==\b/g, score: 0.6, piiType: 'AZURE_SECRET' },
  { name: 'Google Cloud API Key', pattern: /\bAIza[0-9A-Za-z-_]{35}\b/g, score: 0.8, piiType: 'GCP_API_KEY' },
  { name: 'Heroku API Key', pattern: /\b[hH][kK][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, score: 0.8, piiType: 'HEROKU_API_KEY' },

  // SaaS & Developer Tools
  { name: 'Stripe API Key', pattern: /\b(sk|pk)_(live|test)_[0-9a-zA-Z]{24}\b/g, score: 0.8, piiType: 'STRIPE_API_KEY' },
  { name: 'GitHub Personal Access Token', pattern: /\b(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b/g, score: 0.8, piiType: 'GITHUB_PAT' },
  { name: 'Slack Token', pattern: /\bxox[baprs]-[0-9a-zA-Z]{10,48}\b/g, score: 0.8, piiType: 'SLACK_TOKEN' },
  { name: 'Discord Webhook URL', pattern: /https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,19}\/[a-zA-Z0-9_-]{68}/g, score: 0.7, piiType: 'DISCORD_WEBHOOK' },
  { name: 'Twilio Auth Token', pattern: /\b[a-f0-9]{32}\b/g, score: 0.2, piiType: 'TWILIO_AUTH_TOKEN' }, // Low score because it's just a hex string
  { name: 'Mailgun API Key', pattern: /\bkey-[0-9a-zA-Z]{32}\b/g, score: 0.8, piiType: 'MAILGUN_API_KEY' },
  { name: 'Postmark Server Token', pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, score: 0.5, piiType: 'POSTMARK_TOKEN' },

  // Databases & Credentials
  { name: 'Postgres Connection String', pattern: /postgres(?:ql)?:\/\/[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9._-]+:\d+\/[a-zA-Z0-9_-]+/g, score: 0.9, piiType: 'DB_CONNECTION_STRING' },
  { name: 'Mongo Connection String', pattern: /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9._-]+/g, score: 0.9, piiType: 'DB_CONNECTION_STRING' },
  { name: 'Redis Connection String', pattern: /redis:\/\/(?::[a-zA-Z0-9_-]+@)?[a-zA-Z0-9._-]+:\d+/g, score: 0.7, piiType: 'DB_CONNECTION_STRING' },
  { name: 'Private Key', pattern: /-----BEGIN (RSA|OPENSSH|EC|PGP|PRIVATE) KEY-----/g, score: 1.0, piiType: 'PRIVATE_KEY' },

  // PII (Personally Identifiable Information)
  { name: 'Credit Card', pattern: /\b(?:\d[ -]*?){13,16}\b/g, score: 0.5, piiType: 'CREDIT_CARD' },
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, score: 0.6, piiType: 'SSN' },
  { name: 'Email Address', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, score: 0.1, piiType: 'EMAIL' },
  { name: 'Phone Number', pattern: /\b(?:\+?\d{1,3}[ -.]?)?\(?\d{3}\)?[ -.]?\d{3}[ -.]?\d{4}\b/g, score: 0.1, piiType: 'PHONE' },
  { name: 'Bitcoin Address', pattern: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, score: 0.4, piiType: 'BTC_ADDRESS' },
  { name: 'Ethereum Address', pattern: /\b0x[a-fA-F0-9]{40}\b/g, score: 0.4, piiType: 'ETH_ADDRESS' },
];
