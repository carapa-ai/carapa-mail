// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Inline setup UI — single HTML page for managing email accounts.
 * Now loads from an external HTML file to improve maintainability.
 */
export function getSetupPage(options: { allowSignup: boolean; hasToken: boolean; publicHostname: string; smtpPort: number; imapProxyPort: number; mcpPort: number; mcpEnabled: boolean; mcpPublicUrl: string; allowPromptOverride: boolean; allowPromptAppend: boolean } = { allowSignup: false, hasToken: false, publicHostname: '', smtpPort: 2525, imapProxyPort: 1993, mcpPort: 3466, mcpEnabled: false, mcpPublicUrl: '', allowPromptOverride: true, allowPromptAppend: true }): string {
  let html = readFileSync(join(__dirname, 'setup.html'), 'utf-8');
  const css = readFileSync(join(__dirname, 'setup.css'), 'utf-8');
  const js = readFileSync(join(__dirname, 'setup.js'), 'utf-8');
  const logo = readFileSync(join(__dirname, 'logo.base64'), 'utf-8');

  html = html.replace('/*INJECT_CSS*/', css);
  html = html.replace('/*INJECT_JS*/', js);
  html = html.replace('/*INJECT_LOGO*/', logo);


  html = html.replace(/\{\{\s*ALLOW_SIGNUP\s*\}\}/g, String(options.allowSignup));
  html = html.replace(/\{\{\s*PUBLIC_HOSTNAME\s*\}\}/g, String(options.publicHostname));
  html = html.replace(/\{\{\s*SMTP_PORT\s*\}\}/g, String(options.smtpPort));
  html = html.replace(/\{\{\s*IMAP_PORT\s*\}\}/g, String(options.imapProxyPort));
  html = html.replace(/\{\{\s*MCP_PORT\s*\}\}/g, String(options.mcpPort));
  html = html.replace(/\{\{\s*MCP_ENABLED\s*\}\}/g, String(options.mcpEnabled));
  html = html.replace(/\{\{\s*MCP_PUBLIC_URL\s*\}\}/g, String(options.mcpPublicUrl));
  html = html.replace(/\{\{\s*HAS_TOKEN\s*\}\}/g, String(options.hasToken));
  html = html.replace(/\{\{\s*ALLOW_PROMPT_OVERRIDE\s*\}\}/g, String(options.allowPromptOverride));
  html = html.replace(/\{\{\s*ALLOW_PROMPT_APPEND\s*\}\}/g, String(options.allowPromptAppend));

  return html;
}
