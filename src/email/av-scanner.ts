// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { spawn } from 'child_process';
import { AV_COMMAND as CONFIG_AV_COMMAND, AV_TIMEOUT as CONFIG_AV_TIMEOUT } from '../config.js';
import { logger } from '../logger.js';

export interface AvScanResult {
  safe: boolean;
  threats: string[];
}

/**
 * Scan attachments using an external antivirus command (e.g. ClamAV).
 * Each attachment's content is piped to the command via stdin.
 * Exit code 0 = clean, non-zero = infected (ClamAV convention).
 *
 * AV_COMMAND is read from config.js (mockable via Bun's mock.module in unit tests).
 * Pass an explicit `avCommand` to override the config value (used by integration tests).
 *
 * If no command is configured, returns safe (no-op).
 */
export async function scanWithAv(
  attachments: { filename: string; content: Buffer }[],
  avCommand?: string,
): Promise<AvScanResult> {
  const AV_COMMAND = avCommand ?? CONFIG_AV_COMMAND;
  const AV_TIMEOUT = CONFIG_AV_TIMEOUT;
  if (!AV_COMMAND || attachments.length === 0) {
    return { safe: true, threats: [] };
  }

  const parts = AV_COMMAND.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
  const [cmd, ...args] = parts.map(p => p.replace(/^["']|["']$/g, ''));
  const threats: string[] = [];

  for (const att of attachments) {
    try {
      const { exitCode, stdout: avStdout, stderr: avStderr } = await new Promise<{ exitCode: number; stdout: string; stderr: string }>((resolve, reject) => {
        const proc = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] });
        let stdout = '';
        let stderr = '';

        const timer = setTimeout(() => {
          proc.kill('SIGKILL');
          reject(new Error('AV scan timed out'));
        }, AV_TIMEOUT);

        proc.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
        proc.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

        proc.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });

        proc.on('close', (code) => {
          clearTimeout(timer);
          resolve({ exitCode: code ?? 1, stdout, stderr });
        });

        proc.stdin.on('error', (err) => {
          // Ignore EPIPE/ECONNRESET if clamscan exits early (e.g. found virus)
          logger.debug('av-scanner', `Stdin error for ${att.filename}: ${err.message}`);
        });

        // Write content and close stdin
        proc.stdin.write(att.content);
        proc.stdin.end();
      });

      if (exitCode !== 0) {
        const detection = avStdout.trim() || avStderr.trim() || `exit code ${exitCode}`;
        threats.push(`${att.filename} flagged by antivirus: ${detection}`);
        logger.warn('av-scanner', `AV flagged ${att.filename} (code ${exitCode}): ${detection}`);
      } else {
        logger.debug('av-scanner', `AV clean: ${att.filename}`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn('av-scanner', `AV scan failed for ${att.filename}: ${msg}`);
      threats.push(`${att.filename} (AV scan failed: ${msg})`);
    }
  }

  return { safe: threats.length === 0, threats };
}
