// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe, beforeEach, afterEach, mock } from 'bun:test';
import { LogLevel, setLogLevel, logger } from './logger.js';

describe('Logger', () => {
  let logSpy: ReturnType<typeof mock>;
  let warnSpy: ReturnType<typeof mock>;
  let errorSpy: ReturnType<typeof mock>;

  beforeEach(() => {
    logSpy = mock(() => { });
    warnSpy = mock(() => { });
    errorSpy = mock(() => { });
    // @ts-ignore - mock console methods
    console.log = logSpy;
    // @ts-ignore
    console.warn = warnSpy;
    // @ts-ignore
    console.error = errorSpy;
  });

  afterEach(() => {
    // Reset to default INFO level
    setLogLevel(LogLevel.INFO);
  });

  test('info logs to console.log', () => {
    logger.info('test', 'hello');
    expect(logSpy).toHaveBeenCalledTimes(1);
    const msg = logSpy.mock.calls[0][0] as string;
    expect(msg).toContain('[INFO]');
    expect(msg).toContain('[test]');
    expect(msg).toContain('hello');
  });

  test('warn logs to console.warn', () => {
    logger.warn('comp', 'warning message');
    expect(warnSpy).toHaveBeenCalledTimes(1);
    const msg = warnSpy.mock.calls[0][0] as string;
    expect(msg).toContain('[WARN]');
    expect(msg).toContain('[comp]');
    expect(msg).toContain('warning message');
  });

  test('error logs to console.error', () => {
    logger.error('comp', 'error message');
    expect(errorSpy).toHaveBeenCalledTimes(1);
    const msg = errorSpy.mock.calls[0][0] as string;
    expect(msg).toContain('[ERROR]');
    expect(msg).toContain('error message');
  });

  test('debug is suppressed at INFO level (default)', () => {
    logger.debug('comp', 'debug message');
    expect(logSpy).not.toHaveBeenCalled();
  });

  test('debug is shown at DEBUG level', () => {
    setLogLevel(LogLevel.DEBUG);
    logger.debug('comp', 'debug message');
    expect(logSpy).toHaveBeenCalledTimes(1);
    const msg = logSpy.mock.calls[0][0] as string;
    expect(msg).toContain('[DEBUG]');
  });

  test('setting ERROR level suppresses info and warn', () => {
    setLogLevel(LogLevel.ERROR);
    logger.info('comp', 'info');
    logger.warn('comp', 'warn');
    logger.error('comp', 'error');
    expect(logSpy).not.toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalledTimes(1);
  });

  test('setting WARN level suppresses info and debug', () => {
    setLogLevel(LogLevel.WARN);
    logger.debug('c', 'debug');
    logger.info('c', 'info');
    logger.warn('c', 'warn');
    logger.error('c', 'error');
    expect(logSpy).not.toHaveBeenCalled();
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalledTimes(1);
  });

  test('log messages include ISO timestamp', () => {
    logger.info('comp', 'timestamped');
    const msg = logSpy.mock.calls[0][0] as string;
    // ISO timestamp pattern: 2024-01-01T00:00:00.000Z
    expect(msg).toMatch(/\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });

  test('passes extra args through', () => {
    const extra = { key: 'value' };
    logger.info('comp', 'with extra', extra);
    expect(logSpy).toHaveBeenCalledTimes(1);
    expect(logSpy.mock.calls[0][1]).toBe(extra);
  });
});
