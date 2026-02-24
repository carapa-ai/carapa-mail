// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

const LOG_LEVELS: Record<string, LogLevel> = {
  'debug': LogLevel.DEBUG,
  'info': LogLevel.INFO,
  'warn': LogLevel.WARN,
  'error': LogLevel.ERROR
};

let currentLogLevel = LOG_LEVELS[(process.env.LOG_LEVEL || 'info').toLowerCase()] ?? LogLevel.INFO;

export function setLogLevel(level: LogLevel | string) {
  if (typeof level === 'string') {
    currentLogLevel = LOG_LEVELS[level.toLowerCase()] ?? currentLogLevel;
  } else {
    currentLogLevel = level;
  }
}

function log(level: LogLevel, component: string, message: string, ...args: any[]) {
  if (level < currentLogLevel) return;

  const timestamp = new Date().toISOString();
  const levelStr = LogLevel[level];
  const formattedMessage = `[${timestamp}] [${levelStr}] [${component}] ${message}`;

  if (level === LogLevel.ERROR) {
    console.error(formattedMessage, ...args);
  } else if (level === LogLevel.WARN) {
    console.warn(formattedMessage, ...args);
  } else {
    console.log(formattedMessage, ...args);
  }
}

export const logger = {
  debug: (component: string, message: string, ...args: any[]) => log(LogLevel.DEBUG, component, message, ...args),
  info: (component: string, message: string, ...args: any[]) => log(LogLevel.INFO, component, message, ...args),
  warn: (component: string, message: string, ...args: any[]) => log(LogLevel.WARN, component, message, ...args),
  error: (component: string, message: string, ...args: any[]) => log(LogLevel.ERROR, component, message, ...args),
};
