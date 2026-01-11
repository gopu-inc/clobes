const chalk = require('chalk');
const moment = require('moment');

const LOG_LEVELS = {
    FATAL: 0,
    ERROR: 1,
    WARNING: 2,
    INFO: 3,
    DEBUG: 4,
    TRACE: 5
};

class Logger {
    constructor(config = {}) {
        this.config = {
            colors: true,
            timestamp: true,
            level: 'INFO',
            ...config
        };
        this.currentLevel = LOG_LEVELS[this.config.level.toUpperCase()] || LOG_LEVELS.INFO;
    }

    setLevel(level) {
        const newLevel = LOG_LEVELS[level.toUpperCase()];
        if (newLevel !== undefined) {
            this.currentLevel = newLevel;
        }
    }

    formatMessage(level, message, colorFn) {
        const timestamp = moment().format('YYYY-MM-DD HH:mm:ss');
        const levelStr = level.padEnd(7);
        
        if (this.config.colors) {
            return `${chalk.gray(timestamp)} ${colorFn(levelStr)} ${message}`;
        } else {
            return `${timestamp} ${levelStr} ${message}`;
        }
    }

    log(level, levelValue, message, colorFn) {
        if (levelValue <= this.currentLevel) {
            console.log(this.formatMessage(level, message, colorFn));
        }
    }

    fatal(message) {
        this.log('FATAL', LOG_LEVELS.FATAL, message, chalk.bgRed.white.bold);
    }

    error(message) {
        this.log('ERROR', LOG_LEVELS.ERROR, message, chalk.red.bold);
    }

    warning(message) {
        this.log('WARNING', LOG_LEVELS.WARNING, message, chalk.yellow);
    }

    info(message) {
        this.log('INFO', LOG_LEVELS.INFO, message, chalk.blue);
    }

    debug(message) {
        this.log('DEBUG', LOG_LEVELS.DEBUG, message, chalk.magenta);
    }

    trace(message) {
        this.log('TRACE', LOG_LEVELS.TRACE, message, chalk.gray);
    }

    success(message) {
        if (LOG_LEVELS.INFO <= this.currentLevel) {
            console.log(this.formatMessage('SUCCESS', message, chalk.green));
        }
    }

    progress(current, total, label = '') {
        if (LOG_LEVELS.INFO <= this.currentLevel) {
            const percent = Math.round((current / total) * 100);
            const barLength = 30;
            const filledLength = Math.round((barLength * current) / total);
            const bar = '█'.repeat(filledLength) + '░'.repeat(barLength - filledLength);
            
            if (this.config.colors) {
                process.stdout.write(`${chalk.cyan(label)} [${bar}] ${percent}% (${current}/${total})`);
            } else {
                process.stdout.write(`${label} [${bar}] ${percent}% (${current}/${total})`);
            }
            
            if (current >= total) {
                process.stdout.write('
');
            }
        }
    }

    spinner(text) {
        const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let i = 0;
        
        const interval = setInterval(() => {
            if (this.config.colors) {
                process.stdout.write(`${chalk.yellow(frames[i])} ${text}`);
            } else {
                process.stdout.write(`${frames[i]} ${text}`);
            }
            i = (i + 1) % frames.length;
        }, 100);
        
        return {
            stop: (success = true, message = '') => {
                clearInterval(interval);
                process.stdout.write('');
                if (message) {
                    if (success) {
                        this.success(message);
                    } else {
                        this.error(message);
                    }
                }
            }
        };
    }
}

// Default logger instance
const defaultLogger = new Logger();

module.exports = {
    Logger,
    logger: defaultLogger,
    log: defaultLogger
};
