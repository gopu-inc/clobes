const fs = require('fs');
const path = require('path');
const chalk = require('chalk');
const ora = require('ora');

// Global state
const globalState = {
    config: {
        maxConnections: 10,
        timeout: 30,
        retryAttempts: 3,
        cacheEnabled: true,
        userAgent: 'CLOBES-PRO/4.0.0',
        colors: true,
        progressBars: true,
        verbose: false
    },
    cache: new Map(),
    cacheHits: 0,
    cacheMisses: 0,
    totalRequests: 0,
    totalRequestTime: 0,
    debugMode: false
};

// Logger
const logger = {
    success: (message) => console.log(chalk.green('✓ ') + message),
    error: (message) => console.error(chalk.red('✗ ') + message),
    warning: (message) => console.log(chalk.yellow('⚠ ') + message),
    info: (message) => console.log(chalk.blue('ℹ ') + message),
    debug: (message) => {
        if (globalState.debugMode) {
            console.log(chalk.magenta('🔧 ') + message);
        }
    }
};

// HTTP Client
const http = require('./utils/http');

// Cache system
const cache = require('./lib/cache');

// Command registry
const commands = new Map();

// Register command
function registerCommand(name, handler, options = {}) {
    commands.set(name, { handler, ...options });
}

// Execute command
async function executeCommand(name, args) {
    const command = commands.get(name);
    if (!command) {
        logger.error(`Command not found: ${name}`);
        return false;
    }
    
    try {
        const spinner = ora(`Executing ${name}...`).start();
        const result = await command.handler(args, { logger, http, cache, state: globalState });
        spinner.succeed(`Command ${name} completed`);
        return result;
    } catch (error) {
        logger.error(`Command failed: ${error.message}`);
        return false;
    }
}

// Initialize
async function init() {
    logger.info('Initializing CLOBES Pro v4.0.0');
    
    // Load configuration
    const configPath = path.join(__dirname, '../config/default.json');
    if (fs.existsSync(configPath)) {
        try {
            const configData = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            Object.assign(globalState.config, configData);
            logger.debug('Configuration loaded');
        } catch (error) {
            logger.warning('Failed to load configuration, using defaults');
        }
    }
    
    // Initialize cache
    cache.init(globalState.config.cacheEnabled);
    
    // Register commands
    require('./commands/network').register(registerCommand);
    require('./commands/system').register(registerCommand);
    require('./commands/file').register(registerCommand);
    require('./commands/crypto').register(registerCommand);
    require('./commands/dev').register(registerCommand);
    
    logger.success('CLOBES Pro initialized');
    return true;
}

// Cleanup
function cleanup() {
    cache.cleanup();
    logger.info('CLOBES Pro cleanup completed');
}

module.exports = {
    init,
    cleanup,
    executeCommand,
    logger,
    http,
    cache,
    state: globalState
};
