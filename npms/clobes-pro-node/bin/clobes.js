#!/usr/bin/env node

const { program } = require('commander');
const chalk = require('chalk');
const main = require('../src/index');

// Banner
function printBanner() {
    console.log(chalk.cyan(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🚀 C L O B E S  P R O  v4.0.0                              ║
║   Ultimate Command Line Toolkit                              ║
║   200+ commands • Faster than curl • Smarter                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    `));
}

// Main CLI
program
    .name('clobes')
    .description('CLOBES PRO - Ultimate CLI Toolkit')
    .version('4.0.0')
    .option('-d, --debug', 'Enable debug mode')
    .option('-v, --verbose', 'Enable verbose output')
    .option('--no-color', 'Disable colors');

// Network commands
program
    .command('network')
    .description('Network operations')
    .argument('<command>', 'Network command')
    .argument('[args...]', 'Command arguments')
    .action((command, args) => {
        require('../src/commands/network').execute(command, args);
    });

// System commands
program
    .command('system')
    .description('System operations')
    .argument('<command>', 'System command')
    .argument('[args...]', 'Command arguments')
    .action((command, args) => {
        require('../src/commands/system').execute(command, args);
    });

// File commands
program
    .command('file')
    .description('File operations')
    .argument('<command>', 'File command')
    .argument('[args...]', 'Command arguments')
    .action((command, args) => {
        require('../src/commands/file').execute(command, args);
    });

// Crypto commands
program
    .command('crypto')
    .description('Cryptography operations')
    .argument('<command>', 'Crypto command')
    .argument('[args...]', 'Command arguments')
    .action((command, args) => {
        require('../src/commands/crypto').execute(command, args);
    });

// Dev commands
program
    .command('dev')
    .description('Development tools')
    .argument('<command>', 'Dev command')
    .argument('[args...]', 'Command arguments')
    .action((command, args) => {
        require('../src/commands/dev').execute(command, args);
    });

// Version command
program
    .command('version')
    .description('Show version information')
    .action(() => {
        printBanner();
        console.log(`Version: 4.0.0 "Thunderbolt"`);
        console.log(`Build: ${new Date().toISOString()}`);
    });

// Help command
program
    .command('help')
    .description('Show help information')
    .argument('[command]', 'Command to get help for')
    .action((cmd) => {
        if (cmd) {
            // Show specific command help
            console.log(`Help for command: ${cmd}`);
            console.log('Detailed help coming soon...');
        } else {
            printBanner();
            console.log(chalk.cyan('\nAvailable categories:'));
            console.log('  network  - Network operations');
            console.log('  system   - System operations');
            console.log('  file     - File operations');
            console.log('  crypto   - Cryptography');
            console.log('  dev      - Development tools');
            console.log(chalk.cyan('\nExamples:'));
            console.log('  clobes network get https://api.github.com');
            console.log('  clobes system info');
            console.log('  clobes file find /var/log *.log');
            console.log('  clobes crypto generate-password');
            console.log('  clobes dev compile program.c');
            console.log(chalk.cyan('\nUse "clobes help <command>" for detailed help'));
        }
    });

// Parse arguments
program.parse(process.argv);

// If no arguments, show help
if (process.argv.length === 2) {
    program.help();
}