const os = require('os');
const fs = require('fs');
const util = require('util');
const { exec } = require('child_process');
const execAsync = util.promisify(exec);

class SystemCommands {
    constructor() {
        this.commands = new Map();
        this.registerCommands();
    }

    registerCommands() {
        this.commands.set('info', {
            handler: this.info,
            description: 'System information',
            usage: 'info'
        });

        this.commands.set('processes', {
            handler: this.processes,
            description: 'List processes',
            usage: 'processes [--top=10]'
        });

        this.commands.set('users', {
            handler: this.users,
            description: 'List users',
            usage: 'users'
        });

        this.commands.set('disks', {
            handler: this.disks,
            description: 'Disk usage',
            usage: 'disks'
        });

        this.commands.set('memory', {
            handler: this.memory,
            description: 'Memory usage',
            usage: 'memory'
        });

        this.commands.set('cpu', {
            handler: this.cpu,
            description: 'CPU information',
            usage: 'cpu'
        });

        this.commands.set('network', {
            handler: this.network,
            description: 'Network interfaces',
            usage: 'network'
        });

        this.commands.set('logs', {
            handler: this.logs,
            description: 'View system logs',
            usage: 'logs [--lines=10]'
        });

        this.commands.set('clean', {
            handler: this.clean,
            description: 'Clean temporary files',
            usage: 'clean [--all]'
        });

        this.commands.set('update', {
            handler: this.update,
            description: 'Update system packages',
            usage: 'update'
        });
    }

    // System info handler
    async info() {
        console.log('System Information:');
        console.log('══════════════════════════════════════════');
        
        console.log(`Hostname: ${os.hostname()}`);
        console.log(`Platform: ${os.platform()} ${os.arch()}`);
        console.log(`Release: ${os.release()}`);
        console.log(`Type: ${os.type()}`);
        
        const uptime = this.formatUptime(os.uptime());
        console.log(`Uptime: ${uptime}`);
        
        console.log(`
CPU: ${os.cpus()[0].model}`);
        console.log(`Cores: ${os.cpus().length}`);
        
        const totalMem = (os.totalmem() / 1024 / 1024 / 1024).toFixed(2);
        const freeMem = (os.freemem() / 1024 / 1024 / 1024).toFixed(2);
        const usedMem = (totalMem - freeMem).toFixed(2);
        console.log(`
Memory: ${usedMem} GB used / ${freeMem} GB free / ${totalMem} GB total`);
        
        const load = os.loadavg();
        console.log(`Load Average: ${load[0].toFixed(2)}, ${load[1].toFixed(2)}, ${load[2].toFixed(2)}`);
        
        console.log(`
User: ${os.userInfo().username}`);
        console.log(`Home: ${os.userInfo().homedir}`);
        
        console.log(`
Network Interfaces:`);
        const interfaces = os.networkInterfaces();
        Object.keys(interfaces).forEach(iface => {
            interfaces[iface].forEach(address => {
                if (address.family === 'IPv4' && !address.internal) {
                    console.log(`  ${iface}: ${address.address}`);
                }
            });
        });
    }

    // Processes handler
    async processes(args) {
        const top = this.getOption(args, '--top', 10);
        
        try {
            const { stdout } = await execAsync('ps aux --sort=-%cpu');
            const lines = stdout.split('
');
            
            console.log(`Top ${top} processes by CPU usage:`);
            console.log('══════════════════════════════════════════');
            console.log('USER       PID    %CPU   %MEM   COMMAND');
            console.log('──────────────────────────────────────────');
            
            let count = 0;
            for (let i = 1; i < lines.length && count < top; i++) {
                const line = lines[i].trim();
                if (line) {
                    const parts = line.split(/\s+/);
                    if (parts.length >= 11) {
                        console.log(`${parts[0].padEnd(10)} ${parts[1].padEnd(6)} ${parts[2].padEnd(6)} ${parts[3].padEnd(6)} ${parts[10]}`);
                        count++;
                    }
                }
            }
        } catch (error) {
            throw new Error(`Failed to get processes: ${error.message}`);
        }
    }

    // Users handler
    async users() {
        try {
            const { stdout } = await execAsync('cat /etc/passwd');
            const lines = stdout.split('
');
            
            console.log('System Users:');
            console.log('══════════════════════════════════════════');
            console.log('Username      UID     GID     Home');
            console.log('──────────────────────────────────────────');
            
            lines.forEach(line => {
                if (line.trim()) {
                    const parts = line.split(':');
                    if (parts.length >= 6) {
                        const [username, , uid, gid, , home] = parts;
                        console.log(`${username.padEnd(12)} ${uid.padEnd(7)} ${gid.padEnd(7)} ${home}`);
                    }
                }
            });
        } catch (error) {
            console.log('Note: Could not read /etc/passwd');
            console.log('Current user:', os.userInfo().username);
        }
    }

    // Disks handler
    async disks() {
        try {
            const { stdout } = await execAsync('df -h');
            console.log('Disk Usage:');
            console.log('══════════════════════════════════════════');
            console.log(stdout);
        } catch (error) {
            // Fallback to Node.js method
            console.log('Disk information (Node.js):');
            const drives = [];
            
            // Check common mount points
            const paths = ['/', '/home', '/var', '/usr'];
            paths.forEach(path => {
                try {
                    const stats = fs.statfsSync(path);
                    const total = (stats.blocks * stats.bsize) / 1024 / 1024 / 1024;
                    const free = (stats.bfree * stats.bsize) / 1024 / 1024 / 1024;
                    const used = total - free;
                    const percent = ((used / total) * 100).toFixed(1);
                    
                    drives.push({
                        path: path,
                        total: total.toFixed(2),
                        used: used.toFixed(2),
                        free: free.toFixed(2),
                        percent: percent
                    });
                } catch (e) {
                    // Path not accessible
                }
            });
            
            if (drives.length > 0) {
                console.log('Filesystem            Size  Used  Avail  Use%  Mounted on');
                drives.forEach(drive => {
                    console.log(`${drive.path.padEnd(20)} ${drive.total}G ${drive.used}G ${drive.free}G ${drive.percent}%`);
                });
            }
        }
    }

    // Memory handler
    async memory() {
        const total = (os.totalmem() / 1024 / 1024 / 1024).toFixed(2);
        const free = (os.freemem() / 1024 / 1024 / 1024).toFixed(2);
        const used = (total - free).toFixed(2);
        const percent = ((used / total) * 100).toFixed(1);
        
        console.log('Memory Usage:');
        console.log('══════════════════════════════════════════');
        console.log(`Total:     ${total} GB`);
        console.log(`Used:      ${used} GB (${percent}%)`);
        console.log(`Free:      ${free} GB`);
        
        // Show memory usage bar
        const barLength = 40;
        const filled = Math.round((used / total) * barLength);
        const bar = '█'.repeat(filled) + '░'.repeat(barLength - filled);
        console.log(`
[${bar}] ${percent}%`);
    }

    // CPU handler
    async cpu() {
        const cpus = os.cpus();
        
        console.log('CPU Information:');
        console.log('══════════════════════════════════════════');
        console.log(`Model: ${cpus[0].model}`);
        console.log(`Cores: ${cpus.length}`);
        console.log(`Architecture: ${os.arch()}`);
        console.log(`Speed: ${cpus[0].speed} MHz`);
        
        console.log('
CPU Usage per Core:');
        console.log('Core     User (%)   System (%)   Idle (%)');
        console.log('──────────────────────────────────────────');
        
        cpus.forEach((cpu, i) => {
            const total = cpu.times.user + cpu.times.nice + cpu.times.sys + cpu.times.idle + cpu.times.irq;
            const user = ((cpu.times.user / total) * 100).toFixed(1);
            const sys = ((cpu.times.sys / total) * 100).toFixed(1);
            const idle = ((cpu.times.idle / total) * 100).toFixed(1);
            
            console.log(`${i.toString().padEnd(8)} ${user.padEnd(11)} ${sys.padEnd(12)} ${idle}`);
        });
    }

    // Network handler
    async network() {
        const interfaces = os.networkInterfaces();
        
        console.log('Network Interfaces:');
        console.log('══════════════════════════════════════════');
        
        Object.keys(interfaces).forEach(iface => {
            console.log(`
${iface}:`);
            interfaces[iface].forEach(address => {
                console.log(`  Family: ${address.family}`);
                console.log(`  Address: ${address.address}`);
                console.log(`  Netmask: ${address.netmask}`);
                console.log(`  MAC: ${address.mac || 'N/A'}`);
                console.log(`  Internal: ${address.internal}`);
                console.log('  ──────────────────────');
            });
        });
    }

    // Logs handler
    async logs(args) {
        const lines = this.getOption(args, '--lines', 10);
        
        console.log(`Last ${lines} lines of system logs:`);
        
        // Try different log files
        const logFiles = [
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/system.log'
        ];
        
        for (const logFile of logFiles) {
            if (fs.existsSync(logFile)) {
                try {
                    const { stdout } = await execAsync(`tail -n ${lines} ${logFile}`);
                    console.log(`
${logFile}:`);
                    console.log('══════════════════════════════════════════');
                    console.log(stdout);
                    return;
                } catch (error) {
                    // Try next file
                }
            }
        }
        
        console.log('Could not access system logs. You may need sudo privileges.');
    }

    // Clean handler
    async clean(args) {
        const cleanAll = args.includes('--all');
        
        console.log('Cleaning temporary files...');
        
        const tempDirs = [
            os.tmpdir(),
            '/tmp',
            '/var/tmp'
        ];
        
        let cleaned = 0;
        for (const tempDir of tempDirs) {
            if (fs.existsSync(tempDir)) {
                try {
                    const files = fs.readdirSync(tempDir);
                    for (const file of files) {
                        const filePath = `${tempDir}/${file}`;
                        try {
                            // Only clean old temp files
                            const stats = fs.statSync(filePath);
                            const age = Date.now() - stats.mtimeMs;
                            
                            if (cleanAll || age > 24 * 60 * 60 * 1000) { // Older than 1 day
                                if (fs.lstatSync(filePath).isDirectory()) {
                                    fs.rmSync(filePath, { recursive: true, force: true });
                                } else {
                                    fs.unlinkSync(filePath);
                                }
                                cleaned++;
                            }
                        } catch (e) {
                            // Skip files we can't access
                        }
                    }
                } catch (e) {
                    // Skip directories we can't access
                }
            }
        }
        
        console.log(`Cleaned ${cleaned} temporary files.`);
        
        if (cleanAll) {
            console.log('
Cleaning package cache...');
            try {
                await execAsync('sudo apt-get clean 2>/dev/null || sudo yum clean all 2>/dev/null || true');
                console.log('Package cache cleaned.');
            } catch (error) {
                console.log('Note: Could not clean package cache.');
            }
        }
    }

    // Update handler
    async update() {
        console.log('Updating system packages...');
        
        try {
            // Try apt-get (Debian/Ubuntu)
            const { stdout } = await execAsync('sudo apt-get update && sudo apt-get upgrade -y');
            console.log(stdout);
            console.log('
System update completed.');
        } catch (error) {
            try {
                // Try yum (RHEL/CentOS)
                const { stdout } = await execAsync('sudo yum update -y');
                console.log(stdout);
                console.log('
System update completed.');
            } catch (error2) {
                console.log('Could not update system. Please update manually.');
                console.log('For Debian/Ubuntu: sudo apt-get update && sudo apt-get upgrade');
                console.log('For RHEL/CentOS: sudo yum update');
            }
        }
    }

    // Helper methods
    formatUptime(seconds) {
        const days = Math.floor(seconds / (24 * 60 * 60));
        const hours = Math.floor((seconds % (24 * 60 * 60)) / (60 * 60));
        const minutes = Math.floor((seconds % (60 * 60)) / 60);
        
        const parts = [];
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        
        return parts.join(' ') || '< 1 minute';
    }

    getOption(args, optionName, defaultValue) {
        for (let i = 0; i < args.length; i++) {
            if (args[i].startsWith(optionName)) {
                if (args[i].includes('=')) {
                    return args[i].split('=')[1];
                } else if (i + 1 < args.length) {
                    return args[i + 1];
                }
            }
        }
        return defaultValue;
    }

    // Execute command
    async execute(command, args) {
        const cmd = this.commands.get(command);
        if (!cmd) {
            throw new Error(`Unknown system command: ${command}`);
        }
        
        return cmd.handler.call(this, args);
    }

    // Register with main system
    register(registerFn) {
        for (const [name, cmd] of this.commands.entries()) {
            registerFn(`system.${name}`, async (args, context) => {
                return this.execute(name, args);
            }, {
                description: cmd.description,
                usage: cmd.usage
            });
        }
    }
}

// Export singleton instance
const systemCommands = new SystemCommands();
module.exports = systemCommands;
