const http = require('../utils/http');
const logger = require('../utils/logger').logger;
const dns = require('dns');
const net = require('net');
const { exec } = require('child_process');
const util = require('util');
const execAsync = util.promisify(exec);

class NetworkCommands {
    constructor() {
        this.commands = new Map();
        this.registerCommands();
    }

    registerCommands() {
        // GET request
        this.commands.set('get', {
            handler: this.get,
            description: 'HTTP GET request',
            usage: 'get <url> [--json] [--headers]'
        });

        // POST request
        this.commands.set('post', {
            handler: this.post,
            description: 'HTTP POST request',
            usage: 'post <url> <data> [--json]'
        });

        // Download
        this.commands.set('download', {
            handler: this.download,
            description: 'Download file',
            usage: 'download <url> <output>'
        });

        // Ping
        this.commands.set('ping', {
            handler: this.ping,
            description: 'Ping host',
            usage: 'ping <host> [--count=4] [--interval=1]'
        });

        // Port scan
        this.commands.set('scan', {
            handler: this.scan,
            description: 'Port scan',
            usage: 'scan <host> <port> [--timeout=1000]'
        });

        // DNS lookup
        this.commands.set('dns', {
            handler: this.dnsLookup,
            description: 'DNS lookup',
            usage: 'dns <domain> [--type=A]'
        });

        // Get public IP
        this.commands.set('myip', {
            handler: this.getPublicIP,
            description: 'Get public IP address',
            usage: 'myip'
        });

        // Speed test
        this.commands.set('speedtest', {
            handler: this.speedTest,
            description: 'Internet speed test',
            usage: 'speedtest'
        });

        // Benchmark
        this.commands.set('benchmark', {
            handler: this.benchmark,
            description: 'Benchmark URL',
            usage: 'benchmark <url> [--requests=100] [--concurrent=10]'
        });
    }

    // GET request handler
    async get(args) {
        const url = args[0];
        if (!url) {
            throw new Error('URL is required');
        }

        const spinner = logger.spinner(`Fetching ${url}`);
        
        try {
            const result = await http.get(url);
            spinner.stop(true, 'Request completed');
            
            console.log(`Status: ${result.status}`);
            console.log(`Time: ${result.time}ms`);
            console.log(`Size: ${result.size} bytes`);
            
            if (args.includes('--headers')) {
                console.log('
Headers:');
                Object.entries(result.headers).forEach(([key, value]) => {
                    console.log(`  ${key}: ${value}`);
                });
            }
            
            if (args.includes('--json')) {
                console.log('
Response:');
                console.log(JSON.stringify(result.data, null, 2));
            } else if (typeof result.data === 'string') {
                console.log('
Response:');
                console.log(result.data.substring(0, 1000) + (result.data.length > 1000 ? '...' : ''));
            }
            
            return result;
        } catch (error) {
            spinner.stop(false, error.message);
            throw error;
        }
    }

    // POST request handler
    async post(args) {
        const url = args[0];
        const data = args[1];
        
        if (!url || !data) {
            throw new Error('URL and data are required');
        }

        let parsedData;
        try {
            parsedData = JSON.parse(data);
        } catch {
            parsedData = data;
        }

        const spinner = logger.spinner(`POST to ${url}`);
        
        try {
            const result = await http.post(url, parsedData);
            spinner.stop(true, 'POST completed');
            
            console.log(`Status: ${result.status}`);
            console.log(`Time: ${result.time}ms`);
            
            if (args.includes('--json')) {
                console.log('
Response:');
                console.log(JSON.stringify(result.data, null, 2));
            }
            
            return result;
        } catch (error) {
            spinner.stop(false, error.message);
            throw error;
        }
    }

    // Download handler
    async download(args) {
        const url = args[0];
        const output = args[1];
        
        if (!url || !output) {
            throw new Error('URL and output path are required');
        }

        console.log(`Downloading ${url} to ${output}`);
        
        try {
            const result = await http.download(url, output, (percent, downloaded, total, speed) => {
                const speedMB = (speed / 1024 / 1024).toFixed(2);
                const downloadedMB = (downloaded / 1024 / 1024).toFixed(2);
                const totalMB = total ? (total / 1024 / 1024).toFixed(2) : '?';
                
                process.stdout.write(`Progress: ${percent}% | ${downloadedMB}/${totalMB} MB | ${speedMB} MB/s`);
            });
            
            console.log(`
Download completed: ${output}`);
            console.log(`Size: ${(result.size / 1024 / 1024).toFixed(2)} MB`);
            console.log(`Time: ${(result.time / 1000).toFixed(2)} seconds`);
            
            return result;
        } catch (error) {
            console.error(`
Download failed: ${error.message}`);
            throw error;
        }
    }

    // Ping handler
    async ping(args) {
        const host = args[0];
        if (!host) {
            throw new Error('Host is required');
        }

        const count = this.getOption(args, '--count', 4);
        const interval = this.getOption(args, '--interval', 1);

        console.log(`Pinging ${host} ${count} times...`);
        
        try {
            const { stdout } = await execAsync(`ping -c ${count} -i ${interval} ${host}`);
            console.log(stdout);
            return stdout;
        } catch (error) {
            // ping returns error when packets are lost, but we still want output
            if (error.stdout) {
                console.log(error.stdout);
                return error.stdout;
            }
            throw new Error(`Ping failed: ${error.message}`);
        }
    }

    // Port scan handler
    async scan(args) {
        const host = args[0];
        const port = parseInt(args[1]);
        
        if (!host || !port) {
            throw new Error('Host and port are required');
        }

        const timeout = this.getOption(args, '--timeout', 1000);
        
        return new Promise((resolve) => {
            const socket = new net.Socket();
            socket.setTimeout(timeout);
            
            socket.on('connect', () => {
                console.log(`Port ${port} on ${host} is OPEN`);
                socket.destroy();
                resolve(true);
            });
            
            socket.on('timeout', () => {
                console.log(`Port ${port} on ${host} is CLOSED (timeout)`);
                socket.destroy();
                resolve(false);
            });
            
            socket.on('error', () => {
                console.log(`Port ${port} on ${host} is CLOSED`);
                socket.destroy();
                resolve(false);
            });
            
            socket.connect(port, host);
        });
    }

    // DNS lookup handler
    async dnsLookup(args) {
        const domain = args[0];
        if (!domain) {
            throw new Error('Domain is required');
        }

        const type = this.getOption(args, '--type', 'A');
        
        console.log(`DNS lookup for ${domain} (${type} records):`);
        
        try {
            switch (type.toUpperCase()) {
                case 'A':
                    const addresses = await dns.promises.resolve4(domain);
                    addresses.forEach(addr => console.log(`  A: ${addr}`));
                    break;
                    
                case 'AAAA':
                    const ipv6addrs = await dns.promises.resolve6(domain);
                    ipv6addrs.forEach(addr => console.log(`  AAAA: ${addr}`));
                    break;
                    
                case 'MX':
                    const mxRecords = await dns.promises.resolveMx(domain);
                    mxRecords.forEach(record => console.log(`  MX: ${record.exchange} (priority: ${record.priority})`));
                    break;
                    
                case 'TXT':
                    const txtRecords = await dns.promises.resolveTxt(domain);
                    txtRecords.forEach(record => console.log(`  TXT: ${record.join('')}`));
                    break;
                    
                default:
                    throw new Error(`Unsupported DNS type: ${type}`);
            }
        } catch (error) {
            throw new Error(`DNS lookup failed: ${error.message}`);
        }
    }

    // Get public IP handler
    async getPublicIP() {
        try {
            const result = await http.get('https://api.ipify.org?format=json');
            console.log(`Public IP: ${result.data.ip}`);
            return result.data.ip;
        } catch (error) {
            throw new Error(`Failed to get public IP: ${error.message}`);
        }
    }

    // Speed test handler
    async speedTest() {
        console.log('Running speed test...');
        
        // Simple speed test by downloading a test file
        const testFiles = [
            'http://ipv4.download.thinkbroadband.com/10MB.zip',
            'http://ipv4.download.thinkbroadband.com/20MB.zip'
        ];
        
        for (const url of testFiles) {
            console.log(`
Testing with ${url}`);
            
            try {
                const startTime = Date.now();
                const result = await http.get(url);
                const endTime = Date.now();
                
                const timeSeconds = (endTime - startTime) / 1000;
                const sizeMB = result.size / 1024 / 1024;
                const speedMbps = (sizeMB * 8) / timeSeconds;
                
                console.log(`Downloaded: ${sizeMB.toFixed(2)} MB`);
                console.log(`Time: ${timeSeconds.toFixed(2)} seconds`);
                console.log(`Speed: ${speedMbps.toFixed(2)} Mbps`);
            } catch (error) {
                console.log(`Speed test failed for ${url}: ${error.message}`);
            }
        }
    }

    // Benchmark handler
    async benchmark(args) {
        const url = args[0];
        if (!url) {
            throw new Error('URL is required');
        }

        const requests = this.getOption(args, '--requests', 100);
        const concurrent = this.getOption(args, '--concurrent', 10);
        
        try {
            const results = await http.benchmark(url, requests, concurrent);
            
            console.log('
Benchmark Results:');
            console.log('══════════════════════════════════════════');
            console.log(`URL: ${url}`);
            console.log(`Total Requests: ${results.totalRequests}`);
            console.log(`Successful: ${results.successful}`);
            console.log(`Failed: ${results.failed}`);
            console.log(`Success Rate: ${((results.successful / results.totalRequests) * 100).toFixed(2)}%`);
            console.log(`Total Time: ${results.totalTime}ms`);
            console.log(`Avg Time per Request: ${results.avgTime.toFixed(2)}ms`);
            console.log(`Min Time: ${results.minTime}ms`);
            console.log(`Max Time: ${results.maxTime}ms`);
            console.log(`Requests per Second: ${results.requestsPerSecond.toFixed(2)}`);
            
            return results;
        } catch (error) {
            throw new Error(`Benchmark failed: ${error.message}`);
        }
    }

    // Helper method to get option values
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
            throw new Error(`Unknown network command: ${command}`);
        }
        
        return cmd.handler.call(this, args);
    }

    // Register with main system
    register(registerFn) {
        for (const [name, cmd] of this.commands.entries()) {
            registerFn(`network.${name}`, async (args, context) => {
                return this.execute(name, args);
            }, {
                description: cmd.description,
                usage: cmd.usage
            });
        }
    }
}

// Export singleton instance
const networkCommands = new NetworkCommands();
module.exports = networkCommands;
