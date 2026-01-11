const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const archiver = require('archiver');
const { createGzip, createGunzip } = require('zlib');
const { pipeline } = require('stream');
const { promisify } = require('util');
const pipe = promisify(pipeline);

class FileCommands {
    constructor() {
        this.commands = new Map();
        this.registerCommands();
    }

    registerCommands() {
        this.commands.set('find', {
            handler: this.find,
            description: 'Find files',
            usage: 'find <directory> <pattern> [--recursive]'
        });

        this.commands.set('size', {
            handler: this.size,
            description: 'Get file/directory size',
            usage: 'size <path>'
        });

        this.commands.set('hash', {
            handler: this.hash,
            description: 'Calculate file hash',
            usage: 'hash <file> [algorithm=sha256]'
        });

        this.commands.set('compare', {
            handler: this.compare,
            description: 'Compare files',
            usage: 'compare <file1> <file2>'
        });

        this.commands.set('compress', {
            handler: this.compress,
            description: 'Compress file',
            usage: 'compress <file> [--level=6]'
        });

        this.commands.set('decompress', {
            handler: this.decompress,
            description: 'Decompress file',
            usage: 'decompress <file>'
        });

        this.commands.set('stats', {
            handler: this.stats,
            description: 'File statistics',
            usage: 'stats <file>'
        });

        this.commands.set('backup', {
            handler: this.backup,
            description: 'Backup directory',
            usage: 'backup <source> <destination>'
        });

        this.commands.set('restore', {
            handler: this.restore,
            description: 'Restore backup',
            usage: 'restore <backup> <destination>'
        });
    }

    // Find files handler
    async find(args) {
        const directory = args[0];
        const pattern = args[1];
        const recursive = args.includes('--recursive');
        
        if (!directory || !pattern) {
            throw new Error('Directory and pattern are required');
        }

        if (!fs.existsSync(directory)) {
            throw new Error(`Directory not found: ${directory}`);
        }

        console.log(`Finding files matching "${pattern}" in ${directory}:`);
        
        const found = await this.findFiles(directory, pattern, recursive);
        
        if (found.length === 0) {
            console.log('No files found.');
        } else {
            found.forEach(file => console.log(`  ${file}`));
            console.log(`
Found ${found.length} files.`);
        }
        
        return found;
    }

    // Find files recursively
    async findFiles(dir, pattern, recursive) {
        const results = [];
        const regex = new RegExp(pattern.replace(/\*/g, '.*').replace(/\?/g, '.'));
        
        async function search(currentDir) {
            try {
                const items = await fs.readdir(currentDir);
                
                for (const item of items) {
                    const fullPath = path.join(currentDir, item);
                    const stat = await fs.stat(fullPath);
                    
                    if (stat.isDirectory() && recursive) {
                        await search(fullPath);
                    } else if (stat.isFile() && regex.test(item)) {
                        results.push(fullPath);
                    }
                }
            } catch (error) {
                // Skip directories we can't access
            }
        }
        
        await search(dir);
        return results;
    }

    // Size handler
    async size(args) {
        const target = args[0];
        if (!target) {
            throw new Error('Path is required');
        }

        if (!fs.existsSync(target)) {
            throw new Error(`Path not found: ${target}`);
        }

        const stats = await fs.stat(target);
        
        if (stats.isDirectory()) {
            const size = await this.getDirectorySize(target);
            console.log(`Directory: ${target}`);
            console.log(`Size: ${this.formatBytes(size)}`);
            console.log(`Files: ${await this.countFiles(target)}`);
        } else {
            console.log(`File: ${target}`);
            console.log(`Size: ${this.formatBytes(stats.size)}`);
            console.log(`Permissions: ${stats.mode.toString(8).slice(-3)}`);
            console.log(`Modified: ${stats.mtime.toLocaleString()}`);
            console.log(`Owner: ${stats.uid}:${stats.gid}`);
        }
    }

    // Get directory size recursively
    async getDirectorySize(dir) {
        let total = 0;
        
        async function traverse(currentDir) {
            const items = await fs.readdir(currentDir);
            
            for (const item of items) {
                const fullPath = path.join(currentDir, item);
                const stat = await fs.stat(fullPath);
                
                if (stat.isDirectory()) {
                    await traverse(fullPath);
                } else {
                    total += stat.size;
                }
            }
        }
        
        await traverse(dir);
        return total;
    }

    // Count files in directory
    async countFiles(dir) {
        let count = 0;
        
        async function traverse(currentDir) {
            const items = await fs.readdir(currentDir);
            
            for (const item of items) {
                const fullPath = path.join(currentDir, item);
                const stat = await fs.stat(fullPath);
                
                if (stat.isDirectory()) {
                    await traverse(fullPath);
                } else {
                    count++;
                }
            }
        }
        
        await traverse(dir);
        return count;
    }

    // Hash handler
    async hash(args) {
        const file = args[0];
        const algorithm = args[1] || 'sha256';
        
        if (!file) {
            throw new Error('File is required');
        }

        if (!fs.existsSync(file)) {
            throw new Error(`File not found: ${file}`);
        }

        console.log(`Calculating ${algorithm.toUpperCase()} hash for ${file}:`);
        
        try {
            const hash = crypto.createHash(algorithm);
            const stream = fs.createReadStream(file);
            
            await new Promise((resolve, reject) => {
                stream.on('data', chunk => hash.update(chunk));
                stream.on('end', () => resolve());
                stream.on('error', reject);
            });
            
            const digest = hash.digest('hex');
            console.log(`${algorithm.toUpperCase()}: ${digest}`);
            return digest;
        } catch (error) {
            throw new Error(`Failed to calculate hash: ${error.message}`);
        }
    }

    // Compare files handler
    async compare(args) {
        const file1 = args[0];
        const file2 = args[1];
        
        if (!file1 || !file2) {
            throw new Error('Two files are required');
        }

        if (!fs.existsSync(file1)) {
            throw new Error(`File not found: ${file1}`);
        }
        if (!fs.existsSync(file2)) {
            throw new Error(`File not found: ${file2}`);
        }

        console.log(`Comparing ${file1} and ${file2}:`);
        
        const stats1 = await fs.stat(file1);
        const stats2 = await fs.stat(file2);
        
        console.log(`File 1 size: ${this.formatBytes(stats1.size)}`);
        console.log(`File 2 size: ${this.formatBytes(stats2.size)}`);
        
        if (stats1.size !== stats2.size) {
            console.log('Files have different sizes.');
            return false;
        }
        
        // Compare hashes
        const hash1 = await this.hash([file1, 'md5']);
        const hash2 = await this.hash([file2, 'md5']);
        
        if (hash1 === hash2) {
            console.log('Files are identical.');
            return true;
        } else {
            console.log('Files are different.');
            return false;
        }
    }

    // Compress handler
    async compress(args) {
        const file = args[0];
        const level = this.getOption(args, '--level', 6);
        
        if (!file) {
            throw new Error('File is required');
        }

        if (!fs.existsSync(file)) {
            throw new Error(`File not found: ${file}`);
        }

        const outputFile = `${file}.gz`;
        console.log(`Compressing ${file} to ${outputFile}...`);
        
        try {
            const gzip = createGzip({ level: parseInt(level) });
            const source = fs.createReadStream(file);
            const destination = fs.createWriteStream(outputFile);
            
            await pipe(source, gzip, destination);
            
            const originalSize = (await fs.stat(file)).size;
            const compressedSize = (await fs.stat(outputFile)).size;
            const ratio = ((originalSize - compressedSize) / originalSize * 100).toFixed(2);
            
            console.log(`Compression completed:`);
            console.log(`  Original: ${this.formatBytes(originalSize)}`);
            console.log(`  Compressed: ${this.formatBytes(compressedSize)}`);
            console.log(`  Ratio: ${ratio}%`);
            
            return outputFile;
        } catch (error) {
            throw new Error(`Compression failed: ${error.message}`);
        }
    }

    // Decompress handler
    async decompress(args) {
        const file = args[0];
        if (!file) {
            throw new Error('File is required');
        }

        if (!fs.existsSync(file)) {
            throw new Error(`File not found: ${file}`);
        }

        if (!file.endsWith('.gz')) {
            throw new Error('File must have .gz extension');
        }

        const outputFile = file.replace(/\.gz$/, '');
        console.log(`Decompressing ${file} to ${outputFile}...`);
        
        try {
            const gunzip = createGunzip();
            const source = fs.createReadStream(file);
            const destination = fs.createWriteStream(outputFile);
            
            await pipe(source, gunzip, destination);
            
            console.log(`Decompression completed: ${outputFile}`);
            return outputFile;
        } catch (error) {
            throw new Error(`Decompression failed: ${error.message}`);
        }
    }

    // Stats handler
    async stats(args) {
        const file = args[0];
        if (!file) {
            throw new Error('File is required');
        }

        if (!fs.existsSync(file)) {
            throw new Error(`File not found: ${file}`);
        }

        const stats = await fs.stat(file);
        
        console.log(`Statistics for ${file}:`);
        console.log('══════════════════════════════════════════');
        
        console.log(`Size: ${this.formatBytes(stats.size)}`);
        console.log(`Type: ${stats.isDirectory() ? 'Directory' : stats.isFile() ? 'File' : 'Other'}`);
        console.log(`Permissions: ${stats.mode.toString(8).slice(-3)}`);
        console.log(`Created: ${stats.birthtime.toLocaleString()}`);
        console.log(`Modified: ${stats.mtime.toLocaleString()}`);
        console.log(`Accessed: ${stats.atime.toLocaleString()}`);
        console.log(`Owner: ${stats.uid}:${stats.gid}`);
        
        if (stats.isFile()) {
            const content = await fs.readFile(file, 'utf8').catch(() => '');
            const lines = content.split('
').length;
            const words = content.split(/\s+/).filter(w => w).length;
            const chars = content.length;
            
            console.log(`
Content:`);
            console.log(`  Lines: ${lines}`);
            console.log(`  Words: ${words}`);
            console.log(`  Characters: ${chars}`);
        }
    }

    // Backup handler
    async backup(args) {
        const source = args[0];
        const destination = args[1];
        
        if (!source || !destination) {
            throw new Error('Source and destination are required');
        }

        if (!fs.existsSync(source)) {
            throw new Error(`Source not found: ${source}`);
        }

        const backupFile = path.join(destination, `backup_${Date.now()}.tar.gz`);
        console.log(`Creating backup of ${source} to ${backupFile}...`);
        
        try {
            await fs.ensureDir(destination);
            
            const output = fs.createWriteStream(backupFile);
            const archive = archiver('tar', {
                gzip: True,
                gzipOptions: { level: 6 }
            });
            
            archive.pipe(output);
            archive.directory(source, False);
            
            await archive.finalize();
            
            const size = (await fs.stat(backupFile)).size;
            console.log(`Backup created: ${backupFile} (${this.formatBytes(size)})`);
            return backupFile;
        } catch (error) {
            throw new Error(`Backup failed: ${error.message}`);
        }
    }

    // Restore handler
    async restore(args) {
        const backup = args[0];
        const destination = args[1];
        
        if (!backup || !destination) {
            throw new Error('Backup file and destination are required');
        }

        if (!fs.existsSync(backup)) {
            throw new Error(`Backup file not found: ${backup}`);
        }

        console.log(`Restoring backup ${backup} to ${destination}...`);
        
        try {
            await fs.ensureDir(destination);
            
            // For simplicity, we'll just extract tar.gz files
            // In production, you'd use a proper tar extraction library
            const { exec } = require('child_process');
            const { promisify } = require('util');
            const execAsync = promisify(exec);
            
            await execAsync(`tar -xzf "${backup}" -C "${destination}"`);
            
            console.log(`Backup restored to ${destination}`);
            return True;
        } catch (error) {
            throw new Error(`Restore failed: ${error.message}`);
        }
    }

    // Helper methods
    formatBytes(bytes) {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let size = bytes;
        let unitIndex = 0;
        
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        
        return `${size.toFixed(2)} ${units[unitIndex]}`;
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
            throw new Error(`Unknown file command: ${command}`);
        }
        
        return cmd.handler.call(this, args);
    }

    // Register with main system
    register(registerFn) {
        for (const [name, cmd] of this.commands.entries()) {
            registerFn(`file.${name}`, async (args, context) => {
                return this.execute(name, args);
            }, {
                description: cmd.description,
                usage: cmd.usage
            });
        }
    }
}

// Export singleton instance
const fileCommands = new FileCommands();
module.exports = fileCommands;
