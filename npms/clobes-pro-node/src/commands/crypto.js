const crypto = require('crypto');
const CryptoJS = require('crypto-js');

class CryptoCommands {
    constructor() {
        this.commands = new Map();
        this.registerCommands();
    }

    registerCommands() {
        this.commands.set('hash', {
            handler: this.hash,
            description: 'Hash string or file',
            usage: 'hash <input> [algorithm=sha256]'
        });

        this.commands.set('encrypt', {
            handler: this.encrypt,
            description: 'Encrypt text',
            usage: 'encrypt <text> <key> [algorithm=aes-256-cbc]'
        });

        this.commands.set('decrypt', {
            handler: this.decrypt,
            description: 'Decrypt text',
            usage: 'decrypt <text> <key> [algorithm=aes-256-cbc]'
        });

        this.commands.set('generate-password', {
            handler: this.generatePassword,
            description: 'Generate secure password',
            usage: 'generate-password [length=16] [--symbols] [--numbers]'
        });

        this.commands.set('generate-key', {
            handler: this.generateKey,
            description: 'Generate encryption key',
            usage: 'generate-key [bits=256]'
        });

        this.commands.set('encode', {
            handler: this.encode,
            description: 'Encode data',
            usage: 'encode <type> <data>'
        });

        this.commands.set('decode', {
            handler: this.decode,
            description: 'Decode data',
            usage: 'decode <type> <data>'
        });
    }

    // Hash handler
    async hash(args) {
        const input = args[0];
        const algorithm = args[1] || 'sha256';
        
        if (!input) {
            throw new Error('Input is required');
        }

        // Check if input is a file path
        const fs = require('fs');
        let data;
        
        if (fs.existsSync(input)) {
            // It's a file
            console.log(`Hashing file: ${input}`);
            data = fs.readFileSync(input);
        } else {
            // It's a string
            console.log(`Hashing string: ${input}`);
            data = input;
        }

        const hash = crypto.createHash(algorithm);
        hash.update(data);
        const digest = hash.digest('hex');
        
        console.log(`${algorithm.toUpperCase()}: ${digest}`);
        
        // Also show other common hashes for comparison
        if (typeof data === 'string') {
            console.log('
Other hashes for comparison:');
            ['md5', 'sha1', 'sha256', 'sha512'].forEach(algo => {
                if (algo !== algorithm) {
                    const h = crypto.createHash(algo);
                    h.update(data);
                    console.log(`${algo.toUpperCase()}: ${h.digest('hex')}`);
                }
            });
        }
        
        return digest;
    }

    // Encrypt handler
    async encrypt(args) {
        const text = args[0];
        const key = args[1];
        const algorithm = args[2] || 'aes-256-cbc';
        
        if (!text || !key) {
            throw new Error('Text and key are required');
        }

        console.log(`Encrypting with ${algorithm}:`);
        console.log(`Text: ${text.substring(0, 50)}${text.length > 50 ? '...' : ''}`);
        
        let encrypted;
        
        switch (algorithm.toLowerCase()) {
            case 'aes-256-cbc':
                encrypted = CryptoJS.AES.encrypt(text, key).toString();
                break;
                
            case 'des':
                encrypted = CryptoJS.DES.encrypt(text, key).toString();
                break;
                
            case 'tripledes':
                encrypted = CryptoJS.TripleDES.encrypt(text, key).toString();
                break;
                
            case 'rabbit':
                encrypted = CryptoJS.Rabbit.encrypt(text, key).toString();
                break;
                
            case 'rc4':
                encrypted = CryptoJS.RC4.encrypt(text, key).toString();
                break;
                
            default:
                throw new Error(`Unsupported algorithm: ${algorithm}`);
        }
        
        console.log(`Encrypted: ${encrypted}`);
        return encrypted;
    }

    // Decrypt handler
    async decrypt(args) {
        const text = args[0];
        const key = args[1];
        const algorithm = args[2] || 'aes-256-cbc';
        
        if (!text || !key) {
            throw new Error('Text and key are required');
        }

        console.log(`Decrypting with ${algorithm}:`);
        
        let decrypted;
        
        try {
            switch (algorithm.toLowerCase()) {
                case 'aes-256-cbc':
                    decrypted = CryptoJS.AES.decrypt(text, key).toString(CryptoJS.enc.Utf8);
                    break;
                    
                case 'des':
                    decrypted = CryptoJS.DES.decrypt(text, key).toString(CryptoJS.enc.Utf8);
                    break;
                    
                case 'tripledes':
                    decrypted = CryptoJS.TripleDES.decrypt(text, key).toString(CryptoJS.enc.Utf8);
                    break;
                    
                case 'rabbit':
                    decrypted = CryptoJS.Rabbit.decrypt(text, key).toString(CryptoJS.enc.Utf8);
                    break;
                    
                case 'rc4':
                    decrypted = CryptoJS.RC4.decrypt(text, key).toString(CryptoJS.enc.Utf8);
                    break;
                    
                default:
                    throw new Error(`Unsupported algorithm: ${algorithm}`);
            }
            
            if (!decrypted) {
                throw new Error('Decryption failed - wrong key or corrupted data');
            }
            
            console.log(`Decrypted: ${decrypted}`);
            return decrypted;
        } catch (error) {
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }

    // Generate password handler
    async generatePassword(args) {
        const length = parseInt(args[0]) || 16;
        const includeSymbols = args.includes('--symbols');
        const includeNumbers = args.includes('--numbers') || true;
        
        if (length < 8) {
            throw new Error('Password length must be at least 8 characters');
        }
        if (length > 128) {
            throw new Error('Password length cannot exceed 128 characters');
        }

        console.log(`Generating ${length}-character password:`);
        
        let charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (includeNumbers) charset += '0123456789';
        if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        let password = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = crypto.randomInt(0, charset.length);
            password += charset[randomIndex];
        }
        
        console.log(`Password: ${password}`);
        
        // Calculate password strength
        const strength = this.calculatePasswordStrength(password);
        console.log(`Strength: ${strength.score}/10 - ${strength.label}`);
        
        // Show hashes for reference
        console.log('
Hashes for reference:');
        console.log(`MD5: ${crypto.createHash('md5').update(password).digest('hex')}`);
        console.log(`SHA256: ${crypto.createHash('sha256').update(password).digest('hex')}`);
        
        return password;
    }

    // Generate key handler
    async generateKey(args) {
        const bits = parseInt(args[0]) || 256;
        
        if (![128, 192, 256].includes(bits)) {
            throw new Error('Key size must be 128, 192, or 256 bits');
        }

        console.log(`Generating ${bits}-bit encryption key:`);
        
        const key = crypto.randomBytes(bits / 8);
        const keyHex = key.toString('hex');
        const keyBase64 = key.toString('base64');
        
        console.log(`Hex: ${keyHex}`);
        console.log(`Base64: ${keyBase64}`);
        
        // Generate IV if needed
        if (bits >= 256) {
            const iv = crypto.randomBytes(16);
            console.log(`
IV (Hex): ${iv.toString('hex')}`);
            console.log(`IV (Base64): ${iv.toString('base64')}`);
        }
        
        return {
            hex: keyHex,
            base64: keyBase64,
            bits: bits
        };
    }

    // Encode handler
    async encode(args) {
        const type = args[0];
        const data = args.slice(1).join(' ');
        
        if (!type || !data) {
            throw new Error('Type and data are required');
        }

        console.log(`Encoding data as ${type}:`);
        console.log(`Input: ${data.substring(0, 100)}${data.length > 100 ? '...' : ''}`);
        
        let encoded;
        
        switch (type.toLowerCase()) {
            case 'base64':
                encoded = Buffer.from(data).toString('base64');
                break;
                
            case 'hex':
                encoded = Buffer.from(data).toString('hex');
                break;
                
            case 'url':
                encoded = encodeURIComponent(data);
                break;
                
            case 'base64url':
                encoded = Buffer.from(data).toString('base64')
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=/g, '');
                break;
                
            default:
                throw new Error(`Unsupported encoding type: ${type}`);
        }
        
        console.log(`Encoded: ${encoded}`);
        return encoded;
    }

    // Decode handler
    async decode(args) {
        const type = args[0];
        const data = args.slice(1).join(' ');
        
        if (!type || !data) {
            throw new Error('Type and data are required');
        }

        console.log(`Decoding ${type} data:`);
        
        let decoded;
        
        try {
            switch (type.toLowerCase()) {
                case 'base64':
                    decoded = Buffer.from(data, 'base64').toString('utf8');
                    break;
                    
                case 'hex':
                    decoded = Buffer.from(data, 'hex').toString('utf8');
                    break;
                    
                case 'url':
                    decoded = decodeURIComponent(data);
                    break;
                    
                case 'base64url':
                    const base64 = data.replace(/-/g, '+').replace(/_/g, '/');
                    decoded = Buffer.from(base64, 'base64').toString('utf8');
                    break;
                    
                default:
                    throw new Error(`Unsupported decoding type: ${type}`);
            }
            
            console.log(`Decoded: ${decoded}`);
            return decoded;
        } catch (error) {
            throw new Error(`Decoding failed: ${error.message}`);
        }
    }

    // Helper method to calculate password strength
    calculatePasswordStrength(password) {
        let score = 0;
        
        // Length check
        if (password.length >= 8) score += 2;
        if (password.length >= 12) score += 2;
        if (password.length >= 16) score += 1;
        
        // Character variety checks
        if (/[a-z]/.test(password)) score += 1;
        if (/[A-Z]/.test(password)) score += 1;
        if (/[0-9]/.test(password)) score += 1;
        if (/[^a-zA-Z0-9]/.test(password)) score += 1;
        
        // Pattern checks (penalize simple patterns)
        if (/(.){2,}/.test(password)) score -= 1; // Repeated characters
        if (/^[0-9]+$/.test(password)) score -= 1; // Only numbers
        if (/^[a-zA-Z]+$/.test(password)) score -= 1; // Only letters
        
        // Ensure score is between 0 and 10
        score = Math.max(0, Math.min(10, score));
        
        const labels = [
            'Very Weak', 'Very Weak', 'Weak', 'Weak', 'Fair',
            'Fair', 'Good', 'Good', 'Strong', 'Very Strong', 'Excellent'
        ];
        
        return {
            score: score,
            label: labels[score]
        };
    }

    // Execute command
    async execute(command, args) {
        const cmd = this.commands.get(command);
        if (!cmd) {
            throw new Error(`Unknown crypto command: ${command}`);
        }
        
        return cmd.handler.call(this, args);
    }

    // Register with main system
    register(registerFn) {
        for (const [name, cmd] of this.commands.entries()) {
            registerFn(`crypto.${name}`, async (args, context) => {
                return this.execute(name, args);
            }, {
                description: cmd.description,
                usage: cmd.usage
            });
        }
    }
}

// Export singleton instance
const cryptoCommands = new CryptoCommands();
module.exports = cryptoCommands;
