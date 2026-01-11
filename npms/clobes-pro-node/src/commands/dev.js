const fs = require('fs-extra');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

class DevCommands {
    constructor() {
        this.commands = new Map();
        this.registerCommands();
    }

    registerCommands() {
        this.commands.set('compile', {
            handler: this.compile,
            description: 'Compile C program',
            usage: 'compile <file.c> [--output=<name>]'
        });

        this.commands.set('run', {
            handler: this.run,
            description: 'Run executable',
            usage: 'run <file> [args...]'
        });

        this.commands.set('test', {
            handler: this.test,
            description: 'Run tests',
            usage: 'test [directory]'
        });

        this.commands.set('format', {
            handler: this.format,
            description: 'Format code',
            usage: 'format <file> [--language=auto]'
        });

        this.commands.set('analyze', {
            handler: this.analyze,
            description: 'Code analysis',
            usage: 'analyze <file>'
        });

        this.commands.set('docs', {
            handler: this.docs,
            description: 'Generate documentation',
            usage: 'docs <directory> [--output=docs]'
        });

        this.commands.set('lint', {
            handler: this.lint,
            description: 'Lint code',
            usage: 'lint <file> [--language=auto]'
        });
    }

    // Compile handler
    async compile(args) {
        const file = args[0];
        if (!file) {
            throw new Error('Source file is required');
        }

        if (!file.endsWith('.c')) {
            throw new Error('File must have .c extension');
        }

        if (!fs.existsSync(file)) {
            throw new Error(`File not found: ${file}`);
        }

        // Get output name
        let outputName = this.getOption(args, '--output', null);
        if (!outputName) {
            outputName = path.basename(file, '.c');
        }

        console.log(`Compiling ${file} to ${outputName}...`);
        
        try {
            const { stdout, stderr } = await execAsync(
                `gcc -Wall -Wextra -O2 "${file}" -o "${outputName}"`
            );
            
            if (stderr) {
                console.warn('Compilation warnings:');
                console.warn(stderr);
            }
            
            // Check if executable was created
            if (fs.existsSync(outputName)) {
                const stats = fs.statSync(outputName);
                console.log(`Compilation successful: ${outputName}`);
                console.log(`Size: ${(stats.size / 1024).toFixed(2)} KB`);
                
                // Show file info
                const { stdout: fileInfo } = await execAsync(`file "${outputName}"`);
                console.log(`Type: ${fileInfo.trim()}`);
                
                return outputName;
            } else {
                throw new Error('Executable was not created');
            }
        } catch (error) {
            if (error.stderr) {
                console.error('Compilation errors:');
                console.error(error.stderr);
            }
            throw new Error(`Compilation failed: ${error.message}`);
        }
    }

    // Run handler
    async run(args) {
        const file = args[0];
        const runArgs = args.slice(1);
        
        if (!file) {
            throw new Error('Executable file is required');
        }

        if (!fs.existsSync(file)) {
            throw new Error(`File not found: ${file}`);
        }

        // Check if file is executable
        try {
            await fs.access(file, fs.constants.X_OK);
        } catch {
            console.warn('File is not executable. Trying to make it executable...');
            await execAsync(`chmod +x "${file}"`);
        }

        console.log(`Running ${file} ${runArgs.join(' ')}...`);
        console.log('══════════════════════════════════════════');
        
        try {
            const { stdout, stderr } = await execAsync(`"${file}" ${runArgs.join(' ')}`, {
                stdio: 'inherit'
            });
            
            if (stderr) {
                console.error('
Standard Error:');
                console.error(stderr);
            }
            
            return stdout;
        } catch (error) {
            if (error.stdout) console.log(error.stdout);
            if (error.stderr) console.error(error.stderr);
            throw new Error(`Program execution failed: ${error.message}`);
        }
    }

    // Test handler
    async test(args) {
        const directory = args[0] || '.';
        
        if (!fs.existsSync(directory)) {
            throw new Error(`Directory not found: ${directory}`);
        }

        console.log(`Looking for tests in ${directory}...`);
        
        // Look for test files
        const testFiles = await this.findTestFiles(directory);
        
        if (testFiles.length === 0) {
            console.log('No test files found.');
            return [];
        }
        
        console.log(`Found ${testFiles.length} test file(s):`);
        testFiles.forEach(file => console.log(`  ${file}`));
        
        console.log('
Running tests...');
        console.log('══════════════════════════════════════════');
        
        const results = [];
        for (const testFile of testFiles) {
            console.log(`
Running: ${path.basename(testFile)}`);
            
            try {
                // Make file executable if needed
                await execAsync(`chmod +x "${testFile}" 2>/dev/null || true`);
                
                // Run test
                const { stdout, stderr } = await execAsync(`"${testFile}"`, {
                    timeout: 30000
                });
                
                console.log('✓ PASS');
                if (stdout.trim()) {
                    console.log(`Output: ${stdout.substring(0, 200)}${stdout.length > 200 ? '...' : ''}`);
                }
                
                results.push({
                    file: testFile,
                    passed: true,
                    output: stdout,
                    error: null
                });
            } catch (error) {
                console.log('✗ FAIL');
                if (error.stdout) console.log(`Output: ${error.stdout.substring(0, 200)}`);
                if (error.stderr) console.error(`Error: ${error.stderr.substring(0, 200)}`);
                
                results.push({
                    file: testFile,
                    passed: false,
                    output: error.stdout,
                    error: error.stderr || error.message
                });
            }
        }
        
        // Summary
        const passed = results.filter(r => r.passed).length;
        const failed = results.filter(r => !r.passed).length;
        
        console.log('
══════════════════════════════════════════');
        console.log(`Test Summary: ${passed} passed, ${failed} failed, ${results.length} total`);
        
        return results;
    }

    // Format handler
    async format(args) {
        const file = args[0];
        if (!file) {
            throw new Error('File is required');
        }

        if (!fs.existsSync(file)) {
            throw new Error(`File not found: ${file}`);
        }

        const language = this.getOption(args, '--language', 'auto');
        const detectedLang = language === 'auto' ? this.detectLanguage(file) : language;
        
        console.log(`Formatting ${file} (${detectedLang})...`);
        
        try {
            let command;
            
            switch (detectedLang.toLowerCase()) {
                case 'c':
                case 'cpp':
                    command = `clang-format -i "${file}" 2>/dev/null || echo "Install clang-format for C/C++ formatting"`;
                    break;
                    
                case 'python':
                    command = `black "${file}" 2>/dev/null || autopep8 --in-place "${file}" 2>/dev/null || echo "Install black or autopep8 for Python formatting"`;
                    break;
                    
                case 'javascript':
                case 'typescript':
                    command = `prettier --write "${file}" 2>/dev/null || echo "Install prettier for JavaScript/TypeScript formatting"`;
                    break;
                    
                case 'java':
                    command = `google-java-format -i "${file}" 2>/dev/null || echo "Install google-java-format for Java formatting"`;
                    break;
                    
                case 'go':
                    command = `gofmt -w "${file}" 2>/dev/null || echo "Install gofmt for Go formatting"`;
                    break;
                    
                default:
                    // Basic formatting for other files
                    const content = await fs.readFile(file, 'utf8');
                    const formatted = this.basicFormat(content);
                    await fs.writeFile(file, formatted);
                    console.log('Basic formatting applied (line length: 80)');
                    return True;
            }
            
            const { stdout, stderr } = await execAsync(command);
            if (stdout) console.log(stdout);
            if (stderr) console.error(stderr);
            
            console.log('Formatting completed');
            return True;
        } catch (error) {
            throw new Error(`Formatting failed: ${error.message}`);
        }
    }

    // Analyze handler
    async analyze(args) {
        const file = args[0];
        if (!file) {
            throw new Error('File is required');
        }

        if (!fs.existsSync(file)) {
            throw new Error(`File not found: ${file}`);
        }

        const language = this.detectLanguage(file);
        console.log(`Analyzing ${file} (${language})...`);
        
        try {
            let command;
            
            switch (language.toLowerCase()) {
                case 'c':
                case 'cpp':
                    command = `cppcheck --enable=all "${file}" 2>&1 | head -30`;
                    break;
                    
                case 'python':
                    command = `pylint "${file}" 2>&1 | tail -20`;
                    break;
                    
                case 'javascript':
                    command = `eslint "${file}" 2>/dev/null || echo "Install eslint for JavaScript analysis"`;
                    break;
                    
                case 'java':
                    command = `checkstyle -c /sun_checks.xml "${file}" 2>/dev/null || echo "Install checkstyle for Java analysis"`;
                    break;
                    
                default:
                    console.log(`No specific analyzer for ${language}`);
                    await this.basicAnalysis(file);
                    return;
            }
            
            const { stdout, stderr } = await execAsync(command);
            if (stdout) console.log(stdout);
            if (stderr) console.error(stderr);
            
        } catch (error) {
            console.log(`Analysis failed: ${error.message}`);
        }
    }

    // Docs handler
    async docs(args) {
        const directory = args[0] || '.';
        const outputDir = this.getOption(args, '--output', 'docs');
        
        if (!fs.existsSync(directory)) {
            throw new Error(`Directory not found: ${directory}`);
        }

        console.log(`Generating documentation from ${directory} to ${outputDir}...`);
        
        try {
            await fs.ensureDir(outputDir);
            
            // Look for source files
            const sourceFiles = await this.findSourceFiles(directory);
            
            if (sourceFiles.length === 0) {
                console.log('No source files found for documentation.');
                return;
            }
            
            console.log(`Found ${sourceFiles.length} source file(s)`);
            
            // Create basic documentation
            const docs = await this.generateBasicDocs(sourceFiles, directory);
            const indexFile = path.join(outputDir, 'index.html');
            
            await fs.writeFile(indexFile, this.createHtmlDocs(docs));
            
            console.log(`Documentation generated: ${indexFile}`);
            console.log(`Open file://${path.resolve(indexFile)} in your browser`);
            
            return indexFile;
        } catch (error) {
            throw new Error(`Documentation generation failed: ${error.message}`);
        }
    }

    // Lint handler
    async lint(args) {
        const file = args[0];
        if (!file) {
            throw new Error('File is required');
        }

        if (!fs.existsSync(file)) {
            throw new Error(`File not found: ${file}`);
        }

        const language = this.getOption(args, '--language', 'auto');
        const detectedLang = language === 'auto' ? this.detectLanguage(file) : language;
        
        console.log(`Linting ${file} (${detectedLang})...`);
        
        // Basic linting checks
        const issues = await this.basicLint(file, detectedLang);
        
        if (issues.length === 0) {
            console.log('✓ No issues found');
        } else {
            console.log(`Found ${issues.length} issue(s):`);
            issues.forEach(issue => {
                console.log(`  ${issue.severity.toUpperCase()}: ${issue.message} (line ${issue.line})`);
            });
        }
        
        return issues;
    }

    // Helper methods
    async findTestFiles(dir) {
        const testFiles = [];
        
        async function traverse(currentDir) {
            try {
                const items = await fs.readdir(currentDir);
                
                for (const item of items) {
                    const fullPath = path.join(currentDir, item);
                    const stat = await fs.stat(fullPath);
                    
                    if (stat.isDirectory()) {
                        await traverse(fullPath);
                    } else if (stat.isFile()) {
                        const name = item.toLowerCase();
                        if (name.includes('test') || name.includes('spec')) {
                            // Check if it's likely a test file
                            const ext = path.extname(item).toLowerCase();
                            if (['', '.sh', '.js', '.py', '.rb', '.php'].includes(ext)) {
                                testFiles.push(fullPath);
                            }
                        }
                    }
                }
            } catch (error) {
                // Skip directories we can't access
            }
        }
        
        await traverse(dir);
        return testFiles;
    }

    detectLanguage(filename) {
        const ext = path.extname(filename).toLowerCase();
        
        const languageMap = {
            '.c': 'C',
            '.cpp': 'C++',
            '.cc': 'C++',
            '.h': 'C/C++ Header',
            '.hpp': 'C++ Header',
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.go': 'Go',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.rs': 'Rust',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.scala': 'Scala',
            '.pl': 'Perl',
            '.lua': 'Lua',
            '.sh': 'Shell',
            '.bash': 'Bash',
            '.zsh': 'Zsh',
            '.fish': 'Fish',
            '.ps1': 'PowerShell',
            '.bat': 'Batch',
            '.cmd': 'CMD',
            '.html': 'HTML',
            '.css': 'CSS',
            '.json': 'JSON',
            '.xml': 'XML',
            '.yaml': 'YAML',
            '.yml': 'YAML',
            '.md': 'Markdown',
            '.txt': 'Text'
        };
        
        return languageMap[ext] || 'Unknown';
    }

    basicFormat(content) {
        // Simple formatter: wrap lines at 80 characters
        const lines = content.split('
');
        const formatted = [];
        
        for (const line of lines) {
            if (line.length <= 80) {
                formatted.push(line);
            } else {
                // Simple word wrap
                let currentLine = '';
                const words = line.split(' ');
                
                for (const word of words) {
                    if ((currentLine + ' ' + word).length <= 80) {
                        currentLine += (currentLine ? ' ' : '') + word;
                    } else {
                        if (currentLine) formatted.push(currentLine);
                        currentLine = word;
                    }
                }
                
                if (currentLine) formatted.push(currentLine);
            }
        }
        
        return formatted.join('
');
    }

    async basicAnalysis(file) {
        const content = await fs.readFile(file, 'utf8');
        const lines = content.split('
');
        
        console.log('
Basic Analysis:');
        console.log('══════════════════════════════════════════');
        console.log(`Lines: ${lines.length}`);
        console.log(`Characters: ${content.length}`);
        
        const codeLines = lines.filter(line => line.trim() && !line.trim().startsWith('//') && !line.trim().startsWith('#'));
        console.log(`Code lines: ${codeLines.length}`);
        
        const commentLines = lines.filter(line => line.trim().startsWith('//') || line.trim().startsWith('#'));
        console.log(`Comment lines: ${commentLines.length}`);
        
        const emptyLines = lines.filter(line => !line.trim());
        console.log(`Empty lines: ${emptyLines.length}`);
        
        // Check for long lines
        const longLines = lines.filter((line, index) => line.length > 120);
        if (longLines.length > 0) {
            console.log(`
Warning: ${longLines.length} lines exceed 120 characters`);
            longLines.slice(0, 5).forEach((line, i) => {
                console.log(`  Line ${lines.indexOf(line) + 1}: ${line.substring(0, 50)}...`);
            });
        }
    }

    async findSourceFiles(dir) {
        const sourceFiles = [];
        const extensions = ['.c', '.cpp', '.py', '.js', '.java', '.go', '.rb', '.php', '.rs'];
        
        async function traverse(currentDir) {
            try {
                const items = await fs.readdir(currentDir);
                
                for (const item of items) {
                    const fullPath = path.join(currentDir, item);
                    const stat = await fs.stat(fullPath);
                    
                    if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
                        await traverse(fullPath);
                    } else if (stat.isFile()) {
                        const ext = path.extname(item).toLowerCase();
                        if (extensions.includes(ext)) {
                            sourceFiles.push(fullPath);
                        }
                    }
                }
            } catch (error) {
                // Skip directories we can't access
            }
        }
        
        await traverse(dir);
        return sourceFiles;
    }

    async generateBasicDocs(files, baseDir) {
        const docs = [];
        
        for (const file of files) {
            const relativePath = path.relative(baseDir, file);
            const content = await fs.readFile(file, 'utf8');
            const language = this.detectLanguage(file);
            
            // Extract basic info
            const lines = content.split('
');
            const functions = lines.filter(line => 
                line.includes('function') || 
                line.includes('def ') || 
                line.match(/^\s*\w+\s+\w+\(/) ||
                line.includes('public') && line.includes('(')
            );
            
            docs.push({
                file: relativePath,
                language: language,
                lines: lines.length,
                functions: functions.slice(0, 10).map(f => f.trim()),
                preview: content.substring(0, 500)
            });
        }
        
        return docs;
    }

    createHtmlDocs(docs) {
        return `
<!DOCTYPE html>
<html>
<head>
    <title>Code Documentation</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        .file { border: 1px solid #ccc; margin: 10px 0; padding: 10px; }
        .language { color: #666; font-size: 0.9em; }
        .functions { margin-top: 10px; }
        .function { background: #f0f0f0; padding: 5px; margin: 2px 0; }
        .preview { margin-top: 10px; font-size: 0.9em; color: #333; }
    </style>
</head>
<body>
    <h1>Code Documentation</h1>
    <p>Generated ${new Date().toLocaleString()}</p>
    
    ${docs.map(doc => `
    <div class="file">
        <h3>${doc.file}</h3>
        <div class="language">${doc.language} • ${doc.lines} lines</div>
        
        ${doc.functions.length > 0 ? `
        <div class="functions">
            <h4>Functions:</h4>
            ${doc.functions.map(f => `<div class="function">${f}</div>`).join('')}
        </div>
        ` : ''}
        
        <div class="preview">
            <h4>Preview:</h4>
            <pre>${doc.preview}</pre>
        </div>
    </div>
    `).join('')}
</body>
</html>
        `;
    }

    async basicLint(file, language) {
        const issues = [];
        const content = await fs.readFile(file, 'utf8');
        const lines = content.split('
');
        
        // Check for trailing whitespace
        lines.forEach((line, index) => {
            if (line.endsWith(' ') || line.endsWith('	')) {
                issues.push({
                    line: index + 1,
                    message: 'Trailing whitespace',
                    severity: 'warning'
                });
            }
        });
        
        // Check line length
        lines.forEach((line, index) => {
            if (line.length > 120) {
                issues.push({
                    line: index + 1,
                    message: `Line too long (${line.length} > 120 characters)`,
                    severity: 'warning'
                });
            }
        });
        
        // Language-specific checks
        if (language.toLowerCase() === 'python') {
            lines.forEach((line, index) => {
                if (line.includes('print ') && !line.includes('print(')) {
                    issues.push({
                        line: index + 1,
                        message: 'Use print() function instead of print statement',
                        severity: 'warning'
                    });
                }
            });
        }
        
        if (language.toLowerCase() === 'javascript') {
            lines.forEach((line, index) => {
                if (line.includes('console.log') && line.includes('//')) {
                    issues.push({
                        line: index + 1,
                        message: 'Consider removing console.log before committing',
                        severity: 'info'
                    });
                }
            });
        }
        
        return issues;
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
            throw new Error(`Unknown dev command: ${command}`);
        }
        
        return cmd.handler.call(this, args);
    }

    // Register with main system
    register(registerFn) {
        for (const [name, cmd] of this.commands.entries()) {
            registerFn(`dev.${name}`, async (args, context) => {
                return this.execute(name, args);
            }, {
                description: cmd.description,
                usage: cmd.usage
            });
        }
    }
}

// Export singleton instance
const devCommands = new DevCommands();
module.exports = devCommands;
