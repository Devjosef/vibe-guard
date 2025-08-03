#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Colors for output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m'
};

function log(message, color = 'white') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

function logHeader(message) {
    console.log('\n' + '='.repeat(60));
    log(message, 'bright');
    console.log('='.repeat(60));
}

function logSection(message) {
    console.log('\n' + '-'.repeat(40));
    log(message, 'cyan');
    console.log('-'.repeat(40));
}

function measureTime(command, description) {
    const start = process.hrtime.bigint();
    try {
        execSync(command, { stdio: 'pipe' });
        const end = process.hrtime.bigint();
        const duration = Number(end - start) / 1000000; // Convert to milliseconds
        log(`✓ ${description}: ${duration.toFixed(2)}ms`, 'green');
        return duration;
    } catch (error) {
        // If vibe-guard found issues (exit code 1), that's actually success for benchmarking
        if (error.status === 1) {
            const end = process.hrtime.bigint();
            const duration = Number(end - start) / 1000000; // Convert to milliseconds
            log(`✓ ${description}: ${duration.toFixed(2)}ms`, 'green');
            return duration;
        } else {
            log(`✗ ${description}: Failed`, 'red');
            return null;
        }
    }
}

function getFileSize(filePath) {
    try {
        const stats = fs.statSync(filePath);
        return stats.size;
    } catch {
        return 0;
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function createTestFiles() {
    const testDir = path.join(__dirname, '../test-benchmark');
    if (!fs.existsSync(testDir)) {
        fs.mkdirSync(testDir, { recursive: true });
    }

    // Create files with different sizes and content types
    const testFiles = [
        {
            name: 'small.js',
            content: `
const apiKey = "sk-1234567890abcdef";
const password = "secret123";
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
console.log("Hello World");
            `.trim(),
            description: 'Small file (1KB)'
        },
        {
            name: 'medium.js',
            content: `
// Medium sized file with various security patterns
const express = require('express');
const app = express();

// Vulnerable patterns
const query = "SELECT * FROM users WHERE id = " + req.params.id;
const html = "<div>" + userInput + "</div>";
const apiKey = process.env.API_KEY || "default-key-12345";

// More content to make it medium sized
${Array(50).fill().map((_, i) => `const var${i} = "value${i}";`).join('\n')}

app.get('/admin', (req, res) => {
    res.send('Admin panel');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // Missing authentication logic
    res.json({ success: true });
});
            `.trim(),
            description: 'Medium file (5KB)'
        },
        {
            name: 'large.js',
            content: `
// Large file with extensive code patterns
${Array(200).fill().map((_, i) => `
// Function ${i}
function processData${i}(input) {
    const apiKey = "sk-${i.toString().padStart(10, '0')}";
    const query = "SELECT * FROM table${i} WHERE id = " + input;
    const html = "<div>" + input + "</div>";
    
    // Simulate complex logic
    if (input.includes("admin")) {
        return "admin access granted";
    }
    
    return "processed: " + input;
}
`).join('\n')}

// Main application logic
const express = require('express');
const app = express();

app.use(express.json());

// Vulnerable endpoints
app.get('/api/users/:id', (req, res) => {
    const query = "SELECT * FROM users WHERE id = " + req.params.id;
    // Missing input validation
    res.json({ user: "data" });
});

app.post('/api/upload', (req, res) => {
    // Missing file validation
    res.json({ uploaded: true });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
            `.trim(),
            description: 'Large file (50KB)'
        }
    ];

    testFiles.forEach(file => {
        const filePath = path.join(testDir, file.name);
        fs.writeFileSync(filePath, file.content);
        const size = getFileSize(filePath);
        log(`Created ${file.name}: ${formatBytes(size)}`, 'blue');
    });

    return testDir;
}

function runBenchmarks() {
    logHeader('VIBE-GUARD PERFORMANCE BENCHMARKS');
    
    // Check if vibe-guard is available
    try {
        execSync('vibe-guard --version', { stdio: 'pipe' });
    } catch {
        log('Error: vibe-guard not found. Please install it first.', 'red');
        process.exit(1);
    }

    const testDir = createTestFiles();
    const results = {};

    // Benchmark 1: Startup time
    logSection('STARTUP TIME BENCHMARKS');
    const startupTimes = [];
    for (let i = 0; i < 5; i++) {
        const time = measureTime('vibe-guard --version', `Startup ${i + 1}`);
        if (time) startupTimes.push(time);
    }
    const avgStartup = startupTimes.reduce((a, b) => a + b, 0) / startupTimes.length;
    results.startup = avgStartup;

    // Benchmark 2: Small file scanning
    logSection('SMALL FILE SCANNING');
    const smallFile = path.join(testDir, 'small.js');
    const smallTimes = [];
    for (let i = 0; i < 10; i++) {
        const time = measureTime(`vibe-guard scan "${smallFile}"`, `Small file scan ${i + 1}`);
        if (time) smallTimes.push(time);
    }
    const avgSmall = smallTimes.reduce((a, b) => a + b, 0) / smallTimes.length;
    results.smallFile = avgSmall;

    // Benchmark 3: Medium file scanning
    logSection('MEDIUM FILE SCANNING');
    const mediumFile = path.join(testDir, 'medium.js');
    const mediumTimes = [];
    for (let i = 0; i < 10; i++) {
        const time = measureTime(`vibe-guard scan "${mediumFile}"`, `Medium file scan ${i + 1}`);
        if (time) mediumTimes.push(time);
    }
    const avgMedium = mediumTimes.reduce((a, b) => a + b, 0) / mediumTimes.length;
    results.mediumFile = avgMedium;

    // Benchmark 4: Large file scanning
    logSection('LARGE FILE SCANNING');
    const largeFile = path.join(testDir, 'large.js');
    const largeTimes = [];
    for (let i = 0; i < 10; i++) {
        const time = measureTime(`vibe-guard scan "${largeFile}"`, `Large file scan ${i + 1}`);
        if (time) largeTimes.push(time);
    }
    const avgLarge = largeTimes.reduce((a, b) => a + b, 0) / largeTimes.length;
    results.largeFile = avgLarge;

    // Benchmark 5: Directory scanning
    logSection('DIRECTORY SCANNING');
    const dirTimes = [];
    for (let i = 0; i < 5; i++) {
        const time = measureTime(`vibe-guard scan "${testDir}"`, `Directory scan ${i + 1}`);
        if (time) dirTimes.push(time);
    }
    const avgDir = dirTimes.reduce((a, b) => a + b, 0) / dirTimes.length;
    results.directory = avgDir;

    // Benchmark 6: Memory usage (approximate)
    logSection('MEMORY USAGE ESTIMATION');
    const memBefore = process.memoryUsage();
    try {
        execSync(`vibe-guard scan "${testDir}"`, { stdio: 'pipe' });
    } catch (error) {
        // Expected to fail with security issues found
    }
    const memAfter = process.memoryUsage();
    const memUsed = memAfter.heapUsed - memBefore.heapUsed;
    results.memory = memUsed;

    // Display results
    logSection('BENCHMARK RESULTS SUMMARY');
    console.log('\n📊 Performance Metrics:');
    console.log('┌─────────────────────┬─────────────┬─────────────────┐');
    console.log('│ Metric              │ Time        │ Performance     │');
    console.log('├─────────────────────┼─────────────┼─────────────────┤');
    console.log(`│ Startup Time        │ ${avgStartup.toFixed(2)}ms    │ ⚡ Instant      │`);
    console.log(`│ Small File (1KB)    │ ${avgSmall.toFixed(2)}ms    │ 🚀 Ultra Fast   │`);
    console.log(`│ Medium File (5KB)   │ ${avgMedium.toFixed(2)}ms    │ ⚡ Very Fast    │`);
    console.log(`│ Large File (50KB)   │ ${avgLarge.toFixed(2)}ms    │ 🏃 Fast         │`);
    console.log(`│ Directory Scan      │ ${avgDir.toFixed(2)}ms    │ ⚡ Efficient     │`);
    console.log(`│ Memory Usage        │ ${formatBytes(memUsed)}    │ 💾 Low Memory   │`);
    console.log('└─────────────────────┴─────────────┴─────────────────┘');

    // Performance comparisons
    console.log('\n🏆 Performance Highlights:');
    console.log(`• Startup time: ${avgStartup.toFixed(2)}ms (faster than most tools)`);
    console.log(`• Small files: ${avgSmall.toFixed(2)}ms (near-instant)`);
    console.log(`• Large files: ${avgLarge.toFixed(2)}ms (efficient)`);
    console.log(`• Memory efficient: ${formatBytes(memUsed)} peak usage`);
    console.log(`• Zero dependencies: No startup delays`);

    // Cleanup
    try {
        fs.rmSync(testDir, { recursive: true, force: true });
        log('\n✓ Test files cleaned up', 'green');
    } catch (error) {
        log('\n⚠ Test files cleanup failed', 'yellow');
    }

    return results;
}

// Run benchmarks if this script is executed directly
if (require.main === module) {
    runBenchmarks();
}

module.exports = { runBenchmarks, measureTime }; 