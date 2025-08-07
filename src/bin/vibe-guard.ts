#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import VibeGuard from '../index';
import { ScanOptions } from '../types';
import { VERSION } from '../types/version';

const program = new Command();

program
  .name('vibe-guard')
  .description('🛡️  Vibe-Guard Security Scanner - Catch security issues before they catch you!')
  .version(VERSION);

import * as fs from 'fs';

async function handleScan(target: string, options: any) {
  try {
    console.log(chalk.blue.bold('🛡️  Starting Vibe-Guard Security Scan...\n'));
    const scanOptions: ScanOptions = {
      target,
      format: options.format as 'table' | 'json' | 'sarif' | 'html',
      verbose: options.verbose,
      exclude: options.exclude,
      include: options.include
    };
    const vibeGuard = new VibeGuard();
    const output = await vibeGuard.scanAndFormat(scanOptions);
    
    if (options.outputFile) {
      fs.writeFileSync(options.outputFile, output);
      console.log(chalk.green(`✅ Results written to: ${options.outputFile}`));
    } else {
      console.log(output);
    }
    
    const result = await vibeGuard.scan(scanOptions);
    if (result.issuesFound > 0) {
      process.exit(1);
    }
  } catch (error) {
    console.error(chalk.red.bold('❌ Error:'), error instanceof Error ? error.message : 'Unknown error');
    process.exit(1);
  }
}

program
  .command('scan')
  .description('Scan files or directories for security issues')
  .argument('<target>', 'File or directory to scan')
  .option('-f, --format <format>', 'Output format (table, json, sarif, html)')
  .option('-o, --output-file <file>', 'Write output to file')
  .option('-v, --verbose', 'Verbose output', false)
  .option('--exclude <patterns...>', 'Exclude patterns')
  .option('--include <patterns...>', 'Include patterns')
  .action(handleScan);

// Default action - moved to end to avoid conflicts with commands

program
  .command('rules')
  .description('List all available security rules')
  .action(() => {
    const vibeGuard = new VibeGuard();
    const rules = vibeGuard.getRules();
    console.log(chalk.blue.bold('🛡️  Available Security Rules:\n'));
    rules.forEach(rule => {
      const severityColor = rule.severity === 'critical' ? chalk.red.bold :
                           rule.severity === 'high' ? chalk.red :
                           rule.severity === 'medium' ? chalk.yellow :
                           chalk.blue;
      console.log(`${chalk.bold(rule.name)} ${severityColor(`[${rule.severity.toUpperCase()}]`)}`);
      console.log(`  ${chalk.gray(rule.description)}\n`);
    });
  });

program
  .command('version')
  .description('Show version information')
  .action(() => {
    console.log(chalk.blue.bold('🛡️  Vibe-Guard Security Scanner'));
    const vibeGuard = new VibeGuard();
    console.log(`Version: ${vibeGuard.getVersion()}`);
    console.log('Built for developers who code fast and need security that keeps up! 🚀');
    console.log(chalk.gray('TypeScript-powered, zero-dependency security scanning'));
  });

program
  .command('init')
  .description('Create a default vibe-guard.json configuration file')
  .action(() => {
    const vibeGuard = new VibeGuard();
    vibeGuard.createConfigFile();
  });

program
  .command('config')
  .description('Show sample configuration')
  .action(() => {
    const vibeGuard = new VibeGuard();
    console.log(chalk.blue.bold('📝 Sample vibe-guard.json Configuration:\n'));
    console.log(vibeGuard.generateConfig());
  });

program
  .command('learn')
  .description('Learn about security concepts and vulnerabilities')
  .argument('[topic]', 'Security topic to learn about (xss, sql-injection, csrf, etc.)')
  .action((topic: string | undefined) => {
    const vibeGuard = new VibeGuard();
    if (topic) {
      const rule = vibeGuard.getRuleByName(topic);
      if (rule) {
        console.log(chalk.blue.bold(`📚 Learning about: ${rule.name}\n`));
        console.log(chalk.white(rule.description));
        console.log(chalk.yellow(`\nSeverity: ${rule.severity.toUpperCase()}`));
        console.log(chalk.gray(`\nThis rule helps detect ${rule.name.toLowerCase()} vulnerabilities.`));
      } else {
        console.log(chalk.red(`❌ Unknown topic: ${topic}`));
        console.log(chalk.gray('Use "vibe-guard rules" to see available topics.'));
      }
    } else {
      console.log(chalk.blue.bold('📚 Vibe-Guard Security Learning Center\n'));
      console.log(chalk.white('Learn about security vulnerabilities and how to prevent them.\n'));
      console.log(chalk.yellow('Available topics:'));
      const rules = vibeGuard.getRules();
      rules.forEach(rule => {
        console.log(`  • ${rule.name.toLowerCase().replace(/-/g, ' ')}`);
      });
      console.log(chalk.gray('\nExample: vibe-guard learn xss-detection'));
    }
  });

program
  .command('demo')
  .description('Run security scan on demo files to see how it works')
  .action(async () => {
    console.log(chalk.blue.bold('🎯 Vibe-Guard Security Demo\n'));
    console.log(chalk.white('Creating demo files with security vulnerabilities...\n'));
    
    // Create demo files with vulnerabilities
    const demoDir = './vibe-guard-demo';
    if (!fs.existsSync(demoDir)) {
      fs.mkdirSync(demoDir);
    }
    
    // Demo file with XSS vulnerability
    const xssDemo = `${demoDir}/vulnerable-app.js`;
    fs.writeFileSync(xssDemo, `
// Demo file with XSS vulnerability
app.get('/user', (req, res) => {
  const userInput = req.query.name;
  res.send('<h1>Hello ' + userInput + '</h1>'); // XSS vulnerability
});

// SQL Injection demo
app.get('/users', (req, res) => {
  const id = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ' + id; // SQL injection
  db.query(query);
});

// Hardcoded secrets
const API_KEY = 'sk-1234567890abcdef'; // Exposed secret
const PASSWORD = 'admin123'; // Hardcoded password
`);

    console.log(chalk.green('✅ Created demo files with security vulnerabilities'));
    console.log(chalk.gray(`Location: ${demoDir}`));
    console.log(chalk.white('\nRunning security scan...\n'));
    
    try {
      const vibeGuard = new VibeGuard();
      const output = await vibeGuard.scanAndFormat({
        target: demoDir,
        format: 'table',
        verbose: true
      });
      console.log(output);
      
      console.log(chalk.blue('\n🎓 What you learned:'));
      console.log(chalk.white('• XSS vulnerabilities in user input'));
      console.log(chalk.white('• SQL injection in database queries'));
      console.log(chalk.white('• Exposed secrets and hardcoded credentials'));
      console.log(chalk.gray('\nClean up: rm -rf vibe-guard-demo'));
    } catch (error) {
      console.error(chalk.red('Error running demo:', error));
    }
  });

program
  .command('community')
  .description('Join the Vibe-Guard community and contribute')
  .action(() => {
    console.log(chalk.blue.bold('🤝 Vibe-Guard Community\n'));
    console.log(chalk.white('Join us in making the web more secure!\n'));
    console.log(chalk.yellow('📚 Learn:'));
    console.log(chalk.white('  • vibe-guard learn [topic] - Learn about security concepts'));
    console.log(chalk.white('  • vibe-guard demo - Try the tool with demo files\n'));
    console.log(chalk.yellow('🔧 Contribute:'));
    console.log(chalk.white('  • GitHub: https://github.com/Devjosef/vibe-guard'));
    console.log(chalk.white('  • Issues: https://github.com/Devjosef/vibe-guard/issues'));
    console.log(chalk.white('  • Discussions: https://github.com/Devjosef/vibe-guard/discussions\n'));
    console.log(chalk.yellow('📖 Resources:'));
    console.log(chalk.white('  • Documentation: https://devjosef.github.io/vibe-guard/'));
    console.log(chalk.white('  • Security Rules: vibe-guard rules'));
    console.log(chalk.white('  • Examples: vibe-guard demo\n'));
    console.log(chalk.gray('Built for developers who code fast and need security that keeps up!'));
  });

program
  .command('stats')
  .description('Show Vibe-Guard usage statistics and impact')
  .action(() => {
    console.log(chalk.blue.bold('📊 Vibe-Guard Impact Statistics\n'));
    console.log(chalk.white('Your security scanning impact:\n'));
    console.log(chalk.yellow('🛡️ Security Rules: 25'));
    console.log(chalk.white('  • Covers OWASP Top 10'));
    console.log(chalk.white('  • Modern web vulnerabilities'));
    console.log(chalk.white('  • AI/ML security concerns\n'));
    console.log(chalk.yellow('🌍 Global Reach:'));
    console.log(chalk.white('  • Cross-platform (Linux, macOS, Windows)'));
    console.log(chalk.white('  • Multiple package managers'));
    console.log(chalk.white('  • Zero dependencies\n'));
    console.log(chalk.yellow('🎯 Use Cases:'));
    console.log(chalk.white('  • CI/CD security scanning'));
    console.log(chalk.white('  • Pre-commit hooks'));
    console.log(chalk.white('  • Security audits'));
    console.log(chalk.white('  • Educational tool\n'));
    console.log(chalk.gray('Every scan makes the web a little more secure! 🚀'));
  });

process.on('unhandledRejection', (reason, promise) => {
  console.error(chalk.red.bold('❌ Unhandled Rejection at:'), promise, chalk.red('reason:'), reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error(chalk.red.bold('❌ Uncaught Exception:'), error);
  process.exit(1);
});

// Default action for when no command is specified
program
  .argument('[target]', 'File or directory to scan')
  .option('-f, --format <format>', 'Output format (table, json, sarif, html)')
  .option('-o, --output-file <file>', 'Write output to file')
  .option('-v, --verbose', 'Verbose output', false)
  .option('--exclude <patterns...>', 'Exclude patterns')
  .option('--include <patterns...>', 'Include patterns')
  .action((target: string | undefined, options: any) => {
    if (target) {
      handleScan(target, options);
    } else {
      program.help();
    }
  });

program.parse(); 