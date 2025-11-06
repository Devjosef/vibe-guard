import { Command } from 'commander';
import chalk from 'chalk';
import VibeGuard from '../index';
import { ScanOptions, SeverityLevel } from '../types';
import { VERSION } from '../types/version';
import * as fs from 'fs';
import * as readline from 'readline';

const program = new Command();

// ASCII Art Logo
function displayLogo() {
  const logo = [
    '██╗   ██╗██╗██████╗ ███████╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ',
    '╚██╗ ██╔╝██║██╔══██╗██╔════╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗',
    ' ╚████╔╝ ██║██████╔╝█████╗      ██║  ███╗██║   ██║███████║██████╔╝██║  ██║',
    '  ╚██╔╝  ██║██╔══██╗██╔══╝      ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║',
    '   ██║   ██║██████╔╝███████╗    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝',
    '   ╚═╝   ╚═╝╚═════╝ ╚══════╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ '
  ];

  logo.forEach((line, index) => {
    let color;
    switch (index) {
      case 0: color = chalk.blue; break;
      case 1: color = chalk.blueBright; break;
      case 2: color = chalk.cyan; break;
      case 3: color = chalk.cyanBright; break;
      case 4: color = chalk.blueBright; break;
      case 5: color = chalk.blue; break;
      default: color = chalk.blue;
    }
    console.log(color.bold(line));
  });

  console.log(chalk.blue.bold('                           ██  SECURITY SCANNER  ██\n'));
}

/**
 * Run a scan and return an exit code instead of terminating the process.
 * Returns: 0 = success (no issues), 1 = issues found, 2 = error/invalid args
 */
async function handleScan(target: string, options: any): Promise<number> {
  try {
    console.log(chalk.blue.bold('╔══════════════════════════════════════════════════════════════════════════════╗'));
    console.log(chalk.blue.bold('║                        STARTING VIBE-GUARD SECURITY SCAN                        ║'));
    console.log(chalk.blue.bold('║                              THREAT DETECTION ACTIVE                           ║'));
    console.log(chalk.blue.bold('╚══════════════════════════════════════════════════════════════════════════════╝\n'));

    if (options.severity && !['critical', 'high', 'medium', 'low'].includes(options.severity)) {
      console.error(chalk.red.bold('❌ Error: Invalid severity level. Must be one of: critical, high, medium, low'));
      return 2;
    }

    const scanOptions: ScanOptions = {
      target,
      format: options.format as 'table' | 'json' | 'sarif' | 'html',
      verbose: options.verbose,
      exclude: options.exclude,
      include: options.include
    };

    if (options.severity) scanOptions.severity = options.severity as SeverityLevel;
    if (options.config) scanOptions.config = options.config;
    if (options.parallel) scanOptions.parallel = options.parallel;
    if (options.maxFiles) scanOptions.maxFiles = parseInt(options.maxFiles);

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
      return 1;
    }

    return 0;
  } catch (error) {
    console.error(chalk.red.bold('❌ Error:'), error instanceof Error ? error.message : 'Unknown error');
    return 2;
  }
}

program
  .name('vibe-guard')
  .description('██  Vibe-Guard Security Scanner - Catch security issues before they catch you!')
  .version(VERSION)
  .hook('preAction', () => {
    displayLogo();
  });

program
  .command('start')
  .description('Start interactive Vibe-Guard session')
  .action(() => {
    // Persistent menu implemented with callback-style readline.
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    const menu = `\nChoose an option:\n1. 🔍 Scan a file or directory\n2. 📋 View all security rules\n3. ⚙️  Create configuration file\n4. 📊 Show sample configuration\n5. ℹ️  About Vibe-Guard\n6. 🚪 Exit\n\nPlease enter your choice (1-6): `;

    // Display logo once at start
    displayLogo();

  const pause = (next: () => void) => rl.question(chalk.gray('\nPress Enter to continue...'), () => next());

  const showMenu = () => {
      rl.question(menu, (answer: string) => {
        const choice = answer.trim();
        switch (choice) {
          case '1': {
            rl.question('Enter file or directory to scan (default: .): ', (target: string) => {
              Promise.resolve(handleScan(target || '.', { verbose: false }))
                .catch(err => console.error(chalk.red('Scan error:'), err))
                .finally(() => pause(() => showMenu()));
            });
            break;
          }
          case '2': {
            const vibeGuard = new VibeGuard();
            const rules = vibeGuard.getRules();
            console.log(chalk.blue.bold('\nAvailable Security Rules:\n'));
            rules.forEach(rule => {
              const severityColor = rule.severity === 'critical' ? chalk.red.bold :
                                   rule.severity === 'high' ? chalk.red :
                                   rule.severity === 'medium' ? chalk.yellow :
                                   chalk.blue;
              console.log(`${chalk.bold(rule.name)} ${severityColor(`[${rule.severity.toUpperCase()}]`)}`);
              console.log(`  ${chalk.gray(rule.description)}\n`);
            });
            pause(() => showMenu());
            break;
          }
          case '3': {
            const vibeGuard = new VibeGuard();
            vibeGuard.createConfigFile();
            pause(() => showMenu());
            break;
          }
          case '4': {
            const vibeGuard = new VibeGuard();
            console.log(chalk.blue.bold('\nSample vibe-guard.json Configuration:\n'));
            console.log(vibeGuard.generateConfig());
            pause(() => showMenu());
            break;
          }
          case '5': {
            console.log(chalk.white('\nVibe-Guard Security Scanner - Designed for fast and secure development with AI-powered scanning.\n'));
            pause(() => showMenu());
            break;
          }
          case '6': {
            console.log(chalk.green('\nExiting Vibe-Guard. Stay secure! 🚀'));
            rl.close();
            break;
          }
          default: {
            console.log(chalk.red('\nInvalid choice. Please select 1-6.'));
            showMenu();
          }
        }
      });
    };

    showMenu();

    rl.on('close', () => {
      process.exit(0);
    });
  });

program
  .command('scan')
  .description('Scan files or directories for security issues')
  .argument('<target>', 'File or directory to scan')
  .option('-f, --format <format>', 'Output format (table, json, sarif, html)')
  .option('-o, --output-file <file>', 'Write output to file')
  .option('-v, --verbose', 'Verbose output', false)
  .option('-s, --severity <level>', 'Minimum severity level (critical, high, medium, low)')
  .option('-c, --config <file>', 'Path to configuration file')
  .option('--parallel', 'Enable parallel processing for better performance')
  .option('--max-files <number>', 'Maximum files to process concurrently')
  .option('--exclude <patterns...>', 'Exclude patterns')
  .option('--include <patterns...>', 'Include patterns')
  .action(async (target: string, options: any) => {
    const code = await handleScan(target, options);
    // Exit with the same semantics as the previous implementation
    process.exit(code);
  });

program
  .command('rules')
  .description('List all available security rules')
  .action(() => {
    const vibeGuard = new VibeGuard();
    const rules = vibeGuard.getRules();
    console.log(chalk.blue.bold('╔══════════════════════════════════════════════════════════════════════════════╗'));
    console.log(chalk.blue.bold('║                           AVAILABLE SECURITY RULES                           ║'));
    console.log(chalk.blue.bold('║                              THREAT DETECTION MATRIX                          ║'));
    console.log(chalk.blue.bold('╚══════════════════════════════════════════════════════════════════════════════╝\n'));
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
    console.log(chalk.blue.bold('╔══════════════════════════════════════════════════════════════════════════════╗'));
    console.log(chalk.blue.bold('║                           VIBE-GUARD SECURITY SCANNER                        ║'));
    console.log(chalk.blue.bold('║                              THREAT DETECTION ENGINE                          ║'));
    console.log(chalk.blue.bold('╚══════════════════════════════════════════════════════════════════════════════╝'));
    const vibeGuard = new VibeGuard();
    console.log(chalk.blue.bold(`\nVERSION: ${vibeGuard.getVersion()}`));
    console.log(chalk.gray('Built for developers who code fast and need security that keeps up! 🚀'));
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
    
    const demoDir = './vibe-guard-demo';
    if (!fs.existsSync(demoDir)) {
      fs.mkdirSync(demoDir);
    }
    
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
          console.log(chalk.yellow('██ Security Rules: 25'));
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