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
      console.error(chalk.red.bold('Error: Invalid severity level. Must be one of: critical, high, medium, low'));
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
      console.log(chalk.green(`Results written to: ${options.outputFile}`));
    } else {
      console.log(output);
    }

    const result = await vibeGuard.scan(scanOptions);
    if (result.issuesFound > 0) {
      return 1;
    }

    return 0;
  } catch (error) {
    console.error(chalk.red.bold('Error:'), error instanceof Error ? error.message : 'Unknown error');
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
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    const menu = `\nChoose an option:\n1. Scan a file or directory\n2. View all security rules\n3. Create configuration file\n4. Show sample configuration\n5. About Vibe-Guard\n6. Exit\n\nPlease enter your choice (1-6): `;

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
            console.log(chalk.green('\nExiting Vibe-Guard. Stay secure!'));
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
