#!/usr/bin/env node
import { Command, Option } from 'commander';
import chalk from 'chalk';
import VibeGuard from '../index';
import { ScanOptions } from '../types';
import { VERSION } from '../types/version';
import * as fs from 'fs';
import * as readline from 'readline';

const program = new Command();

interface ScanCliOptions {
  format?: 'table' | 'json' | 'sarif' | 'html';
  outputFile?: string;
}

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
async function handleScan(target: string, options: ScanCliOptions): Promise<number> {
  try {
    const scanOptions: ScanOptions = {
      target,
      format: options.format ?? 'table',
      verbose: false
    };

    const vibeGuard = new VibeGuard();
    const result = await vibeGuard.scan(scanOptions);
    const output = vibeGuard.formatResults(result, scanOptions.format);

    if (options.outputFile) {
      fs.writeFileSync(options.outputFile, output);
      console.error(chalk.green(`Results written to: ${options.outputFile}`));
    } else {
      console.log(output);
    }

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
  .version(VERSION);

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
              Promise.resolve(handleScan(target || '.', {}))
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
  .addOption(new Option('-f, --format <format>', 'Output format')
    .choices(['table', 'json', 'sarif', 'html'])
    .default('table'))
  .option('-o, --output-file <file>', 'Write output to a file')
  .action(async (target: string, options: ScanCliOptions) => {
    process.exitCode = await handleScan(target, options);
  });

void program.parseAsync(process.argv);
