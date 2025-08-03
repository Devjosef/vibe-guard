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

process.on('unhandledRejection', (reason, promise) => {
  console.error(chalk.red.bold('❌ Unhandled Rejection at:'), promise, chalk.red('reason:'), reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error(chalk.red.bold('❌ Uncaught Exception:'), error);
  process.exit(1);
});

program.parse(); 