#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import VibeGuard from '../index';
import { ScanOptions } from '../types';

const program = new Command();

program
  .name('vibe-guard')
  .description('🛡️  Vibe-Guard Security Scanner - Catch security issues before they catch you!')
  .version('1.0.0');

// Scan command (main functionality)
program
  .command('scan')
  .description('Scan files or directories for security issues')
  .argument('<target>', 'File or directory to scan')
  .option('-f, --format <format>', 'Output format (table, json)', 'table')
  .option('-v, --verbose', 'Verbose output', false)
  .option('--exclude <patterns...>', 'Exclude patterns')
  .option('--include <patterns...>', 'Include patterns')
  .action(async (target: string, options: any) => {
    try {
      console.log(chalk.blue.bold('🛡️  Starting Vibe-Guard Security Scan...\n'));
      
      const scanOptions: ScanOptions = {
        target,
        format: options.format as 'table' | 'json',
        verbose: options.verbose,
        exclude: options.exclude,
        include: options.include
      };

      const vibeGuard = new VibeGuard();
      const output = await vibeGuard.scanAndFormat(scanOptions);
      
      console.log(output);
      
      // Exit with error code if issues found
      const result = await vibeGuard.scan(scanOptions);
      if (result.issuesFound > 0) {
        process.exit(1);
      }
      
    } catch (error) {
      console.error(chalk.red.bold('❌ Error:'), error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

// Default action (scan without explicit 'scan' command for backward compatibility)
program
  .argument('[target]', 'File or directory to scan')
  .option('-f, --format <format>', 'Output format (table, json)', 'table')
  .option('-v, --verbose', 'Verbose output', false)
  .option('--exclude <patterns...>', 'Exclude patterns')
  .option('--include <patterns...>', 'Include patterns')
  .action(async (target?: string, options?: any) => {
    // Only run if target is provided and no subcommand was used
    if (target && !process.argv.includes('scan') && !process.argv.includes('rules') && !process.argv.includes('version')) {
      try {
        console.log(chalk.blue.bold('🛡️  Starting Vibe-Guard Security Scan...\n'));
        
        const scanOptions: ScanOptions = {
          target,
          format: options.format as 'table' | 'json',
          verbose: options.verbose,
          exclude: options.exclude,
          include: options.include
        };

        const vibeGuard = new VibeGuard();
        const output = await vibeGuard.scanAndFormat(scanOptions);
        
        console.log(output);
        
        // Exit with error code if issues found
        const result = await vibeGuard.scan(scanOptions);
        if (result.issuesFound > 0) {
          process.exit(1);
        }
        
      } catch (error) {
        console.error(chalk.red.bold('❌ Error:'), error instanceof Error ? error.message : 'Unknown error');
        process.exit(1);
      }
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
    const vibeGuard = new VibeGuard();
    console.log(chalk.blue.bold('🛡️  Vibe-Guard Security Scanner'));
    console.log(`Version: ${vibeGuard.getVersion()}`);
    console.log('Built for developers who code fast and need security that keeps up! 🚀');
    console.log(chalk.gray('TypeScript-powered, zero-dependency security scanning'));
  });

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error(chalk.red.bold('❌ Unhandled Rejection at:'), promise, chalk.red('reason:'), reason);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error(chalk.red.bold('❌ Uncaught Exception:'), error);
  process.exit(1);
});

program.parse(); 