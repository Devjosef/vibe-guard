import * as fs from 'fs';
import * as path from 'path';
import { VibeGuardConfig, ScanOptions, SeverityLevel } from './types';

export class ConfigLoader {
  private static readonly CONFIG_FILES = [
    'vibe-guard.json',
    '.vibe-guard.json',
    'vibe-guard.config.json'
  ];

  // Loads the config file from the project path
  static loadConfig(projectPath: string): VibeGuardConfig {
    const configPath = this.findConfigFile(projectPath);
    if (!configPath) {
      return {};
    }

    try {
      const configContent = fs.readFileSync(configPath, 'utf-8');
      const config = JSON.parse(configContent);
      
      return this.validateConfig(config);
    } catch (error) {
      console.warn(`Warning: Could not load config from ${configPath}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return {};
    }
  }

  // Finds the config file from the project path
  static findConfigFile(projectPath: string): string | null {
    let currentPath = path.resolve(projectPath);
    
    while (currentPath !== path.dirname(currentPath)) {
      for (const configFile of this.CONFIG_FILES) {
        const configPath = path.join(currentPath, configFile);
        if (fs.existsSync(configPath)) {
          return configPath;
        }
      }
      currentPath = path.dirname(currentPath);
    }
    
    return null;
  }

  // Validates the config file
  private static validateConfig(config: any): VibeGuardConfig {
    const validated: VibeGuardConfig = {};

    if (config.outputFormat && ['table', 'json', 'sarif', 'html'].includes(config.outputFormat)) {
      validated.outputFormat = config.outputFormat;
    }

    if (config.severity && ['critical', 'high', 'medium', 'low'].includes(config.severity)) {
      validated.severity = config.severity as SeverityLevel;
    }

    if (Array.isArray(config.exclude)) {
      validated.exclude = config.exclude.filter((item: any) => typeof item === 'string');
    }

    if (Array.isArray(config.include)) {
      validated.include = config.include.filter((item: any) => typeof item === 'string');
    }

    if (typeof config.outputFile === 'string') {
      validated.outputFile = config.outputFile;
    }

    if (typeof config.maxFileSize === 'string') {
      validated.maxFileSize = config.maxFileSize;
    }

    if (typeof config.verbose === 'boolean') {
      validated.verbose = config.verbose;
    }

    if (typeof config.parallel === 'boolean') {
      validated.parallel = config.parallel;
    }

    if (typeof config.maxWorkers === 'number' && config.maxWorkers > 0) {
      validated.maxWorkers = config.maxWorkers;
    }

    if (config.rules && typeof config.rules === 'object') {
      validated.rules = {};
      for (const [ruleName, ruleConfig] of Object.entries(config.rules)) {
        if (typeof ruleConfig === 'object' && ruleConfig !== null) {
          const rule = ruleConfig as any;
          validated.rules[ruleName] = {
            enabled: typeof rule.enabled === 'boolean' ? rule.enabled : true,
            severity: ['critical', 'high', 'medium', 'low'].includes(rule.severity) ? rule.severity : undefined,
            patterns: Array.isArray(rule.patterns) ? rule.patterns.filter((p: any) => typeof p === 'string') : undefined,
            excludePatterns: Array.isArray(rule.excludePatterns) ? rule.excludePatterns.filter((p: any) => typeof p === 'string') : undefined
          };
        }
      }
    }

    return validated;
  }

  // Merges the config file with the CLI options
  static mergeConfig(config: VibeGuardConfig, cliOptions: Partial<ScanOptions>): ScanOptions {
    return {
      target: cliOptions.target || '.',
      format: cliOptions.format ?? config.outputFormat ?? 'table',
      verbose: cliOptions.verbose ?? config.verbose ?? false,
      exclude: cliOptions.exclude || config.exclude || [],
      include: cliOptions.include || config.include || []
    };
  }

  static createDefaultConfig(): VibeGuardConfig {
    return {
      exclude: [
        'node_modules/**',
        'dist/**',
        'build/**',
        '.git/**',
        'coverage/**',
        '**/*.min.js',
        '**/*.bundle.js'
      ],
      outputFormat: 'table',
      verbose: false,
      severity: 'low',
      maxFileSize: '5MB',
      parallel: false,
      maxWorkers: 4
    };
  }

  // Generates a sample config file
  static generateSampleConfig(): string {
    const sampleConfig = {
      exclude: [
        'node_modules/**',
        'dist/**',
        'build/**',
        '.git/**',
        'coverage/**',
        '**/*.min.js',
        '**/*.bundle.js'
      ],
      include: [
        'src/**/*.{js,ts,jsx,tsx}',
        'lib/**/*.{js,ts}'
      ],
      outputFormat: 'table',
      outputFile: 'security-report.json',
      verbose: false,
      severity: 'low',
      maxFileSize: '5MB',
      parallel: false,
      maxWorkers: 4,
      rules: {
        'sql-injection': {
          enabled: true,
          severity: 'critical'
        },
        'xss-detection': {
          enabled: true,
          severity: 'high'
        },
        'exposed-secrets': {
          enabled: true,
          severity: 'critical'
        }
      }
    };

    return JSON.stringify(sampleConfig, null, 2);
  }
} 