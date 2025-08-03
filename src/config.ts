import * as fs from 'fs';
import * as path from 'path';
import { VibeGuardConfig, ScanOptions, SeverityLevel } from './types';

export class ConfigLoader {
  private static readonly CONFIG_FILES = [
    'vibe-guard.json',
    '.vibe-guard.json',
    'vibe-guard.config.json'
  ];

  /**
   * Load configuration from the nearest vibe-guard.json file
   */
  static loadConfig(projectPath: string): VibeGuardConfig {
    const configPath = this.findConfigFile(projectPath);
    if (!configPath) {
      return {};
    }

    try {
      const configContent = fs.readFileSync(configPath, 'utf-8');
      const config = JSON.parse(configContent);
      
      // Validate and normalize config
      return this.validateConfig(config);
    } catch (error) {
      console.warn(`Warning: Could not load config from ${configPath}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return {};
    }
  }

  /**
   * Find the nearest configuration file in the project hierarchy
   */
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

  /**
   * Validate and normalize configuration
   */
  private static validateConfig(config: any): VibeGuardConfig {
    const validated: VibeGuardConfig = {};

    // Validate output format
    if (config.outputFormat && ['table', 'json', 'sarif', 'html'].includes(config.outputFormat)) {
      validated.outputFormat = config.outputFormat;
    }

    // Validate severity
    if (config.severity && ['critical', 'high', 'medium', 'low'].includes(config.severity)) {
      validated.severity = config.severity as SeverityLevel;
    }

    // Validate arrays
    if (Array.isArray(config.exclude)) {
      validated.exclude = config.exclude.filter((item: any) => typeof item === 'string');
    }

    if (Array.isArray(config.include)) {
      validated.include = config.include.filter((item: any) => typeof item === 'string');
    }

    // Validate strings
    if (typeof config.outputFile === 'string') {
      validated.outputFile = config.outputFile;
    }

    if (typeof config.maxFileSize === 'string') {
      validated.maxFileSize = config.maxFileSize;
    }

    // Validate booleans
    if (typeof config.verbose === 'boolean') {
      validated.verbose = config.verbose;
    }

    if (typeof config.parallel === 'boolean') {
      validated.parallel = config.parallel;
    }

    // Validate numbers
    if (typeof config.maxWorkers === 'number' && config.maxWorkers > 0) {
      validated.maxWorkers = config.maxWorkers;
    }

    // Validate rules configuration
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

  /**
   * Merge configuration with CLI options (CLI takes precedence)
   */
  static mergeConfig(config: VibeGuardConfig, cliOptions: Partial<ScanOptions>): ScanOptions {
    return {
      target: cliOptions.target || '.',
      format: cliOptions.format ?? config.outputFormat ?? 'table',
      verbose: cliOptions.verbose ?? config.verbose ?? false,
      exclude: cliOptions.exclude || config.exclude || [],
      include: cliOptions.include || config.include || []
    };
  }

  /**
   * Create a default configuration file
   */
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

  /**
   * Generate a sample configuration file content
   */
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