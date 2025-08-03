import * as fs from 'fs';
import * as path from 'path';
import { FileScanner } from './scanner';
import { Reporter } from './reporter';
import { ScanOptions, ScanResult, BaseRule } from './types';
import { ConfigLoader } from './config';
import { ExposedSecretsRule } from './rules/exposed-secrets';
import { MissingAuthenticationRule } from './rules/missing-authentication';
import { OpenCorsRule } from './rules/open-cors';
import { HardcodedSensitiveDataRule } from './rules/hardcoded-sensitive-data';
import { InsecureHttpRule } from './rules/insecure-http';
import { SqlInjectionRule } from './rules/sql-injection';
import { UnvalidatedInputRule } from './rules/unvalidated-input';
import { DirectoryTraversalRule } from './rules/directory-traversal';
import { InsecureDependenciesRule } from './rules/insecure-dependencies';
import { MissingSecurityHeadersRule } from './rules/missing-security-headers';
import { XssDetectionRule } from './rules/xss-detection';
import { CsrfProtectionRule } from './rules/csrf-protection';
import { InsecureDeserializationRule } from './rules/insecure-deserialization';
import { BrokenAccessControlRule } from './rules/broken-access-control';
import { InsecureFileUploadRule } from './rules/insecure-file-upload';
import { InsecureRandomGenerationRule } from './rules/insecure-random-generation';
import { InsecureLoggingRule } from './rules/insecure-logging';
import { InsecureSessionManagementRule } from './rules/insecure-session-management';
import { InsecureErrorHandlingRule } from './rules/insecure-error-handling';
import { InsecureConfigurationRule } from './rules/insecure-configuration';
import { VERSION } from './types/version';

export class VibeGuard {
  private scanner: FileScanner;
  private reporter: Reporter;
  private rules: BaseRule[];

  constructor() {
    this.rules = [
      new ExposedSecretsRule(),
      new MissingAuthenticationRule(),
      new OpenCorsRule(),
      new HardcodedSensitiveDataRule(),
      new InsecureHttpRule(),
      new SqlInjectionRule(),
      new UnvalidatedInputRule(),
      new DirectoryTraversalRule(),
      new InsecureDependenciesRule(),
      new MissingSecurityHeadersRule(),
      new XssDetectionRule(),
      new CsrfProtectionRule(),
      new InsecureDeserializationRule(),
      new BrokenAccessControlRule(),
      new InsecureFileUploadRule(),
      new InsecureRandomGenerationRule(),
      new InsecureLoggingRule(),
      new InsecureSessionManagementRule(),
      new InsecureErrorHandlingRule(),
      new InsecureConfigurationRule()
    ];
    this.scanner = new FileScanner();
    this.reporter = new Reporter();
  }

  async scan(options: ScanOptions): Promise<ScanResult> {
    // Load configuration from vibe-guard.json
    const config = ConfigLoader.loadConfig(options.target);
    
    // Merge config with CLI options (CLI takes precedence)
    const mergedOptions = ConfigLoader.mergeConfig(config, options);
    
    const targetPath = path.resolve(mergedOptions.target);
    
    if (mergedOptions.verbose) {
      console.log('Configuration loaded from:', ConfigLoader.findConfigFile(options.target) || 'none');
      console.log('Number of rules:', this.rules.length);
    }
    
    if (!fs.existsSync(targetPath)) {
      throw new Error(`Target path does not exist: ${targetPath}`);
    }

    const stats = fs.statSync(targetPath);
    
    if (mergedOptions.verbose) {
      console.log('Target type:', stats.isFile() ? 'file' : 'directory');
    }
    
    if (stats.isFile()) {
      if (mergedOptions.verbose) {
        console.log('Scanning single file...');
      }
      const result = await this.scanner.scanFile(targetPath, this.rules);
      if (mergedOptions.verbose) {
        console.log('Scan completed:', {
          filesScanned: result.filesScanned,
          issuesFound: result.issuesFound,
          summary: result.summary
        });
      }
      return result;
    } else if (stats.isDirectory()) {
      if (mergedOptions.verbose) {
        console.log('Scanning directory...');
      }
      return await this.scanner.scanDirectory(targetPath, this.rules);
    } else {
      throw new Error(`Target path is neither a file nor a directory: ${targetPath}`);
    }
  }

  formatResults(result: ScanResult, format: 'table' | 'json' | 'sarif' | 'html' = 'table'): string {
    switch (format) {
      case 'json':
        return this.reporter.formatJson(result);
      case 'sarif':
        return this.reporter.formatSarif(result);
      case 'html':
        return this.reporter.formatHtml(result);
      case 'table':
      default:
        return this.reporter.formatTable(result);
    }
  }

  async scanAndFormat(options: ScanOptions): Promise<string> {
    const result = await this.scan(options);
    return this.formatResults(result, options.format);
  }

  getRules(): BaseRule[] {
    return [...this.rules];
  }

  getRuleByName(name: string): BaseRule | undefined {
    return this.rules.find(rule => rule.name === name);
  }

  getVersion(): string {
    return VERSION;
  }

  /**
   * Generate a sample configuration file
   */
  generateConfig(): string {
    return ConfigLoader.generateSampleConfig();
  }

  /**
   * Create a default configuration file in the current directory
   */
  createConfigFile(): void {
    const configPath = path.join(process.cwd(), 'vibe-guard.json');
    if (fs.existsSync(configPath)) {
      console.log('Configuration file already exists: vibe-guard.json');
      return;
    }

    const configContent = ConfigLoader.generateSampleConfig();
    fs.writeFileSync(configPath, configContent);
    console.log('Created configuration file: vibe-guard.json');
  }
}

export * from './types';
export * from './rules';
export { FileScanner } from './scanner';
export { Reporter } from './reporter';

export default VibeGuard; 