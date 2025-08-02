import * as fs from 'fs';
import * as path from 'path';
import { FileScanner } from './scanner';
import { Reporter } from './reporter';
import { ScanOptions, ScanResult, BaseRule } from './types';
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
    const targetPath = path.resolve(options.target);
    
    console.log('DEBUG: VibeGuard.scan called with target:', targetPath);
    console.log('DEBUG: Number of rules:', this.rules.length);
    
    if (!fs.existsSync(targetPath)) {
      throw new Error(`Target path does not exist: ${targetPath}`);
    }

    const stats = fs.statSync(targetPath);
    console.log('DEBUG: Target is file:', stats.isFile());
    console.log('DEBUG: Target is directory:', stats.isDirectory());
    
    if (stats.isFile()) {
      console.log('DEBUG: Calling scanner.scanFile...');
      const result = await this.scanner.scanFile(targetPath, this.rules);
      console.log('DEBUG: scanFile result:', {
        filesScanned: result.filesScanned,
        issuesFound: result.issuesFound,
        summary: result.summary
      });
      return result;
    } else if (stats.isDirectory()) {
      console.log('DEBUG: Calling scanner.scanDirectory...');
      return await this.scanner.scanDirectory(targetPath, this.rules);
    } else {
      throw new Error(`Target path is neither a file nor a directory: ${targetPath}`);
    }
  }

  formatResults(result: ScanResult, format: 'table' | 'json' = 'table'): string {
    switch (format) {
      case 'json':
        return this.reporter.formatJson(result);
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
}

export * from './types';
export * from './rules';
export { FileScanner } from './scanner';
export { Reporter } from './reporter';

export default VibeGuard; 