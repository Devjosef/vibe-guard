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
      new MissingSecurityHeadersRule()
    ];
    this.scanner = new FileScanner();
    this.reporter = new Reporter();
  }

  async scan(options: ScanOptions): Promise<ScanResult> {
    const targetPath = path.resolve(options.target);
    
    // Verify target exists
    if (!fs.existsSync(targetPath)) {
      throw new Error(`Target path does not exist: ${targetPath}`);
    }

    const stats = fs.statSync(targetPath);
    
    if (stats.isFile()) {
      return await this.scanner.scanFile(targetPath, this.rules);
    } else if (stats.isDirectory()) {
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
    try {
      const packagePath = path.join(__dirname, '..', 'package.json');
      const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf-8'));
      return packageJson.version || '1.0.0';
    } catch {
      return '1.0.0';
    }
  }
}

// Export everything for external use
export * from './types';
export * from './rules';
export { FileScanner } from './scanner';
export { Reporter } from './reporter';

// Default export
export default VibeGuard; 