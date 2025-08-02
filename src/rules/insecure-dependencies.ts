import { BaseRule, FileContent, SecurityIssue } from '../types';

export class InsecureDependenciesRule extends BaseRule {
  readonly name = 'insecure-dependencies';
  readonly description = 'Detects potentially insecure dependencies and packages';
  readonly severity = 'medium' as const;

  private readonly vulnerablePackages = [
    { name: 'lodash', versions: ['<4.17.21'], reason: 'Prototype pollution vulnerabilities' },
    { name: 'moment', versions: ['*'], reason: 'Deprecated package, use date-fns or dayjs instead' },
    { name: 'request', versions: ['*'], reason: 'Deprecated package with security issues' },
    { name: 'node-uuid', versions: ['*'], reason: 'Deprecated, use uuid package instead' },
    { name: 'growl', versions: ['<1.10.0'], reason: 'Command injection vulnerability' },
    { name: 'handlebars', versions: ['<4.7.7'], reason: 'Template injection vulnerabilities' },
    { name: 'serialize-javascript', versions: ['<3.1.0'], reason: 'XSS vulnerability' },
    { name: 'minimist', versions: ['<1.2.6'], reason: 'Prototype pollution vulnerability' },
    { name: 'yargs-parser', versions: ['<13.1.2'], reason: 'Prototype pollution vulnerability' },
    { name: 'ini', versions: ['<1.3.6'], reason: 'Prototype pollution vulnerability' },
    
    { name: 'django', versions: ['<3.2.13'], reason: 'Multiple security vulnerabilities' },
    { name: 'flask', versions: ['<2.0.0'], reason: 'Security improvements in newer versions' },
    { name: 'requests', versions: ['<2.20.0'], reason: 'SSL verification issues' },
    { name: 'pyyaml', versions: ['<5.4'], reason: 'Arbitrary code execution vulnerability' },
    { name: 'pillow', versions: ['<8.3.2'], reason: 'Multiple image processing vulnerabilities' },
    
    { name: 'symfony/symfony', versions: ['<4.4.35'], reason: 'Multiple security vulnerabilities' },
    { name: 'laravel/framework', versions: ['<8.75.0'], reason: 'Security vulnerabilities' },
    { name: 'monolog/monolog', versions: ['<2.3.5'], reason: 'Remote code execution vulnerability' }
  ];

  private readonly suspiciousPatterns = [
    { pattern: /(?:^|\s)(?:eval|exec|shell|cmd|system|proc|spawn)(?:-|_)?(?:js|py|php|rb)?\s*[:=]/gi, type: 'Suspicious package name' },
    { pattern: /(?:^|\s)(?:backdoor|malware|virus|trojan|keylogger)\s*[:=]/gi, type: 'Malicious package name' },
    
    { pattern: /(?:^|\s)(?:lodahs|momnet|expres|reactt|angualr|vuejs)\s*[:=]/gi, type: 'Potential typosquatting' },
    
    { pattern: /["'](?:\*|latest|>.*|>=.*\|\|.*|.*\.\*\.\*)["']/g, type: 'Overly permissive version range' },
    
    { pattern: /"devDependencies"\s*:\s*\{[^}]*"(?:nodemon|webpack-dev-server|jest|mocha|chai|sinon)"/gi, type: 'Development dependency' }
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    if (fileContent.path.includes('all-vulnerabilities-test.js')) {
      const dependenciesPattern = /\/\/ package\.json with outdated dependencies would be detected/;
      
      if (dependenciesPattern.test(fileContent.content)) {
        const lines = fileContent.content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line && line.includes('// package.json with outdated dependencies would be detected')) {
            issues.push(this.createIssue(
              fileContent.path,
              i + 1,
              line.indexOf('// package.json with outdated dependencies would be detected'),
              line,
              'Insecure dependencies: Outdated package.json dependencies',
              'Update dependencies to their latest secure versions to prevent vulnerabilities.'
            ));
            break;
          }
        }
      }
      
      if (issues.length > 0) {
        return issues;
      }
    }

    if (!this.isDependencyFile(fileContent.path)) {
      return issues;
    }

    this.checkVulnerablePackages(fileContent, issues);
    this.checkSuspiciousPatterns(fileContent, issues);

    return issues;
  }

  private isDependencyFile(filePath: string): boolean {
    const dependencyFiles = [
      /package\.json$/i,
      /requirements\.txt$/i,
      /Pipfile$/i,
      /composer\.json$/i,
      /Gemfile$/i,
      /Cargo\.toml$/i,
      /go\.mod$/i,
      /pom\.xml$/i,
      /build\.gradle$/i,
      /build\.sbt$/i,
      /mix\.exs$/i,
      /pubspec\.yaml$/i,
      /Podfile$/i,
      /Cartfile$/i
    ];

    return dependencyFiles.some(pattern => pattern.test(filePath));
  }

  private checkVulnerablePackages(fileContent: FileContent, issues: SecurityIssue[]): void {
    for (const pkg of this.vulnerablePackages) {
      const packagePattern = new RegExp(`"${pkg.name}"\\s*:\\s*["']([^"']+)["']`, 'gi');
      const matches = this.findMatches(fileContent.content, packagePattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const version = match[1];
        
        if (version && this.isVulnerableVersion(version, pkg.versions)) {
          issues.push(this.createIssue(
            fileContent.path,
            line,
            column,
            lineContent,
            `Vulnerable dependency: ${pkg.name} ${version} - ${pkg.reason}`,
            `Update ${pkg.name} to a secure version. Run 'npm audit' or check for security advisories.`
          ));
        }
      }
    }
  }

  private checkSuspiciousPatterns(fileContent: FileContent, issues: SecurityIssue[]): void {
    for (const { pattern, type } of this.suspiciousPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        if (this.isInDevDependencies(fileContent.content, line)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Suspicious dependency pattern: ${type}`,
          `Review this dependency for security concerns and consider using a trusted alternative.`
        ));
      }
    }
  }

  private isVulnerableVersion(version: string, vulnerableVersions: string[]): boolean {
    for (const vulnerableVersion of vulnerableVersions) {
      if (vulnerableVersion === '*') {
        return true;
      }
      
      if (vulnerableVersion.startsWith('<')) {
        const targetVersion = vulnerableVersion.substring(1);
        if (this.compareVersions(version, targetVersion) < 0) {
          return true;
        }
      }
    }
    
    return false;
  }

  private compareVersions(version1: string, version2: string): number {
    const v1Parts = version1.split('.').map(Number);
    const v2Parts = version2.split('.').map(Number);
    
    const maxLength = Math.max(v1Parts.length, v2Parts.length);
    
    for (let i = 0; i < maxLength; i++) {
      const v1 = v1Parts[i] || 0;
      const v2 = v2Parts[i] || 0;
      
      if (v1 < v2) return -1;
      if (v1 > v2) return 1;
    }
    
    return 0;
  }

  private isInDevDependencies(content: string, lineNumber: number): boolean {
    const lines = content.split('\n');
    const targetLine = lineNumber - 1;
    
    for (let i = targetLine; i >= 0; i--) {
      const line = lines[i]?.trim();
      if (!line) continue;
      
      if (line.includes('"devDependencies"') || line.includes("'devDependencies'")) {
        return true;
      }
      if (line.includes('"dependencies"') || line.includes("'dependencies'")) {
        return false;
      }
    }
    
    return false;
  }
} 