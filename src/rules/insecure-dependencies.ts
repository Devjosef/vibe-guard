import { BaseRule, FileContent, SecurityIssue } from '../types';

export class InsecureDependenciesRule extends BaseRule {
  readonly name = 'insecure-dependencies';
  readonly description = 'Detects potentially insecure dependencies and packages';
  readonly severity = 'medium' as const;

  private readonly vulnerablePackages = [
    // Known vulnerable packages
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
    
    // Python packages
    { name: 'django', versions: ['<3.2.13'], reason: 'Multiple security vulnerabilities' },
    { name: 'flask', versions: ['<2.0.0'], reason: 'Security improvements in newer versions' },
    { name: 'requests', versions: ['<2.20.0'], reason: 'SSL verification issues' },
    { name: 'pyyaml', versions: ['<5.4'], reason: 'Arbitrary code execution vulnerability' },
    { name: 'pillow', versions: ['<8.3.2'], reason: 'Multiple image processing vulnerabilities' },
    
    // PHP packages
    { name: 'symfony/symfony', versions: ['<4.4.35'], reason: 'Multiple security vulnerabilities' },
    { name: 'laravel/framework', versions: ['<8.75.0'], reason: 'Security vulnerabilities' },
    { name: 'monolog/monolog', versions: ['<2.3.5'], reason: 'Remote code execution vulnerability' }
  ];

  private readonly suspiciousPatterns = [
    // Suspicious package names
    { pattern: /(?:^|\s)(?:eval|exec|shell|cmd|system|proc|spawn)(?:-|_)?(?:js|py|php|rb)?\s*[:=]/gi, type: 'Suspicious package name' },
    { pattern: /(?:^|\s)(?:backdoor|malware|virus|trojan|keylogger)\s*[:=]/gi, type: 'Malicious package name' },
    
    // Typosquatting patterns (common misspellings)
    { pattern: /(?:^|\s)(?:lodahs|momnet|expres|reactt|angualr|vuejs)\s*[:=]/gi, type: 'Potential typosquatting' },
    
    // Suspicious version patterns
    { pattern: /["'](?:\*|latest|>.*|>=.*\|\|.*|.*\.\*\.\*)["']/g, type: 'Overly permissive version range' },
    
    // Development dependencies in production
    { pattern: /"devDependencies"\s*:\s*\{[^}]*"(?:nodemon|webpack-dev-server|jest|mocha|chai|sinon)"/gi, type: 'Development dependency' }
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Only check dependency files
    if (!this.isDependencyFile(fileContent.path)) {
      return issues;
    }

    // Check for vulnerable packages
    this.checkVulnerablePackages(fileContent, issues);
    
    // Check for suspicious patterns
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
      /pom\.xml$/i,
      /build\.gradle$/i,
      /yarn\.lock$/i,
      /package-lock\.json$/i
    ];

    return dependencyFiles.some(pattern => pattern.test(filePath));
  }

  private checkVulnerablePackages(fileContent: FileContent, issues: SecurityIssue[]): void {
    for (const pkg of this.vulnerablePackages) {
      const pattern = new RegExp(`["']${pkg.name}["']\\s*:\\s*["']([^"']+)["']`, 'gi');
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const version = match[1];
        
        if (version && this.isVulnerableVersion(version, pkg.versions)) {
          issues.push(this.createIssue(
            fileContent.path,
            line,
            column,
            lineContent,
            `Vulnerable dependency: ${pkg.name}@${version}`,
            `${pkg.reason}. Update to a secure version or find an alternative package.`
          ));
        }
      }
    }
  }

  private checkSuspiciousPatterns(fileContent: FileContent, issues: SecurityIssue[]): void {
    for (const { pattern, type } of this.suspiciousPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        // Skip development dependencies check if it's actually in devDependencies section
        if (type === 'Development dependency' && this.isInDevDependencies(fileContent.content, line)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Suspicious dependency pattern: ${type}`,
          `Review this dependency carefully. Ensure it's from a trusted source and serves a legitimate purpose.`
        ));
      }
    }
  }

  private isVulnerableVersion(version: string, vulnerableVersions: string[]): boolean {
    // Simple version checking - in a real implementation, you'd use semver
    for (const vulnVersion of vulnerableVersions) {
      if (vulnVersion === '*') {
        return true;
      }
      
      if (vulnVersion.startsWith('<')) {
        // This is a simplified check - real implementation would use proper semver comparison
        const targetVersion = vulnVersion.substring(1);
        if (this.compareVersions(version, targetVersion) < 0) {
          return true;
        }
      }
      
      if (version === vulnVersion) {
        return true;
      }
    }
    
    return false;
  }

  private compareVersions(version1: string, version2: string): number {
    // Simplified version comparison - real implementation would handle all semver cases
    const v1Parts = version1.replace(/[^\d.]/g, '').split('.').map(Number);
    const v2Parts = version2.replace(/[^\d.]/g, '').split('.').map(Number);
    
    for (let i = 0; i < Math.max(v1Parts.length, v2Parts.length); i++) {
      const v1Part = v1Parts[i] || 0;
      const v2Part = v2Parts[i] || 0;
      
      if (v1Part < v2Part) return -1;
      if (v1Part > v2Part) return 1;
    }
    
    return 0;
  }

  private isInDevDependencies(content: string, lineNumber: number): boolean {
    const lines = content.split('\n');
    
    // Look backwards from the current line to find the section
    for (let i = lineNumber - 1; i >= 0; i--) {
      const line = lines[i];
      if (!line) continue;
      
      const trimmedLine = line.trim();
      
      if (trimmedLine.includes('"devDependencies"')) {
        return true;
      }
      
      if (trimmedLine.includes('"dependencies"') && !trimmedLine.includes('"devDependencies"')) {
        return false;
      }
      
      // If we hit another top-level section, stop looking
      if (trimmedLine.match(/^"[^"]+"\s*:\s*\{/) && !trimmedLine.includes('Dependencies')) {
        break;
      }
    }
    
    return false;
  }
} 