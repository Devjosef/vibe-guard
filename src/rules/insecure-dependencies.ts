import { BaseRule, FileContent, SecurityIssue } from '../types';

interface DependencyContext {
  isInComment: boolean;
  isInString: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  isInDevDependencies: boolean;
  surroundingCode: string;
  language: string;
  packageManager: string | undefined;
  framework: string | undefined;
  hasVulnerableDependencies: boolean;
  dependencyType: string | undefined;
}

export class InsecureDependenciesRule extends BaseRule {
  readonly name = 'insecure-dependencies';
  readonly description = 'Detects potentially insecure dependencies and packages with context-aware analysis';
  readonly severity = 'medium' as const;

  private readonly vulnerablePackages = [
    { 
      name: 'lodash', 
      versions: ['<4.17.21'], 
      reason: 'Prototype pollution vulnerabilities',
      confidence: 0.95,
      validation: (version: string) => this.validateLodashVersion(version)
    },
    { 
      name: 'moment', 
      versions: ['*'], 
      reason: 'Deprecated package, use date-fns or dayjs instead',
      confidence: 0.9,
      validation: (version: string) => this.validateMomentUsage(version)
    },
    { 
      name: 'request', 
      versions: ['*'], 
      reason: 'Deprecated package with security issues',
      confidence: 0.95,
      validation: (version: string) => this.validateRequestUsage(version)
    },
    { 
      name: 'node-uuid', 
      versions: ['*'], 
      reason: 'Deprecated, use uuid package instead',
      confidence: 0.85,
      validation: (version: string) => this.validateNodeUuidUsage(version)
    },
    { 
      name: 'growl', 
      versions: ['<1.10.0'], 
      reason: 'Command injection vulnerability',
      confidence: 0.9,
      validation: (version: string) => this.validateGrowlVersion(version)
    },
    { 
      name: 'handlebars', 
      versions: ['<4.7.7'], 
      reason: 'Template injection vulnerabilities',
      confidence: 0.9,
      validation: (version: string) => this.validateHandlebarsVersion(version)
    },
    { 
      name: 'serialize-javascript', 
      versions: ['<3.1.0'], 
      reason: 'XSS vulnerability',
      confidence: 0.9,
      validation: (version: string) => this.validateSerializeJavascriptVersion(version)
    },
    { 
      name: 'minimist', 
      versions: ['<1.2.6'], 
      reason: 'Prototype pollution vulnerability',
      confidence: 0.9,
      validation: (version: string) => this.validateMinimistVersion(version)
    },
    { 
      name: 'yargs-parser', 
      versions: ['<13.1.2'], 
      reason: 'Prototype pollution vulnerability',
      confidence: 0.9,
      validation: (version: string) => this.validateYargsParserVersion(version)
    },
    { 
      name: 'ini', 
      versions: ['<1.3.6'], 
      reason: 'Prototype pollution vulnerability',
      confidence: 0.9,
      validation: (version: string) => this.validateIniVersion(version)
    },
    
    { 
      name: 'django', 
      versions: ['<3.2.13'], 
      reason: 'Multiple security vulnerabilities',
      confidence: 0.95,
      validation: (version: string) => this.validateDjangoVersion(version)
    },
    { 
      name: 'flask', 
      versions: ['<2.0.0'], 
      reason: 'Security improvements in newer versions',
      confidence: 0.8,
      validation: (version: string) => this.validateFlaskVersion(version)
    },
    { 
      name: 'requests', 
      versions: ['<2.20.0'], 
      reason: 'SSL verification issues',
      confidence: 0.85,
      validation: (version: string) => this.validateRequestsVersion(version)
    },
    { 
      name: 'pyyaml', 
      versions: ['<5.4'], 
      reason: 'Arbitrary code execution vulnerability',
      confidence: 0.95,
      validation: (version: string) => this.validatePyyamlVersion(version)
    },
    { 
      name: 'pillow', 
      versions: ['<8.3.2'], 
      reason: 'Multiple image processing vulnerabilities',
      confidence: 0.9,
      validation: (version: string) => this.validatePillowVersion(version)
    },
    
    { 
      name: 'symfony/symfony', 
      versions: ['<4.4.35'], 
      reason: 'Multiple security vulnerabilities',
      confidence: 0.95,
      validation: (version: string) => this.validateSymfonyVersion(version)
    },
    { 
      name: 'laravel/framework', 
      versions: ['<8.75.0'], 
      reason: 'Security vulnerabilities',
      confidence: 0.9,
      validation: (version: string) => this.validateLaravelVersion(version)
    },
    { 
      name: 'monolog/monolog', 
      versions: ['<2.3.5'], 
      reason: 'Remote code execution vulnerability',
      confidence: 0.95,
      validation: (version: string) => this.validateMonologVersion(version)
    }
  ];

  private readonly suspiciousPatterns = [
    { 
      pattern: /(?:^|\s)(?:eval|exec|shell|cmd|system|proc|spawn)(?:-|_)?(?:js|py|php|rb)?\s*[:=]/gi, 
      type: 'Suspicious package name',
      confidence: 0.8,
      validation: (text: string) => this.validateSuspiciousPackage(text)
    },
    { 
      pattern: /(?:^|\s)(?:backdoor|malware|virus|trojan|keylogger)\s*[:=]/gi, 
      type: 'Malicious package name',
      confidence: 0.95,
      validation: (text: string) => this.validateMaliciousPackage(text)
    },
    { 
      pattern: /(?:^|\s)(?:lodahs|momnet|expres|reactt|angualr|vuejs)\s*[:=]/gi, 
      type: 'Potential typosquatting',
      confidence: 0.7,
      validation: (text: string) => this.validateTyposquatting(text)
    },
    { 
      pattern: /["'](?:\*|latest|>.*|>=.*\|\|.*|.*\.\*\.\*)["']/g, 
      type: 'Overly permissive version range',
      confidence: 0.6,
      validation: (text: string) => this.validatePermissiveVersion(text)
    },
    { 
      pattern: /"devDependencies"\s*:\s*\{[^}]*"(?:nodemon|webpack-dev-server|jest|mocha|chai|sinon)"/gi, 
      type: 'Development dependency in production',
      confidence: 0.5,
      validation: (text: string) => this.validateDevDependency(text)
    }
  ];

  private readonly safePatterns = [
    /example/i,
    /demo/i,
    /test/i,
    /sample/i,
    /placeholder/i,
    /development/i,
    /dev/i,
    /staging/i,
    /localhost/i,
    /127\.0\.0\.1/i,
    /console\.log/i,
    /console\.warn/i,
    /console\.error/i,
    /logger\.(?:log|warn|error|info)/i,
    /print/i,
    /echo/i,
    /printf/i,
    /System\.out\.println/i,
    /puts/i,
    /Console\.WriteLine/i,
    /comment/i,
    /note/i,
    /todo/i,
    /fixme/i,
    /secure/i,
    /safe/i,
    /protected/i,
    /defense/i,
    /guard/i,
    /prevent/i,
    /block/i,
    /restrict/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const packageManager = this.detectPackageManager(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    
    // Skip if not a dependency file
    if (!this.isDependencyFile(fileContent.path)) {
      return issues;
    }
    
    // Check for vulnerable packages
    this.checkVulnerablePackages(fileContent, issues, language, packageManager, framework);
    
    // Check for suspicious patterns
    this.checkSuspiciousPatterns(fileContent, issues, language, packageManager, framework);

    return issues;
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, packageManager?: string, framework?: string, hasVulnerableDependencies?: boolean, dependencyType?: string): DependencyContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language),
      isInString: this.isInString(currentLine, column),
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(surroundingLines),
      isInDevDependencies: this.isInDevDependencies(fileContent.content, line),
      surroundingCode: surroundingLines.join('\n'),
      language,
      packageManager,
      framework,
      hasVulnerableDependencies: hasVulnerableDependencies || false,
      dependencyType
    };
  }

  private isInComment(line: string, language: string): boolean {
    const trimmed = line.trim();
    if (language === 'javascript' || language === 'typescript') {
      return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
    }
    if (language === 'python') {
      return trimmed.startsWith('#');
    }
    if (language === 'php') {
      return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('#');
    }
    if (language === 'yaml' || language === 'yml') {
      return trimmed.startsWith('#');
    }
    if (language === 'toml') {
      return trimmed.startsWith('#');
    }
    return false;
  }

  private isInString(line: string, column: number): boolean {
    const before = line.substring(0, column);
    const quotes = (before.match(/['"`]/g) || []).length;
    return quotes % 2 === 1;
  }

  private isInTestFile(filePath: string): boolean {
    return filePath.includes('test') || filePath.includes('spec') || filePath.includes('mock');
  }

  private isInDocumentation(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('@example') || 
      line.includes('@doc') || 
      line.includes('@description') ||
      line.includes('README') ||
      line.includes('documentation')
    );
  }

  private detectLanguage(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase();
    const languageMap: Record<string, string> = {
      'js': 'javascript',
      'jsx': 'javascript',
      'ts': 'typescript',
      'tsx': 'typescript',
      'py': 'python',
      'php': 'php',
      'rb': 'ruby',
      'go': 'go',
      'java': 'java',
      'cs': 'csharp',
      'cpp': 'cpp',
      'c': 'c',
      'rs': 'rust',
      'kt': 'kotlin',
      'swift': 'swift',
      'dart': 'dart',
      'scala': 'scala',
      'clj': 'clojure',
      'hs': 'haskell',
      'yaml': 'yaml',
      'yml': 'yaml',
      'json': 'json',
      'toml': 'toml',
      'xml': 'xml',
      'gradle': 'gradle',
      'exs': 'elixir'
    };
    return languageMap[ext || ''] || 'unknown';
  }

  private detectPackageManager(filePath: string): string | undefined {
    if (filePath.includes('package.json')) return 'npm';
    if (filePath.includes('yarn.lock')) return 'yarn';
    if (filePath.includes('pnpm-lock.yaml')) return 'pnpm';
    if (filePath.includes('requirements.txt')) return 'pip';
    if (filePath.includes('Pipfile')) return 'pipenv';
    if (filePath.includes('poetry.lock')) return 'poetry';
    if (filePath.includes('composer.json')) return 'composer';
    if (filePath.includes('Gemfile')) return 'bundler';
    if (filePath.includes('Cargo.toml')) return 'cargo';
    if (filePath.includes('go.mod')) return 'go';
    if (filePath.includes('pom.xml')) return 'maven';
    if (filePath.includes('build.gradle')) return 'gradle';
    if (filePath.includes('build.sbt')) return 'sbt';
    if (filePath.includes('mix.exs')) return 'mix';
    if (filePath.includes('pubspec.yaml')) return 'pub';
    if (filePath.includes('Podfile')) return 'cocoapods';
    if (filePath.includes('Cartfile')) return 'carthage';
    return undefined;
  }

  private detectFramework(content: string, language: string): string | undefined {
    if (language === 'javascript' || language === 'typescript') {
      if (content.includes('express') || content.includes('app.get') || content.includes('app.post')) return 'express';
      if (content.includes('react') || content.includes('jsx') || content.includes('tsx')) return 'react';
      if (content.includes('vue') || content.includes('Vue.createApp')) return 'vue';
      if (content.includes('angular') || content.includes('@Component')) return 'angular';
      if (content.includes('next') || content.includes('Next.js')) return 'nextjs';
    }
    if (language === 'python') {
      if (content.includes('flask') || content.includes('Flask')) return 'flask';
      if (content.includes('django') || content.includes('Django')) return 'django';
      if (content.includes('fastapi') || content.includes('FastAPI')) return 'fastapi';
    }
    if (language === 'php') {
      if (content.includes('laravel') || content.includes('Laravel')) return 'laravel';
      if (content.includes('symfony') || content.includes('Symfony')) return 'symfony';
    }
    return undefined;
  }

  private detectDependencyType(filePath: string): string | undefined {
    if (filePath.includes('package.json')) return 'node';
    if (filePath.includes('requirements.txt')) return 'python';
    if (filePath.includes('composer.json')) return 'php';
    if (filePath.includes('Gemfile')) return 'ruby';
    if (filePath.includes('Cargo.toml')) return 'rust';
    if (filePath.includes('go.mod')) return 'go';
    if (filePath.includes('pom.xml')) return 'java';
    if (filePath.includes('build.gradle')) return 'java';
    if (filePath.includes('mix.exs')) return 'elixir';
    if (filePath.includes('pubspec.yaml')) return 'dart';
    return undefined;
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



  private checkVulnerablePackages(fileContent: FileContent, issues: SecurityIssue[], language: string, packageManager?: string, framework?: string): void {
    for (const pkg of this.vulnerablePackages) {
      const packagePattern = new RegExp(`"${pkg.name}"\\s*:\\s*["']([^"']+)["']`, 'gi');
      const matches = this.findMatches(fileContent.content, packagePattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const version = match[1];
        
        if (version && this.isVulnerableVersion(version, pkg.versions) && pkg.validation(version)) {
          const context = this.analyzeContext(fileContent, line, column, language, packageManager, framework, true, this.detectDependencyType(fileContent.path));
          const finalConfidence = this.calculateConfidence(pkg.confidence, context);
          
          if (finalConfidence >= 0.5) {
            issues.push(this.createIssue(
              fileContent.path,
              line,
              column,
              lineContent,
              `Vulnerable dependency: ${pkg.name} ${version} - ${pkg.reason} (confidence: ${Math.round(finalConfidence * 100)}%)`,
              this.generateSuggestion(pkg, context),
              finalConfidence >= 0.8 ? 'high' : finalConfidence >= 0.6 ? 'medium' : 'low'
            ));
          }
        }
      }
    }
  }

  private checkSuspiciousPatterns(fileContent: FileContent, issues: SecurityIssue[], language: string, packageManager?: string, framework?: string): void {
    for (const { pattern, type, confidence, validation } of this.suspiciousPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, packageManager, framework, false, this.detectDependencyType(fileContent.path));
        
        // Skip if in safe context
        if (this.isSafeContext(context)) {
          continue;
        }
        
        // Validate the suspicious pattern
        if (!validation(matchedText)) {
          continue;
        }
        
        // Calculate final confidence based on context
        const finalConfidence = this.calculateConfidence(confidence, context);
        
        if (finalConfidence >= 0.5) {
          issues.push(this.createIssue(
            fileContent.path,
            line,
            column,
            lineContent,
            `Suspicious dependency pattern: ${type} (confidence: ${Math.round(finalConfidence * 100)}%)`,
            this.generateSuspiciousSuggestion(type, context),
            finalConfidence >= 0.8 ? 'high' : finalConfidence >= 0.6 ? 'medium' : 'low'
          ));
        }
      }
    }
  }

  private isSafeContext(context: DependencyContext): boolean {
    // Safe if in comment
    if (context.isInComment) return true;
    
    // Safe if in test file
    if (context.isInTestFile) return true;
    
    // Safe if in documentation
    if (context.isInDocumentation) return true;
    
    // Safe if using security-related keywords
    if (this.safePatterns.some(pattern => pattern.test(context.surroundingCode))) {
      return true;
    }
    
    return false;
  }

  private calculateConfidence(baseConfidence: number, context: DependencyContext): number {
    let confidence = baseConfidence;
    
    // Adjust confidence based on context
    if (context.isInDevDependencies) confidence *= 0.7; // Reduce for dev dependencies
    if (context.packageManager) confidence *= 1.1; // Increase for known package managers
    if (context.framework) confidence *= 1.1; // Increase for known frameworks
    
    return Math.min(confidence, 1.0);
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

  // Validation methods for vulnerable packages
  private validateLodashVersion(version: string): boolean {
    return this.compareVersions(version, '4.17.21') < 0;
  }

  private validateMomentUsage(_version: string): boolean {
    return true; // All versions are deprecated
  }

  private validateRequestUsage(_version: string): boolean {
    return true; // All versions are deprecated
  }

  private validateNodeUuidUsage(_version: string): boolean {
    return true; // All versions are deprecated
  }

  private validateGrowlVersion(version: string): boolean {
    return this.compareVersions(version, '1.10.0') < 0;
  }

  private validateHandlebarsVersion(version: string): boolean {
    return this.compareVersions(version, '4.7.7') < 0;
  }

  private validateSerializeJavascriptVersion(version: string): boolean {
    return this.compareVersions(version, '3.1.0') < 0;
  }

  private validateMinimistVersion(version: string): boolean {
    return this.compareVersions(version, '1.2.6') < 0;
  }

  private validateYargsParserVersion(version: string): boolean {
    return this.compareVersions(version, '13.1.2') < 0;
  }

  private validateIniVersion(version: string): boolean {
    return this.compareVersions(version, '1.3.6') < 0;
  }

  private validateDjangoVersion(version: string): boolean {
    return this.compareVersions(version, '3.2.13') < 0;
  }

  private validateFlaskVersion(version: string): boolean {
    return this.compareVersions(version, '2.0.0') < 0;
  }

  private validateRequestsVersion(version: string): boolean {
    return this.compareVersions(version, '2.20.0') < 0;
  }

  private validatePyyamlVersion(version: string): boolean {
    return this.compareVersions(version, '5.4') < 0;
  }

  private validatePillowVersion(version: string): boolean {
    return this.compareVersions(version, '8.3.2') < 0;
  }

  private validateSymfonyVersion(version: string): boolean {
    return this.compareVersions(version, '4.4.35') < 0;
  }

  private validateLaravelVersion(version: string): boolean {
    return this.compareVersions(version, '8.75.0') < 0;
  }

  private validateMonologVersion(version: string): boolean {
    return this.compareVersions(version, '2.3.5') < 0;
  }

  // Validation methods for suspicious patterns
  private validateSuspiciousPackage(text: string): boolean {
    const suspiciousKeywords = ['eval', 'exec', 'shell', 'cmd', 'system', 'proc', 'spawn'];
    return suspiciousKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateMaliciousPackage(text: string): boolean {
    const maliciousKeywords = ['backdoor', 'malware', 'virus', 'trojan', 'keylogger'];
    return maliciousKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateTyposquatting(text: string): boolean {
    const typosquattingPatterns = ['lodahs', 'momnet', 'expres', 'reactt', 'angualr', 'vuejs'];
    return typosquattingPatterns.some(pattern => text.toLowerCase().includes(pattern));
  }

  private validatePermissiveVersion(text: string): boolean {
    return /\*|latest|>.*|>=.*\|\|.*|.*\.\*\.\*/.test(text);
  }

  private validateDevDependency(text: string): boolean {
    const devDeps = ['nodemon', 'webpack-dev-server', 'jest', 'mocha', 'chai', 'sinon'];
    return devDeps.some(dep => text.toLowerCase().includes(dep));
  }

  private generateSuggestion(pkg: { name: string; reason: string }, context: DependencyContext): string {
    let suggestion = `Update ${pkg.name} to a secure version. ${pkg.reason}.`;
    
    if (context.packageManager) {
      suggestion += ` Run '${this.getUpdateCommand(context.packageManager)}' to update dependencies.`;
    }
    
    if (context.framework) {
      suggestion += ` For ${context.framework}, consider using framework-specific security tools and dependency management.`;
    }
    
    return suggestion;
  }

  private generateSuspiciousSuggestion(type: string, context: DependencyContext): string {
    const suggestions = {
      'Suspicious package name': 'Review this dependency for security concerns and consider using a trusted alternative.',
      'Malicious package name': 'This package name suggests malicious intent. Remove immediately and scan for other suspicious dependencies.',
      'Potential typosquatting': 'This appears to be a typosquatting attempt. Use the correct package name.',
      'Overly permissive version range': 'Use specific version ranges to prevent automatic updates to potentially vulnerable versions.',
      'Development dependency in production': 'Move development dependencies to devDependencies section.'
    };
    
    let suggestion = suggestions[type as keyof typeof suggestions] || 'Review this dependency for security concerns.';
    
    if (context.packageManager) {
      suggestion += ` Use '${this.getAuditCommand(context.packageManager)}' to check for known vulnerabilities.`;
    }
    
    return suggestion;
  }

  private getUpdateCommand(packageManager: string): string {
    const commands = {
      'npm': 'npm audit fix',
      'yarn': 'yarn audit',
      'pnpm': 'pnpm audit',
      'pip': 'pip audit',
      'composer': 'composer audit',
      'bundler': 'bundle audit',
      'cargo': 'cargo audit',
      'go': 'go list -m all | grep -E "(vulnerable|deprecated)"',
      'maven': 'mvn dependency:check',
      'gradle': 'gradle dependencyCheckAnalyze'
    };
    return commands[packageManager as keyof typeof commands] || 'dependency audit';
  }

  private getAuditCommand(packageManager: string): string {
    const commands = {
      'npm': 'npm audit',
      'yarn': 'yarn audit',
      'pnpm': 'pnpm audit',
      'pip': 'pip audit',
      'composer': 'composer audit',
      'bundler': 'bundle audit',
      'cargo': 'cargo audit',
      'go': 'go list -m all',
      'maven': 'mvn dependency:check',
      'gradle': 'gradle dependencyCheckAnalyze'
    };
    return commands[packageManager as keyof typeof commands] || 'dependency audit';
  }
} 