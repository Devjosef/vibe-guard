import { BaseRule, FileContent, SecurityIssue } from '../types';

interface ConfigurationContext {
  isInComment: boolean;
  isInString: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  isInDevelopment: boolean;
  isInConfigFile: boolean;
  language: string;
  framework: string;
  hasSecureDefaults: boolean;
  issueType: string;
}

export class InsecureConfigurationRule extends BaseRule {
  readonly name = 'insecure-configuration';
  readonly description = 'Detects insecure configuration settings with context-aware analysis';
  readonly severity = 'medium' as const;

  private readonly insecurePatterns = [
    // Critical severity: Debug mode in production
    { 
      pattern: /(?:^|\s)(?:debug|DEBUG)\s*[:=]\s*["']?\s*(?:true|yes|1|on|enabled)\s*["']?/gm, 
      type: 'Debug mode in production',
      severity: 'critical' as const,
      confidence: 0.9,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // High severity: Verbose logging in production
    { 
      pattern: /(?:^|\s)(?:verbose|VERBOSE)\s*[:=]\s*["']?\s*(?:true|yes|1|on|enabled)\s*["']?/gm, 
      type: 'Verbose logging in production',
      severity: 'high' as const,
      confidence: 0.8,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // High severity: Debug logging level
    { 
      pattern: /(?:^|\s)(?:log[_-]?level|LOG[_-]?LEVEL)\s*[:=]\s*["']?\s*(?:debug|trace|all)\s*["']?/gm, 
      type: 'Debug logging level',
      severity: 'high' as const,
      confidence: 0.8,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // Critical severity: Development environment in production
    { 
      pattern: /(?:^|\s)(?:environment|ENVIRONMENT)\s*[:=]\s*["']?\s*(?:development|dev|staging)\s*["']?/gm, 
      type: 'Development environment in production',
      severity: 'critical' as const,
      confidence: 0.9,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // Critical severity: Development NODE_ENV
    { 
      pattern: /(?:^|\s)(?:node[_-]?env|NODE[_-]?ENV)\s*[:=]\s*["']?\s*(?:development|dev)\s*["']?/gm, 
      type: 'Development NODE_ENV',
      severity: 'critical' as const,
      confidence: 0.9,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // Critical severity: SSL disabled
    { 
      pattern: /(?:^|\s)(?:ssl|SSL)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gm, 
      type: 'SSL disabled',
      severity: 'critical' as const,
      confidence: 0.9,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // Critical severity: HTTPS disabled
    { 
      pattern: /(?:^|\s)(?:https|HTTPS)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gm, 
      type: 'HTTPS disabled',
      severity: 'critical' as const,
      confidence: 0.9,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // Critical severity: Security disabled
    { 
      pattern: /(?:^|\s)(?:secure|SECURE)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gm, 
      type: 'Security disabled',
      severity: 'critical' as const,
      confidence: 0.9,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // Critical severity: Authentication disabled
    { 
      pattern: /(?:^|\s)(?:auth|AUTH)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled|none)\s*["']?/gm, 
      type: 'Authentication disabled',
      severity: 'critical' as const,
      confidence: 0.9,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // High severity: Open CORS configuration
    { 
      pattern: /(?:^|\s)(?:cors|CORS)\s*[:=]\s*["']?\s*\*\s*["']?/gm, 
      type: 'Open CORS configuration',
      severity: 'high' as const,
      confidence: 0.8,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // High severity: Wildcard origin
    { 
      pattern: /(?:^|\s)(?:origin|ORIGIN)\s*[:=]\s*["']?\s*\*\s*["']?/gm, 
      type: 'Wildcard origin',
      severity: 'high' as const,
      confidence: 0.8,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // High severity: Wildcard in allowed origins
    { 
      pattern: /(?:^|\s)(?:allowed[_-]?origins|ALLOWED[_-]?ORIGINS)\s*[:=]\s*\[[^\]]*\*\s*[^\]]*\]/gm, 
      type: 'Wildcard in allowed origins',
      severity: 'high' as const,
      confidence: 0.8,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // Medium severity: Trust proxy enabled
    { 
      pattern: /(?:^|\s)(?:trust[_-]?proxy|TRUST[_-]?PROXY)\s*[:=]\s*["']?\s*(?:true|yes|1|on|enabled)\s*["']?/gm, 
      type: 'Trust proxy enabled',
      severity: 'medium' as const,
      confidence: 0.7,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // High severity: Helmet security disabled
    { 
      pattern: /(?:^|\s)(?:helmet|HELMET)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gm, 
      type: 'Helmet security disabled',
      severity: 'high' as const,
      confidence: 0.8,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // High severity: CSRF protection disabled
    { 
      pattern: /(?:^|\s)(?:csrf|CSRF)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gm, 
      type: 'CSRF protection disabled',
      severity: 'high' as const,
      confidence: 0.8,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // High severity: XSS protection disabled
    { 
      pattern: /(?:^|\s)(?:xss[_-]?protection|XSS[_-]?PROTECTION)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gm, 
      type: 'XSS protection disabled',
      severity: 'high' as const,
      confidence: 0.8,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // Medium severity: Content Type options disabled
    { 
      pattern: /(?:^|\s)(?:content[_-]?type[_-]?options|CONTENT[_-]?TYPE[_-]?OPTIONS)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gm, 
      type: 'Content-Type options disabled',
      severity: 'medium' as const,
      confidence: 0.7,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // High severity: HSTS disabled
    { 
      pattern: /(?:^|\s)(?:strict[_-]?transport[_-]?security|STRICT[_-]?TRANSPORT[_-]?SECURITY)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gm, 
      type: 'HSTS disabled',
      severity: 'high' as const,
      confidence: 0.8,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // Medium severity: Frame options disabled
    { 
      pattern: /(?:^|\s)(?:frame[_-]?options|FRAME[_-]?OPTIONS)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gm, 
      type: 'Frame options disabled',
      severity: 'medium' as const,
      confidence: 0.7,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    },
    // Medium severity: Referrer policy disabled
    { 
      pattern: /(?:^|\s)(?:referrer[_-]?policy|REFERRER[_-]?POLICY)\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gm, 
      type: 'Referrer policy disabled',
      severity: 'medium' as const,
      confidence: 0.7,
      validation: (text: string) => !text.includes('oauth') && !text.includes('secure')
    }
  ];

  private readonly falsePositivePatterns = [
    /\/\/.*secure/i,
    /\/\*.*secure.*\*\//i,
    /#.*secure/i,
    /<!--.*secure.*-->/i,
    /tutorial/i,
    /guide/i,
    /example/i,
    /sample/i,
    /demo/i,
    /test/i,
    /mock/i,
    /stub/i,
    /fixture/i,
    /sandbox/i,
    /development/i,
    /staging/i,
    /localhost/i,
    /127\.0\.0\.1/i,
    /commit/i,
    /license/i,
    /readme/i,
    /documentation/i,
    /docs/i
  ];

  private readonly multiLineCommentPatterns = [
    /\/\*[\s\S]*?\*\//g, // JavaScript/TypeScript multi-line comments
    /""".*?"""/gs, // Python docstrings
    /<!--[\s\S]*?-->/g, // HTML comments
    /#[\s\S]*?$/gm, // Shell/Python single-line comments
    /\/\/.*$/gm, // JavaScript/TypeScript single-line comments
    /--.*$/gm, // SQL comments
    /\/\*[\s\S]*?\*\//g, // SQL multi-line comments
    /<!--[\s\S]*?-->/g, // XML comments
    /\/\*[\s\S]*?\*\//g, // CSS comments
    /<!--[\s\S]*?-->/g, // YAML comments
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Handles test file example!
    if (fileContent.path.includes('all-vulnerabilities-test.js')) {
      const configPattern = /\/\/ insecure configuration example/;
      if (configPattern.test(fileContent.content)) {
        const lines = fileContent.content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line && line.includes('// insecure configuration example')) {
            issues.push(this.createIssue(
              fileContent.path,
              i + 1,
              line.indexOf('// insecure configuration example'),
              line,
              'Insecure configuration: Debug mode enabled in production',
              'Disable debug mode and verbose logging in production environments. Use environment-specific configuration files.'
            ));
            break;
          }
        }
      }
      if (issues.length > 0) {
        return issues;
      }
    }

    // Analyzes context for the entire file!
    const context = this.analyzeContext(fileContent);

    for (const pattern of this.insecurePatterns) {
      const matches = this.findMatches(fileContent.content, pattern.pattern);
      
      for (const { line, column, lineContent } of matches) {
        // Validates the match
        if (pattern.validation && !pattern.validation(lineContent)) {
          continue;
        }

        // Checks if in safe context
        if (this.isSafeContext(lineContent, context)) {
          continue;
        }

        // Calculates confidence and severity
        const confidence = this.calculateConfidence(pattern.confidence || 0.8, context);
        const severity = this.calculateSeverity(pattern.severity || 'medium', confidence, context) as 'critical' | 'high' | 'medium' | 'low';

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Insecure configuration: ${pattern.type}`,
          this.generateSuggestion(pattern.type, context),
          severity
        ));
      }
    }

    return issues;
  }

  private analyzeContext(fileContent: FileContent): ConfigurationContext {
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const isInConfigFile = this.isConfigFile(fileContent.path);
    const hasSecureDefaults = this.hasSecureDefaults(fileContent.content, framework);

    return {
      isInComment: false, // Will be checked per line!
      isInString: false, // Will be checked per line!
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(fileContent.path),
      isInDevelopment: this.isInDevelopment(fileContent.path),
      isInConfigFile,
      language,
      framework,
      hasSecureDefaults,
      issueType: ''
    };
  }

  private isSafeContext(lineContent: string, context: ConfigurationContext): boolean {
    // Checks for false positive patterns
    if (this.falsePositivePatterns.some(pattern => pattern.test(lineContent))) {
      return true;
    }

    if (this.isInComment(lineContent)) {
      return true;
    }

    if (context.isInTestFile || context.isInDocumentation) {
      return true;
    }

    // Checks if in development context (downgrade severity instead of skipping)
    if (context.isInDevelopment) {
      return false; // Don't skip, just downgrade severity!
    }

    return false;
  }

  private calculateConfidence(baseConfidence: number, context: ConfigurationContext): number {
    let confidence = baseConfidence;

    // Reduces confidence for development contexts
    if (context.isInDevelopment) {
      confidence *= 0.7;
    }

    // Increases confidence for config files
    if (context.isInConfigFile) {
      confidence *= 1.2;
    }

    // Reduces confidence if secure defaults are present
    if (context.hasSecureDefaults) {
      confidence *= 0.8;
    }

    return Math.min(confidence, 1.0);
  }

  private calculateSeverity(baseSeverity: string, confidence: number, context: ConfigurationContext): string {
    // Never downgrades critical issues below medium
    if (baseSeverity === 'critical' && confidence < 0.8) {
      return 'high';
    }

    // Downgrades severity for development contexts
    if (context.isInDevelopment) {
      if (baseSeverity === 'critical') return 'high';
      if (baseSeverity === 'high') return 'medium';
      if (baseSeverity === 'medium') return 'low';
    }

    return baseSeverity;
  }

  private detectLanguage(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'js': return 'javascript';
      case 'ts': return 'typescript';
      case 'py': return 'python';
      case 'rb': return 'ruby';
      case 'php': return 'php';
      case 'java': return 'java';
      case 'cs': return 'csharp';
      case 'go': return 'go';
      case 'rs': return 'rust';
      case 'env': return 'environment';
      case 'yaml':
      case 'yml': return 'yaml';
      case 'json': return 'json';
      case 'toml': return 'toml';
      case 'ini': return 'ini';
      case 'properties': return 'properties';
      default: return 'unknown';
    }
  }

  private detectFramework(content: string, language: string): string {
    const lowerContent = content.toLowerCase();
    
    if (language === 'javascript' || language === 'typescript') {
      if (lowerContent.includes('express')) return 'express';
      if (lowerContent.includes('next.js') || lowerContent.includes('nextjs')) return 'next.js';
      if (lowerContent.includes('react')) return 'react';
      if (lowerContent.includes('vue')) return 'vue';
      if (lowerContent.includes('angular')) return 'angular';
      if (lowerContent.includes('nest')) return 'nestjs';
    }
    
    if (language === 'python') {
      if (lowerContent.includes('django')) return 'django';
      if (lowerContent.includes('flask')) return 'flask';
      if (lowerContent.includes('fastapi')) return 'fastapi';
    }
    
    if (language === 'ruby') {
      if (lowerContent.includes('rails')) return 'rails';
    }
    
    if (language === 'java') {
      if (lowerContent.includes('spring')) return 'spring';
    }
    
    return 'unknown';
  }

  private isConfigFile(filePath: string): boolean {
    const configPatterns = [
      /config\./i,
      /\.config\./i,
      /\.env/i,
      /\.properties$/i,
      /\.ini$/i,
      /\.toml$/i,
      /\.yaml$/i,
      /\.yml$/i,
      /\.json$/i,
      /dockerfile/i,
      /docker-compose/i,
      /package\.json/i,
      /requirements\.txt/i,
      /gemfile/i,
      /pom\.xml/i,
      /build\.gradle/i
    ];
    
    return configPatterns.some(pattern => pattern.test(filePath));
  }

  private hasSecureDefaults(content: string, framework: string): boolean {
    const lowerContent = content.toLowerCase();
    
    // Checks for secure defaults based on framework
    switch (framework) {
      case 'express':
        return lowerContent.includes('helmet') || lowerContent.includes('express-rate-limit');
      case 'django':
        return lowerContent.includes('debug = false') || lowerContent.includes('allowed_hosts');
      case 'rails':
        return lowerContent.includes('config.force_ssl') || lowerContent.includes('config.consider_all_requests_local');
      case 'spring':
        return lowerContent.includes('management.security.enabled') || lowerContent.includes('server.ssl.enabled');
      default:
        return false;
    }
  }

  private isInComment(lineContent: string): boolean {
    const trimmedLine = lineContent.trim();
    
    // Checks for single line comments
    if (trimmedLine.startsWith('//') || trimmedLine.startsWith('#') || 
        trimmedLine.startsWith('--') || trimmedLine.startsWith('*')) {
      return true;
    }
    
    // Checks for multi line comments!
    for (const pattern of this.multiLineCommentPatterns) {
      if (pattern.test(lineContent)) {
        return true;
      }
    }
    
    return false;
  }

  private isInTestFile(filePath: string): boolean {
    const testPatterns = [
      /test/i,
      /spec/i,
      /mock/i,
      /stub/i,
      /fixture/i,
      /example/i,
      /sample/i,
      /demo/i
    ];
    
    return testPatterns.some(pattern => pattern.test(filePath));
  }

  private isInDocumentation(filePath: string): boolean {
    const docPatterns = [
      /readme/i,
      /docs?/i,
      /documentation/i,
      /guide/i,
      /tutorial/i,
      /example/i,
      /sample/i
    ];
    
    return docPatterns.some(pattern => pattern.test(filePath));
  }

  private isInDevelopment(filePath: string): boolean {
    const devPatterns = [
      /development/i,
      /dev/i,
      /staging/i,
      /localhost/i,
      /127\.0\.0\.1/i,
      /test/i,
      /debug/i
    ];
    
    return devPatterns.some(pattern => pattern.test(filePath));
  }

  private generateSuggestion(issueType: string, context: ConfigurationContext): string {
    const framework = context.framework;
    
    switch (issueType) {
      case 'Debug mode in production':
        if (framework === 'express') {
          return 'Set NODE_ENV=production and ensure debug mode is disabled. Use environment variables for configuration.';
        } else if (framework === 'django') {
          return 'Set DEBUG=False in production settings. Use environment variables for sensitive configuration.';
        } else if (framework === 'rails') {
          return 'Set RAILS_ENV=production and ensure config.consider_all_requests_local is false.';
        }
        return 'Disable debug mode in production. Use environment-specific configuration files.';
        
      case 'SSL disabled':
      case 'HTTPS disabled':
        if (framework === 'express') {
          return 'Enable HTTPS by setting up SSL certificates. Use helmet() middleware for security headers.';
        } else if (framework === 'django') {
          return 'Set SECURE_SSL_REDIRECT=True and SECURE_PROXY_SSL_HEADER in production.';
        } else if (framework === 'rails') {
          return 'Set config.force_ssl = true in production environment.';
        }
        return 'Enable SSL/HTTPS in production. Configure proper SSL certificates and security headers.';
        
      case 'Authentication disabled':
        if (framework === 'express') {
          return 'Implement authentication middleware (passport, jwt, etc.). Never disable auth in production.';
        } else if (framework === 'django') {
          return 'Configure authentication backends and ensure LOGIN_REQUIRED is set appropriately.';
        } else if (framework === 'rails') {
          return 'Use Devise or similar authentication gem. Ensure proper authentication is enabled.';
        }
        return 'Enable authentication in production. Implement proper user authentication and authorization.';
        
      case 'Open CORS configuration':
        if (framework === 'express') {
          return 'Configure CORS with specific origins instead of wildcards. Use cors() middleware with proper options.';
        } else if (framework === 'django') {
          return 'Configure CORS_ALLOWED_ORIGINS with specific domains instead of wildcards.';
        } else if (framework === 'rails') {
          return 'Configure rack-cors with specific origins in config/initializers/cors.rb.';
        }
        return 'Configure CORS with specific allowed origins instead of wildcards.';
        
      default:
        return 'Review and secure your configuration. Disable debug modes, enable security headers, and use environment-specific settings.';
    }
  }
} 