import { BaseRule, FileContent, SecurityIssue, SeverityLevel } from '../types';

interface SecurityHeadersContext {
  isInComment: boolean;
  isInString: boolean;
  isInConfiguration: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
  hasServerCode: boolean;
  hasSecurityHeaders: boolean;
  configurationType: string | undefined;
}

interface SecurityHeader {
  name: string;
  severity: SeverityLevel;
  description: string;
  isLegacy?: boolean;
  validation: (content: string) => boolean;
  suggestion: string;
}

export class MissingSecurityHeadersRule extends BaseRule {
  readonly name = 'missing-security-headers';
  readonly description = 'Detects missing HTTP security headers with context-aware analysis';
  readonly severity = 'medium' as const;

  private readonly securityHeaders: SecurityHeader[] = [
    { 
      name: 'Content-Security-Policy',
      severity: 'critical',
      description: 'Critical security header to prevent XSS attacks',
      validation: (content: string) => this.validateCSP(content),
      suggestion: 'Implement Content-Security-Policy to prevent XSS attacks'
    },
    { 
      name: 'Strict-Transport-Security',
      severity: 'critical',
      description: 'Critical security header to enforce HTTPS connections',
      validation: (content: string) => this.validateHSTS(content),
      suggestion: 'Implement HSTS to enforce HTTPS connections'
    },
    { 
      name: 'X-Frame-Options',
      severity: 'high',
      description: 'High priority header to prevent clickjacking attacks',
      validation: (content: string) => this.validateXFrameOptions(content),
      suggestion: 'Set X-Frame-Options to prevent clickjacking attacks'
    },
    { 
      name: 'Referrer-Policy',
      severity: 'high',
      description: 'High priority header to control referrer information',
      validation: (content: string) => this.validateReferrerPolicy(content),
      suggestion: 'Set Referrer-Policy to control referrer information'
    },
    { 
      name: 'X-Content-Type-Options',
      severity: 'medium',
      description: 'Medium priority header to prevent MIME type sniffing',
      validation: (content: string) => this.validateXContentTypeOptions(content),
      suggestion: 'Set X-Content-Type-Options to nosniff to prevent MIME type sniffing'
    },
    { 
      name: 'Permissions-Policy',
      severity: 'medium',
      description: 'Medium priority header to control browser features',
      validation: (content: string) => this.validatePermissionsPolicy(content),
      suggestion: 'Implement Permissions-Policy to control browser features'
    },
    { 
      name: 'X-XSS-Protection',
      severity: 'low',
      description: 'Legacy header for XSS protection (optional)',
      isLegacy: true,
      validation: (content: string) => this.validateXXSSProtection(content),
      suggestion: 'X-XSS-Protection is legacy and optional. Consider using Content-Security-Policy instead'
    },
    { 
      name: 'X-Permitted-Cross-Domain-Policies',
      severity: 'low',
      description: 'Low priority header to control cross-domain access',
      validation: (content: string) => this.validateXPermittedCrossDomainPolicies(content),
      suggestion: 'Set X-Permitted-Cross-Domain-Policies to control cross-domain access'
    }
  ];

  private readonly serverPatterns = [
    // Express.js patterns
    { 
      pattern: /\bapp\.(?:get|post|put|delete|patch|use)\s*\(/gi, 
      type: 'Express route handler',
      framework: 'express'
    },
    { 
      pattern: /\broter\.(?:get|post|put|delete|patch|use)\s*\(/gi, 
      type: 'Express router',
      framework: 'express'
    },
    { 
      pattern: /\bapp\.listen\s*\(/gi, 
      type: 'Express server',
      framework: 'express'
    },
    
    // Next.js API routes
    { 
      pattern: /\bexport\s+(?:default\s+)?(?:async\s+)?function\s+handler/gi, 
      type: 'Next.js API handler',
      framework: 'nextjs'
    },
    { 
      pattern: /\bexport\s+(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\([^)]*req[^)]*res[^)]*\)/gi, 
      type: 'Next.js API function',
      framework: 'nextjs'
    },
    
    // Node.js HTTP server
    { 
      pattern: /\bcreateServer\s*\(\s*(?:async\s+)?\([^)]*req[^)]*res[^)]*\)/gi, 
      type: 'Node.js HTTP server',
      framework: 'nodejs'
    },
    { 
      pattern: /\bhttp\.createServer/gi, 
      type: 'HTTP server creation',
      framework: 'nodejs'
    },
    
    // Framework response patterns
    { 
      pattern: /\bres\.(?:send|json|render|redirect)/gi, 
      type: 'Response method',
      framework: 'express'
    },
    { 
      pattern: /\bresponse\.(?:send|json|render|redirect)/gi, 
      type: 'Response method',
      framework: 'general'
    },
    
    // Flask patterns
    { 
      pattern: /\b@app\.route/gi, 
      type: 'Flask route',
      framework: 'flask'
    },
    { 
      pattern: /\breturn\s+(?:render_template|jsonify|redirect)/gi, 
      type: 'Flask response',
      framework: 'flask'
    },
    
    // Django patterns
    { 
      pattern: /\bdef\s+\w+\s*\([^)]*request[^)]*\)/gi, 
      type: 'Django view function',
      framework: 'django'
    },
    { 
      pattern: /\bHttpResponse\s*\(/gi, 
      type: 'Django HTTP response',
      framework: 'django'
    },
    
    // Rails patterns
    { 
      pattern: /\bclass\s+\w+Controller\s*</gi, 
      type: 'Rails controller',
      framework: 'rails'
    },
    { 
      pattern: /\bdef\s+\w+\s*#\s*action/gi, 
      type: 'Rails action',
      framework: 'rails'
    },
    { 
      pattern: /\brender\s+(?:json|html|xml)/gi, 
      type: 'Rails response',
      framework: 'rails'
    },
    
    // Spring patterns
    { 
      pattern: /\b@RestController/gi, 
      type: 'Spring REST controller',
      framework: 'spring'
    },
    { 
      pattern: /\b@Controller/gi, 
      type: 'Spring controller',
      framework: 'spring'
    },
    { 
      pattern: /\b@GetMapping|\b@PostMapping|\b@PutMapping|\b@DeleteMapping/gi, 
      type: 'Spring mapping',
      framework: 'spring'
    },
    
    // ASP.NET patterns
    { 
      pattern: /\bpublic\s+class\s+\w+Controller\s*:\s*Controller/gi, 
      type: 'ASP.NET controller',
      framework: 'aspnet'
    },
    { 
      pattern: /\bpublic\s+(?:async\s+)?\w+\s+\w+\s*\([^)]*\)/gi, 
      type: 'ASP.NET action',
      framework: 'aspnet'
    },
    
    // PHP patterns
    { 
      pattern: /\bheader\s*\(\s*['"`][^'"`]*['"`]/gi, 
      type: 'PHP header function',
      framework: 'php'
    },
    
    // Laravel patterns
    { 
      pattern: /\bRoute::(?:get|post|put|delete|patch)/gi, 
      type: 'Laravel route',
      framework: 'laravel'
    },
    { 
      pattern: /\breturn\s+(?:response|view|json)/gi, 
      type: 'Laravel response',
      framework: 'laravel'
    }
  ];

  private readonly safePatterns = [
    /\bexample\b/i,
    /\bdemo\b/i,
    /\btest\b/i,
    /\bsample\b/i,
    /\bplaceholder\b/i,
    /\bdevelopment\b/i,
    /\bdev\b/i,
    /\bstaging\b/i,
    /\blocalhost\b/i,
    /\b127\.0\.0\.1\b/i,
    /\bconsole\.log\b/i,
    /\bconsole\.warn\b/i,
    /\bconsole\.error\b/i,
    /\blogger\.(?:log|warn|error|info)\b/i,
    /\bprint\b/i,
    /\becho\b/i,
    /\bprintf\b/i,
    /\bSystem\.out\.println\b/i,
    /\bputs\b/i,
    /\bConsole\.WriteLine\b/i,
    /\bcomment\b/i,
    /\bnote\b/i,
    /\btodo\b/i,
    /\bfixme\b/i,
    /\bsecure\b/i,
    /\bsafe\b/i,
    /\bprotected\b/i,
    /\bdefense\b/i,
    /\bguard\b/i,
    /\bprevent\b/i,
    /\bblock\b/i,
    /\brestrict\b/i,
    /\bdocumentation\b/i,
    /\bconfig\b/i,
    /\bsettings\b/i,
    /\bREADME\b/i,
    /\bCHANGELOG\b/i,
    /\bLICENSE\b/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const configurationType = this.detectConfigurationType(fileContent.path);
    const hasServerCode = this.hasServerCode(fileContent.content);
    const hasSecurityHeaders = this.hasSecurityHeaders(fileContent.content);
    
    // Skip if no server code detected and not a configuration file
    if (!hasServerCode && !configurationType) {
      return issues;
    }
    
    // Check for missing security headers and report each separately
    const missingHeaders = this.checkMissingHeaders(fileContent);
    
    if (missingHeaders.length > 0) {
      const location = this.findReportLocation(fileContent);
      
      if (location) {
        const context = this.analyzeContext(fileContent, location.line, location.column, language, framework, hasServerCode, hasSecurityHeaders, configurationType);
        
        // Skip if in safe context to prevent false positives
        if (!this.isSafeContext(context)) {
          // Report each missing header as a separate issue
          for (const header of missingHeaders) {
            const severity = this.determineSeverity(header.severity, context);
            const suggestion = this.getRemediationMessage(header, context);
            
            issues.push(this.createIssue(
              fileContent.path,
              location.line,
              location.column,
              location.lineContent,
              `Missing security header: ${header.name} (${header.description})`,
              suggestion,
              severity
            ));
          }
        }
      }
    }

    return issues;
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string, hasServerCode?: boolean, hasSecurityHeaders?: boolean, configurationType?: string): SecurityHeadersContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language),
      isInString: this.isInString(currentLine, column),
      isInConfiguration: this.isInConfiguration(surroundingLines),
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(surroundingLines),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework,
      hasServerCode: hasServerCode || false,
      hasSecurityHeaders: hasSecurityHeaders || false,
      configurationType
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
    if (language === 'ini') {
      return trimmed.startsWith(';') || trimmed.startsWith('#');
    }
    return false;
  }

  private isInString(line: string, column: number): boolean {
    const before = line.substring(0, column);
    const quotes = (before.match(/['"`]/g) || []).length;
    return quotes % 2 === 1;
  }

  private isInConfiguration(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('=') || 
      line.includes(':') || 
      line.includes('[') || 
      line.includes('{')
    );
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

  private isSafeContext(context: SecurityHeadersContext): boolean {
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
      'ini': 'ini',
      'conf': 'conf',
      'toml': 'toml',
      'env': 'env'
    };
    return languageMap[ext || ''] || 'unknown';
  }

  private detectFramework(content: string, language: string): string | undefined {
    // Check for framework patterns in the content
    for (const pattern of this.serverPatterns) {
      if (pattern.pattern.test(content)) {
        return pattern.framework;
      }
    }
    
    // Fallback to language-based detection
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
    if (language === 'ruby') {
      if (content.includes('rails') || content.includes('Rails')) return 'rails';
    }
    if (language === 'java') {
      if (content.includes('spring') || content.includes('Spring')) return 'spring';
    }
    if (language === 'csharp') {
      if (content.includes('asp.net') || content.includes('ASP.NET')) return 'aspnet';
    }
    return undefined;
  }

  private detectConfigurationType(filePath: string): string | undefined {
    const configPatterns = [
      /\.conf$/i,
      /\.config$/i,
      /\.ini$/i,
      /\.yaml$/i,
      /\.yml$/i,
      /\.json$/i,
      /\.toml$/i,
      /\.env$/i,
      /\.properties$/i,
      /config\./i,
      /settings\./i
    ];
    
    for (const pattern of configPatterns) {
      if (pattern.test(filePath)) {
        const ext = filePath.split('.').pop()?.toLowerCase();
        return ext || 'unknown';
      }
    }
    return undefined;
  }

  private hasServerCode(content: string): boolean {
    return this.serverPatterns.some(({ pattern }) => pattern.test(content));
  }

  private hasSecurityHeaders(content: string): boolean {
    return this.securityHeaders.some(header => this.hasSecurityHeader(content, header.name));
  }

  protected override findMatches(content: string, pattern: RegExp): Array<{ match: RegExpMatchArray; line: number; column: number; lineContent: string }> {
    const matches: Array<{ match: RegExpMatchArray; line: number; column: number; lineContent: string }> = [];
    const lines = content.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      
      let match;
      const regex = new RegExp(pattern.source, pattern.flags);
      
      while ((match = regex.exec(line)) !== null) {
        matches.push({
          match,
          line: i + 1,
          column: match.index + 1,
          lineContent: line
        });
      }
    }
    
    return matches;
  }

  private checkMissingHeaders(fileContent: FileContent): SecurityHeader[] {
    const missingHeaders: SecurityHeader[] = [];
    
    for (const header of this.securityHeaders) {
      if (!this.hasSecurityHeader(fileContent.content, header.name)) {
        missingHeaders.push(header);
      }
    }
    
    return missingHeaders;
  }

  private hasSecurityHeader(content: string, header: string): boolean {
    const headerPatterns = [
      // Express.js patterns
      new RegExp(`res\\.(?:set|header)\\s*\\(\\s*['"\`]${header}['"\`]`, 'gi'),
      new RegExp(`res\\.setHeader\\s*\\(\\s*['"\`]${header}['"\`]`, 'gi'),
      
      // Helmet.js patterns
      /helmet\s*\(\s*\)/gi,
      /helmet\./gi,
      
      // Manual header setting
      new RegExp(`['"\`]${header}['"\`]\\s*:\\s*['"\`]`, 'gi'),
      
      // PHP patterns
      new RegExp(`header\\s*\\(\\s*['"\`]${header}:`, 'gi'),
      
      // Python Flask patterns
      new RegExp(`response\\.headers\\[['"\`]${header}['"\`]\\]`, 'gi'),
      
      // Django patterns
      new RegExp(`response\\[['"\`]${header}['"\`]\\]`, 'gi'),
      
      // Configuration patterns
      new RegExp(`${header}\\s*[:=]`, 'gi')
    ];

    return headerPatterns.some(pattern => pattern.test(content));
  }

  private findReportLocation(fileContent: FileContent): { line: number; column: number; lineContent: string } | null {
    for (const { pattern } of this.serverPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      if (matches.length > 0) {
        const firstMatch = matches[0];
        if (firstMatch) {
          return {
            line: firstMatch.line,
            column: firstMatch.column,
            lineContent: firstMatch.lineContent
          };
        }
      }
    }
    return null;
  }

  private determineSeverity(headerSeverity: SeverityLevel, context: SecurityHeadersContext): SeverityLevel {
    // Downgrade severity in development/test contexts instead of skipping
    if (context.isInTestFile || this.isDevelopmentContext(context)) {
      switch (headerSeverity) {
        case 'critical': return 'high';
        case 'high': return 'medium';
        case 'medium': return 'low';
        case 'low': return 'low';
        default: return headerSeverity;
      }
    }
    
    return headerSeverity;
  }

  private isDevelopmentContext(context: SecurityHeadersContext): boolean {
    const devPatterns = [
      /\bdevelopment\b/i,
      /\bdev\b/i,
      /\bstaging\b/i,
      /\blocalhost\b/i,
      /\b127\.0\.0\.1\b/i,
      /\btest\b/i,
      /\bmock\b/i,
      /\bdebug\b/i
    ];
    
    return devPatterns.some(pattern => 
      pattern.test(context.surroundingCode) || 
      pattern.test(context.configurationType || '')
    );
  }

  private getRemediationMessage(header: SecurityHeader, context: SecurityHeadersContext): string {
    const framework = context.framework;
    
    if (header.isLegacy) {
      return `${header.suggestion} This header is legacy and may not be supported in modern browsers.`;
    }
    
    let suggestion = header.suggestion;
    
    if (framework) {
      suggestion += this.getFrameworkSpecificSuggestion(header.name, framework);
    }
    
    if (context.configurationType) {
      suggestion += this.getConfigurationSpecificSuggestion(header.name, context.configurationType);
    }
    
    return suggestion;
  }

  private getFrameworkSpecificSuggestion(headerName: string, framework: string): string {
    const suggestions: Record<string, Record<string, string>> = {
      'Content-Security-Policy': {
        'express': ' Use helmet.js: npm install helmet && app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["\'self\'"] } } }))',
        'flask': ' Use Flask-Talisman: pip install flask-talisman && talisman.content_security_policy = {"default-src": "\'self\'"}',
        'django': ' Add to settings.py: SECURE_CONTENT_TYPE_NOSNIFF = True, SECURE_BROWSER_XSS_FILTER = True',
        'rails': ' Add to application.rb: config.content_security_policy do |policy| policy.default_src :self end',
        'spring': ' Add to WebSecurityConfig: .headers().contentSecurityPolicy("default-src \'self\'")',
        'aspnet': ' Add to Startup.cs: app.Use(async (context, next) => { context.Response.Headers.Add("Content-Security-Policy", "default-src \'self\'"); await next(); })'
      },
      'Strict-Transport-Security': {
        'express': ' Use helmet.js: app.use(helmet({ hsts: { maxAge: 31536000, includeSubDomains: true } }))',
        'flask': ' Use Flask-Talisman: talisman.force_https = True',
        'django': ' Add to settings.py: SECURE_HSTS_SECONDS = 31536000, SECURE_HSTS_INCLUDE_SUBDOMAINS = True',
        'rails': ' Add to application.rb: config.force_ssl = true',
        'spring': ' Add to WebSecurityConfig: .headers().httpStrictTransportSecurity()',
        'aspnet': ' Add to Startup.cs: app.UseHsts()'
      },
      'X-Frame-Options': {
        'express': ' Use helmet.js: app.use(helmet({ frameguard: { action: "deny" } }))',
        'flask': ' Use Flask-Talisman: talisman.frame_options = "DENY"',
        'django': ' Add to settings.py: X_FRAME_OPTIONS = "DENY"',
        'rails': ' Add to application.rb: config.action_dispatch.default_headers["X-Frame-Options"] = "DENY"',
        'spring': ' Add to WebSecurityConfig: .headers().frameOptions().deny()',
        'aspnet': ' Add to Startup.cs: app.Use(async (context, next) => { context.Response.Headers.Add("X-Frame-Options", "DENY"); await next(); })'
      }
    };
    
    return suggestions[headerName]?.[framework] || ` For ${framework}, implement ${headerName} using framework-specific security middleware.`;
  }

  private getConfigurationSpecificSuggestion(headerName: string, configType: string): string {
    const suggestions: Record<string, Record<string, string>> = {
      'Content-Security-Policy': {
        'yaml': ` Add to ${configType} config:\n  security:\n    headers:\n      Content-Security-Policy: "default-src 'self'"`,
        'json': ` Add to ${configType} config:\n  "security": {\n    "headers": {\n      "Content-Security-Policy": "default-src 'self'"\n    }\n  }`,
        'ini': ` Add to ${configType} config:\n[security]\nContent-Security-Policy = default-src 'self'`
      },
      'Strict-Transport-Security': {
        'yaml': ` Add to ${configType} config:\n  security:\n    headers:\n      Strict-Transport-Security: "max-age=31536000; includeSubDomains"`,
        'json': ` Add to ${configType} config:\n  "security": {\n    "headers": {\n      "Strict-Transport-Security": "max-age=31536000; includeSubDomains"\n    }\n  }`,
        'ini': ` Add to ${configType} config:\n[security]\nStrict-Transport-Security = max-age=31536000; includeSubDomains`
      }
    };
    
    return suggestions[headerName]?.[configType] || ` For ${configType} configuration files, ensure proper file permissions and use secure configuration management.`;
  }

  // Validation methods for different security headers
  private validateCSP(content: string): boolean {
    return /Content-Security-Policy/i.test(content);
  }

  private validateXFrameOptions(content: string): boolean {
    return /X-Frame-Options/i.test(content);
  }

  private validateXContentTypeOptions(content: string): boolean {
    return /X-Content-Type-Options/i.test(content);
  }

  private validateXXSSProtection(content: string): boolean {
    return /X-XSS-Protection/i.test(content);
  }

  private validateHSTS(content: string): boolean {
    return /Strict-Transport-Security/i.test(content);
  }

  private validateReferrerPolicy(content: string): boolean {
    return /Referrer-Policy/i.test(content);
  }

  private validatePermissionsPolicy(content: string): boolean {
    return /Permissions-Policy/i.test(content);
  }

  private validateXPermittedCrossDomainPolicies(content: string): boolean {
    return /X-Permitted-Cross-Domain-Policies/i.test(content);
  }


} 