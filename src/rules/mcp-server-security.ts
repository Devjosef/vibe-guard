import { BaseRule, FileContent, SecurityIssue, SeverityLevel } from '../types';

interface McpSecurityContext {
  isInComment: boolean;
  isInString: boolean;
  isInConfiguration: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
  hasMcpContext: boolean;
  configurationType: string | undefined;
}

export class McpServerSecurityRule extends BaseRule {
  readonly name = 'mcp-server-security';
  readonly description = 'Detects insecure Model Context Protocol (MCP) server configurations with context-aware analysis';
  readonly severity = 'high' as const;

  private readonly insecurePatterns = [
    // Critical: Authentication and encryption issues
    { 
      pattern: /\b(?:auth|authentication|authorization)\s*[:=]\s*["']?\s*(?:none|false|disabled|off)\s*["']?/gi, 
      type: 'Disabled MCP Authentication',
      severity: 'critical' as const,
      validation: (text: string) => this.validateDisabledAuth(text)
    },
    { 
      pattern: /\b(?:ssl|tls|https)\s*[:=]\s*["']?\s*(?:false|no|0|disabled|off)\s*["']?/gi, 
      type: 'Disabled MCP Encryption',
      severity: 'critical' as const,
      validation: (text: string) => this.validateDisabledEncryption(text)
    },
    { 
      pattern: /\b(?:token|key|secret|password|api[_-]?key)\s*[:=]\s*["']?\s*(?:test|demo|example|placeholder|123|abc|xyz|password|admin|key|secret|default)\s*["']?/gi, 
      type: 'Weak MCP Credentials',
      severity: 'critical' as const,
      validation: (text: string) => this.validateWeakCredentials(text)
    },
    { 
      pattern: /\b(?:context|contexts|contextFile|contextFiles)\s*[:=]\s*["']?\s*\.\.\/.*\s*["']?/gi, 
      type: 'Path Traversal in MCP Context',
      severity: 'critical' as const,
      validation: (text: string) => this.validatePathTraversal(text)
    },
    
    // High: Access control and binding issues
    { 
      pattern: /\b(?:allow|enable|permit)\s*[:=]\s*["']?\s*(?:all|true|yes|1|any|everyone|public|unrestricted)\s*["']?/gi, 
      type: 'Insecure MCP Access Control',
      severity: 'high' as const,
      validation: (text: string) => this.validateAccessControl(text)
    },
    { 
      pattern: /\b(?:deny|disable|block|restrict)\s*[:=]\s*["']?\s*(?:false|no|0|none|empty)\s*["']?/gi, 
      type: 'Disabled MCP Security',
      severity: 'high' as const,
      validation: (text: string) => this.validateDisabledSecurity(text)
    },
    { 
      pattern: /\b(?:port|host|bind)\s*[:=]\s*["']?\s*(?:0\.0\.0\.0|::)\s*["']?/gi, 
      type: 'Insecure MCP Binding',
      severity: 'high' as const,
      validation: (text: string) => this.validateInsecureBinding(text)
    },
    { 
      pattern: /\b(?:timeout|rate[_-]?limit|throttle)\s*[:=]\s*["']?\s*(?:0|none|unlimited|infinity)\s*["']?/gi, 
      type: 'No MCP Rate Limiting',
      severity: 'high' as const,
      validation: (text: string) => this.validateNoRateLimit(text)
    },
    
    // Medium: CORS and logging issues
    { 
      pattern: /\b(?:cors|origin)\s*[:=]\s*["']?\s*\*\s*["']?/gi, 
      type: 'Open CORS in MCP',
      severity: 'medium' as const,
      validation: (text: string) => this.validateOpenCors(text)
    },
    { 
      pattern: /\b(?:debug|verbose|log)\s*[:=]\s*["']?\s*(?:true|yes|1|all|detailed)\s*["']?/gi, 
      type: 'Excessive MCP Logging',
      severity: 'medium' as const,
      validation: (text: string) => this.validateExcessiveLogging(text)
    },
    { 
      pattern: /\b(?:port|host|bind)\s*[:=]\s*["']?\s*(?:localhost|127\.0\.0\.1)\s*["']?/gi, 
      type: 'Local MCP Binding',
      severity: 'medium' as const,
      validation: (text: string) => this.validateLocalBinding(text)
    },
    
    // Framework-specific MCP patterns
    { 
      pattern: /\b(?:mcp[_-]?server|model[_-]?context[_-]?protocol)\s*[:=]\s*["']?\s*(?:true|yes|1|enabled)\s*["']?/gi, 
      type: 'MCP Server Enabled',
      severity: 'low' as const,
      validation: (text: string) => this.validateMcpServerEnabled(text)
    },
    { 
      pattern: /\b(?:context[_-]?path|context[_-]?dir)\s*[:=]\s*["']?\s*[^"']{1,20}\s*["']?/gi, 
      type: 'Short MCP Context Path',
      severity: 'medium' as const,
      validation: (text: string) => this.validateShortContextPath(text)
    }
  ];

  private readonly mcpContextPatterns = [
    /context\s*[:=]/gi,
    /contexts\s*[:=]/gi,
    /contextFile\s*[:=]/gi,
    /contextFiles\s*[:=]/gi,
    /contextPath\s*[:=]/gi,
    /contextDir\s*[:=]/gi,
    /contextDirectory\s*[:=]/gi,
    /mcp\s*[:=]/gi,
    /model[_-]?context[_-]?protocol/gi,
    /server[_-]?config/gi,
    /mcp[_-]?server/gi
  ];

  private readonly configurationPatterns = [
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
    const framework = this.detectFramework(fileContent.content, language);
    const configurationType = this.detectConfigurationType(fileContent.path);
    const hasMcpContext = this.hasMcpContext(fileContent.content);
    
    // Skip if no MCP context detected and not a configuration file
    if (!hasMcpContext && !configurationType) {
      return issues;
    }
    
    for (const { pattern, type, severity, validation } of this.insecurePatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework, hasMcpContext, configurationType);
        
        // Skip if in safe context
        if (this.isSafeContext(context)) {
          continue;
        }
        
        // Validate the security issue
        if (!validation(matchedText)) {
          continue;
        }
        
        // Determine final severity based on context
        const finalSeverity = this.determineSeverity(severity, context);
        
        // Determine language for specific remediation
        const detectedLanguage = this.detectLanguage(fileContent.path);

          issues.push(this.createIssue(
            fileContent.path,
            line,
          column + 1,
            lineContent,
          `MCP security issue: ${type}`,
          this.getRemediationMessage(type, detectedLanguage),
          finalSeverity
        ));
      }
    }

    return issues;
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string, hasMcpContext?: boolean, configurationType?: string): McpSecurityContext {
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
      hasMcpContext: hasMcpContext || false,
      configurationType
    };
  }

  private isSafeContext(context: McpSecurityContext): boolean {
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
    
    // Safe if in development/staging context
    if (context.surroundingCode.includes('development') || 
        context.surroundingCode.includes('staging') ||
        context.surroundingCode.includes('localhost')) {
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
    if (language === 'javascript' || language === 'typescript') {
      if (content.includes('express') || content.includes('app.get') || content.includes('app.post')) return 'express';
      if (content.includes('react') || content.includes('jsx') || content.includes('tsx')) return 'react';
      if (content.includes('vue') || content.includes('Vue.createApp')) return 'vue';
      if (content.includes('angular') || content.includes('@Component')) return 'angular';
    }
    if (language === 'python') {
      if (content.includes('flask') || content.includes('Flask')) return 'flask';
      if (content.includes('django') || content.includes('Django')) return 'django';
      if (content.includes('fastapi') || content.includes('FastAPI')) return 'fastapi';
    }
    return undefined;
  }

  private detectConfigurationType(filePath: string): string | undefined {
    for (const pattern of this.configurationPatterns) {
      if (pattern.test(filePath)) {
        const ext = filePath.split('.').pop()?.toLowerCase();
        return ext || 'unknown';
      }
    }
    return undefined;
  }

  private hasMcpContext(content: string): boolean {
    return this.mcpContextPatterns.some(pattern => pattern.test(content));
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

  // Validation methods for different security issues
  private validateAccessControl(text: string): boolean {
    const allowKeywords = ['allow', 'enable', 'permit'];
    const insecureValues = ['all', 'true', 'yes', '1', 'any', 'everyone', 'public', 'unrestricted'];
    return allowKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           insecureValues.some(value => text.toLowerCase().includes(value));
  }

  private validateDisabledSecurity(text: string): boolean {
    const disableKeywords = ['deny', 'disable', 'block', 'restrict'];
    const disabledValues = ['false', 'no', '0', 'none', 'empty'];
    return disableKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           disabledValues.some(value => text.toLowerCase().includes(value));
  }

  private validateDisabledAuth(text: string): boolean {
    const authKeywords = ['auth', 'authentication', 'authorization'];
    const disabledValues = ['none', 'false', 'disabled', 'off'];
    return authKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           disabledValues.some(value => text.toLowerCase().includes(value));
  }

  private validateOpenCors(text: string): boolean {
    return text.toLowerCase().includes('cors') && text.includes('*');
  }

  private validateWeakCredentials(text: string): boolean {
    const credentialKeywords = ['token', 'key', 'secret', 'password'];
    const weakValues = ['test', 'demo', 'example', 'placeholder', '123', 'abc', 'xyz', 'password', 'admin'];
    return credentialKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           weakValues.some(value => text.toLowerCase().includes(value));
  }

  private validateDisabledEncryption(text: string): boolean {
    const encryptionKeywords = ['ssl', 'tls', 'https'];
    const disabledValues = ['false', 'no', '0', 'disabled', 'off'];
    return encryptionKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           disabledValues.some(value => text.toLowerCase().includes(value));
  }

  private validateInsecureBinding(text: string): boolean {
    const bindingKeywords = ['port', 'host', 'bind'];
    const insecureValues = ['0.0.0.0', '::', 'localhost', '127.0.0.1'];
    return bindingKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           insecureValues.some(value => text.toLowerCase().includes(value));
  }

  private validateExcessiveLogging(text: string): boolean {
    const loggingKeywords = ['debug', 'verbose', 'log'];
    const excessiveValues = ['true', 'yes', '1', 'all', 'detailed'];
    return loggingKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           excessiveValues.some(value => text.toLowerCase().includes(value));
  }

  private validateNoRateLimit(text: string): boolean {
    const limitKeywords = ['timeout', 'rate_limit', 'throttle'];
    const unlimitedValues = ['0', 'none', 'unlimited', 'infinity'];
    return limitKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           unlimitedValues.some(value => text.toLowerCase().includes(value));
  }

  private validatePathTraversal(text: string): boolean {
    const contextKeywords = ['context', 'contextFile', 'contextFiles'];
    const traversalPatterns = ['../', '..\\', '/etc/', 'C:\\'];
    return contextKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           traversalPatterns.some(pattern => text.includes(pattern));
  }

  private validateLocalBinding(text: string): boolean {
    const bindingKeywords = ['port', 'host', 'bind'];
    const localValues = ['localhost', '127.0.0.1'];
    return bindingKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           localValues.some(value => text.toLowerCase().includes(value));
  }

  private validateMcpServerEnabled(text: string): boolean {
    const mcpKeywords = ['mcp_server', 'model_context_protocol'];
    const enabledValues = ['true', 'yes', '1', 'enabled'];
    return mcpKeywords.some(keyword => text.toLowerCase().includes(keyword)) &&
           enabledValues.some(value => text.toLowerCase().includes(value));
  }

  private validateShortContextPath(text: string): boolean {
    const contextKeywords = ['context_path', 'context_dir'];
    const pathMatch = text.match(/["']([^"']{1,20})["']/);
    return contextKeywords.some(keyword => text.toLowerCase().includes(keyword)) && 
           pathMatch !== null;
  }

  private determineSeverity(baseSeverity: SeverityLevel, context: McpSecurityContext): SeverityLevel {
    // Downgrade severity in development/test contexts instead of skipping
    if (this.isDevelopmentContext(context) || this.isTestFile(context)) {
      switch (baseSeverity) {
        case 'critical':
          return 'high';
        case 'high':
          return 'medium';
        case 'medium':
          return 'low';
        case 'low':
          return 'low';
        default:
          return baseSeverity;
      }
    }
    
    return baseSeverity;
  }

  private isDevelopmentContext(context: McpSecurityContext): boolean {
    return context.surroundingCode.includes('development') || 
           context.surroundingCode.includes('staging') ||
           context.surroundingCode.includes('localhost') ||
           context.surroundingCode.includes('127.0.0.1');
  }

  private isTestFile(context: McpSecurityContext): boolean {
    return context.isInTestFile;
  }

  private getRemediationMessage(type: string, language: string): string {
    const messages: Record<string, Record<string, string>> = {
      'Disabled MCP Authentication': {
        'javascript': 'Enable authentication for MCP server. Use JWT tokens, API keys, or OAuth2. Implement proper user management.',
        'python': 'Enable authentication for MCP server. Use Flask-JWT-Extended, Django REST framework, or FastAPI security.',
        'php': 'Enable authentication for MCP server. Use JWT tokens or session-based authentication.',
        'java': 'Enable authentication for MCP server. Use Spring Security or JWT tokens.',
        'ruby': 'Enable authentication for MCP server. Use Devise, JWT, or custom authentication.',
        'csharp': 'Enable authentication for MCP server. Use ASP.NET Core Identity or JWT tokens.',
        'general': 'Enable authentication for MCP server. Use secure authentication mechanisms like JWT tokens or API keys.'
      },
      'Disabled MCP Encryption': {
        'javascript': 'Enable SSL/TLS encryption for MCP server. Use HTTPS with valid certificates.',
        'python': 'Enable SSL/TLS encryption for MCP server. Use HTTPS with valid certificates.',
        'php': 'Enable SSL/TLS encryption for MCP server. Use HTTPS with valid certificates.',
        'java': 'Enable SSL/TLS encryption for MCP server. Use HTTPS with valid certificates.',
        'ruby': 'Enable SSL/TLS encryption for MCP server. Use HTTPS with valid certificates.',
        'csharp': 'Enable SSL/TLS encryption for MCP server. Use HTTPS with valid certificates.',
        'general': 'Enable SSL/TLS encryption for MCP server. Use HTTPS with valid certificates.'
      },
      'Weak MCP Credentials': {
        'javascript': 'Use strong, unique credentials for MCP server. Use environment variables or secure secret stores.',
        'python': 'Use strong, unique credentials for MCP server. Use environment variables or secure secret stores.',
        'php': 'Use strong, unique credentials for MCP server. Use environment variables or secure secret stores.',
        'java': 'Use strong, unique credentials for MCP server. Use environment variables or secure secret stores.',
        'ruby': 'Use strong, unique credentials for MCP server. Use environment variables or secure secret stores.',
        'csharp': 'Use strong, unique credentials for MCP server. Use environment variables or secure secret stores.',
        'general': 'Use strong, unique credentials for MCP server. Use environment variables or secure secret stores.'
      },
      'Path Traversal in MCP Context': {
        'javascript': 'Validate and sanitize file paths in MCP context. Use absolute paths and implement proper path validation.',
        'python': 'Validate and sanitize file paths in MCP context. Use absolute paths and implement proper path validation.',
        'php': 'Validate and sanitize file paths in MCP context. Use absolute paths and implement proper path validation.',
        'java': 'Validate and sanitize file paths in MCP context. Use absolute paths and implement proper path validation.',
        'ruby': 'Validate and sanitize file paths in MCP context. Use absolute paths and implement proper path validation.',
        'csharp': 'Validate and sanitize file paths in MCP context. Use absolute paths and implement proper path validation.',
        'general': 'Validate and sanitize file paths in MCP context. Use absolute paths and implement proper path validation.'
      },
      'Insecure MCP Access Control': {
        'javascript': 'Implement proper access controls for MCP server. Use role-based access control (RBAC) and principle of least privilege.',
        'python': 'Implement proper access controls for MCP server. Use role-based access control (RBAC) and principle of least privilege.',
        'php': 'Implement proper access controls for MCP server. Use role-based access control (RBAC) and principle of least privilege.',
        'java': 'Implement proper access controls for MCP server. Use role-based access control (RBAC) and principle of least privilege.',
        'ruby': 'Implement proper access controls for MCP server. Use role-based access control (RBAC) and principle of least privilege.',
        'csharp': 'Implement proper access controls for MCP server. Use role-based access control (RBAC) and principle of least privilege.',
        'general': 'Implement proper access controls for MCP server. Use role-based access control (RBAC) and principle of least privilege.'
      },
      'Disabled MCP Security': {
        'javascript': 'Enable security features for MCP server. Use security-by-default approach.',
        'python': 'Enable security features for MCP server. Use security-by-default approach.',
        'php': 'Enable security features for MCP server. Use security-by-default approach.',
        'java': 'Enable security features for MCP server. Use security-by-default approach.',
        'ruby': 'Enable security features for MCP server. Use security-by-default approach.',
        'csharp': 'Enable security features for MCP server. Use security-by-default approach.',
        'general': 'Enable security features for MCP server. Use security-by-default approach.'
      },
      'Insecure MCP Binding': {
        'javascript': 'Bind MCP server to specific interfaces. Avoid binding to 0.0.0.0 in production.',
        'python': 'Bind MCP server to specific interfaces. Avoid binding to 0.0.0.0 in production.',
        'php': 'Bind MCP server to specific interfaces. Avoid binding to 0.0.0.0 in production.',
        'java': 'Bind MCP server to specific interfaces. Avoid binding to 0.0.0.0 in production.',
        'ruby': 'Bind MCP server to specific interfaces. Avoid binding to 0.0.0.0 in production.',
        'csharp': 'Bind MCP server to specific interfaces. Avoid binding to 0.0.0.0 in production.',
        'general': 'Bind MCP server to specific interfaces. Avoid binding to 0.0.0.0 in production.'
      },
      'No MCP Rate Limiting': {
        'javascript': 'Implement rate limiting for MCP server. Use express-rate-limit or similar middleware.',
        'python': 'Implement rate limiting for MCP server. Use Flask-Limiter or Django REST framework throttling.',
        'php': 'Implement rate limiting for MCP server. Use rate limiting middleware or Redis.',
        'java': 'Implement rate limiting for MCP server. Use Spring Boot Actuator or custom rate limiting.',
        'ruby': 'Implement rate limiting for MCP server. Use Rack::Attack or similar middleware.',
        'csharp': 'Implement rate limiting for MCP server. Use ASP.NET Core rate limiting middleware.',
        'general': 'Implement rate limiting for MCP server. Use appropriate timeout values and throttling.'
      },
      'Open CORS in MCP': {
        'javascript': 'Configure CORS for MCP server with specific allowed origins. Avoid using wildcard (*) for production.',
        'python': 'Configure CORS for MCP server with specific allowed origins. Avoid using wildcard (*) for production.',
        'php': 'Configure CORS for MCP server with specific allowed origins. Avoid using wildcard (*) for production.',
        'java': 'Configure CORS for MCP server with specific allowed origins. Avoid using wildcard (*) for production.',
        'ruby': 'Configure CORS for MCP server with specific allowed origins. Avoid using wildcard (*) for production.',
        'csharp': 'Configure CORS for MCP server with specific allowed origins. Avoid using wildcard (*) for production.',
        'general': 'Configure CORS for MCP server with specific allowed origins. Avoid using wildcard (*) for production.'
      },
      'Excessive MCP Logging': {
        'javascript': 'Configure appropriate logging levels for MCP server in production. Avoid logging sensitive information.',
        'python': 'Configure appropriate logging levels for MCP server in production. Avoid logging sensitive information.',
        'php': 'Configure appropriate logging levels for MCP server in production. Avoid logging sensitive information.',
        'java': 'Configure appropriate logging levels for MCP server in production. Avoid logging sensitive information.',
        'ruby': 'Configure appropriate logging levels for MCP server in production. Avoid logging sensitive information.',
        'csharp': 'Configure appropriate logging levels for MCP server in production. Avoid logging sensitive information.',
        'general': 'Configure appropriate logging levels for MCP server in production. Avoid logging sensitive information.'
      },
      'Local MCP Binding': {
        'javascript': 'Consider binding MCP server to external interfaces for production deployment.',
        'python': 'Consider binding MCP server to external interfaces for production deployment.',
        'php': 'Consider binding MCP server to external interfaces for production deployment.',
        'java': 'Consider binding MCP server to external interfaces for production deployment.',
        'ruby': 'Consider binding MCP server to external interfaces for production deployment.',
        'csharp': 'Consider binding MCP server to external interfaces for production deployment.',
        'general': 'Consider binding MCP server to external interfaces for production deployment.'
      },
      'MCP Server Enabled': {
        'javascript': 'MCP server is enabled. Ensure proper security configuration is in place.',
        'python': 'MCP server is enabled. Ensure proper security configuration is in place.',
        'php': 'MCP server is enabled. Ensure proper security configuration is in place.',
        'java': 'MCP server is enabled. Ensure proper security configuration is in place.',
        'ruby': 'MCP server is enabled. Ensure proper security configuration is in place.',
        'csharp': 'MCP server is enabled. Ensure proper security configuration is in place.',
        'general': 'MCP server is enabled. Ensure proper security configuration is in place.'
      },
      'Short MCP Context Path': {
        'javascript': 'Use longer, more descriptive context paths for MCP server. Consider using UUIDs or hashed paths.',
        'python': 'Use longer, more descriptive context paths for MCP server. Consider using UUIDs or hashed paths.',
        'php': 'Use longer, more descriptive context paths for MCP server. Consider using UUIDs or hashed paths.',
        'java': 'Use longer, more descriptive context paths for MCP server. Consider using UUIDs or hashed paths.',
        'ruby': 'Use longer, more descriptive context paths for MCP server. Consider using UUIDs or hashed paths.',
        'csharp': 'Use longer, more descriptive context paths for MCP server. Consider using UUIDs or hashed paths.',
        'general': 'Use longer, more descriptive context paths for MCP server. Consider using UUIDs or hashed paths.'
      },
      'general': {
        'javascript': 'Review and secure your MCP server configuration. Implement proper authentication, authorization, and access controls.',
        'python': 'Review and secure your MCP server configuration. Implement proper authentication, authorization, and access controls.',
        'php': 'Review and secure your MCP server configuration. Implement proper authentication, authorization, and access controls.',
        'java': 'Review and secure your MCP server configuration. Implement proper authentication, authorization, and access controls.',
        'ruby': 'Review and secure your MCP server configuration. Implement proper authentication, authorization, and access controls.',
        'csharp': 'Review and secure your MCP server configuration. Implement proper authentication, authorization, and access controls.',
        'general': 'Review and secure your MCP server configuration. Implement proper authentication, authorization, and access controls.'
      }
    };

    return messages[type]?.[language] || messages['general']?.[language] || (messages['general'] && messages['general']['general']) || 'Review and secure your MCP server configuration. Implement proper authentication, authorization, and access controls.';
  }


}