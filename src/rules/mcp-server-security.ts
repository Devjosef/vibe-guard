import { BaseRule, FileContent, SecurityIssue } from '../types';

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
    { 
      pattern: /(?:^|\s)(?:allow|enable|permit)\s*[:=]\s*["']?\s*(?:all|true|yes|1|any|everyone|public|unrestricted)\s*["']?/gi, 
      type: 'Insecure MCP Access Control',
      confidence: 0.9,
      validation: (text: string) => this.validateAccessControl(text)
    },
    { 
      pattern: /(?:^|\s)(?:deny|disable|block|restrict)\s*[:=]\s*["']?\s*(?:false|no|0|none|empty)\s*["']?/gi, 
      type: 'Disabled MCP Security',
      confidence: 0.85,
      validation: (text: string) => this.validateDisabledSecurity(text)
    },
    { 
      pattern: /(?:^|\s)(?:auth|authentication|authorization)\s*[:=]\s*["']?\s*(?:none|false|disabled|off)\s*["']?/gi, 
      type: 'Disabled MCP Authentication',
      confidence: 0.95,
      validation: (text: string) => this.validateDisabledAuth(text)
    },
    { 
      pattern: /(?:^|\s)(?:cors|origin)\s*[:=]\s*["']?\s*\*\s*["']?/gi, 
      type: 'Open CORS in MCP',
      confidence: 0.8,
      validation: (text: string) => this.validateOpenCors(text)
    },
    { 
      pattern: /(?:^|\s)(?:token|key|secret|password)\s*[:=]\s*["']?\s*(?:test|demo|example|placeholder|123|abc|xyz|password|admin)\s*["']?/gi, 
      type: 'Weak MCP Credentials',
      confidence: 0.9,
      validation: (text: string) => this.validateWeakCredentials(text)
    },
    { 
      pattern: /(?:^|\s)(?:ssl|tls|https)\s*[:=]\s*["']?\s*(?:false|no|0|disabled|off)\s*["']?/gi, 
      type: 'Disabled MCP Encryption',
      confidence: 0.95,
      validation: (text: string) => this.validateDisabledEncryption(text)
    },
    { 
      pattern: /(?:^|\s)(?:port|host|bind)\s*[:=]\s*["']?\s*(?:0\.0\.0\.0|::|localhost|127\.0\.0\.1)\s*["']?/gi, 
      type: 'Insecure MCP Binding',
      confidence: 0.7,
      validation: (text: string) => this.validateInsecureBinding(text)
    },
    { 
      pattern: /(?:^|\s)(?:debug|verbose|log)\s*[:=]\s*["']?\s*(?:true|yes|1|all|detailed)\s*["']?/gi, 
      type: 'Excessive MCP Logging',
      confidence: 0.6,
      validation: (text: string) => this.validateExcessiveLogging(text)
    },
    { 
      pattern: /(?:^|\s)(?:timeout|rate[_-]?limit|throttle)\s*[:=]\s*["']?\s*(?:0|none|unlimited|infinity)\s*["']?/gi, 
      type: 'No MCP Rate Limiting',
      confidence: 0.75,
      validation: (text: string) => this.validateNoRateLimit(text)
    },
    { 
      pattern: /(?:^|\s)(?:context|contexts|contextFile|contextFiles)\s*[:=]\s*["']?\s*\.\.\/.*\s*["']?/gi, 
      type: 'Path Traversal in MCP Context',
      confidence: 0.8,
      validation: (text: string) => this.validatePathTraversal(text)
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
    
    for (const { pattern, type, confidence, validation } of this.insecurePatterns) {
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
        
        // Calculate final confidence based on context
        const finalConfidence = this.calculateConfidence(confidence, context);
        
        if (finalConfidence >= 0.5) {
          issues.push(this.createIssue(
            fileContent.path,
            line,
            column,
            lineContent,
            `MCP security issue: ${type} (confidence: ${Math.round(finalConfidence * 100)}%)`,
            this.generateSuggestion(type, context),
            finalConfidence >= 0.8 ? 'high' : finalConfidence >= 0.6 ? 'medium' : 'low'
          ));
        }
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

  private calculateConfidence(baseConfidence: number, context: McpSecurityContext): number {
    let confidence = baseConfidence;
    
    // Adjust confidence based on context
    if (context.hasMcpContext) confidence *= 1.2; // Increase for MCP context
    if (context.configurationType) confidence *= 1.1; // Increase for config files
    if (context.isInConfiguration) confidence *= 1.1; // Increase for configuration context
    
    return Math.min(confidence, 1.0);
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

  private generateSuggestion(type: string, context: McpSecurityContext): string {
    const suggestions = {
      'Insecure MCP Access Control': 'Implement proper access controls with specific permissions. Use role-based access control (RBAC) and principle of least privilege.',
      'Disabled MCP Security': 'Enable security features and implement proper security controls. Use security-by-default approach.',
      'Disabled MCP Authentication': 'Enable authentication and implement proper user management. Use strong authentication mechanisms.',
      'Open CORS in MCP': 'Configure CORS with specific allowed origins. Avoid using wildcard (*) for production environments.',
      'Weak MCP Credentials': 'Use strong, unique credentials and implement proper credential management. Use environment variables or secure secret stores.',
      'Disabled MCP Encryption': 'Enable SSL/TLS encryption for all communications. Use strong encryption protocols and certificates.',
      'Insecure MCP Binding': 'Bind to specific interfaces and use proper network security. Avoid binding to 0.0.0.0 in production.',
      'Excessive MCP Logging': 'Configure appropriate logging levels for production. Avoid logging sensitive information.',
      'No MCP Rate Limiting': 'Implement rate limiting and throttling to prevent abuse. Use appropriate timeout values.',
      'Path Traversal in MCP Context': 'Validate and sanitize file paths. Use absolute paths and implement proper path validation.'
    };
    
    let suggestion = suggestions[type as keyof typeof suggestions] || 'Review and secure your MCP server configuration. Implement proper authentication, authorization, and access controls.';
    
    if (context.framework) {
      suggestion += ` For ${context.framework}, consider using framework-specific security middleware and configuration validation.`;
    }
    
    if (context.configurationType) {
      suggestion += ` For ${context.configurationType} configuration files, ensure proper file permissions and use secure configuration management.`;
    }
    
    return suggestion;
  }
}