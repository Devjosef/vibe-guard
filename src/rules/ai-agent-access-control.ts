import { BaseRule, FileContent, SecurityIssue } from '../types';

interface AiAgentContext {
  isInComment: boolean;
  isInString: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  isInDevelopment: boolean;
  isInSandbox: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
  hasAuthChecks: boolean;
  isProtectedEnvironment: boolean;
}

export class AiAgentAccessControlRule extends BaseRule {
  readonly name = 'ai-agent-access-control';
  readonly description = 'Detects insecure AI agent access controls and privilege escalation with context-aware analysis';
  readonly severity = 'critical' as const;

  private readonly accessControlPatterns = [
    // AI Agent with elevated privileges - tighter patterns
    { 
      pattern: /(?:ai[_-]?agent|agent|bot|assistant)\s*[:=]\s*['"`]?(?:admin|root|superuser|sudo)['"`]?/gi, 
      type: 'Elevated AI Agent Privileges',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateElevatedPrivileges(text)
    },
    { 
      pattern: /(?:permissions?|roles?|access)\s*[:=]\s*['"`]?(?:all|full|unlimited|wildcard)['"`]?/gi, 
      type: 'Unlimited AI Agent Permissions',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateUnlimitedPermissions(text)
    },
    
    // Authentication bypass patterns
    { 
      pattern: /(?:auth|authentication)\s*[:=]\s*['"`]?(?:false|no|0|disabled|off)['"`]?/gi, 
      type: 'Disabled AI Agent Authentication',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateDisabledAuth(text)
    },
    
    // Missing RBAC for AI agents - more specific
    { 
      pattern: /(?:ai[_-]?agent|agent|bot|assistant)\s*[:=]\s*['"`]?[^'"`]*\b(?:without|no|missing)\s+(?:role|permission|access[_-]?control)['"`]?/gi, 
      type: 'Missing AI Agent RBAC',
      confidence: 0.85,
      severity: 'high' as const,
      validation: (text: string) => this.validateMissingRBAC(text)
    },
    
    // AI Agent with persistent elevated access
    { 
      pattern: /(?:ai[_-]?agent|agent|bot|assistant).*?(?:permanent|persistent|always|forever).*?(?:admin|root|elevated)/gi, 
      type: 'Persistent Elevated AI Access',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validatePersistentAccess(text)
    },
    
    // AI Agent bypassing authentication
    { 
      pattern: /(?:ai[_-]?agent|agent|bot|assistant).*?(?:bypass|skip|ignore).*?(?:auth|authentication|login)/gi, 
      type: 'AI Agent Auth Bypass',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateAuthBypass(text)
    },
    
    // AI Agent with system-level access
    { 
      pattern: /(?:ai[_-]?agent|agent|bot|assistant).*?(?:system|os|kernel|hardware)/gi, 
      type: 'AI Agent System Access',
      confidence: 0.8,
      severity: 'high' as const,
      validation: (text: string) => this.validateSystemAccess(text)
    },
    
    // MCP Server insecure access - tighter patterns
    { 
      pattern: /(?:mcp|model[_-]?context[_-]?protocol).*?(?:unrestricted|open|public)/gi, 
      type: 'Insecure MCP Server Access',
      confidence: 0.85,
      severity: 'high' as const,
      validation: (text: string) => this.validateInsecureMCP(text)
    },
    { 
      pattern: /(?:mcp[_-]?server|model[_-]?context[_-]?protocol).*?(?:no[_-]?auth|without[_-]?auth)/gi, 
      type: 'MCP Server Without Auth',
      confidence: 0.9,
      severity: 'high' as const,
      validation: (text: string) => this.validateMCPNoAuth(text)
    },
    
    // AI Agent with file system access
    { 
      pattern: /(?:ai[_-]?agent|agent|bot|assistant).*?(?:file|directory|path|fs)/gi, 
      type: 'AI Agent File System Access',
      confidence: 0.75,
      severity: 'medium' as const,
      validation: (text: string) => this.validateFileSystemAccess(text)
    },
    
    // AI Agent with network access
    { 
      pattern: /(?:ai[_-]?agent|agent|bot|assistant).*?(?:network|http|https|api|endpoint)/gi, 
      type: 'AI Agent Network Access',
      confidence: 0.7,
      severity: 'medium' as const,
      validation: (text: string) => this.validateNetworkAccess(text)
    }
  ];

  private readonly falsePositivePatterns = [
    // Development and testing patterns
    /example/i,
    /demo/i,
    /test/i,
    /mock/i,
    /sample/i,
    /placeholder/i,
    /comment/i,
    /todo/i,
    /fixme/i,
    /\/\/.*/i,
    /#.*/i,
    /\/\*.*\*\//i,
    /<!--.*-->/i,
    /development/i,
    /dev/i,
    /staging/i,
    /localhost/i,
    
    // Sandbox and safe environments
    /sandbox/i,
    /isolated/i,
    /contained/i,
    /restricted/i,
    /safe[_-]?mode/i,
    /demo[_-]?mode/i,
    /test[_-]?environment/i,
    
    // Documentation and examples
    /documentation/i,
    /docs?/i,
    /readme/i,
    /example[_-]?config/i,
    /sample[_-]?config/i,
    
    // Security related patterns (likely safe)
    /secure/i,
    /protected/i,
    /guarded/i,
    /monitored/i,
    /audited/i,
    /logged/i,
    /restricted/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const hasAuthChecks = this.hasAuthChecks(fileContent.content);
    const isProtectedEnvironment = this.isProtectedEnvironment(fileContent.content);

    for (const { pattern, type, confidence, severity, validation } of this.accessControlPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework, hasAuthChecks, isProtectedEnvironment);
        
        // Skip if in safe context
        if (this.isSafeContext(context)) {
          continue;
        }
        
        // Validate the access control issue
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
            `${severity.toUpperCase()}: ${type} detected (confidence: ${Math.round(finalConfidence * 100)}%): ${this.getLineContext(lineContent, column)}`,
            this.generateSuggestion(type, context),
            severity
          ));
        }
      }
    }

    return issues;
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string, hasAuthChecks?: boolean, isProtectedEnvironment?: boolean): AiAgentContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language),
      isInString: this.isInString(currentLine, column),
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(fileContent.path),
      isInDevelopment: this.isInDevelopment(surroundingLines),
      isInSandbox: this.isInSandbox(surroundingLines),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework,
      hasAuthChecks: hasAuthChecks || false,
      isProtectedEnvironment: isProtectedEnvironment || false
    };
  }

  private isSafeContext(context: AiAgentContext): boolean {
  
    if (context.isInComment) return true;
    
    
    if (context.isInTestFile) return true;
    
    
    if (context.isInDocumentation) return true;
    
    
    if (context.isInDevelopment) return true;
    
    
    if (context.isInSandbox) return true;
    
    
    if (this.falsePositivePatterns.some(pattern => pattern.test(context.surroundingCode))) {
      return true;
    }
    
    
    if (context.hasAuthChecks) return true;
    
    
    if (context.isProtectedEnvironment) return true;
    
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
      'cs': 'csharp'
    };
    return languageMap[ext || ''] || 'unknown';
  }

  private detectFramework(content: string, language: string): string | undefined {
    if (language === 'javascript' || language === 'typescript') {
      if (content.includes('openai') || content.includes('OpenAI')) return 'openai';
      if (content.includes('anthropic') || content.includes('Anthropic')) return 'anthropic';
      if (content.includes('langchain') || content.includes('LangChain')) return 'langchain';
      if (content.includes('llama') || content.includes('Llama')) return 'llama';
    }
    if (language === 'python') {
      if (content.includes('openai') || content.includes('OpenAI')) return 'openai';
      if (content.includes('anthropic') || content.includes('Anthropic')) return 'anthropic';
      if (content.includes('langchain') || content.includes('LangChain')) return 'langchain';
      if (content.includes('transformers') || content.includes('Transformers')) return 'transformers';
    }
    return undefined;
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

  private isInDocumentation(filePath: string): boolean {
    const docPatterns = [
      /docs?\//i,
      /documentation/i,
      /examples?/i,
      /samples?/i,
      /tutorials?/i,
      /guides?/i,
      /readme/i,
      /\.md$/i,
      /\.rst$/i,
      /\.txt$/i
    ];
    return docPatterns.some(pattern => pattern.test(filePath));
  }

  private isInDevelopment(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('development') || 
      line.includes('dev') ||
      line.includes('staging') ||
      line.includes('localhost') ||
      line.includes('127.0.0.1') ||
      line.includes('NODE_ENV') ||
      line.includes('DEBUG')
    );
  }

  private isInSandbox(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('sandbox') || 
      line.includes('isolated') ||
      line.includes('contained') ||
      line.includes('restricted') ||
      line.includes('safe[_-]?mode') ||
      line.includes('demo[_-]?mode')
    );
  }

  private hasAuthChecks(content: string): boolean {
    const authPatterns = [
      /auth/i,
      /authentication/i,
      /authorization/i,
      /permission/i,
      /role/i,
      /access[_-]?control/i,
      /rbac/i,
      /middleware/i,
      /guard/i,
      /protect/i,
      /secure/i
    ];
    return authPatterns.some(pattern => pattern.test(content));
  }

  private isProtectedEnvironment(content: string): boolean {
    const protectedPatterns = [
      /sandbox/i,
      /isolated/i,
      /contained/i,
      /restricted/i,
      /monitored/i,
      /audited/i,
      /logged/i,
      /safe/i,
      /protected/i
    ];
    return protectedPatterns.some(pattern => pattern.test(content));
  }

  private calculateConfidence(baseConfidence: number, context: AiAgentContext): number {
    let confidence = baseConfidence;
    
    // Adjust confidence based on context
    if (context.hasAuthChecks) confidence *= 0.6; // Reduce if auth checks present
    if (context.isProtectedEnvironment) confidence *= 0.7; // Reduce if in protected environment
    if (context.framework) confidence *= 1.1; // Increase for known frameworks
    
    return Math.min(confidence, 1.0);
  }

  // Validation methods for different access control issues
  private validateElevatedPrivileges(text: string): boolean {
    const privilegeKeywords = ['admin', 'root', 'superuser', 'sudo'];
    return privilegeKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateUnlimitedPermissions(text: string): boolean {
    const unlimitedKeywords = ['all', 'full', 'unlimited', 'wildcard'];
    return unlimitedKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateDisabledAuth(text: string): boolean {
    const disabledKeywords = ['false', 'no', '0', 'disabled', 'off'];
    return disabledKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateMissingRBAC(text: string): boolean {
    const missingKeywords = ['without', 'no', 'missing'];
    const rbacKeywords = ['role', 'permission', 'access[_-]?control'];
    return missingKeywords.some(missing => text.toLowerCase().includes(missing)) &&
           rbacKeywords.some(rbac => text.toLowerCase().includes(rbac));
  }

  private validatePersistentAccess(text: string): boolean {
    const persistentKeywords = ['permanent', 'persistent', 'always', 'forever'];
    const elevatedKeywords = ['admin', 'root', 'elevated'];
    return persistentKeywords.some(persistent => text.toLowerCase().includes(persistent)) &&
           elevatedKeywords.some(elevated => text.toLowerCase().includes(elevated));
  }

  private validateAuthBypass(text: string): boolean {
    const bypassKeywords = ['bypass', 'skip', 'ignore'];
    const authKeywords = ['auth', 'authentication', 'login'];
    return bypassKeywords.some(bypass => text.toLowerCase().includes(bypass)) &&
           authKeywords.some(auth => text.toLowerCase().includes(auth));
  }

  private validateSystemAccess(text: string): boolean {
    const systemKeywords = ['system', 'os', 'kernel', 'hardware'];
    return systemKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateInsecureMCP(text: string): boolean {
    const insecureKeywords = ['unrestricted', 'open', 'public'];
    return insecureKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateMCPNoAuth(text: string): boolean {
    const noAuthKeywords = ['no[_-]?auth', 'without[_-]?auth'];
    return noAuthKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateFileSystemAccess(text: string): boolean {
    const fsKeywords = ['file', 'directory', 'path', 'fs'];
    return fsKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateNetworkAccess(text: string): boolean {
    const networkKeywords = ['network', 'http', 'https', 'api', 'endpoint'];
    return networkKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private getLineContext(lineContent: string, column: number): string {
    const start = Math.max(0, column - 20);
    const end = Math.min(lineContent.length, column + 20);
    return lineContent.substring(start, end).trim();
  }

  private generateSuggestion(type: string, context: AiAgentContext): string {
    const suggestions = {
      'Elevated AI Agent Privileges': 'Implement least privilege principle. Use role-based access control (RBAC) and temporary elevated access only when necessary.',
      'Unlimited AI Agent Permissions': 'Define specific, limited permissions for AI agents. Use principle of least privilege and granular access controls.',
      'Disabled AI Agent Authentication': 'Enable authentication for all AI agents. Use secure authentication mechanisms and never disable auth in production.',
      'Missing AI Agent RBAC': 'Implement role-based access control for AI agents. Define specific roles and permissions based on agent capabilities.',
      'Persistent Elevated AI Access': 'Use temporary elevated access with time limits. Implement just-in-time access and automatic privilege revocation.',
      'AI Agent Auth Bypass': 'Remove any authentication bypass mechanisms. Implement proper authentication and authorization for all AI agent interactions.',
      'AI Agent System Access': 'Restrict AI agent access to system resources. Use sandboxing and isolation techniques to limit system access.',
      'Insecure MCP Server Access': 'Secure MCP server access with authentication and authorization. Use network isolation and access controls.',
      'MCP Server Without Auth': 'Implement authentication for MCP servers. Use secure authentication mechanisms and access controls.',
      'AI Agent File System Access': 'Limit AI agent file system access to specific directories. Use read-only access where possible and implement access controls.',
      'AI Agent Network Access': 'Restrict AI agent network access to specific endpoints. Use network segmentation and access controls.'
    };
    
    let suggestion = suggestions[type as keyof typeof suggestions] || 'Implement proper access controls for AI agents. Use least privilege principle and secure authentication.';
    
    if (context.framework) {
      suggestion += ` For ${context.framework}, consider using framework-specific security features and access control patterns.`;
      
      if (context.framework === 'openai') {
        suggestion += ' Use OpenAI API key restrictions and content filtering.';
      } else if (context.framework === 'anthropic') {
        suggestion += ' Use Anthropic safety features and content filtering.';
      } else if (context.framework === 'langchain') {
        suggestion += ' Use LangChain security features and agent isolation.';
      }
    }
    
    return suggestion;
  }
}