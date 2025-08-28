import { BaseRule, FileContent, SecurityIssue } from '../types';

interface SensitiveDataContext {
  isInComment: boolean;
  isInString: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  isInDevelopment: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
  hasEnvironmentVariables: boolean;
  issueType: string | undefined;
}

export class HardcodedSensitiveDataRule extends BaseRule {
  readonly name = 'hardcoded-sensitive-data';
  readonly description = 'Detects hardcoded sensitive information in configuration files with context-aware analysis';
  readonly severity = 'critical' as const;

  private readonly sensitivePatterns = [
    // Database connections: Expanded coverage
    { 
      pattern: /(?:database_url|db_url|connection_string)\s*[:=]\s*['"`]([^'"`\s]+)['"`]/gi, 
      type: 'Database Connection',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateDatabaseConnection(text)
    },
    { 
      pattern: /(?:mongodb|mysql|postgres|redis):\/\/[^'"`\s]+/gi, 
      type: 'Database URL',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateDatabaseURL(text)
    },
    
    // JDBC, MSSQL, Oracle patterns: Expanded coverage
    { 
      pattern: /jdbc:(?:mysql|postgresql|oracle|sqlserver|mssql):\/\/[^'"`\s]+/gi, 
      type: 'JDBC Connection String',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateJDBCConnection(text)
    },
    { 
      pattern: /(?:oracle|mssql|sqlserver)_(?:host|server|port|database|db)\s*[:=]\s*['"`][^'"`\s]+['"`]/gi, 
      type: 'Database Configuration',
      confidence: 0.85,
      severity: 'critical' as const,
      validation: (text: string) => this.validateDatabaseConfig(text)
    },
    
    // Encryption keys: Expanded coverage
    { 
      pattern: /(?:encryption_key|secret_key|private_key)\s*[:=]\s*['"`]([a-zA-Z0-9+/=]{20,})['"`]/gi, 
      type: 'Encryption Key',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateEncryptionKey(text)
    },
    { 
      pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi, 
      type: 'Private Key',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validatePrivateKey(text)
    },
    
    // Generic high entropy keys: Expanded coverage
    { 
      pattern: /(?:key|secret|token)\s*[:=]\s*['"`]([a-zA-Z0-9+/=_-]{32,})['"`]/gi, 
      type: 'High-Entropy Secret',
      confidence: 0.8,
      severity: 'critical' as const,
      validation: (text: string) => this.validateHighEntropySecret(text)
    },
    
    // Configuration secrets: Expanded coverage
    { 
      pattern: /(?:app_secret|session_secret|jwt_secret)\s*[:=]\s*['"`]([^'"`\s]{16,})['"`]/gi, 
      type: 'Application Secret',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateApplicationSecret(text)
    },
    { 
      pattern: /(?:salt|hash_salt)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]/gi, 
      type: 'Cryptographic Salt',
      confidence: 0.7,
      severity: 'high' as const,
      validation: (text: string) => this.validateCryptographicSalt(text)
    },
    
    // Third-party service keys: Expanded coverage
    { 
      pattern: /(?:stripe_secret|stripe_key)\s*[:=]\s*['"`](sk_[a-zA-Z0-9_]+)['"`]/gi, 
      type: 'Stripe Secret Key',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateStripeKey(text)
    },
    { 
      pattern: /(?:sendgrid_api_key)\s*[:=]\s*['"`](SG\.[a-zA-Z0-9_\-\.]+)['"`]/gi, 
      type: 'SendGrid API Key',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateSendGridKey(text)
    },
    { 
      pattern: /(?:twilio_auth_token)\s*[:=]\s*['"`]([a-zA-Z0-9]{32})['"`]/gi, 
      type: 'Twilio Auth Token',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateTwilioToken(text)
    },
    
    // AWS, Azure, GCP patterns: Expanded coverage
    { 
      pattern: /(?:aws_access_key|aws_secret_key|azure_key|gcp_key)\s*[:=]\s*['"`]([a-zA-Z0-9+/=]{20,})['"`]/gi, 
      type: 'Cloud Provider Key',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateCloudProviderKey(text)
    },
    
    // Generic API keys: Expanded coverage
    { 
      pattern: /(?:api_key|apikey)\s*[:=]\s*['"`](sk_[a-zA-Z0-9_]+)['"`]/gi, 
      type: 'API Key',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateAPIKey(text)
    },
    
    // Generic sensitive patterns: Expanded coverage
    { 
      pattern: /(?:admin_password|root_password|db_password)\s*[:=]\s*['"`]([^'"`\s]{6,})['"`]/gi, 
      type: 'Admin Password',
      confidence: 0.8,
      severity: 'high' as const,
      validation: (text: string) => this.validateAdminPassword(text)
    },
    { 
      pattern: /(?:webhook_secret|signing_secret)\s*[:=]\s*['"`]([^'"`\s]{16,})['"`]/gi, 
      type: 'Webhook Secret',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateWebhookSecret(text)
    },
    
    // Configuration file patterns: Expanded coverage
    { 
      pattern: /password\s*[:=]\s*['"`](?!.*(?:password|secret|key|token))[^'"`\s]{8,}['"`]/gi, 
      type: 'Configuration Password',
      confidence: 0.7,
      severity: 'high' as const,
      validation: (text: string) => this.validateConfigurationPassword(text)
    }
  ];

  // Multi line comment patterns: Expanded coverage
  private readonly multiLineCommentPatterns = [
    /\/\*[\s\S]*?\*\//g,  // JavaScript/TypeScript multi-line comments
    /""".*?"""/gs,        // Python docstrings
    /<!--.*?-->/gs,       // HTML comments
    /#\[\[.*?\]\]/gs,     // Lua multi-line comments
    /\/\*[\s\S]*?\*\//g,  // C/C++ multi-line comments
    /\/\*[\s\S]*?\*\//g   // Java multi-line comments
  ];

  private readonly falsePositivePatterns = [
    // Common false positive patterns: Expanded coverage
    /example/i,
    /sample/i,
    /demo/i,
    /placeholder/i,
    /your[_-]?(?:key|secret|password)/i,
    /\$\{.*\}/,  // Environment variables
    /%.*%/,      // Windows environment variables
    /\{\{.*\}\}/, // Template variables
    /^[x]+$/i,   // Only x's
    /^[*]+$/,    // Only asterisks
    /^[0]+$/,    // Only zeros
    /^[1]+$/,    // Only ones
    /test/i,
    /mock/i,
    /fake/i,
    /dummy/i,
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
    /\/\/.*(?:password|secret|key)/i,
    /#.*(?:password|secret|key)/i,
    /\/\*.*(?:password|secret|key).*\*\//i,
    /<!--.*(?:password|secret|key).*-->/i,
    /password.*=.*['"`]password['"`]/i,
    /secret.*=.*['"`]secret['"`]/i,
    /key.*=.*['"`]key['"`]/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const hasEnvironmentVariables = this.hasEnvironmentVariables(fileContent.content);

    // Focuses on configuration files and certain code files
    if (!this.isSensitiveFile(fileContent.path)) {
      return issues;
    }

    for (const { pattern, type, confidence, severity, validation } of this.sensitivePatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework, hasEnvironmentVariables, type);
        
        // Skips if in safe context
        if (this.isSafeContext(context)) {
          continue;
        }
        
        // Validates the sensitive data issue
        if (!validation(matchedText)) {
          continue;
        }
        
        // Calculates final confidence and severity based on context
        const finalConfidence = this.calculateConfidence(confidence, context);
        const finalSeverity = this.calculateSeverity(severity, context);
        
        if (finalConfidence >= 0.5) {
          issues.push(this.createIssue(
            fileContent.path,
            line,
            column,
            lineContent,
            `${finalSeverity.toUpperCase()}: Hardcoded ${type} found (confidence: ${Math.round(finalConfidence * 100)}%): ${this.maskSensitiveData(matchedText)}`,
            this.generateSuggestion(type, context),
            finalSeverity
          ));
        }
      }
    }

    return issues;
  }

  // Context analysis methods: Expanded coverage
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
      'env': 'environment',
      'yaml': 'yaml',
      'yml': 'yaml',
      'json': 'json',
      'toml': 'toml',
      'ini': 'ini',
      'properties': 'properties'
    };
    return languageMap[ext || ''] || 'unknown';
  }

  private detectFramework(content: string, language: string): string | undefined {
    if (language === 'javascript' || language === 'typescript') {
      if (content.includes('express') || content.includes('app.get') || content.includes('app.post')) return 'express';
      if (content.includes('next') || content.includes('Next.js')) return 'nextjs';
      if (content.includes('react') || content.includes('jsx') || content.includes('tsx')) return 'react';
    }
    if (language === 'python') {
      if (content.includes('django') || content.includes('Django')) return 'django';
      if (content.includes('flask') || content.includes('Flask')) return 'flask';
    }
    if (language === 'php') {
      if (content.includes('laravel') || content.includes('Laravel')) return 'laravel';
    }
    return undefined;
  }

  private hasEnvironmentVariables(content: string): boolean {
    const envPatterns = [
      /process\.env\./i,
      /os\.environ\./i,
      /\$_ENV/i,
      /getenv\(/i,
      /System\.getenv\(/i
    ];
    return envPatterns.some(pattern => pattern.test(content));
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string, hasEnvironmentVariables?: boolean, issueType?: string): SensitiveDataContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language, fileContent.content, line),
      isInString: this.isInString(currentLine, column),
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(fileContent.path),
      isInDevelopment: this.isInDevelopment(surroundingLines),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework,
      hasEnvironmentVariables: hasEnvironmentVariables || false,
      issueType
    };
  }

  private isSafeContext(context: SensitiveDataContext): boolean {
    
    if (context.isInComment) return true;
    
    if (context.isInTestFile) return true;
    
    if (context.isInDocumentation) return true;
    
    if (context.isInDevelopment) return true;
    
    if (this.falsePositivePatterns.some(pattern => pattern.test(context.surroundingCode))) {
      return true;
    }
    
    return false;
  }

  private isInComment(line: string, language: string, fullContent: string, lineNumber: number): boolean {
    const trimmed = line.trim();
    
    // Checks for single line comments
    if (language === 'javascript' || language === 'typescript') {
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) return true;
    }
    if (language === 'python') {
      if (trimmed.startsWith('#')) return true;
    }
    if (language === 'php') {
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('#')) return true;
    }
    if (language === 'yaml') {
      if (trimmed.startsWith('#')) return true;
    }
    
    // Checks for multi line comments
    const beforeContent = fullContent.split('\n').slice(0, lineNumber).join('\n');
    
    for (const pattern of this.multiLineCommentPatterns) {
      const matches = beforeContent.match(pattern);
      if (matches && matches.length > 0) {
        // Checks if the current line is within a multi line comment
        const lastMatch = matches[matches.length - 1];
        if (lastMatch) {
          const lastMatchIndex = beforeContent.lastIndexOf(lastMatch);
          const commentEndIndex = lastMatchIndex + lastMatch.length;
          
          // If we're still within the comment, returns true
          if (commentEndIndex >= beforeContent.length) {
            return true;
          }
        }
      }
    }
    
    return false;
  }

  private isInString(line: string, column: number): boolean {
    const before = line.substring(0, column);
    const quotes = (before.match(/['"`]/g) || []).length;
    return quotes % 2 === 1;
  }

  private isInTestFile(filePath: string): boolean {
    return filePath.includes('test') || 
           filePath.includes('spec') || 
           filePath.includes('__tests__') ||
           filePath.includes('mock') ||
           filePath.match(/\.(test|spec)\./i) !== null;
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

  private calculateConfidence(baseConfidence: number, context: SensitiveDataContext): number {
    let confidence = baseConfidence;
    
    // Adjusts confidence based on context
    if (context.hasEnvironmentVariables) confidence *= 0.8; // Reduces if env vars present
    if (context.framework) confidence *= 1.1; // Increases for known frameworks
    
    return Math.min(confidence, 1.0);
  }

  private calculateSeverity(baseSeverity: 'critical' | 'high' | 'medium', context: SensitiveDataContext): 'critical' | 'high' | 'medium' {
    let severity = baseSeverity;
    
    // Adjusts severity based on context
    if (context.hasEnvironmentVariables) {
      if (severity === 'critical') severity = 'high';
    }
    
    return severity;
  }

  private generateSuggestion(type: string, context: SensitiveDataContext): string {
    const suggestions = {
      'Database Connection': 'Move database connection strings to environment variables. Use connection pooling and secure credential management.',
      'Database URL': 'Use environment variables for database URLs. Implement proper connection string management.',
      'JDBC Connection String': 'Store JDBC connection strings in environment variables or secure configuration files.',
      'Database Configuration': 'Use environment variables for database configuration. Implement secure credential management.',
      'Encryption Key': 'Store encryption keys in environment variables or use a key management service (KMS).',
      'Private Key': 'Store private keys in secure key management systems. Never commit private keys to version control.',
      'High-Entropy Secret': 'Move high-entropy secrets to environment variables or secure secret management systems.',
      'Application Secret': 'Use environment variables for application secrets. Implement secure secret rotation.',
      'Cryptographic Salt': 'Generate salts dynamically or store in secure configuration. Use cryptographically secure random generation.',
      'Stripe Secret Key': 'Use Stripe\'s environment variables (STRIPE_SECRET_KEY). Never expose live keys in code.',
      'SendGrid API Key': 'Store SendGrid API keys in environment variables. Use API key rotation.',
      'Twilio Auth Token': 'Use Twilio\'s environment variables (TWILIO_AUTH_TOKEN). Implement secure token management.',
      'Cloud Provider Key': 'Use cloud provider IAM roles and environment variables. Implement least privilege access.',
      'API Key': 'Store API keys in environment variables. Use API key rotation and secure storage.',
      'Admin Password': 'Use environment variables for admin passwords. Implement secure password management.',
      'Webhook Secret': 'Store webhook secrets in environment variables. Use secure secret management.',
      'Configuration Password': 'Move passwords to environment variables. Use secure configuration management.'
    };
    
    let suggestion = suggestions[type as keyof typeof suggestions] || 'Move sensitive data to environment variables or secure configuration management. Use proper secret management practices.';
    
    if (context.framework) {
      suggestion += ` For ${context.framework}, consider using framework-specific configuration management.`;
      
      if (context.framework === 'express') {
        suggestion += ' Use dotenv for environment variables and express-session for secure session management.';
      } else if (context.framework === 'django') {
        suggestion += ' Use Django\'s settings.py with environment variables and django-environ for configuration.';
      } else if (context.framework === 'laravel') {
        suggestion += ' Use Laravel\'s .env files and config caching for secure configuration management.';
      }
    }
    
    if (context.language === 'environment') {
      suggestion += ' Consider using a secrets management service like AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault.';
    }
    
    return suggestion;
  }

  private isSensitiveFile(filePath: string): boolean {
    const sensitiveFiles = [
      /\.env/i,
      /\.config/i,
      /\.conf/i,
      /\.ini/i,
      /\.properties/i,
      /\.yaml/i,
      /\.yml/i,
      /\.json/i,
      /\.toml/i,
      /config\./i,
      /settings\./i,
      /constants\./i,
      /\.js$/i,
      /\.ts$/i,
      /\.py$/i,
      /\.php$/i,
      /\.rb$/i,
      /\.jsx$/i,
      /\.tsx$/i,
      /\.vue$/i,
      /\.svelte$/i
    ];

    return sensitiveFiles.some(pattern => pattern.test(filePath));
  }

  private maskSensitiveData(data: string): string {
    if (data.length <= 8) {
      return '*'.repeat(data.length);
    }
    
    const start = data.substring(0, 4);
    const end = data.substring(data.length - 4);
    const middle = '*'.repeat(Math.min(data.length - 8, 10));
    
    return `${start}${middle}${end}`;
  }

  // Validation methods for different sensitive data patterns: Expanded coverage
  private validateDatabaseConnection(text: string): boolean {
    return /(?:database_url|db_url|connection_string)\s*[:=]/.test(text);
  }

  private validateDatabaseURL(text: string): boolean {
    return /(?:mongodb|mysql|postgres|redis):\/\//.test(text);
  }

  private validateJDBCConnection(text: string): boolean {
    return /jdbc:(?:mysql|postgresql|oracle|sqlserver|mssql):\/\//.test(text);
  }

  private validateDatabaseConfig(text: string): boolean {
    return /(?:oracle|mssql|sqlserver)_(?:host|server|port|database|db)\s*[:=]/.test(text);
  }

  private validateEncryptionKey(text: string): boolean {
    return /(?:encryption_key|secret_key|private_key)\s*[:=]/.test(text) && /[a-zA-Z0-9+/=]{20,}/.test(text);
  }

  private validatePrivateKey(text: string): boolean {
    return /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/.test(text);
  }

  private validateHighEntropySecret(text: string): boolean {
    return /(?:key|secret|token)\s*[:=]/.test(text) && /[a-zA-Z0-9+/=_-]{32,}/.test(text);
  }

  private validateApplicationSecret(text: string): boolean {
    return /(?:app_secret|session_secret|jwt_secret)\s*[:=]/.test(text);
  }

  private validateCryptographicSalt(text: string): boolean {
    return /(?:salt|hash_salt)\s*[:=]/.test(text);
  }

  private validateStripeKey(text: string): boolean {
    return /(?:stripe_secret|stripe_key)\s*[:=]/.test(text) && /sk_/.test(text);
  }

  private validateSendGridKey(text: string): boolean {
    return /(?:sendgrid_api_key)\s*[:=]/.test(text) && /SG\./.test(text);
  }

  private validateTwilioToken(text: string): boolean {
    return /(?:twilio_auth_token)\s*[:=]/.test(text);
  }

  private validateCloudProviderKey(text: string): boolean {
    return /(?:aws_access_key|aws_secret_key|azure_key|gcp_key)\s*[:=]/.test(text);
  }

  private validateAPIKey(text: string): boolean {
    return /(?:api_key|apikey)\s*[:=]/.test(text) && /sk_/.test(text);
  }

  private validateAdminPassword(text: string): boolean {
    return /(?:admin_password|root_password|db_password)\s*[:=]/.test(text);
  }

  private validateWebhookSecret(text: string): boolean {
    return /(?:webhook_secret|signing_secret)\s*[:=]/.test(text);
  }

  private validateConfigurationPassword(text: string): boolean {
    return /password\s*[:=]/.test(text) && !/(?:password|secret|key|token)/.test(text);
  }
} 