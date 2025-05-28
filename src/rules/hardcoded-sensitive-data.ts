import { BaseRule, FileContent, SecurityIssue } from '../types';

export class HardcodedSensitiveDataRule extends BaseRule {
  readonly name = 'hardcoded-sensitive-data';
  readonly description = 'Detects hardcoded sensitive information in configuration files';
  readonly severity = 'critical' as const;

  private readonly sensitivePatterns = [
    // Database connections
    { pattern: /(?:database_url|db_url|connection_string)\s*[:=]\s*['"`]([^'"`\s]+)['"`]/gi, type: 'Database Connection' },
    { pattern: /(?:mongodb|mysql|postgres|redis):\/\/[^'"`\s]+/gi, type: 'Database URL' },
    
    // Encryption keys
    { pattern: /(?:encryption_key|secret_key|private_key)\s*[:=]\s*['"`]([a-zA-Z0-9+/=]{20,})['"`]/gi, type: 'Encryption Key' },
    { pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi, type: 'Private Key' },
    
    // Configuration secrets
    { pattern: /(?:app_secret|session_secret|jwt_secret)\s*[:=]\s*['"`]([^'"`\s]{16,})['"`]/gi, type: 'Application Secret' },
    { pattern: /(?:salt|hash_salt)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]/gi, type: 'Cryptographic Salt' },
    
    // Third-party service keys
    { pattern: /(?:stripe_secret|stripe_key)\s*[:=]\s*['"`](sk_[a-zA-Z0-9_]+)['"`]/gi, type: 'Stripe Secret Key' },
    { pattern: /(?:sendgrid_api_key)\s*[:=]\s*['"`](SG\.[a-zA-Z0-9_\-\.]+)['"`]/gi, type: 'SendGrid API Key' },
    { pattern: /(?:twilio_auth_token)\s*[:=]\s*['"`]([a-zA-Z0-9]{32})['"`]/gi, type: 'Twilio Auth Token' },
    
    // Generic sensitive patterns
    { pattern: /(?:admin_password|root_password|db_password)\s*[:=]\s*['"`]([^'"`\s]{6,})['"`]/gi, type: 'Admin Password' },
    { pattern: /(?:webhook_secret|signing_secret)\s*[:=]\s*['"`]([^'"`\s]{16,})['"`]/gi, type: 'Webhook Secret' },
    
    // Configuration file patterns
    { pattern: /password\s*[:=]\s*['"`](?!.*(?:password|secret|key|token))[^'"`\s]{8,}['"`]/gi, type: 'Configuration Password' }
  ];

  private readonly falsePositivePatterns = [
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
    /fake/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Focus on configuration files and certain code files
    if (!this.isSensitiveFile(fileContent.path)) {
      return issues;
    }

    for (const { pattern, type } of this.sensitivePatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        
        // Skip false positives
        if (this.isFalsePositive(matchedText)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Hardcoded ${type} found: ${this.maskSensitiveData(matchedText)}`,
          `Move sensitive data to environment variables or secure configuration management. Use process.env.VARIABLE_NAME or a secrets management service.`
        ));
      }
    }

    return issues;
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
      /\.rb$/i
    ];

    return sensitiveFiles.some(pattern => pattern.test(filePath));
  }

  private isFalsePositive(text: string): boolean {
    return this.falsePositivePatterns.some(pattern => pattern.test(text));
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
} 