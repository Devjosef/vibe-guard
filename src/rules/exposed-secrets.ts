import { BaseRule, FileContent, SecurityIssue } from '../types';

export class ExposedSecretsRule extends BaseRule {
  readonly name = 'exposed-secrets';
  readonly description = 'Detects exposed API keys, tokens, and credentials';
  readonly severity = 'critical' as const;

  private readonly secretPatterns = [
    { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi, type: 'API Key' },
    { pattern: /(?:secret[_-]?key|secretkey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi, type: 'Secret Key' },
    { pattern: /(?:access[_-]?token|accesstoken)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi, type: 'Access Token' },
    
    { pattern: /AKIA[0-9A-Z]{16}/g, type: 'AWS Access Key' },
    { pattern: /(?:aws[_-]?secret|AWS_SECRET)\s*[:=]\s*['"`]([a-zA-Z0-9/+=]{40})/gi, type: 'AWS Secret' },
    
    { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: 'GitHub Personal Access Token' },
    { pattern: /ghs_[a-zA-Z0-9]{36}/g, type: 'GitHub App Token' },
    { pattern: /ghr_[a-zA-Z0-9]{36}/g, type: 'GitHub Refresh Token' },
    
    { pattern: /AIza[0-9A-Za-z_\-]{35}/g, type: 'Google API Key' },
    
    { pattern: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g, type: 'Slack Token' },
    
    { pattern: /eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*/g, type: 'JWT Token' },
    
    { pattern: /(?:mongodb|mysql|postgres|redis):\/\/[^\s'"]+/gi, type: 'Database URL' },
    
    { pattern: /(?:secret|token|key|auth|password)\s*[:=]\s*['"`]([A-Za-z0-9+/]{40,}={0,2})['"`]/gi, type: 'Base64 Encoded Secret' },
    
    { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{8,})/gi, type: 'Password' },
    { pattern: /(?:^|[^a-zA-Z0-9_])(?:token|auth)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi, type: 'Auth Token' }
  ];

  private readonly falsePositivePatterns = [
    /example/i,
    /demo/i,
    /placeholder/i,
    /your[_-]?key/i,
    /your[_-]?token/i,
    /your[_-]?secret/i,
    /\$\{.*\}/,
    /%.*%/,
    /\{\{.*\}\}/,
    /^xxx+$/i,
    /^aaa+$/i,
    /^000+$/,
    /^111+$/,
    /^123+$/,
    /test/i,
    /mock/i,
    /sample/i,
    /dummy/i,
    /fake/i,
    /^(.)\1{7,}$/,
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
    /\/\/.*(?:key|token|secret)/i,
    /#.*(?:key|token|secret)/i,
    /\/\*.*(?:key|token|secret).*\*\//i,
    /<!--.*(?:key|token|secret).*-->/i,
    /key.*=.*['"`]key['"`]/i,
    /token.*=.*['"`]token['"`]/i,
    /secret.*=.*['"`]secret['"`]/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, type } of this.secretPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        
        if (this.isFalsePositive(matchedText)) {
          continue;
        }

        if (type === 'Base64 Encoded Secret' && !this.isValidBase64Secret(matchedText)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Exposed ${type} detected: ${this.maskSecret(matchedText)}`,
          `Remove hardcoded secrets and use environment variables or secure secret management instead. Consider using tools like dotenv for local development.`
        ));
      }
    }

    return issues;
  }

  private isFalsePositive(text: string): boolean {
    if (this.falsePositivePatterns.some(pattern => pattern.test(text))) {
      return true;
    }

    const secretMatch = text.match(/['"`]([^'"`]+)['"`]/);
    if (secretMatch && secretMatch[1]) {
      const secretValue = secretMatch[1];
      
      if (/^(.)\1{7,}$/.test(secretValue)) {
        return true;
      }
      
      if (/^(012|123|234|345|456|567|678|789|890)+$/.test(secretValue)) {
        return true;
      }
    }

    return false;
  }

  private isValidBase64Secret(text: string): boolean {
    try {
      const base64Match = text.match(/([A-Za-z0-9+/]{32,}={0,2})/);
      if (!base64Match || !base64Match[1]) return false;
      
      const base64String = base64Match[1];
      
      const decoded = Buffer.from(base64String, 'base64').toString('utf-8');
      
      if (/^(test|example|demo|placeholder|sample|dummy)/i.test(decoded)) {
        return false;
      }
      
      if (decoded.length < 8) {
        return false;
      }
      
      if (/^(.)\1+$/.test(decoded)) {
        return false;
      }
      
      return true;
    } catch {
      return false;
    }
  }

  private maskSecret(secret: string): string {
    if (secret.length <= 8) {
      return '*'.repeat(secret.length);
    }
    
    const start = secret.substring(0, 4);
    const end = secret.substring(secret.length - 4);
    const middle = '*'.repeat(Math.min(secret.length - 8, 10));
    
    return `${start}${middle}${end}`;
  }
} 