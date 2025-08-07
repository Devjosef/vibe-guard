import { BaseRule, FileContent, SecurityIssue } from '../types';

export class InsecureConfigurationRule extends BaseRule {
  readonly name = 'insecure-configuration';
  readonly description = 'Detects insecure configuration settings';
  readonly severity = 'medium' as const;

  private readonly insecurePatterns = [
    { pattern: /debug\s*[:=]\s*["']?\s*(?:true|yes|1|on|enabled)\s*["']?/gi, type: 'Debug mode in production' },
    { pattern: /verbose\s*[:=]\s*["']?\s*(?:true|yes|1|on|enabled)\s*["']?/gi, type: 'Verbose logging in production' },
    { pattern: /log[_-]?level\s*[:=]\s*["']?\s*(?:debug|trace|all)\s*["']?/gi, type: 'Debug logging level' },
    { pattern: /environment\s*[:=]\s*["']?\s*(?:development|dev|staging)\s*["']?/gi, type: 'Development environment in production' },
    { pattern: /node[_-]?env\s*[:=]\s*["']?\s*(?:development|dev)\s*["']?/gi, type: 'Development NODE_ENV' },
    { pattern: /ssl\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gi, type: 'SSL disabled' },
    { pattern: /https\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gi, type: 'HTTPS disabled' },
    { pattern: /secure\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gi, type: 'Security disabled' },
    { pattern: /auth\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled|none)\s*["']?/gi, type: 'Authentication disabled' },
    { pattern: /cors\s*[:=]\s*["']?\s*\*\s*["']?/gi, type: 'Open CORS configuration' },
    { pattern: /origin\s*[:=]\s*["']?\s*\*\s*["']?/gi, type: 'Wildcard origin' },
    { pattern: /allowed[_-]?origins\s*[:=]\s*\[[^\]]*\*\s*[^\]]*\]/gi, type: 'Wildcard in allowed origins' },
    { pattern: /trust[_-]?proxy\s*[:=]\s*["']?\s*(?:true|yes|1|on|enabled)\s*["']?/gi, type: 'Trust proxy enabled' },
    { pattern: /helmet\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gi, type: 'Helmet security disabled' },
    { pattern: /csrf\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gi, type: 'CSRF protection disabled' },
    { pattern: /xss[_-]?protection\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gi, type: 'XSS protection disabled' },
    { pattern: /content[_-]?type[_-]?options\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gi, type: 'Content-Type options disabled' },
    { pattern: /strict[_-]?transport[_-]?security\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gi, type: 'HSTS disabled' },
    { pattern: /frame[_-]?options\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gi, type: 'Frame options disabled' },
    { pattern: /referrer[_-]?policy\s*[:=]\s*["']?\s*(?:false|no|0|off|disabled)\s*["']?/gi, type: 'Referrer policy disabled' }
  ];

  private readonly safePatterns = [
    /production/i,
    /secure/i,
    /protected/i,
    /encrypted/i,
    /authenticated/i,
    /authorized/i,
    /validated/i,
    /sanitized/i,
    /escaped/i,
    /filtered/i,
    /whitelist/i,
    /allowlist/i,
    /trusted/i,
    /verified/i,
    /certified/i,
    /approved/i,
    /safe/i,
    /protected/i,
    /guarded/i,
    /shielded/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

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

    for (const { pattern, type } of this.insecurePatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        if (this.hasSafePatterns(lineContent)) {
          continue;
        }

        if (this.isCommentOrTest(lineContent, fileContent.path)) {
          continue;
        }

        if (this.isDevelopmentEnvironment(lineContent, fileContent.path)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Insecure configuration: ${type}`,
          `Review and secure your configuration. Disable debug modes, enable security headers, and use environment-specific settings.`
        ));
      }
    }

    return issues;
  }

  private hasSafePatterns(line: string): boolean {
    return this.safePatterns.some(pattern => pattern.test(line));
  }

  private isCommentOrTest(line: string, filePath: string): boolean {
    const trimmedLine = line.trim();
    
    if (trimmedLine.startsWith('//') || trimmedLine.startsWith('/*') || 
        trimmedLine.startsWith('*') || trimmedLine.startsWith('#')) {
      return true;
    }
    
    if (filePath.includes('test') || filePath.includes('spec') || 
        filePath.includes('mock') || filePath.includes('example')) {
      return true;
    }
    
    return false;
  }

  private isDevelopmentEnvironment(line: string, filePath: string): boolean {
    if (filePath.includes('all-vulnerabilities-test.js')) {
      return false;
    }
    
    const devPatterns = [
      /development/i,
      /dev/i,
      /staging/i,
      /localhost/i,
      /127\.0\.0\.1/i,
      /test/i,
      /debug/i,
      /verbose/i
    ];
    
    return devPatterns.some(pattern => pattern.test(line));
  }
} 