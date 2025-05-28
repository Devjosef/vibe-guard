import { BaseRule, FileContent, SecurityIssue } from '../types';

export class InsecureHttpRule extends BaseRule {
  readonly name = 'insecure-http';
  readonly description = 'Detects insecure HTTP usage instead of HTTPS';
  readonly severity = 'medium' as const;

  private readonly httpPatterns = [
    // Direct HTTP URLs
    { pattern: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"`\s]+['"`]/gi, type: 'HTTP URL' },
    
    // API endpoints
    { pattern: /(?:api_url|endpoint|base_url)\s*[:=]\s*['"`]http:\/\/[^'"`\s]+['"`]/gi, type: 'HTTP API Endpoint' },
    { pattern: /fetch\s*\(\s*['"`]http:\/\/[^'"`\s]+['"`]/gi, type: 'HTTP Fetch Request' },
    { pattern: /axios\.(?:get|post|put|delete)\s*\(\s*['"`]http:\/\/[^'"`\s]+['"`]/gi, type: 'HTTP Axios Request' },
    
    // Configuration
    { pattern: /(?:protocol|scheme)\s*[:=]\s*['"`]http['"`]/gi, type: 'HTTP Protocol Configuration' },
    { pattern: /secure\s*[:=]\s*false/gi, type: 'Insecure Configuration' },
    
    // Express/Node.js specific
    { pattern: /app\.listen\s*\(\s*\d+\s*,\s*['"`]0\.0\.0\.0['"`]/gi, type: 'HTTP Server Binding' },
    { pattern: /createServer\s*\(\s*(?!.*https)/gi, type: 'HTTP Server Creation' },
    
    // Cookie security
    { pattern: /httpOnly\s*:\s*false/gi, type: 'Insecure Cookie Configuration' },
    { pattern: /secure\s*:\s*false/gi, type: 'Insecure Cookie Security' },
    
    // Mixed content
    { pattern: /src\s*=\s*['"`]http:\/\/[^'"`\s]+['"`]/gi, type: 'Mixed Content Resource' },
    { pattern: /href\s*=\s*['"`]http:\/\/[^'"`\s]+['"`]/gi, type: 'Mixed Content Link' },
    
    // Framework specific
    { pattern: /@RequestMapping.*http:/gi, type: 'HTTP Spring Mapping' },
    { pattern: /ALLOWED_HOSTS\s*=\s*\[\s*['"`]\*['"`]/gi, type: 'Permissive Host Configuration' }
  ];

  private readonly safePatterns = [
    /localhost/i,
    /127\.0\.0\.1/,
    /0\.0\.0\.0/,
    /\.local/i,
    /development/i,
    /dev/i,
    /staging/i,
    /test/i,
    /mock/i,
    /example/i,
    /placeholder/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, type } of this.httpPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        
        // Skip if it's in a development/test context
        if (this.isDevelopmentContext(matchedText) || this.isDevelopmentContext(lineContent)) {
          continue;
        }

        // Skip if the file appears to be a test or development file
        if (this.isTestFile(fileContent.path)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Insecure ${type} detected: ${this.extractUrl(matchedText)}`,
          `Use HTTPS instead of HTTP for secure communication. Replace 'http://' with 'https://' and ensure SSL/TLS certificates are properly configured.`
        ));
      }
    }

    return issues;
  }

  private isDevelopmentContext(text: string): boolean {
    return this.safePatterns.some(pattern => pattern.test(text));
  }

  private isTestFile(filePath: string): boolean {
    const testPatterns = [
      /test/i,
      /spec/i,
      /\.test\./i,
      /\.spec\./i,
      /__tests__/i,
      /tests\//i,
      /spec\//i,
      /dev/i,
      /development/i,
      /local/i
    ];

    return testPatterns.some(pattern => pattern.test(filePath));
  }

  private extractUrl(text: string): string {
    const urlMatch = text.match(/http:\/\/[^'"`\s]+/);
    return urlMatch ? urlMatch[0] : text;
  }
} 