import { BaseRule, FileContent, SecurityIssue } from '../types';

export class OpenCorsRule extends BaseRule {
  readonly name = 'open-cors';
  readonly description = 'Detects overly permissive CORS configurations';
  readonly severity = 'high' as const;

  private readonly corsPatterns = [
    // Wildcard CORS origins
    { pattern: /Access-Control-Allow-Origin\s*:\s*['"`]\*['"`]/gi, message: 'Wildcard CORS origin allows any domain' },
    { pattern: /cors\(\s*\{\s*origin\s*:\s*['"`]\*['"`]/gi, message: 'CORS middleware configured with wildcard origin' },
    { pattern: /\.header\s*\(\s*['"`]Access-Control-Allow-Origin['"`]\s*,\s*['"`]\*['"`]/gi, message: 'Manual CORS header set to wildcard' },
    
    // Express CORS middleware with wildcard
    { pattern: /app\.use\s*\(\s*cors\s*\(\s*\{\s*origin\s*:\s*true/gi, message: 'CORS origin set to true (allows all origins)' },
    { pattern: /app\.use\s*\(\s*cors\s*\(\s*\)\s*\)/gi, message: 'CORS middleware used without origin restrictions' },
    
    // Permissive credentials
    { pattern: /Access-Control-Allow-Credentials\s*:\s*['"`]true['"`]/gi, message: 'CORS credentials enabled - ensure origin is restricted' },
    
    // Overly broad methods
    { pattern: /Access-Control-Allow-Methods\s*:\s*['"`]\*['"`]/gi, message: 'CORS allows all HTTP methods' },
    { pattern: /Access-Control-Allow-Headers\s*:\s*['"`]\*['"`]/gi, message: 'CORS allows all headers' },
    
    // Framework-specific patterns
    { pattern: /@CrossOrigin\s*\(\s*origins\s*=\s*['"`]\*['"`]/gi, message: 'Spring @CrossOrigin annotation with wildcard origin' },
    { pattern: /enable_cors\s*\(\s*origins\s*=\s*\[\s*['"`]\*['"`]/gi, message: 'FastAPI CORS with wildcard origin' }
  ];

  private readonly safePatterns = [
    /localhost/i,
    /127\.0\.0\.1/,
    /\.local/i,
    /development/i,
    /staging/i,
    /test/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, message } of this.corsPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        // Skip if it's in a development/test context
        if (this.isDevelopmentContext(fileContent.content, line)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Permissive CORS configuration: ${message}`,
          `Restrict CORS origins to specific domains. Use specific origins like 'https://yourdomain.com' instead of '*'. Consider using environment variables for different environments.`
        ));
      }
    }

    return issues;
  }

  private isDevelopmentContext(content: string, lineNumber: number): boolean {
    const lines = content.split('\n');
    const contextRange = 5;
    
    const startLine = Math.max(0, lineNumber - contextRange - 1);
    const endLine = Math.min(lines.length, lineNumber + contextRange);
    
    const contextLines = lines.slice(startLine, endLine).join('\n');
    
    return this.safePatterns.some(pattern => pattern.test(contextLines));
  }
} 