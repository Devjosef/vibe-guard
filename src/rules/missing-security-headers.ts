import { BaseRule, FileContent, SecurityIssue } from '../types';

export class MissingSecurityHeadersRule extends BaseRule {
  readonly name = 'missing-security-headers';
  readonly description = 'Detects missing HTTP security headers';
  readonly severity = 'medium' as const;

  private readonly securityHeaders = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Strict-Transport-Security',
    'Referrer-Policy',
    'Permissions-Policy',
    'X-Permitted-Cross-Domain-Policies'
  ];

  private readonly serverPatterns = [
    // Express.js patterns
    { pattern: /app\.(?:get|post|put|delete|patch|use)\s*\(/gi, type: 'Express route handler' },
    { pattern: /router\.(?:get|post|put|delete|patch|use)\s*\(/gi, type: 'Express router' },
    { pattern: /app\.listen\s*\(/gi, type: 'Express server' },
    
    // Next.js API routes
    { pattern: /export\s+(?:default\s+)?(?:async\s+)?function\s+handler/gi, type: 'Next.js API handler' },
    { pattern: /export\s+(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\([^)]*req[^)]*res[^)]*\)/gi, type: 'Next.js API function' },
    
    // Node.js HTTP server
    { pattern: /createServer\s*\(\s*(?:async\s+)?\([^)]*req[^)]*res[^)]*\)/gi, type: 'Node.js HTTP server' },
    { pattern: /http\.createServer/gi, type: 'HTTP server creation' },
    
    // Framework response patterns
    { pattern: /res\.(?:send|json|render|redirect)/gi, type: 'Response method' },
    { pattern: /response\.(?:send|json|render|redirect)/gi, type: 'Response method' },
    
    // Flask patterns
    { pattern: /@app\.route/gi, type: 'Flask route' },
    { pattern: /return\s+(?:render_template|jsonify|redirect)/gi, type: 'Flask response' },
    
    // Django patterns
    { pattern: /def\s+\w+\s*\([^)]*request[^)]*\)/gi, type: 'Django view function' },
    { pattern: /HttpResponse\s*\(/gi, type: 'Django HTTP response' },
    
    // PHP patterns
    { pattern: /header\s*\(\s*['"`][^'"`]*['"`]/gi, type: 'PHP header function' }
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Only check server/web application files
    if (!this.isWebApplicationFile(fileContent.path)) {
      return issues;
    }

    // Check if file contains server/route patterns
    const hasServerCode = this.hasServerCode(fileContent.content);
    if (!hasServerCode) {
      return issues;
    }

    // Check for missing security headers
    this.checkMissingHeaders(fileContent, issues);

    return issues;
  }

  private isWebApplicationFile(filePath: string): boolean {
    const webFiles = [
      /\.js$/i,
      /\.ts$/i,
      /\.jsx$/i,
      /\.tsx$/i,
      /\.py$/i,
      /\.php$/i,
      /\.rb$/i,
      /\.go$/i,
      /\.java$/i,
      /\.cs$/i
    ];

    // Skip test files
    const testPatterns = [
      /test/i,
      /spec/i,
      /\.test\./i,
      /\.spec\./i,
      /__tests__/i
    ];

    if (testPatterns.some(pattern => pattern.test(filePath))) {
      return false;
    }

    return webFiles.some(pattern => pattern.test(filePath));
  }

  private hasServerCode(content: string): boolean {
    return this.serverPatterns.some(({ pattern }) => pattern.test(content));
  }

  private checkMissingHeaders(fileContent: FileContent, issues: SecurityIssue[]): void {
    const content = fileContent.content;
    const missingHeaders: string[] = [];

    for (const header of this.securityHeaders) {
      if (!this.hasSecurityHeader(content, header)) {
        missingHeaders.push(header);
      }
    }

    if (missingHeaders.length > 0) {
      // Find a good location to report the issue (first route handler or server setup)
      const location = this.findReportLocation(fileContent);
      
      if (location) {
        issues.push(this.createIssue(
          fileContent.path,
          location.line,
          location.column,
          location.lineContent,
          `Missing security headers: ${missingHeaders.join(', ')}`,
          `Add security headers to protect against common attacks. Consider using helmet.js for Express or implementing headers manually: ${this.getHeaderRecommendations(missingHeaders)}`
        ));
      }
    }
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
      new RegExp(`response\\[['"\`]${header}['"\`]\\]`, 'gi')
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

  private getHeaderRecommendations(missingHeaders: string[]): string {
    const recommendations: string[] = [];
    
    if (missingHeaders.includes('Content-Security-Policy')) {
      recommendations.push("CSP: \"default-src 'self'\"");
    }
    
    if (missingHeaders.includes('X-Frame-Options')) {
      recommendations.push("X-Frame-Options: 'DENY'");
    }
    
    if (missingHeaders.includes('X-Content-Type-Options')) {
      recommendations.push("X-Content-Type-Options: 'nosniff'");
    }
    
    if (missingHeaders.includes('Strict-Transport-Security')) {
      recommendations.push("HSTS: 'max-age=31536000; includeSubDomains'");
    }

    return recommendations.slice(0, 2).join(', ') + (recommendations.length > 2 ? '...' : '');
  }
} 