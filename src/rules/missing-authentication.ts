import { BaseRule, FileContent, SecurityIssue } from '../types';

export class MissingAuthenticationRule extends BaseRule {
  readonly name = 'missing-authentication';
  readonly description = 'Detects potentially unprotected routes and endpoints';
  readonly severity = 'high' as const;

  private readonly routePatterns = [
    // Express.js
    { pattern: /app\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*(?!.*auth|.*login|.*verify|.*middleware)/gi, framework: 'Express' },
    { pattern: /router\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*(?!.*auth|.*login|.*verify|.*middleware)/gi, framework: 'Express' },
    
    // Next.js API routes
    { pattern: /export\s+(?:default\s+)?(?:async\s+)?function\s+handler\s*\([^)]*\)\s*\{(?![\s\S]*auth|[\s\S]*login|[\s\S]*verify)/gi, framework: 'Next.js' },
    
    // Flask
    { pattern: /@app\.route\s*\(\s*['"`]([^'"`]+)['"`](?:[^)]*)\)\s*\n\s*def\s+\w+\s*\([^)]*\)\s*:(?![\s\S]*auth|[\s\S]*login|[\s\S]*verify)/gi, framework: 'Flask' },
    
    // FastAPI
    { pattern: /@app\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]\s*\)\s*\n\s*(?:async\s+)?def\s+\w+\s*\([^)]*\)\s*:(?![\s\S]*auth|[\s\S]*login|[\s\S]*verify)/gi, framework: 'FastAPI' },
    
    // Laravel
    { pattern: /Route::(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*(?!.*auth|.*login|.*verify|.*middleware)/gi, framework: 'Laravel' }
  ];

  private readonly protectedPatterns = [
    /auth/i,
    /login/i,
    /verify/i,
    /middleware/i,
    /guard/i,
    /protect/i,
    /secure/i,
    /jwt/i,
    /token/i,
    /session/i,
    /permission/i,
    /role/i
  ];

  private readonly publicEndpoints = [
    /\/public/i,
    /\/health/i,
    /\/ping/i,
    /\/status/i,
    /\/docs/i,
    /\/swagger/i,
    /\/api-docs/i,
    /\/favicon/i,
    /\/robots\.txt/i,
    /\/sitemap/i,
    /\/login/i,
    /\/register/i,
    /\/signup/i,
    /\/forgot-password/i,
    /\/reset-password/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, framework } of this.routePatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const route = this.extractRoute(match);
        
        // Skip if it's a known public endpoint
        if (this.isPublicEndpoint(route)) {
          continue;
        }

        // Skip if the surrounding code suggests authentication
        if (this.hasAuthenticationContext(fileContent.content, line)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Potentially unprotected ${framework} route: ${route}`,
          `Add authentication middleware or verify that this endpoint should be publicly accessible. Consider using authentication guards, middleware, or decorators.`
        ));
      }
    }

    return issues;
  }

  private extractRoute(match: RegExpMatchArray): string {
    // Try to find the route path in the match
    for (let i = 1; i < match.length; i++) {
      const matchGroup = match[i];
      if (matchGroup && matchGroup.startsWith('/')) {
        return matchGroup;
      }
    }
    return match[0] || '';
  }

  private isPublicEndpoint(route: string): boolean {
    return this.publicEndpoints.some(pattern => pattern.test(route));
  }

  private hasAuthenticationContext(content: string, lineNumber: number): boolean {
    const lines = content.split('\n');
    const contextRange = 10; // Check 10 lines before and after
    
    const startLine = Math.max(0, lineNumber - contextRange - 1);
    const endLine = Math.min(lines.length, lineNumber + contextRange);
    
    const contextLines = lines.slice(startLine, endLine).join('\n');
    
    return this.protectedPatterns.some(pattern => pattern.test(contextLines));
  }
} 