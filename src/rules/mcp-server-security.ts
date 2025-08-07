import { BaseRule, FileContent, SecurityIssue } from '../types';

export class McpServerSecurityRule extends BaseRule {
  readonly name = 'mcp-server-security';
  readonly description = 'Detects insecure Model Context Protocol (MCP) server configurations';
  readonly severity = 'high' as const;

  private readonly insecurePatterns = [
    { pattern: /(?:^|\s)(?:allow|enable|permit)\s*[:=]\s*["']?\s*(?:all|true|yes|1|any|everyone|public|unrestricted)\s*["']?/gi, type: 'Insecure MCP configuration' },
    { pattern: /(?:^|\s)(?:deny|disable|block|restrict)\s*[:=]\s*["']?\s*(?:false|no|0|none|empty)\s*["']?/gi, type: 'Disabled MCP security' },
    { pattern: /(?:^|\s)(?:auth|authentication|authorization)\s*[:=]\s*["']?\s*(?:none|false|disabled|off)\s*["']?/gi, type: 'Disabled MCP authentication' },
    { pattern: /(?:^|\s)(?:cors|origin)\s*[:=]\s*["']?\s*\*\s*["']?/gi, type: 'Open CORS in MCP' },
    { pattern: /(?:^|\s)(?:token|key|secret)\s*[:=]\s*["']?\s*(?:test|demo|example|placeholder|123|abc|xyz)\s*["']?/gi, type: 'Weak MCP credentials' }
  ];

  private readonly contextPatterns = [
    /context\s*[:=]/gi,
    /contexts\s*[:=]/gi,
    /contextFile\s*[:=]/gi,
    /contextFiles\s*[:=]/gi,
    /contextPath\s*[:=]/gi,
    /contextDir\s*[:=]/gi,
    /contextDirectory\s*[:=]/gi
  ];

  private readonly falsePositivePatterns = [
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
    /\/\/.*(?:mcp|context)/i,
    /#.*(?:mcp|context)/i,
    /\/\*.*(?:mcp|context).*\*\//i,
    /<!--.*(?:mcp|context).*-->/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    if (fileContent.path.includes('test') || fileContent.path.includes('spec') || 
        fileContent.path.includes('mock') || fileContent.path.includes('example')) {
      return issues;
    }

    const lines = fileContent.content.split('\n');
    let contextFileCount = 0;
    let contextContentCount = 0;
    let securityIssueCount = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;

      const trimmedLine = line.trim();

      if (this.contextPatterns.some(pattern => pattern.test(trimmedLine))) {
        contextFileCount++;
      }

      if (trimmedLine.includes('context') && !this.falsePositivePatterns.some(pattern => pattern.test(trimmedLine))) {
        contextContentCount++;
      }

      for (const { pattern, type } of this.insecurePatterns) {
        if (pattern.test(trimmedLine)) {
          securityIssueCount++;
          issues.push(this.createIssue(
            fileContent.path,
            i + 1,
            line.indexOf(trimmedLine) + 1,
            line,
            `Insecure MCP configuration: ${type}`,
            `Review and secure your MCP server configuration. Implement proper authentication, authorization, and access controls.`
          ));
        }
      }
    }

    if (contextFileCount > 0 && contextContentCount > 0 && securityIssueCount === 0) {
      const contextRatio = contextContentCount / lines.length;
      if (contextRatio > 0.3) {
        return issues;
      }
    }

    return issues;
  }
}