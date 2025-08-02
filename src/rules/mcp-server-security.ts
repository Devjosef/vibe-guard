import { BaseRule, FileContent, SecurityIssue } from '../types';

export class McpServerSecurityRule extends BaseRule {
  readonly name = 'mcp-server-security';
  readonly description = 'Detects security vulnerabilities in Model Context Protocol (MCP) servers';
  readonly severity = 'high' as const;

  private readonly mcpSecurityPatterns = [
    // MCP Server vulnerabilities
    { pattern: /(?:mcp|model[_-]?context[_-]?protocol).*?(?:vulnerability|exploit|cve)/gi, type: 'MCP Server Vulnerability' },
    { pattern: /(?:echo[_-]?leak|cve[_-]?2025[_-]?32711)/gi, type: 'EchoLeak Vulnerability' },
    // Insecure MCP configuration (improved: match as standalone words)
    { pattern: /(?:mcp[_-]?server|model[_-]?context[_-]?protocol).*?\b(insecure|unsafe|unprotected)\b/gi, type: 'Insecure MCP Configuration' },
    // MCP Server without authentication
    { pattern: /(?:mcp[_-]?server|model[_-]?context[_-]?protocol).*?\b(no[_-]?auth|without[_-]?auth|anonymous)\b/gi, type: 'MCP Server Without Auth' },
    // MCP Server with weak encryption
    { pattern: /(?:mcp|model[_-]?context[_-]?protocol).*?\b(weak|broken|deprecated)\b.*?\b(encryption|ssl|tls)\b/gi, type: 'Weak MCP Encryption' },
    // MCP Server exposed to network
    { pattern: /(?:mcp[_-]?server|model[_-]?context[_-]?protocol).*?\b(public|exposed|unrestricted)\b/gi, type: 'Exposed MCP Server' }
  ];

  private readonly falsePositivePatterns = [
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
    /secure/i,
    /protect/i,
    /encrypt/i,
    /auth/i
  ];

  private readonly contextFilePatterns = [
    /\.dev\./i,
    /\.test\./i,
    /__tests__/i,
    /\.example\./i,
    /\.sample\./i,
    /\.mock\./i,
    /docs?\//i,
    /readme/i,
    /\.md$/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Skip dev/test/example files entirely
    if (this.isContextFile(fileContent.path) || this.isContextContent(fileContent.content)) {
      return issues;
    }

    for (const { pattern, type } of this.mcpSecurityPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      for (const { line, column, lineContent } of matches) {
        if (this.isFalsePositive(lineContent, fileContent.path)) {
          continue;
        }
        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `High: ${type} detected`,
          `Implement proper MCP server security. Use strong authentication, encryption, and network isolation. Apply patches for known vulnerabilities like EchoLeak (CVE-2025-32711).`,
          'high'
        ));
      }
    }
    return issues;
  }

  private isFalsePositive(lineContent: string, filePath: string): boolean {
    // Check for context files
    if (this.isContextFile(filePath)) return true;
    // Check for context content
    if (this.isContextContent(lineContent)) return true;
    // Check basic false positive patterns
    return this.falsePositivePatterns.some(pattern => pattern.test(lineContent));
  }

  private isContextFile(filePath: string): boolean {
    return this.contextFilePatterns.some(pattern => pattern.test(filePath));
  }

  private isContextContent(content: string): boolean {
    // If the content contains only dev/test/example indicators, skip
    return /dev(elopment)?|test|mock|example|sample|localhost|staging/i.test(content);
  }
}