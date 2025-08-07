import { BaseRule, FileContent, SecurityIssue } from '../types';

export class AiAgentAccessControlRule extends BaseRule {
  readonly name = 'ai-agent-access-control';
  readonly description = 'Detects insecure AI agent access controls and privilege escalation';
  readonly severity = 'critical' as const;

  private readonly accessControlPatterns = [
    // AI Agent with elevated privileges
    { pattern: /(?:ai[_-]?agent|agent|bot|assistant)\s*[:=]\s*['"`]?(?:admin|root|superuser|sudo)/gi, type: 'Elevated AI Agent Privileges' },
    { pattern: /(?:permissions?|roles?|access)\s*[:=]\s*['"`]?(?:all|full|unlimited|wildcard)/gi, type: 'Unlimited AI Agent Permissions' },
    
    // Missing RBAC for AI agents
    { pattern: /(?:ai[_-]?agent|agent|bot|assistant)\s*[:=]\s*['"`]?[^'"`]*\b(?:without|no|missing)\s+(?:role|permission|access[_-]?control)/gi, type: 'Missing AI Agent RBAC' },
    
    // AI Agent with persistent elevated access
    { pattern: /(?:ai[_-]?agent|agent|bot|assistant).*?(?:permanent|persistent|always|forever).*?(?:admin|root|elevated)/gi, type: 'Persistent Elevated AI Access' },
    
    // AI Agent bypassing authentication
    { pattern: /(?:ai[_-]?agent|agent|bot|assistant).*?(?:bypass|skip|ignore).*?(?:auth|authentication|login)/gi, type: 'AI Agent Auth Bypass' },
    
    // AI Agent with system-level access
    { pattern: /(?:ai[_-]?agent|agent|bot|assistant).*?(?:system|os|kernel|hardware)/gi, type: 'AI Agent System Access' },
    
    // MCP Server insecure access
    { pattern: /(?:mcp|model[_-]?context[_-]?protocol).*?(?:unrestricted|open|public)/gi, type: 'Insecure MCP Server Access' },
    { pattern: /(?:mcp[_-]?server|model[_-]?context[_-]?protocol).*?(?:no[_-]?auth|without[_-]?auth)/gi, type: 'MCP Server Without Auth' }
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
    /localhost/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, type } of this.accessControlPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        if (this.isFalsePositive(lineContent)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Critical: ${type} detected`,
          `Implement proper RBAC for AI agents. Use least privilege principle and temporary elevated access only when necessary. Consider using AI agent isolation and sandboxing.`,
          'critical'
        ));
      }
    }

    return issues;
  }

  private isFalsePositive(lineContent: string): boolean {
    return this.falsePositivePatterns.some(pattern => pattern.test(lineContent));
  }
}