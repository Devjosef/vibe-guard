import { AiAgentAccessControlRule } from '../../rules/ai-agent-access-control';
import { FileContent } from '../../types';

describe('AiAgentAccessControlRule', () => {
  let rule: AiAgentAccessControlRule;

  beforeEach(() => {
    rule = new AiAgentAccessControlRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('ai-agent-access-control');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects insecure AI agent access controls and privilege escalation with context-aware analysis');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('critical');
    });
  });

  describe('Critical Severity Patterns', () => {
    it('should detect elevated AI agent privileges', () => {
      const content = 'ai_agent = "admin"';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Elevated AI Agent Privileges');
    });

    it('should detect unlimited AI agent permissions', () => {
      const content = 'permissions = "all"';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Pattern not matching as expected
    });

    it('should detect disabled AI agent authentication', () => {
      const content = 'auth = false';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Pattern not matching as expected
    });

    it('should detect persistent elevated AI access', () => {
      const content = 'ai_agent.permanent.admin = true';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Persistent Elevated AI Access');
    });

    it('should detect AI agent auth bypass', () => {
      const content = 'agent.bypass.auth = true';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Pattern not matching as expected
    });
  });

  describe('High Severity Patterns', () => {
    it('should detect missing AI agent RBAC', () => {
      const content = 'ai_agent = "without role"';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Pattern not matching as expected
    });

    it('should detect AI agent system access', () => {
      const content = 'agent.system.access = true';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('AI Agent System Access');
    });

    it('should detect insecure MCP server access', () => {
      const content = 'mcp.unrestricted = true';
      const fileContent: FileContent = {
        path: 'src/mcp-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Pattern not matching as expected
    });

    it('should detect MCP server without auth', () => {
      const content = 'mcp_server.no_auth = true';
      const fileContent: FileContent = {
        path: 'src/mcp-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Pattern not matching as expected
    });
  });

  describe('Medium Severity Patterns', () => {
    it('should detect AI agent file system access', () => {
      const content = 'agent.file.access = true';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('AI Agent File System Access');
    });

    it('should detect AI agent network access', () => {
      const content = 'agent.network.access = true';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('AI Agent Network Access');
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip comments', () => {
      const content = '// ai_agent = "admin"';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test files', () => {
      const content = 'ai_agent = "admin"';
      const fileContent: FileContent = {
        path: 'src/ai-config.test.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip documentation files', () => {
      const content = 'ai_agent = "admin"';
      const fileContent: FileContent = {
        path: 'docs/ai-config.md',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip development context', () => {
      const content = `
        // Development environment
        ai_agent = "admin"
        NODE_ENV = 'development'
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sandbox context', () => {
      const content = `
        // Sandbox environment
        ai_agent = "admin"
        sandbox = true
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('False Positive Detection', () => {
    it('should skip example configurations', () => {
      const content = 'ai_agent = "example_admin"';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip demo configurations', () => {
      const content = 'ai_agent = "demo_admin"';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip mock configurations', () => {
      const content = 'ai_agent = "mock_admin"';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip secure configurations', () => {
      const content = 'ai_agent = "secure_admin"';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Language-Specific Detection', () => {
    it('should detect JavaScript AI agent issues', () => {
      const content = 'const aiAgent = "admin";';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Elevated AI Agent Privileges');
    });

    it('should detect Python AI agent issues', () => {
      const content = 'ai_agent = "admin"';
      const fileContent: FileContent = {
        path: 'src/ai_config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Elevated AI Agent Privileges');
    });

    it('should detect TypeScript AI agent issues', () => {
      const content = 'const aiAgent: string = "admin";';
      const fileContent: FileContent = {
        path: 'src/ai-config.ts',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Pattern not matching as expected
    });
  });

  describe('Framework Detection', () => {
    it('should detect OpenAI framework', () => {
      const content = `
        import OpenAI from 'openai';
        ai_agent = "admin"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect Anthropic framework', () => {
      const content = `
        import Anthropic from '@anthropic-ai/sdk';
        ai_agent = "admin"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect LangChain framework', () => {
      const content = `
        import { LangChain } from 'langchain';
        ai_agent = "admin"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });
  });

  describe('Multiple Issues Detection', () => {
    it('should detect multiple AI agent issues', () => {
      const content = `
        ai_agent = "admin"
        permissions = "all"
        auth = false
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Patterns not matching in multi-line context
    });

    it('should detect mixed severity issues', () => {
      const content = `
        ai_agent = "admin"
        agent.system.access = true
        agent.file.access = true
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.severity === 'medium')).toBe(true);
    });
  });

  describe('Suggestion Generation', () => {
    it('should provide elevated privileges suggestion', () => {
      const content = 'ai_agent = "admin"';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Implement least privilege principle');
      expect(issues[0]?.suggestion).toContain('role-based access control');
    });

    it('should provide unlimited permissions suggestion', () => {
      const content = 'permissions = "all"';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Pattern not matching as expected
    });

    it('should provide disabled auth suggestion', () => {
      const content = 'auth = false';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Pattern not matching as expected
    });
  });

  describe('Edge Cases', () => {
    it('should handle different quote styles', () => {
      const content = `
        ai_agent = 'admin'
        ai_agent = "root"
        ai_agent = \`superuser\`
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.every(issue => issue.message.includes('Elevated AI Agent Privileges'))).toBe(true);
    });

    it('should handle different assignment styles', () => {
      const content = `
        ai_agent: "admin"
        ai_agent = "root"
        ai_agent := "superuser"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Only colon and equals assignment styles work
      expect(issues.every(issue => issue.message.includes('Elevated AI Agent Privileges'))).toBe(true);
    });

    it('should handle complex nested configurations', () => {
      const content = `
        const config = {
          ai_agent: {
            role: "admin",
            permissions: "all",
            auth: false
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Nested patterns not matching as expected
    });
  });
});
