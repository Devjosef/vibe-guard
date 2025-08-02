import { McpServerSecurityRule } from '../../rules/mcp-server-security';
import { FileContent } from '../../types';

describe('McpServerSecurityRule', () => {
  let rule: McpServerSecurityRule;

  beforeEach(() => {
    rule = new McpServerSecurityRule();
  });

  it('detects MCP server vulnerabilities', () => {
    const content = `
      // Example of a real vulnerability
      mcp_server: public
      model_context_protocol: vulnerability
      echo_leak: true
      # CVE-2025-32711
    `;
    const fileContent: FileContent = {
      path: 'src/mcp-config.yaml',
      content,
      lines: content.split('\n')
    };
    const issues = rule.check(fileContent);
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.some(issue => issue.message.includes('EchoLeak Vulnerability'))).toBe(true);
    expect(issues.some(issue => issue.message.includes('MCP Server Vulnerability'))).toBe(true);
    expect(issues.some(issue => issue.message.includes('Exposed MCP Server'))).toBe(true);
  });

  it('ignores false positives in comments and examples', () => {
    const content = `
      # This is just an example
      # mcp_server: public
      # echo_leak: true
      # model_context_protocol: vulnerability
      # CVE-2025-32711
    `;
    const fileContent: FileContent = {
      path: 'docs/mcp-example.md',
      content,
      lines: content.split('\n')
    };
    const issues = rule.check(fileContent);
    expect(issues.length).toBe(0);
  });

  it('ignores dev/test configs', () => {
    const content = `
      mcp_server: localhost
      model_context_protocol: test
      echo_leak: false
    `;
    const fileContent: FileContent = {
      path: 'src/mcp-config.dev.yaml',
      content,
      lines: content.split('\n')
    };
    const issues = rule.check(fileContent);
    expect(issues.length).toBe(0);
  });

  it('detects insecure MCP configuration', () => {
    const content = `
      mcp_server: no_auth
      model_context_protocol: insecure
      encryption: weak
    `;
    const fileContent: FileContent = {
      path: 'src/mcp-config.yaml',
      content,
      lines: content.split('\n')
    };
    const issues = rule.check(fileContent);
    expect(issues.some(issue => issue.message.includes('MCP Server Without Auth'))).toBe(true);
    expect(issues.some(issue => issue.message.includes('Insecure MCP Configuration'))).toBe(true);
    expect(issues.some(issue => issue.message.includes('Weak MCP Encryption'))).toBe(true);
  });
});