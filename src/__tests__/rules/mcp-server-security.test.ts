import { McpServerSecurityRule } from '../../rules/mcp-server-security';
import { FileContent } from '../../types';

describe('McpServerSecurityRule', () => {
  let rule: McpServerSecurityRule;

  beforeEach(() => {
    rule = new McpServerSecurityRule();
  });

  it('detects insecure MCP configuration', () => {
    const content = `
      allow: all
      enable: true
      permit: everyone
      auth: none
      authentication: false
      cors: "*"
      origin: "*"
      token: "test"
      key: "demo"
    `;
    const fileContent: FileContent = {
      path: 'src/mcp-config.yaml',
      content,
      lines: content.split('\n')
    };
    const issues = rule.check(fileContent);
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.some(issue => issue.message.includes('Insecure MCP configuration'))).toBe(true);
    expect(issues.some(issue => issue.message.includes('Disabled MCP authentication'))).toBe(true);
    expect(issues.some(issue => issue.message.includes('Open CORS in MCP'))).toBe(true);
  });

  it('ignores false positives in comments and examples', () => {
    const content = `
      # This is just an example
      # allow: all
      # auth: none
      # cors: "*"
      # token: "test"
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
      allow: localhost
      auth: development
      cors: "localhost"
      token: "dev-token"
    `;
    const fileContent: FileContent = {
      path: 'src/mcp-config.dev.yaml',
      content,
      lines: content.split('\n')
    };
    const issues = rule.check(fileContent);
    expect(issues.length).toBe(0);
  });

  it('detects weak credentials in MCP configuration', () => {
    const content = `
      token: "123"
      key: "abc"
      secret: "xyz"
      password: "test"
    `;
    const fileContent: FileContent = {
      path: 'src/mcp-config.yaml',
      content,
      lines: content.split('\n')
    };
    const issues = rule.check(fileContent);
    expect(issues.some(issue => issue.message.includes('Weak MCP credentials'))).toBe(true);
  });
});