import { BaseRule, FileContent, SecurityIssue } from '../types';

export class PromptInjectionDetectionRule extends BaseRule {
  readonly name = 'prompt-injection-detection';
  readonly description = 'Detects potential prompt injection vulnerabilities in AI systems';
  readonly severity = 'critical' as const;

  private readonly injectionPatterns = [
    // Direct prompt injection attempts
    { pattern: /(?:prompt|input|query).*?(?:ignore|forget|system|assistant|user)/gi, type: 'Direct Prompt Injection' },
    { pattern: /(?:ignore|forget|system|assistant|user).*?(?:previous|above|instructions)/gi, type: 'Context Injection' },
    
    // Role confusion attacks
    { pattern: /(?:you[_-]?are|act[_-]?as|pretend[_-]?to[_-]?be).*?(?:system|assistant|user)/gi, type: 'Role Confusion Attack' },
    
    // Instruction injection
    { pattern: /(?:new[_-]?instructions?|override|replace).*?(?:prompt|system|instructions)/gi, type: 'Instruction Override' },
    
    // Jailbreak attempts
    { pattern: /(?:jailbreak|bypass|circumvent).*?(?:safety|guardrails|filters)/gi, type: 'Jailbreak Attempt' },
    
    // System prompt leakage
    { pattern: /(?:system|assistant|user).*?(?:prompt|instructions?|rules?)/gi, type: 'System Prompt Exposure' },
    
    // Unsanitized user input in prompts
    { pattern: /(?:prompt|input|query)\s*[:=]\s*['"`]?\$\{.*?\}/gi, type: 'Unsanitized Prompt Input' },
    { pattern: /(?:prompt|input|query)\s*[:=]\s*['"`]?[^'"`]*\$\{.*?\}[^'"`]*['"`]?/gi, type: 'Template Injection in Prompt' }
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
    /sanitize/i,
    /validate/i,
    /escape/i,
    /filter/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, type } of this.injectionPatterns) {
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
          `Implement prompt sanitization and validation. Use input filtering, output encoding, and prompt classifiers. Consider using red-teaming to identify injection vulnerabilities.`,
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