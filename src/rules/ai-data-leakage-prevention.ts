import { BaseRule, FileContent, SecurityIssue } from '../types';

export class AiDataLeakagePreventionRule extends BaseRule {
  readonly name = 'ai-data-leakage-prevention';
  readonly description = 'Detects potential data leakage in AI systems and training data exposure';
  readonly severity = 'high' as const;

  private readonly leakagePatterns = [
    // Training data exposure
    { pattern: /(?:training[_-]?data|dataset|corpus).*?(?:expose|leak|public|unrestricted)/gi, type: 'Training Data Exposure' },
    { pattern: /(?:sensitive|confidential|proprietary).*?(?:training|dataset|corpus)/gi, type: 'Sensitive Training Data' },
    
    // Model output containing sensitive data
    { pattern: /(?:model|ai|llm).*?(?:output|response|generation).*?(?:sensitive|confidential|proprietary)/gi, type: 'Sensitive Data in AI Output' },
    
    // Unfiltered AI responses
    { pattern: /(?:ai|model|llm).*?(?:unfiltered|unrestricted|raw).*?(?:output|response)/gi, type: 'Unfiltered AI Output' },
    
    // Data classification bypass
    { pattern: /(?:bypass|ignore|skip).*?(?:classification|label|sensitivity)/gi, type: 'Data Classification Bypass' },
    
    // AI model containing sensitive data
    { pattern: /(?:model|weights|parameters).*?(?:contain|include|embed).*?(?:sensitive|confidential)/gi, type: 'Sensitive Data in Model' },
    
    // Unencrypted AI artifacts
    { pattern: /(?:model|weights|artifacts).*?(?:unencrypted|plaintext|raw)/gi, type: 'Unencrypted AI Artifacts' }
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
    /encrypt/i,
    /protect/i,
    /secure/i,
    /filter/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, type } of this.leakagePatterns) {
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
          `High: ${type} detected`,
          `Implement data loss prevention (DLP) policies. Use sensitivity labels, output filtering, and encryption for AI artifacts. Monitor AI outputs for sensitive data exposure.`,
          'high'
        ));
      }
    }

    return issues;
  }

  private isFalsePositive(lineContent: string): boolean {
    return this.falsePositivePatterns.some(pattern => pattern.test(lineContent));
  }
}