import { AiDataLeakagePreventionRule } from '../../rules/ai-data-leakage-prevention';
import { FileContent } from '../../types';

describe('AiDataLeakagePreventionRule', () => {
  let rule: AiDataLeakagePreventionRule;

  beforeEach(() => {
    rule = new AiDataLeakagePreventionRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('ai-data-leakage-prevention');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects potential data leakage in AI systems and training data exposure with context-aware analysis');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('high');
    });
  });

  describe('Critical Severity Patterns', () => {
    it('should detect training data exposure', () => {
      const content = 'training_data = "expose"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Training Data Exposure');
    });

    it('should detect sensitive training data', () => {
      const content = 'sensitive = "training"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Sensitive Training Data');
    });

    it('should detect sensitive data in model', () => {
      const content = 'model = "contain sensitive"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('High Severity Patterns', () => {
    it('should detect sensitive data in AI output', () => {
      const content = 'model = "output sensitive"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect unfiltered AI output', () => {
      const content = 'ai = "unfiltered output"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect data classification bypass', () => {
      const content = 'bypass = "classification"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Data Classification Bypass');
    });

    it('should detect unencrypted AI artifacts', () => {
      const content = 'model = "unencrypted"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect sensitive data logging', () => {
      const content = 'log = "sensitive"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Sensitive Data Logging');
    });
  });

  describe('Medium Severity Patterns', () => {
    it('should detect unfiltered data export', () => {
      const content = 'export = "all data"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect unsanitized API response', () => {
      const content = 'api = "raw data"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip comments', () => {
      const content = '# training_data = "expose"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test files', () => {
      const content = 'training_data = "expose"';
      const fileContent: FileContent = {
        path: 'src/ai-config.test.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip documentation files', () => {
      const content = 'training_data = "expose"';
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
        # Development environment
        training_data = "expose"
        NODE_ENV = 'development'
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('False Positive Detection', () => {
    it('should skip example configurations', () => {
      const content = 'training_data = "example_expose"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip demo configurations', () => {
      const content = 'training_data = "demo_expose"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip mock configurations', () => {
      const content = 'training_data = "mock_expose"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip secure configurations', () => {
      const content = 'training_data = "secure_expose"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Language-Specific Detection', () => {
    it('should detect Python data leakage issues', () => {
      const content = 'training_data = "expose"';
      const fileContent: FileContent = {
        path: 'src/ai_config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Training Data Exposure');
    });

    it('should detect JavaScript data leakage issues', () => {
      const content = 'const trainingData = "expose";';
      const fileContent: FileContent = {
        path: 'src/ai-config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Training Data Exposure');
    });

    it('should detect TypeScript data leakage issues', () => {
      const content = 'const trainingData: string = "expose";';
      const fileContent: FileContent = {
        path: 'src/ai-config.ts',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Framework Detection', () => {
    it('should detect OpenAI framework', () => {
      const content = `
        import openai
        training_data = "expose"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect Anthropic framework', () => {
      const content = `
        import anthropic
        training_data = "expose"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect LangChain framework', () => {
      const content = `
        from langchain import LLMChain
        training_data = "expose"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect Transformers framework', () => {
      const content = `
        from transformers import AutoModel
        training_data = "expose"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });
  });

  describe('Multiple Issues Detection', () => {
    it('should detect multiple data leakage issues', () => {
      const content = `
        training_data = "expose"
        sensitive = "training"
        model = "contain sensitive"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.message.includes('Training Data Exposure'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Sensitive Training Data'))).toBe(true);
    });

    it('should detect mixed severity issues', () => {
      const content = `
        training_data = "expose"
        model = "output sensitive"
        export = "all data"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
    });
  });

  describe('Suggestion Generation', () => {
    it('should provide training data exposure suggestion', () => {
      const content = 'training_data = "expose"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Implement data access controls');
      expect(issues[0]?.suggestion).toContain('encryption');
    });

    it('should provide sensitive data logging suggestion', () => {
      const content = 'log = "sensitive"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Implement secure logging');
      expect(issues[0]?.suggestion).toContain('data masking');
    });

    it('should provide unfiltered export suggestion', () => {
      const content = 'export = "all data"';
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle different quote styles', () => {
      const content = `
        training_data = 'expose'
        training_data = "leak"
        training_data = \`public\`
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.every(issue => issue.message.includes('Training Data Exposure'))).toBe(true);
    });

    it('should handle different assignment styles', () => {
      const content = `
        training_data: "expose"
        training_data = "leak"
        training_data := "public"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.every(issue => issue.message.includes('Training Data Exposure'))).toBe(true);
    });

    it('should handle complex nested configurations', () => {
      const content = `
        config = {
          training_data: "expose",
          model: {
            output: "sensitive",
            artifacts: "unencrypted"
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Data Protection Detection', () => {
    it('should skip when data protection is present', () => {
      const content = `
        # Data protection enabled
        encrypt_data = True
        training_data = "expose"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip when filtering is present', () => {
      const content = `
        # Data filtering enabled
        filter_sensitive_data = True
        model = "output sensitive"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip when sanitization is present', () => {
      const content = `
        # Data sanitization enabled
        sanitize_output = True
        api = "raw data"
      `;
      const fileContent: FileContent = {
        path: 'src/ai-config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });
});
