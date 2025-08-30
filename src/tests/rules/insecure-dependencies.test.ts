import { InsecureDependenciesRule } from '../../rules/insecure-dependencies';
import { FileContent } from '../../types';

describe('InsecureDependenciesRule', () => {
  let rule: InsecureDependenciesRule;

  beforeEach(() => {
    rule = new InsecureDependenciesRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('insecure-dependencies');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects potentially insecure dependencies and packages with context-aware analysis');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('medium');
    });
  });

  describe('Critical Severity Vulnerable Packages', () => {
    it('should detect vulnerable lodash version', () => {
      const content = '"lodash": "^4.17.15"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Prototype pollution vulnerabilities');
    });

    it('should detect deprecated request package', () => {
      const content = '"request": "^2.88.0"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Deprecated package with security issues');
    });

    it('should detect vulnerable growl version', () => {
      const content = '"growl": "1.9.2"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Command injection vulnerability');
    });

    it('should detect vulnerable handlebars version', () => {
      const content = '"handlebars": "4.7.6"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Template injection vulnerabilities');
    });

    it('should detect vulnerable serialize-javascript version', () => {
      const content = '"serialize-javascript": "3.0.0"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('XSS vulnerability');
    });

    it('should detect vulnerable minimist version', () => {
      const content = '"minimist": "1.2.5"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Prototype pollution vulnerability');
    });

    it('should detect vulnerable yargs-parser version', () => {
      const content = '"yargs-parser": "13.1.1"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Prototype pollution vulnerability');
    });

    it('should detect vulnerable ini version', () => {
      const content = '"ini": "1.3.5"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Prototype pollution vulnerability');
    });

    it('should detect backdoored event-stream package', () => {
      const content = '"event-stream": "^3.3.6"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Backdoored package with malicious code injection');
    });
  });

  describe('High Severity Vulnerable Packages', () => {
    it('should detect deprecated moment package', () => {
      const content = '"moment": "^2.29.4"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Deprecated package with security issues');
    });

    it('should detect deprecated node-uuid package', () => {
      const content = '"node-uuid": "^1.4.8"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Deprecated, use uuid package instead');
    });
  });

  describe('Python Vulnerable Packages', () => {
    it('should detect vulnerable Django version', () => {
      const content = 'Django==3.2.12';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Multiple security vulnerabilities');
    });

    it('should detect vulnerable Flask version', () => {
      const content = 'Flask==1.1.4';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Security improvements in newer versions');
    });

    it('should detect vulnerable requests version', () => {
      const content = 'requests==2.19.1';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('SSL verification issues');
    });

    it('should detect vulnerable PyYAML version', () => {
      const content = 'PyYAML==5.3.1';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Arbitrary code execution vulnerability');
    });

    it('should detect vulnerable Pillow version', () => {
      const content = 'Pillow==8.3.1';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Multiple image processing vulnerabilities');
    });
  });

  describe('PHP Vulnerable Packages', () => {
    it('should detect vulnerable Symfony version', () => {
      const content = '"symfony/symfony": "4.4.34"';
      const fileContent: FileContent = {
        path: 'composer.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Multiple security vulnerabilities');
    });

    it('should detect vulnerable Laravel version', () => {
      const content = '"laravel/framework": "8.74.0"';
      const fileContent: FileContent = {
        path: 'composer.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Security vulnerabilities');
    });

    it('should detect vulnerable Monolog version', () => {
      const content = '"monolog/monolog": "2.3.4"';
      const fileContent: FileContent = {
        path: 'composer.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Remote code execution vulnerability');
    });
  });

  describe('Suspicious Package Patterns', () => {
    it('should detect suspicious package names', () => {
      const content = '"eval-js": "^1.0.0"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect malicious package names', () => {
      const content = '"backdoor": "^1.0.0"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect cryptominer packages', () => {
      const content = '"cryptojs": "^1.0.0"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip comments', () => {
      const content = '// "lodash": "^4.17.15"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
    });

    it('should skip test files', () => {
      const content = '"lodash": "^4.17.15"';
      const fileContent: FileContent = {
        path: 'package.test.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip documentation files', () => {
      const content = '"lodash": "^4.17.15"';
      const fileContent: FileContent = {
        path: 'docs/example.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip dev dependencies', () => {
      const content = `
        {
          "devDependencies": {
            "lodash": "^4.17.15"
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
    });
  });

  describe('False Positive Detection', () => {
    it('should skip tutorial dependencies', () => {
      const content = '"lodash": "^4.17.15"  # tutorial example';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip guide dependencies', () => {
      const content = '"lodash": "^4.17.15"  # guide example';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip example dependencies', () => {
      const content = '"lodash": "^4.17.15"  # example';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sample dependencies', () => {
      const content = '"lodash": "^4.17.15"  # sample';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip demo dependencies', () => {
      const content = '"lodash": "^4.17.15"  # demo';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test dependencies', () => {
      const content = '"lodash": "^4.17.15"  # test';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip mock dependencies', () => {
      const content = '"lodash": "^4.17.15"  # mock';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip stub dependencies', () => {
      const content = '"lodash": "^4.17.15"  # stub';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip fixture dependencies', () => {
      const content = '"lodash": "^4.17.15"  # fixture';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sandbox dependencies', () => {
      const content = '"lodash": "^4.17.15"  # sandbox';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Language-Specific Detection', () => {
    it('should detect Node.js package.json dependencies', () => {
      const content = '"lodash": "^4.17.15"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect Python requirements.txt dependencies', () => {
      const content = 'Django==3.2.12';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect PHP composer.json dependencies', () => {
      const content = '"symfony/symfony": "4.4.34"';
      const fileContent: FileContent = {
        path: 'composer.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect Ruby Gemfile dependencies', () => {
      const content = 'gem "rails", "6.1.4"';
      const fileContent: FileContent = {
        path: 'Gemfile',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Go go.mod dependencies', () => {
      const content = 'require github.com/gorilla/mux v1.8.0';
      const fileContent: FileContent = {
        path: 'go.mod',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Framework Detection', () => {
    it('should detect Express.js dependencies', () => {
      const content = `
        {
          "dependencies": {
            "express": "^4.17.1",
            "lodash": "^4.17.15"
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues.some(issue => issue.message.includes('Prototype pollution vulnerabilities'))).toBe(true);
    });

    it('should detect Django dependencies', () => {
      const content = `
        Django==3.2.12
        requests==2.19.1
      `;
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Laravel dependencies', () => {
      const content = `
        {
          "require": {
            "laravel/framework": "8.74.0",
            "monolog/monolog": "2.3.4"
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'composer.json',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.message.includes('Security vulnerabilities'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Remote code execution vulnerability'))).toBe(true);
    });
  });

  describe('Multiple Issues Detection', () => {
    it('should detect multiple vulnerable dependencies', () => {
      const content = `
        {
          "dependencies": {
            "lodash": "^4.17.15",
            "request": "^2.88.0",
            "moment": "^2.29.4"
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.some(issue => issue.message.includes('Prototype pollution vulnerabilities'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Deprecated package with security issues'))).toBe(true);
    });

    it('should detect mixed severity issues', () => {
      const content = `
        {
          "dependencies": {
            "lodash": "^4.17.15",
            "moment": "^2.29.4",
            "eval-js": "^1.0.0"
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
    });
  });

  describe('Suggestion Generation', () => {
    it('should provide lodash upgrade suggestion', () => {
      const content = '"lodash": "^4.17.15"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Update lodash');
      expect(issues[0]?.suggestion).toContain('secure version');
    });

    it('should provide moment replacement suggestion', () => {
      const content = '"moment": "^2.29.4"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Update moment');
      expect(issues[0]?.suggestion).toContain('date-fns');
    });

    it('should provide request replacement suggestion', () => {
      const content = '"request": "^2.88.0"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Update request');
      expect(issues[0]?.suggestion).toContain('secure version');
    });
  });

  describe('Edge Cases', () => {
    it('should handle different version formats', () => {
      const content = `
        "lodash": "4.17.15"
        "lodash": "^4.17.15"
        "lodash": "~4.17.15"
        "lodash": ">=4.17.15"
      `;
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(5);
      expect(issues.every(issue => issue.message.includes('Prototype pollution vulnerabilities') || issue.message.includes('Overly permissive version range'))).toBe(true);
    });

    it('should handle different package manager formats', () => {
      const content = `
        # Node.js
        "lodash": "^4.17.15"
        
        # Python
        Django==3.2.12
        
        # PHP
        "symfony/symfony": "4.4.34"
      `;
      const fileContent: FileContent = {
        path: 'mixed-dependencies.txt',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should handle complex nested configurations', () => {
      const content = `
        {
          "dependencies": {
            "lodash": "^4.17.15"
          },
          "devDependencies": {
            "moment": "^2.29.4"
          },
          "peerDependencies": {
            "request": "^2.88.0"
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.some(issue => issue.message.includes('Prototype pollution vulnerabilities'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Deprecated package with security issues'))).toBe(true);
    });
  });

  describe('Secure Dependencies Detection', () => {
    it('should skip when lodash is up to date', () => {
      const content = '"lodash": "^4.17.21"';
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
    });

    it('should skip when Django is up to date', () => {
      const content = 'Django==3.2.13';
      const fileContent: FileContent = {
        path: 'requirements.txt',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip when Symfony is up to date', () => {
      const content = '"symfony/symfony": "4.4.35"';
      const fileContent: FileContent = {
        path: 'composer.json',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip when using secure alternatives', () => {
      const content = `
        {
          "dependencies": {
            "uuid": "^8.3.2",
            "axios": "^0.24.0",
            "date-fns": "^2.28.0"
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'package.json',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });
});
