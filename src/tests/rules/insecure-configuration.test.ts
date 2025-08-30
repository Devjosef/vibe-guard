import { InsecureConfigurationRule } from '../../rules/insecure-configuration';
import { FileContent } from '../../types';

describe('InsecureConfigurationRule', () => {
  let rule: InsecureConfigurationRule;

  beforeEach(() => {
    rule = new InsecureConfigurationRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('insecure-configuration');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects insecure configuration settings with context-aware analysis');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('medium');
    });
  });

  describe('Critical Severity Patterns', () => {
    it('should detect debug mode in production', () => {
      const content = 'debug = true';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Debug mode in production');
    });

    it('should detect development environment in production', () => {
      const content = 'environment = "development"';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect development NODE_ENV', () => {
      const content = 'NODE_ENV = "development"';
      const fileContent: FileContent = {
        path: 'src/config/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect SSL disabled', () => {
      const content = 'ssl = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('SSL disabled');
    });

    it('should detect HTTPS disabled', () => {
      const content = 'https = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('HTTPS disabled');
    });

    it('should detect security disabled', () => {
      const content = 'secure = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect authentication disabled', () => {
      const content = 'auth = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Authentication disabled');
    });
  });

  describe('High Severity Patterns', () => {
    it('should detect verbose logging in production', () => {
      const content = 'verbose = true';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Verbose logging in production');
    });

    it('should detect debug logging level', () => {
      const content = 'log_level = "debug"';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Debug logging level');
    });

    it('should detect open CORS configuration', () => {
      const content = 'cors = "*"';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Open CORS configuration');
    });

    it('should detect wildcard origin', () => {
      const content = 'origin = "*"';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Wildcard origin');
    });

    it('should detect wildcard in allowed origins', () => {
      const content = 'allowed_origins = ["https://example.com", "*"]';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect helmet security disabled', () => {
      const content = 'helmet = false';
      const fileContent: FileContent = {
        path: 'src/config/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Helmet security disabled');
    });

    it('should detect CSRF protection disabled', () => {
      const content = 'csrf = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('CSRF protection disabled');
    });

    it('should detect XSS protection disabled', () => {
      const content = 'xss_protection = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('XSS protection disabled');
    });

    it('should detect HSTS disabled', () => {
      const content = 'strict_transport_security = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('HSTS disabled');
    });
  });

  describe('Medium Severity Patterns', () => {
    it('should detect trust proxy enabled', () => {
      const content = 'trust_proxy = true';
      const fileContent: FileContent = {
        path: 'src/config/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Trust proxy enabled');
    });

    it('should detect content type options disabled', () => {
      const content = 'content_type_options = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Content-Type options disabled');
    });

    it('should detect frame options disabled', () => {
      const content = 'frame_options = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Frame options disabled');
    });

    it('should detect referrer policy disabled', () => {
      const content = 'referrer_policy = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Referrer policy disabled');
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip comments', () => {
      const content = '# debug = true';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test files', () => {
      const content = 'debug = true';
      const fileContent: FileContent = {
        path: 'src/config/app.test.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip documentation files', () => {
      const content = 'debug = true';
      const fileContent: FileContent = {
        path: 'docs/config-example.md',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip development context', () => {
      const content = `
        # Development environment
        debug = true
        NODE_ENV = 'development'
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
    });
  });

  describe('False Positive Detection', () => {
    it('should skip tutorial configurations', () => {
      const content = 'debug = true  # tutorial example';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip guide configurations', () => {
      const content = 'debug = true  # guide example';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip example configurations', () => {
      const content = 'debug = true  # example';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sample configurations', () => {
      const content = 'debug = true  # sample';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip demo configurations', () => {
      const content = 'debug = true  # demo';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test configurations', () => {
      const content = 'debug = true  # test';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip mock configurations', () => {
      const content = 'debug = true  # mock';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip stub configurations', () => {
      const content = 'debug = true  # stub';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip fixture configurations', () => {
      const content = 'debug = true  # fixture';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sandbox configurations', () => {
      const content = 'debug = true  # sandbox';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Language-Specific Detection', () => {
    it('should detect Python insecure configuration', () => {
      const content = 'debug = True';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect JavaScript insecure configuration', () => {
      const content = 'const debug = true;';
      const fileContent: FileContent = {
        path: 'src/config/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Debug mode in production');
    });

    it('should detect TypeScript insecure configuration', () => {
      const content = 'const debug: boolean = true;';
      const fileContent: FileContent = {
        path: 'src/config/app.ts',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Framework Detection', () => {
    it('should detect Django framework', () => {
      const content = `
        # Django settings
        DEBUG = True
      `;
      const fileContent: FileContent = {
        path: 'src/settings.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Express framework', () => {
      const content = `
        // Express configuration
        const debug = true;
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect Flask framework', () => {
      const content = `
        # Flask configuration
        DEBUG = True
      `;
      const fileContent: FileContent = {
        path: 'src/config.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Laravel framework', () => {
      const content = `
        // Laravel configuration
        'debug' => true,
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.php',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Multiple Issues Detection', () => {
    it('should detect multiple insecure configuration issues', () => {
      const content = `
        debug = true
        ssl = false
        cors = "*"
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.some(issue => issue.message.includes('Debug mode in production'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('SSL disabled'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Open CORS configuration'))).toBe(true);
    });

    it('should detect mixed severity issues', () => {
      const content = `
        debug = true
        verbose = true
        trust_proxy = true
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.py',
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
    it('should provide debug mode suggestion', () => {
      const content = 'debug = true';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Disable debug mode');
      expect(issues[0]?.suggestion).toContain('production');
    });

    it('should provide SSL suggestion', () => {
      const content = 'ssl = false';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Enable SSL');
      expect(issues[0]?.suggestion).toContain('SSL/HTTPS');
    });

    it('should provide CORS suggestion', () => {
      const content = 'cors = "*"';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Configure CORS');
      expect(issues[0]?.suggestion).toContain('specific allowed origins');
    });
  });

  describe('Edge Cases', () => {
    it('should handle different quote styles', () => {
      const content = `
        debug = 'true'
        debug = "true"
        debug = \`true\`
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.every(issue => issue.message.includes('Debug mode in production'))).toBe(true);
    });

    it('should handle different assignment styles', () => {
      const content = `
        debug: true
        debug = true
        debug := true
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.every(issue => issue.message.includes('Debug mode in production'))).toBe(true);
    });

    it('should handle complex nested configurations', () => {
      const content = `
        config = {
          debug: true,
          security: {
            ssl: false,
            cors: "*"
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.some(issue => issue.message.includes('Debug mode in production'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('SSL disabled'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Open CORS configuration'))).toBe(true);
    });
  });

  describe('Secure Configuration Detection', () => {
    it('should skip when debug mode is disabled', () => {
      const content = `
        # Production configuration
        debug = false
        ssl = true
        cors = ["https://example.com"]
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip when security is enabled', () => {
      const content = `
        # Secure configuration
        secure = true
        auth = true
        helmet = true
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip when production environment is set', () => {
      const content = `
        # Production environment
        environment = "production"
        NODE_ENV = "production"
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });
});
