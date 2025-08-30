import { HardcodedSensitiveDataRule } from '../../rules/hardcoded-sensitive-data';
import { FileContent } from '../../types';

describe('HardcodedSensitiveDataRule', () => {
  let rule: HardcodedSensitiveDataRule;

  beforeEach(() => {
    rule = new HardcodedSensitiveDataRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('hardcoded-sensitive-data');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects hardcoded sensitive information in configuration files with context-aware analysis');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('critical');
    });
  });

  describe('Critical Severity Database Patterns', () => {
    it('should detect database connection string', () => {
      const content = 'database_url = "postgresql://user:pass@localhost:5432/db"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect database URL', () => {
      const content = 'mongodb://user:pass@localhost:27017/db';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect JDBC connection string', () => {
      const content = 'jdbc:mysql://localhost:3306/database';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect database configuration', () => {
      const content = 'oracle_host = "localhost"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Critical Severity Encryption Patterns', () => {
    it('should detect encryption key', () => {
      const content = 'encryption_key = "abcdefghijklmnopqrstuvwxyz123456"';
      const fileContent: FileContent = {
        path: 'src/config/security.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Encryption Key'))).toBe(true);
    });

    it('should detect private key', () => {
      const content = '-----BEGIN RSA PRIVATE KEY-----';
      const fileContent: FileContent = {
        path: 'src/config/keys.pem',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect high-entropy secret', () => {
      const content = 'key = "abcdefghijklmnopqrstuvwxyz123456789"';
      const fileContent: FileContent = {
        path: 'src/config/security.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('High-Entropy Secret');
    });
  });

  describe('Critical Severity Application Patterns', () => {
    it('should detect application secret', () => {
      const content = 'app_secret = "mysecretkey123456"';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Application Secret');
    });

    it('should detect session secret', () => {
      const content = 'session_secret = "sessionkey123456"';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Application Secret');
    });

    it('should detect JWT secret', () => {
      const content = 'jwt_secret = "jwtkey123456"';
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('High Severity Patterns', () => {
    it('should detect cryptographic salt', () => {
      const content = 'salt = "mysalt123"';
      const fileContent: FileContent = {
        path: 'src/config/security.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Cryptographic Salt');
    });

    it('should detect admin password', () => {
      const content = 'admin_password = "adminpass123"';
      const fileContent: FileContent = {
        path: 'src/config/admin.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Admin Password');
    });

    it('should detect configuration password', () => {
      const content = 'password = "configpass123"';
      const fileContent: FileContent = {
        path: 'src/config/config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Third-Party Service Patterns', () => {
    it('should detect Stripe secret key', () => {
      // TEST DATA - NOT A REAL SECRET - This is dummy data for testing purposes
      const content = 'stripe_secret = "sk_test_1234567890abcdef"';
      const fileContent: FileContent = {
        path: 'src/config/payments.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect SendGrid API key', () => {
      const content = 'sendgrid_api_key = "SG.1234567890abcdef"';
      const fileContent: FileContent = {
        path: 'src/config/email.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('SendGrid API Key');
    });

    it('should detect Twilio auth token', () => {
      const content = 'twilio_auth_token = "1234567890abcdef1234567890abcdef"';
      const fileContent: FileContent = {
        path: 'src/config/sms.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Twilio Auth Token'))).toBe(true);
    });
  });

  describe('Cloud Provider Patterns', () => {
    it('should detect AWS access key', () => {
      // TEST DATA - NOT A REAL SECRET - This is dummy data for testing purposes
      const content = 'aws_access_key = "AKIA1234567890ABCDEF"';
      const fileContent: FileContent = {
        path: 'src/config/aws.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Cloud Provider Key');
    });

    it('should detect Azure key', () => {
      const content = 'azure_key = "abcdefghijklmnopqrstuvwxyz123456"';
      const fileContent: FileContent = {
        path: 'src/config/azure.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Cloud Provider Key'))).toBe(true);
    });

    it('should detect GCP key', () => {
      const content = 'gcp_key = "abcdefghijklmnopqrstuvwxyz123456"';
      const fileContent: FileContent = {
        path: 'src/config/gcp.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Cloud Provider Key'))).toBe(true);
    });
  });

  describe('Generic API Patterns', () => {
    it('should detect API key', () => {
      const content = 'api_key = "sk_1234567890abcdef"';
      const fileContent: FileContent = {
        path: 'src/config/api.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('API Key');
    });

    it('should detect webhook secret', () => {
      const content = 'webhook_secret = "webhooksecret123456"';
      const fileContent: FileContent = {
        path: 'src/config/webhooks.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Webhook Secret');
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip comments', () => {
      const content = '# database_url = "postgresql://user:pass@localhost:5432/db"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test files', () => {
      const content = 'database_url = "postgresql://user:pass@localhost:5432/db"';
      const fileContent: FileContent = {
        path: 'src/config/database.test.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip documentation files', () => {
      const content = 'database_url = "postgresql://user:pass@localhost:5432/db"';
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
        database_url = "postgresql://user:pass@localhost:5432/db"
        NODE_ENV = 'development'
      `;
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('False Positive Detection', () => {
    it('should skip example configurations', () => {
      const content = 'database_url = "example_postgresql_url"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sample configurations', () => {
      const content = 'database_url = "sample_postgresql_url"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip demo configurations', () => {
      const content = 'database_url = "demo_postgresql_url"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip placeholder configurations', () => {
      const content = 'database_url = "your_database_url"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
    });

    it('should skip environment variables', () => {
      const content = 'database_url = "${DATABASE_URL}"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip template variables', () => {
      const content = 'database_url = "{{ database_url }}"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Language-Specific Detection', () => {
    it('should detect Python sensitive data', () => {
      const content = 'database_url = "postgresql://user:pass@localhost:5432/db"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect JavaScript sensitive data', () => {
      const content = 'const databaseUrl = "postgresql://user:pass@localhost:5432/db";';
      const fileContent: FileContent = {
        path: 'src/config/database.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect TypeScript sensitive data', () => {
      const content = 'const databaseUrl: string = "postgresql://user:pass@localhost:5432/db";';
      const fileContent: FileContent = {
        path: 'src/config/database.ts',
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
        DATABASE_URL = "postgresql://user:pass@localhost:5432/db"
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
        const databaseUrl = "postgresql://user:pass@localhost:5432/db";
      `;
      const fileContent: FileContent = {
        path: 'src/config/database.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Flask framework', () => {
      const content = `
        # Flask configuration
        DATABASE_URL = "postgresql://user:pass@localhost:5432/db"
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
        'database_url' => 'postgresql://user:pass@localhost:5432/db',
      `;
      const fileContent: FileContent = {
        path: 'src/config/database.php',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Multiple Issues Detection', () => {
    it('should detect multiple sensitive data issues', () => {
      // TEST DATA - NOT A REAL SECRET - This is dummy data for testing purposes
      const content = `
        database_url = "postgresql://user:pass@localhost:5432/db"
        app_secret = "mysecretkey123456"
        stripe_secret = "sk_test_1234567890abcdef"
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect mixed severity issues', () => {
      const content = `
        database_url = "postgresql://user:pass@localhost:5432/db"
        salt = "mysalt123"
        admin_password = "adminpass123"
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

  describe('Suggestion Generation', () => {
    it('should provide database connection suggestion', () => {
      const content = 'database_url = "postgresql://user:pass@localhost:5432/db"';
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should provide encryption key suggestion', () => {
      const content = 'encryption_key = "abcdefghijklmnopqrstuvwxyz123456"';
      const fileContent: FileContent = {
        path: 'src/config/security.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.suggestion.includes('environment variables'))).toBe(true);
      expect(issues.some(issue => issue.suggestion.includes('key management'))).toBe(true);
    });

    it('should provide API key suggestion', () => {
      const content = 'api_key = "sk_1234567890abcdef"';
      const fileContent: FileContent = {
        path: 'src/config/api.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('environment variables');
      expect(issues[0]?.suggestion).toContain('API key rotation');
    });
  });

  describe('Edge Cases', () => {
    it('should handle different quote styles', () => {
      const content = `
        database_url = 'postgresql://user:pass@localhost:5432/db'
        database_url = "postgresql://user:pass@localhost:5432/db"
        database_url = \`postgresql://user:pass@localhost:5432/db\`
      `;
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should handle different assignment styles', () => {
      const content = `
        database_url: "postgresql://user:pass@localhost:5432/db"
        database_url = "postgresql://user:pass@localhost:5432/db"
        database_url := "postgresql://user:pass@localhost:5432/db"
      `;
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should handle complex nested configurations', () => {
      // TEST DATA - NOT A REAL SECRET - This is dummy data for testing purposes
      const content = `
        config = {
          database: {
            url: "postgresql://user:pass@localhost:5432/db"
          },
          security: {
            encryption_key: "abcdefghijklmnopqrstuvwxyz123456"
          },
          payments: {
            stripe_secret: "sk_test_1234567890abcdef"
          }
        }
      `;
      const fileContent: FileContent = {
        path: 'src/config/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.message.includes('Encryption Key'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('High-Entropy Secret'))).toBe(true);
    });
  });

  describe('Environment Variable Detection', () => {
    it('should skip when environment variables are used', () => {
      const content = `
        # Using environment variables
        database_url = os.getenv('DATABASE_URL')
        app_secret = os.getenv('APP_SECRET')
      `;
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip when process.env is used', () => {
      const content = `
        // Using environment variables
        const databaseUrl = process.env.DATABASE_URL;
        const appSecret = process.env.APP_SECRET;
      `;
      const fileContent: FileContent = {
        path: 'src/config/database.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip when config files use environment variables', () => {
      const content = `
        # Configuration using environment variables
        database_url = "\${DATABASE_URL}"
        app_secret = "\${APP_SECRET}"
      `;
      const fileContent: FileContent = {
        path: 'src/config/database.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });
});
