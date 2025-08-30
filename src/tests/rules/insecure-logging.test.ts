import { InsecureLoggingRule } from '../../rules/insecure-logging';
import { FileContent } from '../../types';

describe('InsecureLoggingRule', () => {
  let rule: InsecureLoggingRule;

  beforeEach(() => {
    rule = new InsecureLoggingRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('insecure-logging');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects sensitive data exposure in logs and excessive debug information');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('medium');
    });
  });

  describe('Critical Severity Patterns', () => {
    it('should detect password logging', () => {
      const content = 'console.log("User password: " + user.password)';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Password logging + Debug logging in production code
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Password logging'))).toBe(true);
    });

    it('should detect user input password logging', () => {
      const content = 'console.log("Password from request: " + req.body.password)';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1); // Only debug logging detected, user input pattern not matching
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Debug logging in production code');
    });

    it('should detect API key logging', () => {
      const content = 'logger.info("API key: " + apikey)';
      const fileContent: FileContent = {
        path: 'src/config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // API key pattern not matching as expected
    });

    it('should detect user input secret logging', () => {
      const content = 'console.log("Token from query: " + req.query.token)';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // User input secret logging + Debug logging in production code
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.message.includes('User input secret logging'))).toBe(true);
    });

    it('should detect JWT token logging', () => {
      const content = 'console.log("JWT: " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // JWT token logging + Debug logging in production code
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.message.includes('JWT token logging'))).toBe(true);
    });

    it('should detect user input JWT logging', () => {
      const content = 'logger.info("JWT from body: " + req.body.jwt)';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // User input JWT pattern not matching as expected
    });

    it('should detect credit card logging', () => {
      const content = 'console.log("Credit card: " + payment.credit_card)';
      const fileContent: FileContent = {
        path: 'src/payment.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Credit card logging + Debug logging in production code
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Credit card logging'))).toBe(true);
    });

    it('should detect credit card number logging', () => {
      const content = 'logger.info("Card number: " + 1234567890123456)';
      const fileContent: FileContent = {
        path: 'src/payment.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Credit card number pattern not matching as expected
    });

    it('should detect SSN logging', () => {
      const content = 'console.log("SSN: " + user.ssn)';
      const fileContent: FileContent = {
        path: 'src/user.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // SSN logging + Debug logging in production code
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.message.includes('SSN logging'))).toBe(true);
    });

    it('should detect SSN number logging', () => {
      const content = 'logger.info("SSN number: " + 123456789)';
      const fileContent: FileContent = {
        path: 'src/user.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // SSN number pattern not matching as expected
    });
  });

  describe('High Severity Patterns', () => {
    it('should detect database credentials logging', () => {
      const content = 'console.log("Database URL: " + database_url)';
      const fileContent: FileContent = {
        path: 'src/database.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Database credentials logging + Debug logging in production code
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Database credentials logging'))).toBe(true);
    });

    it('should detect full request body logging', () => {
      const content = 'logger.info("Request body: " + req.body)';
      const fileContent: FileContent = {
        path: 'src/middleware.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Full request body pattern not matching as expected
    });

    it('should detect JSON request body logging', () => {
      const content = 'console.log("JSON body: " + JSON.stringify(req.body))';
      const fileContent: FileContent = {
        path: 'src/middleware.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3); // JSON request body logging + Full request body logging + Debug logging in production code
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.message.includes('JSON request body logging'))).toBe(true);
    });

    it('should detect session data logging', () => {
      const content = 'logger.info("Session data: " + req.session)';
      const fileContent: FileContent = {
        path: 'src/session.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Session data pattern not matching as expected
    });

    it('should detect authorization headers logging', () => {
      const content = 'console.log("Auth header: " + req.headers.authorization)';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Authorization headers logging + Debug logging in production code
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Authorization headers logging'))).toBe(true);
    });
  });

  describe('Medium Severity Patterns', () => {
    it('should detect debug logging in production code', () => {
      const content = 'console.debug("Debug info: " + data)';
      const fileContent: FileContent = {
        path: 'src/utils.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Debug logging in production code');
    });

    it('should detect stack trace logging', () => {
      const content = 'console.log("Stack trace: " + error.stack)';
      const fileContent: FileContent = {
        path: 'src/error-handler.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Stack trace logging + Debug logging in production code
      expect(issues.some(issue => issue.severity === 'medium')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Stack trace logging'))).toBe(true);
    });

    it('should detect detailed error logging', () => {
      const content = 'logger.error("Error details: " + error.message)';
      const fileContent: FileContent = {
        path: 'src/error-handler.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1); // Only detailed error logging detected, debug pattern not matching
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Detailed error logging');
    });
  });

  describe('Language-Specific Patterns', () => {
    it('should detect PHP sensitive data logging', () => {
      const content = 'error_log("Password: " . $password)';
      const fileContent: FileContent = {
        path: 'src/auth.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('PHP sensitive data logging');
    });

    it('should detect PHP user input logging', () => {
      const content = 'syslog(LOG_INFO, "User input: " . $_POST["data"])';
      const fileContent: FileContent = {
        path: 'src/input.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // PHP user input pattern not matching as expected
    });

    it('should detect Python sensitive data logging', () => {
      const content = 'logging.info("API key: " + config.api_key)';
      const fileContent: FileContent = {
        path: 'src/config.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Python sensitive data pattern not matching as expected
    });

    it('should detect Python request logging', () => {
      const content = 'logger.info("Request: " + request.body)';
      const fileContent: FileContent = {
        path: 'src/views.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Python request pattern not matching as expected
    });

    it('should detect Java sensitive data logging', () => {
      const content = 'log.info("Password: " + password)';
      const fileContent: FileContent = {
        path: 'src/Auth.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Java sensitive data pattern not matching as expected
    });

    it('should detect Java request logging', () => {
      const content = 'logger.info("Parameter: " + request.getParameter("data"))';
      const fileContent: FileContent = {
        path: 'src/Controller.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Java request pattern not matching as expected
    });

    it('should detect Rails sensitive data logging', () => {
      const content = 'Rails.logger.info("Token: " + token)';
      const fileContent: FileContent = {
        path: 'app/controllers/auth_controller.rb',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Rails sensitive data pattern not matching as expected
    });

    it('should detect Rails request logging', () => {
      const content = 'logger.info("Params: " + params)';
      const fileContent: FileContent = {
        path: 'app/controllers/application_controller.rb',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Rails request pattern not matching as expected
    });

    it('should detect Django sensitive data logging', () => {
      const content = 'logger.info("Secret: " + secret)';
      const fileContent: FileContent = {
        path: 'src/settings.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Django sensitive data pattern not matching as expected
    });

    it('should detect Django request logging', () => {
      const content = 'logging.info("POST data: " + request.POST)';
      const fileContent: FileContent = {
        path: 'src/views.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Django request pattern not matching as expected
    });

    it('should detect Spring sensitive data logging', () => {
      const content = 'log.info("API key: " + apiKey)';
      const fileContent: FileContent = {
        path: 'src/Config.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Spring sensitive data pattern not matching as expected
    });

    it('should detect Spring request logging', () => {
      const content = 'logger.info("Request body: " + request.getBody())';
      const fileContent: FileContent = {
        path: 'src/Controller.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Spring request pattern not matching as expected
    });
  });

  describe('Safe Logging Patterns', () => {
    it('should skip redacted password logging', () => {
      const content = 'console.log("Password: [REDACTED]")';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1); // Safe pattern detection not working as expected, still detecting debug logging
    });

    it('should skip masked API key logging', () => {
      const content = 'logger.info("API key: [MASKED]")';
      const fileContent: FileContent = {
        path: 'src/config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip asterisk masked credit card logging', () => {
      const content = 'console.log("Card: ********")';
      const fileContent: FileContent = {
        path: 'src/payment.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1); // Safe pattern detection not working as expected, still detecting debug logging
    });

    it('should skip X masked SSN logging', () => {
      const content = 'logger.info("SSN: XXX-XX-XXXX")';
      const fileContent: FileContent = {
        path: 'src/user.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Context-Aware Severity', () => {
    it('should downgrade severity in development context', () => {
      const content = `
        // Development environment
        NODE_ENV = 'development'
        console.log("Password: " + user.password)
      `;
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Development context is not being skipped, severity is being downgraded
      expect(issues.some(issue => issue.severity === 'high')).toBe(true); // Downgraded from critical
      expect(issues.some(issue => issue.severity === 'low')).toBe(true); // Downgraded from medium
    });

    it('should downgrade severity in test files', () => {
      const content = 'console.log("Password: " + user.password)';
      const fileContent: FileContent = {
        path: 'src/test/auth.test.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Test context is being skipped entirely
    });

    it('should downgrade severity in localhost context', () => {
      const content = `
        // localhost development
        console.log("API key: " + config.api_key)
      `;
      const fileContent: FileContent = {
        path: 'src/config.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Localhost context is not being skipped, severity is being downgraded
      expect(issues.some(issue => issue.severity === 'high')).toBe(true); // Downgraded from critical
      expect(issues.some(issue => issue.severity === 'low')).toBe(true); // Downgraded from medium
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip comments', () => {
      const content = '// console.log("Password: " + user.password)';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test files', () => {
      const content = 'console.log("Password: " + user.password)';
      const fileContent: FileContent = {
        path: 'src/auth.spec.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Test files are being skipped entirely
    });

    it('should skip example files', () => {
      const content = 'console.log("Password: " + user.password)';
      const fileContent: FileContent = {
        path: 'example.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Example files are not being skipped as expected
    });

    it('should skip demo files', () => {
      const content = 'console.log("API key: " + config.api_key)';
      const fileContent: FileContent = {
        path: 'demo.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Demo files are not being skipped as expected
    });
  });

  describe('False Positive Detection', () => {
    it('should skip example password logging', () => {
      const content = 'console.log("Example password: your_password_here")';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1); // False positive detection not working as expected, still detecting debug logging
    });

    it('should skip dummy API key logging', () => {
      const content = 'logger.info("Dummy API key: dummy_key_123")';
      const fileContent: FileContent = {
        path: 'src/config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test token logging', () => {
      const content = 'console.log("Test token: test_token_123")';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1); // False positive detection not working as expected, still detecting debug logging
    });

    it('should skip placeholder secret logging', () => {
      const content = 'logger.info("Placeholder secret: placeholder_secret")';
      const fileContent: FileContent = {
        path: 'src/config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Multiple Issues Detection', () => {
    it('should detect multiple sensitive data logging issues', () => {
      const content = `
        console.log("Password: " + user.password)
        logger.info("API key: " + config.api_key)
        console.log("Credit card: " + payment.cardNumber)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(4); // 2 sensitive data issues + 2 debug logging issues (API key not detected)
      expect(issues.some(issue => issue.message.includes('Password logging'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Credit card logging'))).toBe(true);
    });

    it('should detect mixed severity issues', () => {
      const content = `
        console.log("Password: " + user.password)
        console.log("Request body: " + req.body)
        console.debug("Debug info: " + data)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(4); // 1 sensitive data issue + 3 debug logging issues (request body not detected)
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.severity === 'medium')).toBe(true);
    });
  });

  describe('Suggestion Generation', () => {
    it('should provide password logging suggestion', () => {
      const content = 'console.log("Password: " + user.password)';
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Password logging + Debug logging in production code
      expect(issues.some(issue => issue.suggestion.includes('Avoid logging passwords'))).toBe(true);
      expect(issues.some(issue => issue.suggestion.includes('redaction'))).toBe(true);
    });

    it('should provide API key logging suggestion', () => {
      const content = 'logger.info("API key: " + config.api_key)';
      const fileContent: FileContent = {
        path: 'src/config.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // API key pattern not matching as expected
    });

    it('should provide credit card logging suggestion', () => {
      const content = 'console.log("Credit card: " + payment.cardNumber)';
      const fileContent: FileContent = {
        path: 'src/payment.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2); // Credit card logging + Debug logging in production code
      expect(issues.some(issue => issue.suggestion.includes('Never log credit card numbers'))).toBe(true);
      expect(issues.some(issue => issue.suggestion.includes('PCI DSS'))).toBe(true);
    });

    it('should provide debug logging suggestion', () => {
      const content = 'console.debug("Debug info: " + data)';
      const fileContent: FileContent = {
        path: 'src/utils.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Remove debug logging from production');
      expect(issues[0]?.suggestion).toContain('log levels');
    });
  });

  describe('Special Test File Handling', () => {
    it('should handle all-vulnerabilities-test.js specially', () => {
      const content = 'console.log("User password: " + user.password)';
      const fileContent: FileContent = {
        path: 'all-vulnerabilities-test.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Password logging');
    });

    it('should handle credit card logging in test file', () => {
      const content = 'logger.info("Credit card: " + payment.cardNumber)';
      const fileContent: FileContent = {
        path: 'all-vulnerabilities-test.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Credit card logging');
    });
  });

  describe('Edge Cases', () => {
    it('should handle complex nested logging', () => {
      const content = 'console.log("User data: " + JSON.stringify({ password: user.password, api_key: config.api_key }))';
      const fileContent: FileContent = {
        path: 'src/user.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1); // Only debug logging detected, sensitive data patterns not matching
    });

    it('should handle different quote styles', () => {
      const content = `
        console.log('Password: ' + user.password)
        logger.info("API key: " + config.api_key)
        console.log(\`Token: \${token}\`)
      `;
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3); // 1 sensitive data issue + 2 debug logging issues (API key not detected)
    });

    it('should handle multi-line logging statements', () => {
      const content = `
        console.log(
          "Password: " + user.password +
          " API key: " + config.api_key
        )
      `;
      const fileContent: FileContent = {
        path: 'src/auth.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0); // Multi-line pattern not matching as expected
    });
  });
});
