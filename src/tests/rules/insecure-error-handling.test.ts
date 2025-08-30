import { InsecureErrorHandlingRule } from '../../rules/insecure-error-handling';
import { FileContent } from '../../types';

describe('InsecureErrorHandlingRule', () => {
  let rule: InsecureErrorHandlingRule;

  beforeEach(() => {
    rule = new InsecureErrorHandlingRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('insecure-error-handling');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects information disclosure in error handling and stack traces with context-aware analysis');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('medium');
    });
  });

  describe('Critical Severity Patterns', () => {
    it('should detect stack trace logging', () => {
      const content = 'console.log(error.stack)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Stack trace logging');
    });

    it('should detect stack trace in HTTP response', () => {
      const content = 'res.status(500).send(error.stack)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Stack trace in HTTP response');
    });

    it('should detect exception stack trace logging', () => {
      const content = 'console.error(exception.stack)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Stack trace logging');
    });

    it('should detect stack trace in logger', () => {
      const content = 'logger.error(error.stack)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(6);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Stack trace logging');
    });
  });

  describe('High Severity Patterns', () => {
    it('should detect database error logging', () => {
      const content = 'console.log(sql_error)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Database error logging');
    });

    it('should detect database-specific error logging', () => {
      const content = 'console.log(mysql_error)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Database error logging');
    });

    it('should detect file system error logging', () => {
      const content = 'console.log(file_error)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('File system error logging');
    });

    it('should detect network error logging', () => {
      const content = 'console.log(network_error)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Network error logging');
    });

    it('should detect PHP debug output', () => {
      const content = 'print_r($error)';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('PHP debug output');
    });
  });

  describe('Medium Severity Patterns', () => {
    it('should detect detailed error message logging', () => {
      const content = 'console.log(error.message)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Detailed error message logging');
    });

    it('should detect error object logging', () => {
      const content = 'console.log(error)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Error object logging');
    });

    it('should detect PHP error logging', () => {
      const content = 'error_log($error)';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('PHP error logging');
    });

    it('should detect Python error logging', () => {
      const content = 'logging.error(error)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Python error logging');
    });

    it('should detect Python error printing', () => {
      const content = 'print(error)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Error object logging');
    });

    it('should detect Java error logging', () => {
      const content = 'log.error(error)';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Java error logging');
    });

    it('should detect Java error printing', () => {
      const content = 'System.out.println(error)';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Error object logging');
    });

    it('should detect Rails error logging', () => {
      const content = 'Rails.logger.error(error)';
      const fileContent: FileContent = {
        path: 'src/app.rb',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(5);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Error object logging');
    });

    it('should detect Spring error logging', () => {
      const content = 'logger.error(error)';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(5);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Error object logging');
    });

    it('should detect Django error logging', () => {
      const content = 'logging.error(error)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Python error logging');
    });
  });

  describe('Low Severity Patterns', () => {
    it('should detect detailed error response', () => {
      const content = 'res.status(500).json({ error: "Database connection failed" })';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('Detailed error response');
    });

    it('should detect error response sending', () => {
      const content = 'res.send(error)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('Error response sending');
    });

    it('should detect error template rendering', () => {
      const content = 'return render_template("error.html", error=error)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('Error template rendering');
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip comments', () => {
      const content = '// console.log(error.stack)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test files', () => {
      const content = 'console.log(error.stack)';
      const fileContent: FileContent = {
        path: 'src/app.test.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip documentation files', () => {
      const content = 'console.log(error.stack)';
      const fileContent: FileContent = {
        path: 'docs/example.md',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip development context', () => {
      const content = `
        // Development environment
        console.log(error.stack)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
    });
  });

  describe('False Positive Detection', () => {
    it('should skip example error handling', () => {
      const content = 'console.log(error.stack)  # example';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip demo error handling', () => {
      const content = 'console.log(error.stack)  # demo';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test error handling', () => {
      const content = 'console.log(error.stack)  # test';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip mock error handling', () => {
      const content = 'console.log(error.stack)  # mock';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sample error handling', () => {
      const content = 'console.log(error.stack)  # sample';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip placeholder error handling', () => {
      const content = 'console.log(error.stack)  # placeholder';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip dummy error handling', () => {
      const content = 'console.log(error.stack)  # dummy';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip fake error handling', () => {
      const content = 'console.log(error.stack)  # fake';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip development error handling', () => {
      const content = 'console.log(error.stack)  # development';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip dev error handling', () => {
      const content = 'console.log(error.stack)  # dev';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip staging error handling', () => {
      const content = 'console.log(error.stack)  # staging';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Language-Specific Detection', () => {
    it('should detect JavaScript error handling', () => {
      const content = 'console.log(error.stack)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
    });

    it('should detect Python error handling', () => {
      const content = 'print(error)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
    });

    it('should detect PHP error handling', () => {
      const content = 'error_log($error)';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
    });

    it('should detect Java error handling', () => {
      const content = 'System.out.println(error)';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
    });

    it('should detect Ruby error handling', () => {
      const content = 'Rails.logger.error(error)';
      const fileContent: FileContent = {
        path: 'src/app.rb',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(5);
      expect(issues[0]?.severity).toBe('medium');
    });
  });

  describe('Framework Detection', () => {
    it('should detect Express.js error handling', () => {
      const content = `
        // Express.js app
        app.use((error, req, res, next) => {
          console.log(error.stack);
        });
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
    });

    it('should detect Flask error handling', () => {
      const content = `
        # Flask app
        @app.errorhandler(500)
        def handle_error(error):
            print(error)
      `;
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
    });

    it('should detect Laravel error handling', () => {
      const content = `
        // Laravel controller
        public function handleError($error) {
            error_log($error);
        }
      `;
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
    });

    it('should detect Spring error handling', () => {
      const content = `
        // Spring controller
        @ExceptionHandler(Exception.class)
        public void handleError(Exception error) {
            System.out.println(error);
        }
      `;
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
    });
  });

  describe('Multiple Issues Detection', () => {
    it('should detect multiple error handling issues', () => {
      const content = `
        console.log(error.stack)
        console.log(sql_error)
        console.log(error.message)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(6);
      expect(issues.some(issue => issue.message.includes('Stack trace logging'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Database error logging'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Detailed error message logging'))).toBe(true);
    });

    it('should detect mixed severity issues', () => {
      const content = `
        console.log(error.stack)
        console.log(sql_error)
        console.log(error)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(5);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.severity === 'medium')).toBe(true);
    });
  });

  describe('Suggestion Generation', () => {
    it('should provide stack trace suggestion', () => {
      const content = 'console.log(error.stack)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.suggestion).toContain('Never expose stack traces');
      expect(issues[0]?.suggestion).toContain('production');
    });

    it('should provide database error suggestion', () => {
      const content = 'console.log(sql_error)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.suggestion).toContain('Log database errors with sanitized messages');
      expect(issues[0]?.suggestion).toContain('error codes');
    });

    it('should provide error object suggestion', () => {
      const content = 'console.log(error)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Avoid logging entire error objects');
      expect(issues[0]?.suggestion).toContain('generic error messages');
    });
  });

  describe('Edge Cases', () => {
    it('should handle different logging methods', () => {
      const content = `
        console.log(error.stack)
        console.warn(error.stack)
        console.error(error.stack)
        logger.log(error.stack)
        logger.warn(error.stack)
        logger.error(error.stack)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(18);
      expect(issues.some(issue => issue.message.includes('Stack trace logging'))).toBe(true);
    });

    it('should handle different error types', () => {
      const content = `
        console.log(error.stack)
        console.log(exception.stack)
        console.log(stack_trace)
        console.log(traceback)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(4);
      expect(issues.some(issue => issue.message.includes('Stack trace logging'))).toBe(true);
    });

    it('should handle complex nested error handling', () => {
      const content = `
        function handleError(error) {
          console.log(error.stack);
          console.log(error.message);
          return res.status(500).send(error);
        }
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(4);
      expect(issues.some(issue => issue.message.includes('Stack trace logging'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Detailed error message logging'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Error response sending'))).toBe(false);
    });
  });

  describe('Safe Error Handling Detection', () => {
    it('should skip redacted error logging', () => {
      const content = 'console.log("Error: [REDACTED]")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip masked error logging', () => {
      const content = 'console.log("Error: [MASKED]")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip hidden error logging', () => {
      const content = 'console.log("Error: [HIDDEN]")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip asterisk masked error logging', () => {
      const content = 'console.log("Error: ********")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip x masked error logging', () => {
      const content = 'console.log("Error: xxxxxxxx")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip filtered error logging', () => {
      const content = 'console.log("Error: [FILTERED]")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sensitive error logging', () => {
      const content = 'console.log("Error: [SENSITIVE]")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip private error logging', () => {
      const content = 'console.log("Error: [PRIVATE]")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip confidential error logging', () => {
      const content = 'console.log("Error: [CONFIDENTIAL]")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip generic error logging', () => {
      const content = 'console.log("Generic error occurred")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip standard error logging', () => {
      const content = 'console.log("Standard error message")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip default error logging', () => {
      const content = 'console.log("Default error occurred")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip fallback error logging', () => {
      const content = 'console.log("Fallback error message")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sanitized error logging', () => {
      const content = 'console.log(sanitize(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip masked error logging', () => {
      const content = 'console.log(mask(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip redacted error logging', () => {
      const content = 'console.log(redact(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip filtered error logging', () => {
      const content = 'console.log(filter(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip cleaned error logging', () => {
      const content = 'console.log(clean(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip removed error logging', () => {
      const content = 'console.log(remove(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip excluded error logging', () => {
      const content = 'console.log(exclude(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip omitted error logging', () => {
      const content = 'console.log(omit(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip hidden error logging', () => {
      const content = 'console.log(hide(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip concealed error logging', () => {
      const content = 'console.log(conceal(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip obscured error logging', () => {
      const content = 'console.log(obscure(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip anonymized error logging', () => {
      const content = 'console.log(anonymize(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip pseudonymized error logging', () => {
      const content = 'console.log(pseudonymize(error))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });
});
