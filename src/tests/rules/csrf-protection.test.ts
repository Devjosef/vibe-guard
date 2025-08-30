import { CsrfProtectionRule } from '../../rules/csrf-protection';
import { FileContent } from '../../types';

describe('CsrfProtectionRule', () => {
  let rule: CsrfProtectionRule;

  beforeEach(() => {
    rule = new CsrfProtectionRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('csrf-protection');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects missing CSRF protection and unsafe cookie configurations with context-aware analysis');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('high');
    });
  });

  describe('High Severity CSRF Patterns', () => {
    it('should detect form without CSRF token', () => {
      const content = '<form method="post"><input type="text" name="username"></form>';
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Form without CSRF token'))).toBe(true);
    });

    it('should detect form missing CSRF input', () => {
      const content = '<form><input type="text" name="username"></form>';
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Form missing CSRF input');
    });

    it('should detect Express route without CSRF protection', () => {
      const content = 'app.post("/api/users", (req, res) => {});';
      const fileContent: FileContent = {
        path: 'src/routes/users.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Express route without CSRF protection'))).toBe(true);
    });

    it('should detect Express router without CSRF protection', () => {
      const content = 'router.post("/users", (req, res) => {});';
      const fileContent: FileContent = {
        path: 'src/routes/users.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Express router without CSRF protection'))).toBe(true);
    });
  });

  describe('Medium Severity CSRF Patterns', () => {
    it('should detect hidden input without CSRF token', () => {
      const content = '<input type="hidden" name="user_id" value="123">';
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Hidden input without CSRF token');
    });
  });

  describe('Framework-Specific CSRF Patterns', () => {
    it('should detect Django CSRF exemption', () => {
      const content = '@csrf_exempt';
      const fileContent: FileContent = {
        path: 'src/views.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Laravel CSRF directive', () => {
      const content = '@csrf';
      const fileContent: FileContent = {
        path: 'src/views/form.blade.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Flask CSRF exemption', () => {
      const content = '@csrf.exempt';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('AJAX CSRF Patterns', () => {
    it('should detect AJAX request without CSRF token', () => {
      const content = 'fetch("/api/users", { method: "post" });';
      const fileContent: FileContent = {
        path: 'src/static/js/api.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.message).toContain('AJAX request without CSRF token');
    });

    it('should detect Axios request without CSRF token', () => {
      const content = 'axios.post("/api/users", data);';
      const fileContent: FileContent = {
        path: 'src/static/js/api.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.message.includes('Axios request without CSRF token'))).toBe(true);
    });

    it('should detect jQuery AJAX without CSRF token', () => {
      const content = '$.post("/api/users", data);';
      const fileContent: FileContent = {
        path: 'src/static/js/api.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.message).toContain('HTTP client POST without CSRF');
    });
  });

  describe('High Severity Cookie Patterns', () => {
    it('should detect httpOnly disabled', () => {
      const content = 'httpOnly: false';
      const fileContent: FileContent = {
        path: 'src/config/cookies.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Insecure cookie configuration - httpOnly disabled');
    });

    it('should detect secure disabled', () => {
      const content = 'secure: false';
      const fileContent: FileContent = {
        path: 'src/config/cookies.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Insecure cookie configuration - secure disabled');
    });

    it('should detect SameSite none', () => {
      const content = 'sameSite: "none"';
      const fileContent: FileContent = {
        path: 'src/config/cookies.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Unsafe SameSite cookie setting');
    });
  });

  describe('Medium Severity Cookie Patterns', () => {
    it('should detect SameSite lax', () => {
      const content = 'sameSite: "lax"';
      const fileContent: FileContent = {
        path: 'src/config/cookies.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Potentially unsafe SameSite cookie setting');
    });
  });

  describe('Language-Specific Cookie Patterns', () => {
    it('should detect PHP cookie with secure disabled', () => {
      const content = 'setcookie("session", $value, $expire, $path, $domain, false);';
      const fileContent: FileContent = {
        path: 'src/auth.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.message).toContain('PHP cookie with secure disabled');
    });

    it('should detect Python cookie missing security attributes', () => {
      const content = 'response.set_cookie("session", value)';
      const fileContent: FileContent = {
        path: 'src/auth.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.message).toContain('Python cookie missing security attributes');
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip comments', () => {
      const content = '<!-- <form method="post"></form> -->';
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
    });

    it('should skip test files', () => {
      const content = '<form method="post"></form>';
      const fileContent: FileContent = {
        path: 'src/templates/form.test.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip documentation files', () => {
      const content = '<form method="post"></form>';
      const fileContent: FileContent = {
        path: 'docs/form-example.md',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip development context', () => {
      const content = `
        // Development environment
        <form method="post"></form>
        NODE_ENV = 'development'
      `;
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('False Positive Detection', () => {
    it('should skip example configurations', () => {
      const content = '<form method="post" class="example"></form>';
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
    });

    it('should skip demo configurations', () => {
      const content = '<form method="post" class="demo"></form>';
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
    });

    it('should skip mock configurations', () => {
      const content = '<form method="post" class="mock"></form>';
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
    });

    it('should skip secure configurations', () => {
      const content = '<form method="post" class="secure"></form>';
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
    });
  });

  describe('Language-Specific Detection', () => {
    it('should detect JavaScript CSRF issues', () => {
      const content = 'app.post("/api/users", (req, res) => {});';
      const fileContent: FileContent = {
        path: 'src/routes/users.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.message.includes('Express route without CSRF protection'))).toBe(true);
    });

    it('should detect Python CSRF issues', () => {
      const content = '@csrf_exempt';
      const fileContent: FileContent = {
        path: 'src/views.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect PHP CSRF issues', () => {
      const content = 'setcookie("session", $value, $expire, $path, $domain, false);';
      const fileContent: FileContent = {
        path: 'src/auth.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.message).toContain('PHP cookie with secure disabled');
    });
  });

  describe('Framework Detection', () => {
    it('should detect Express framework', () => {
      const content = `
        const express = require('express');
        app.post("/api/users", (req, res) => {});
      `;
      const fileContent: FileContent = {
        path: 'src/routes/users.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
    });

    it('should detect Django framework', () => {
      const content = `
        from django.views.decorators.csrf import csrf_exempt
        @csrf_exempt
      `;
      const fileContent: FileContent = {
        path: 'src/views.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Laravel framework', () => {
      const content = `
        @csrf
        <form method="post">
      `;
      const fileContent: FileContent = {
        path: 'src/views/form.blade.php',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Flask framework', () => {
      const content = `
        from flask import Flask
        @csrf.exempt
      `;
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Multiple Issues Detection', () => {
    it('should detect multiple CSRF issues', () => {
      const content = `
        <form method="post"></form>
        app.post("/api/users", (req, res) => {});
        httpOnly: false
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(5);
      expect(issues.some(issue => issue.message.includes('Form without CSRF token'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Express route without CSRF protection'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('httpOnly disabled'))).toBe(true);
    });

    it('should detect mixed severity issues', () => {
      const content = `
        <form method="post"></form>
        <input type="hidden" name="user_id" value="123">
        sameSite: "lax"
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(4);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.severity === 'medium')).toBe(true);
    });
  });

  describe('Suggestion Generation', () => {
    it('should provide form CSRF suggestion', () => {
      const content = '<form method="post"></form>';
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.suggestion.includes('Add CSRF token'))).toBe(true);
      expect(issues.some(issue => issue.suggestion.includes('hidden input fields'))).toBe(true);
    });

    it('should provide cookie security suggestion', () => {
      const content = 'httpOnly: false';
      const fileContent: FileContent = {
        path: 'src/config/cookies.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Enable httpOnly');
      expect(issues[0]?.suggestion).toContain('XSS attacks');
    });

    it('should provide Express CSRF suggestion', () => {
      const content = 'app.post("/api/users", (req, res) => {});';
      const fileContent: FileContent = {
        path: 'src/routes/users.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.suggestion.includes('CSRF middleware'))).toBe(true);
      expect(issues.some(issue => issue.suggestion.includes('protection'))).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle different quote styles', () => {
      const content = `
        <form method='post'></form>
        <form method="post"></form>
        <form method=\`post\`></form>
      `;
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(6);
      expect(issues.every(issue => issue.message.includes('Form without CSRF token') || issue.message.includes('Form missing CSRF input'))).toBe(true);
    });

    it('should handle different assignment styles', () => {
      const content = `
        httpOnly: false
        httpOnly = false
        httpOnly := false
      `;
      const fileContent: FileContent = {
        path: 'src/config/cookies.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues.every(issue => issue.message.includes('httpOnly disabled'))).toBe(true);
    });

    it('should handle complex nested configurations', () => {
      const content = `
        const config = {
          cookies: {
            httpOnly: false,
            secure: false,
            sameSite: "none"
          },
          routes: {
            post: "/api/users"
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
      expect(issues.some(issue => issue.message.includes('httpOnly disabled'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('secure disabled'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Unsafe SameSite cookie setting'))).toBe(true);
    });
  });

  describe('CSRF Protection Detection', () => {
    it('should skip when CSRF protection is present', () => {
      const content = `
        // CSRF protection enabled
        <form method="post">
          <input type="hidden" name="csrf_token" value="abc123">
        </form>
      `;
      const fileContent: FileContent = {
        path: 'src/templates/form.html',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip when secure cookies are configured', () => {
      const content = `
        // Secure cookie configuration
        httpOnly: true
        secure: true
        sameSite: "strict"
      `;
      const fileContent: FileContent = {
        path: 'src/config/cookies.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip when CSRF middleware is present', () => {
      const content = `
        // CSRF middleware enabled
        app.use(csrf());
        app.post("/api/users", (req, res) => {});
      `;
      const fileContent: FileContent = {
        path: 'src/routes/users.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });
});
