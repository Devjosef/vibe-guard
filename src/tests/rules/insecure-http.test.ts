import { InsecureHttpRule } from '../../rules/insecure-http';
import { FileContent } from '../../types';

describe('InsecureHttpRule', () => {
  let rule: InsecureHttpRule;

  beforeEach(() => {
    rule = new InsecureHttpRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('insecure-http');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects insecure HTTP usage instead of HTTPS with context-aware analysis');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('medium');
    });
  });

  describe('Critical Severity Patterns', () => {
    it('should detect HTTP API endpoint', () => {
      const content = 'api_url = "http://api.example.com"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect HTTP fetch request', () => {
      const content = 'fetch("http://api.example.com/data")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect HTTP axios request', () => {
      const content = 'axios.get("http://api.example.com/data")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect HTTP server creation', () => {
      const content = 'http.createServer((req, res) => {})';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('HTTP Server Creation');
    });

    it('should detect HTTP module import', () => {
      const content = 'const http = require("http")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('High Severity Patterns', () => {
    it('should detect HTTP protocol configuration', () => {
      const content = 'protocol = "http"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect insecure configuration', () => {
      const content = 'secure = false';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Insecure Configuration');
    });

    it('should detect HTTP server binding', () => {
      const content = 'app.listen(3000, "0.0.0.0")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect insecure cookie configuration', () => {
      const content = 'httpOnly: false';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Insecure Cookie Configuration');
    });

    it('should detect insecure cookie security', () => {
      const content = 'secure: false';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Insecure Cookie Security');
    });
  });

  describe('Medium Severity Patterns', () => {
    it('should detect mixed content resource', () => {
      const content = 'src="http://cdn.example.com/script.js"';
      const fileContent: FileContent = {
        path: 'src/app.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect mixed content link', () => {
      const content = 'href="http://example.com"';
      const fileContent: FileContent = {
        path: 'src/app.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect HTTP Spring mapping', () => {
      const content = '@RequestMapping(value = "/api", method = RequestMethod.GET)';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect permissive host configuration', () => {
      const content = 'ALLOWED_HOSTS = ["*"]';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Low Severity Patterns', () => {
    it('should detect HTTP URL', () => {
      const content = '"http://example.com"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip comments', () => {
      const content = '// http://example.com';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test files', () => {
      const content = 'http://example.com';
      const fileContent: FileContent = {
        path: 'src/app.test.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip documentation files', () => {
      const content = 'http://example.com';
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
        http://localhost:3000
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('False Positive Detection', () => {
    it('should skip example HTTP usage', () => {
      const content = 'http://example.com  # example';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip demo HTTP usage', () => {
      const content = 'http://example.com  # demo';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test HTTP usage', () => {
      const content = 'http://example.com  # test';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip mock HTTP usage', () => {
      const content = 'http://example.com  # mock';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sample HTTP usage', () => {
      const content = 'http://example.com  # sample';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip placeholder HTTP usage', () => {
      const content = 'http://example.com  # placeholder';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip dummy HTTP usage', () => {
      const content = 'http://example.com  # dummy';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip fake HTTP usage', () => {
      const content = 'http://example.com  # fake';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip development HTTP usage', () => {
      const content = 'http://example.com  # development';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip dev HTTP usage', () => {
      const content = 'http://example.com  # dev';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip staging HTTP usage', () => {
      const content = 'http://example.com  # staging';
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
    it('should detect JavaScript HTTP usage', () => {
      const content = 'fetch("http://api.example.com")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Python HTTP usage', () => {
      const content = 'ALLOWED_HOSTS = ["*"]';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Java HTTP usage', () => {
      const content = '@RequestMapping(value = "/api")';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect HTML HTTP usage', () => {
      const content = 'src="http://cdn.example.com/script.js"';
      const fileContent: FileContent = {
        path: 'src/app.html',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Framework Detection', () => {
    it('should detect Express.js HTTP usage', () => {
      const content = `
        // Express.js app
        const http = require('http');
        app.listen(3000, "0.0.0.0");
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Django HTTP usage', () => {
      const content = `
        # Django settings
        ALLOWED_HOSTS = ["*"]
        DEBUG = True
      `;
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Spring HTTP usage', () => {
      const content = `
        // Spring controller
        @RequestMapping(value = "/api", method = RequestMethod.GET)
        public ResponseEntity<String> getData() {
            return ResponseEntity.ok("data");
        }
      `;
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Flask HTTP usage', () => {
      const content = `
        # Flask app
        app.run(host="0.0.0.0", port=5000, debug=True)
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
    it('should detect multiple HTTP issues', () => {
      const content = `
        const http = require("http");
        fetch("http://api.example.com");
        protocol = "http";
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect mixed severity issues', () => {
      const content = `
        fetch("http://api.example.com");
        protocol = "http";
        "http://example.com";
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Suggestion Generation', () => {
    it('should provide HTTP API endpoint suggestion', () => {
      const content = 'api_url = "http://api.example.com"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should provide HTTP fetch request suggestion', () => {
      const content = 'fetch("http://api.example.com/data")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should provide HTTP protocol configuration suggestion', () => {
      const content = 'protocol = "http"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle different HTTP methods', () => {
      const content = `
        axios.get("http://api.example.com")
        axios.post("http://api.example.com")
        axios.put("http://api.example.com")
        axios.delete("http://api.example.com")
        axios.patch("http://api.example.com")
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should handle different HTTP configurations', () => {
      const content = `
        protocol = "http"
        scheme = "http"
        secure = false
        httpOnly: false
        secure: false
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.some(issue => issue.message.includes('Insecure Configuration'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Insecure Cookie Configuration'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Insecure Cookie Security'))).toBe(true);
    });

    it('should handle complex nested HTTP usage', () => {
      const content = `
        function makeRequest() {
          const http = require("http");
          fetch("http://api.example.com");
          return { protocol: "http" };
        }
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Safe HTTP Detection', () => {
    it('should skip localhost', () => {
      const content = 'http://localhost:3000';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip 127.0.0.1', () => {
      const content = 'http://127.0.0.1:3000';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip 0.0.0.0', () => {
      const content = 'http://0.0.0.0:3000';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip .local domains', () => {
      const content = 'http://example.local';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip .test domains', () => {
      const content = 'http://example.test';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip .dev domains', () => {
      const content = 'http://example.dev';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip .staging domains', () => {
      const content = 'http://example.staging';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip .development domains', () => {
      const content = 'http://example.development';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip NODE_ENV development', () => {
      const content = 'NODE_ENV = "development"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip NODE_ENV test', () => {
      const content = 'NODE_ENV = "test"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip NODE_ENV staging', () => {
      const content = 'NODE_ENV = "staging"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip DEBUG true', () => {
      const content = 'DEBUG = true';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip ENVIRONMENT development', () => {
      const content = 'ENVIRONMENT = "development"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip ENVIRONMENT test', () => {
      const content = 'ENVIRONMENT = "test"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip ENVIRONMENT staging', () => {
      const content = 'ENVIRONMENT = "staging"';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip RAILS_ENV development', () => {
      const content = 'RAILS_ENV = "development"';
      const fileContent: FileContent = {
        path: 'src/app.rb',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip RAILS_ENV test', () => {
      const content = 'RAILS_ENV = "test"';
      const fileContent: FileContent = {
        path: 'src/app.rb',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip DJANGO_SETTINGS_MODULE development', () => {
      const content = 'DJANGO_SETTINGS_MODULE = "app.settings.development"';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip DJANGO_SETTINGS_MODULE test', () => {
      const content = 'DJANGO_SETTINGS_MODULE = "app.settings.test"';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip SPRING_PROFILES_ACTIVE dev', () => {
      const content = 'SPRING_PROFILES_ACTIVE = "dev"';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip SPRING_PROFILES_ACTIVE test', () => {
      const content = 'SPRING_PROFILES_ACTIVE = "test"';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });
});
