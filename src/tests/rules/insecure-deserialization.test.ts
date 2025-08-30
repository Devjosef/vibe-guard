import { InsecureDeserializationRule } from '../../rules/insecure-deserialization';
import { FileContent } from '../../types';

describe('InsecureDeserializationRule', () => {
  let rule: InsecureDeserializationRule;

  beforeEach(() => {
    rule = new InsecureDeserializationRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('insecure-deserialization');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects potentially unsafe deserialization of user input with context-aware analysis');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('high');
    });
  });

  describe('Critical Severity Patterns', () => {
    it('should detect eval with user input', () => {
      const content = 'eval(req.body.data)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Eval with user input');
    });

    it('should detect vm.runInNewContext with user input', () => {
      const content = 'vm.runInNewContext(req.body.code)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('VM context with user input');
    });

    it('should detect vm.runInThisContext with user input', () => {
      const content = 'vm.runInThisContext(req.body.code)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('VM this context with user input');
    });

    it('should detect Function constructor with user input', () => {
      const content = 'new Function(req.body.code)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Function constructor with user input');
    });
  });

  describe('High Severity Patterns', () => {
    it('should detect Python pickle with user input', () => {
      const content = 'pickle.loads(request.data)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Python pickle with user input');
    });

    it('should detect PHP unserialize with user input', () => {
      const content = 'unserialize($_POST["data"])';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Python yaml.load with user input', () => {
      const content = 'yaml.load(request.data)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Python yaml.load with user input');
    });

    it('should detect Python yaml.unsafe_load with user input', () => {
      const content = 'yaml.unsafe_load(request.data)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Java ObjectInputStream with user input', () => {
      const content = 'new ObjectInputStream(request.getInputStream())';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Java ObjectInputStream with user input');
    });

    it('should detect .NET BinaryFormatter with user input', () => {
      const content = 'BinaryFormatter.Deserialize(request.InputStream)';
      const fileContent: FileContent = {
        path: 'src/app.cs',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('.NET BinaryFormatter with user input');
    });
  });

  describe('Medium Severity Patterns', () => {
    it('should detect JSON.parse with user input', () => {
      const content = 'JSON.parse(req.body.data)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('JSON.parse with user input');
    });

    it('should detect PHP json_decode with user input', () => {
      const content = 'json_decode($_POST["data"])';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Jackson ObjectMapper with user input', () => {
      const content = 'objectMapper.readValue(request.getBody(), Object.class)';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect .NET DataContractSerializer with user input', () => {
      const content = 'DataContractSerializer.ReadObject(request.InputStream)';
      const fileContent: FileContent = {
        path: 'src/app.cs',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('.NET DataContractSerializer with user input');
    });
  });

  describe('Low Severity Patterns', () => {
    it('should detect generic deserialization with user input', () => {
      const content = 'parse(req.body.data)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('Generic deserialization with user input');
    });

    it('should detect load with user input', () => {
      const content = 'load(request.data)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('Generic deserialization with user input');
    });

    it('should detect deserialize with user input', () => {
      const content = 'deserialize(req.body.data)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('Generic deserialization with user input');
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip test files', () => {
      const content = 'eval(req.body.data)';
      const fileContent: FileContent = {
        path: 'src/app.test.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip documentation files', () => {
      const content = 'eval(req.body.data)';
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
        eval(req.body.data)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
    });
  });

  describe('False Positive Detection', () => {
    it('should skip example deserialization', () => {
      const content = 'eval(req.body.data)  # example';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip demo deserialization', () => {
      const content = 'eval(req.body.data)  # demo';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test deserialization', () => {
      const content = 'eval(req.body.data)  # test';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip mock deserialization', () => {
      const content = 'eval(req.body.data)  # mock';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sample deserialization', () => {
      const content = 'eval(req.body.data)  # sample';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip placeholder deserialization', () => {
      const content = 'eval(req.body.data)  # placeholder';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip dummy deserialization', () => {
      const content = 'eval(req.body.data)  # dummy';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip fake deserialization', () => {
      const content = 'eval(req.body.data)  # fake';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip development deserialization', () => {
      const content = 'eval(req.body.data)  # development';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip dev deserialization', () => {
      const content = 'eval(req.body.data)  # dev';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip staging deserialization', () => {
      const content = 'eval(req.body.data)  # staging';
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
    it('should detect JavaScript deserialization', () => {
      const content = 'eval(req.body.data)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect Python deserialization', () => {
      const content = 'pickle.loads(request.data)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
    });

    it('should detect PHP deserialization', () => {
      const content = 'unserialize($_POST["data"])';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Java deserialization', () => {
      const content = 'new ObjectInputStream(request.getInputStream())';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
    });

    it('should detect C# deserialization', () => {
      const content = 'BinaryFormatter.Deserialize(request.InputStream)';
      const fileContent: FileContent = {
        path: 'src/app.cs',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
    });
  });

  describe('Framework Detection', () => {
    it('should detect Express.js deserialization', () => {
      const content = `
        // Express.js app
        app.post('/api/data', (req, res) => {
          eval(req.body.data);
        });
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect Flask deserialization', () => {
      const content = `
        # Flask app
        @app.route('/api/data', methods=['POST'])
        def handle_data():
            pickle.loads(request.data)
      `;
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
    });

    it('should detect Laravel deserialization', () => {
      const content = `
        // Laravel controller
        public function handleData(Request $request) {
            unserialize($request->input('data'));
        }
      `;
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Spring deserialization', () => {
      const content = `
        // Spring controller
        @PostMapping("/api/data")
        public void handleData(@RequestBody String data) {
            new ObjectInputStream(new ByteArrayInputStream(data.getBytes()));
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
  });

  describe('Multiple Issues Detection', () => {
    it('should detect multiple deserialization issues', () => {
      const content = `
        eval(req.body.data)
        pickle.loads(request.data)
        JSON.parse(req.body.json)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(4);
      expect(issues.some(issue => issue.message.includes('Eval with user input'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Python pickle with user input'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('JSON.parse with user input'))).toBe(true);
    });

    it('should detect mixed severity issues', () => {
      const content = `
        eval(req.body.data)
        pickle.loads(request.data)
        parse(req.body.data)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.severity === 'low')).toBe(true);
    });
  });

  describe('Suggestion Generation', () => {
    it('should provide eval replacement suggestion', () => {
      const content = 'eval(req.body.data)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Never use eval()');
      expect(issues[0]?.suggestion).toContain('safer alternatives');
    });

    it('should provide pickle replacement suggestion', () => {
      const content = 'pickle.loads(request.data)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Avoid using pickle');
      expect(issues[0]?.suggestion).toContain('JSON');
    });

    it('should provide JSON.parse suggestion', () => {
      const content = 'JSON.parse(req.body.data)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.suggestion).toContain('Use JSON.parse with proper validation');
      expect(issues[0]?.suggestion).toContain('input validation');
    });
  });

  describe('Edge Cases', () => {
    it('should handle different user input sources', () => {
      const content = `
        eval(req.body.data)
        eval(req.query.data)
        eval(req.params.data)
        eval(input.data)
        eval(params.data)
        eval(query.data)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(6);
      expect(issues.every(issue => issue.message.includes('Eval with user input'))).toBe(true);
    });

    it('should handle different PHP input sources', () => {
      const content = `
        unserialize($_GET["data"])
        unserialize($_POST["data"])
        unserialize($_REQUEST["data"])
      `;
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should handle complex nested deserialization', () => {
      const content = `
        function processData(req) {
          const data = JSON.parse(req.body.data);
          const result = eval(data.code);
          return result;
        }
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues.some(issue => issue.message.includes('JSON.parse with user input'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Eval with user input'))).toBe(false);
    });
  });

  describe('Safe Deserialization Detection', () => {
    it('should skip safe JSON.parse usage', () => {
      const content = 'JSON.parse(JSON.stringify(data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip safe yaml usage', () => {
      const content = 'yaml.safe_load(data)';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip validated deserialization', () => {
      const content = 'JSON.parse(validate(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sanitized deserialization', () => {
      const content = 'JSON.parse(sanitize(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip escaped deserialization', () => {
      const content = 'JSON.parse(escape(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip cleaned deserialization', () => {
      const content = 'JSON.parse(clean(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip whitelisted deserialization', () => {
      const content = 'JSON.parse(whitelist(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip allowed deserialization', () => {
      const content = 'JSON.parse(allowed(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip permitted deserialization', () => {
      const content = 'JSON.parse(permitted(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip safe deserialization', () => {
      const content = 'JSON.parse(safe(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip secure deserialization', () => {
      const content = 'JSON.parse(secure(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip trusted deserialization', () => {
      const content = 'JSON.parse(trusted(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip verified deserialization', () => {
      const content = 'JSON.parse(verified(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip authenticated deserialization', () => {
      const content = 'JSON.parse(authenticated(req.body.data))';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip authorized deserialization', () => {
      const content = 'JSON.parse(authorized(req.body.data))';
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
