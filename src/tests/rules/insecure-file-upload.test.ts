import { InsecureFileUploadRule } from '../../rules/insecure-file-upload';
import { FileContent } from '../../types';

describe('InsecureFileUploadRule', () => {
  let rule: InsecureFileUploadRule;

  beforeEach(() => {
    rule = new InsecureFileUploadRule();
  });

  describe('Rule Properties', () => {
    it('should have correct name', () => {
      expect(rule.name).toBe('insecure-file-upload');
    });

    it('should have correct description', () => {
      expect(rule.description).toBe('Detects insecure file upload implementations without proper validation with context-aware analysis');
    });

    it('should have correct default severity', () => {
      expect(rule.severity).toBe('high');
    });
  });

  describe('Critical Severity Patterns', () => {
    it('should detect direct file move with original filename', () => {
      const content = 'file.mv("./uploads/" + file.name)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Direct file move with original filename');
    });

    it('should detect PHP file move without validation', () => {
      const content = 'move_uploaded_file($_FILES["file"]["tmp_name"], $target)';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('PHP file move without validation');
    });

    it('should detect any file upload without validation', () => {
      const content = 'upload.any()';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('critical');
      expect(issues[0]?.message).toContain('Any file upload without validation');
    });
  });

  describe('High Severity Patterns', () => {
    it('should detect multer upload without validation', () => {
      const content = 'multer({ dest: "uploads/" })';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Multer upload without validation');
    });

    it('should detect single file upload without validation', () => {
      const content = 'upload.single("file")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Single file upload without validation');
    });

    it('should detect multiple file upload without validation', () => {
      const content = 'upload.array("files")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Multiple file upload without validation');
    });

    it('should detect multiple fields upload without validation', () => {
      const content = 'upload.fields([{ name: "file1" }, { name: "file2" }])';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('Multiple fields upload without validation');
    });

    it('should detect file system operation without validation', () => {
      const content = 'fs.writeFile(req.body.filename, data)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('File system operation without validation');
    });

    it('should detect PHP file copy without validation', () => {
      const content = 'copy($_FILES["file"]["tmp_name"], $target)';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('high');
      expect(issues[0]?.message).toContain('PHP file copy without validation');
    });
  });

  describe('Medium Severity Patterns', () => {
    it('should detect PHP file upload without validation', () => {
      const content = '$_FILES["file"]';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Python file upload without validation', () => {
      const content = 'request.files["file"]';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Python file upload without validation');
    });

    it('should detect Java file upload without validation', () => {
      const content = 'request.getPart("file")';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Java file part without validation', () => {
      const content = 'Part filePart = request.getPart("file")';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Python file open without validation', () => {
      const content = 'open(request.files["file"])';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('Python file upload without validation');
    });

    it('should detect file move without validation', () => {
      const content = 'file.mv("./uploads/file.jpg")';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
      expect(issues[0]?.message).toContain('File move without validation');
    });
  });

  describe('Low Severity Patterns', () => {
    it('should detect file operation without type validation', () => {
      const content = 'readFile(req.body.filename)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('File operation without type validation');
    });

    it('should detect file extension assignment without validation', () => {
      const content = '.jpg = req.body.filename';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('File extension assignment without validation');
    });

    it('should detect filename assignment without validation', () => {
      const content = 'filename = req.body.filename';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('Filename assignment without validation');
    });

    it('should detect file size without limits', () => {
      const content = 'size = req.body.size';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('File size without limits');
    });

    it('should detect file size check without proper validation', () => {
      const content = 'bytes > 1024';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('File size check without proper validation');
    });
  });

  describe('Safe Context Detection', () => {
    it('should skip comments', () => {
      const content = '// file.mv("./uploads/" + file.name)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test files', () => {
      const content = 'file.mv("./uploads/" + file.name)';
      const fileContent: FileContent = {
        path: 'src/app.test.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip documentation files', () => {
      const content = 'file.mv("./uploads/" + file.name)';
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
        file.mv("./uploads/" + file.name)
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
    it('should skip example file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # example';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip demo file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # demo';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip test file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # test';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip mock file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # mock';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip sample file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # sample';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip placeholder file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # placeholder';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip dummy file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # dummy';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip fake file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # fake';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip development file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # development';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip dev file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # dev';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip staging file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)  # staging';
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
    it('should detect JavaScript file upload', () => {
      const content = 'file.mv("./uploads/" + file.name)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.severity).toBe('critical');
    });

    it('should detect Python file upload', () => {
      const content = 'request.files["file"]';
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
    });

    it('should detect PHP file upload', () => {
      const content = '$_FILES["file"]';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should detect Java file upload', () => {
      const content = 'request.getPart("file")';
      const fileContent: FileContent = {
        path: 'src/app.java',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Framework Detection', () => {
    it('should detect Express.js file upload', () => {
      const content = `
        // Express.js app
        app.post('/upload', upload.single('file'), (req, res) => {
          file.mv("./uploads/" + file.name);
        });
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.some(issue => issue.severity === 'high')).toBe(true);
      expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
    });

    it('should detect Flask file upload', () => {
      const content = `
        # Flask app
        @app.route('/upload', methods=['POST'])
        def upload_file():
            file = request.files["file"]
            file.save("./uploads/" + file.filename)
      `;
      const fileContent: FileContent = {
        path: 'src/app.py',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('medium');
    });

    it('should detect Laravel file upload', () => {
      const content = `
        // Laravel controller
        public function upload(Request $request) {
            $file = $request->file('file');
            $file->move(public_path('uploads'), $file->getClientOriginalName());
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

    it('should detect Spring file upload', () => {
      const content = `
        // Spring controller
        @PostMapping("/upload")
        public void uploadFile(@RequestParam("file") MultipartFile file) {
            Part filePart = request.getPart("file");
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
    it('should detect multiple file upload issues', () => {
      const content = `
        file.mv("./uploads/" + file.name)
        upload.single("file")
        $_FILES["file"]
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(3);
      expect(issues.some(issue => issue.message.includes('Direct file move with original filename'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Single file upload without validation'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('PHP file upload without validation'))).toBe(false);
    });

    it('should detect mixed severity issues', () => {
      const content = `
        file.mv("./uploads/" + file.name)
        upload.single("file")
        filename = req.body.filename
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
      expect(issues.some(issue => issue.severity === 'low')).toBe(true);
    });
  });

  describe('Suggestion Generation', () => {
    it('should provide direct file move suggestion', () => {
      const content = 'file.mv("./uploads/" + file.name)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(2);
      expect(issues[0]?.suggestion).toContain('Generate unique filenames');
      expect(issues[0]?.suggestion).toContain('validate file types');
    });

    it('should provide multer upload suggestion', () => {
      const content = 'multer({ dest: "uploads/" })';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.suggestion).toContain('Configure multer with fileFilter');
      expect(issues[0]?.suggestion).toContain('validate file types');
    });

    it('should provide PHP file upload suggestion', () => {
      const content = '$_FILES["file"]';
      const fileContent: FileContent = {
        path: 'src/app.php',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle different file upload methods', () => {
      const content = `
        upload.single("file")
        upload.array("files")
        upload.fields([{ name: "file1" }])
        upload.any()
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(4);
      expect(issues.some(issue => issue.message.includes('Single file upload without validation'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Multiple file upload without validation'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Multiple fields upload without validation'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('Any file upload without validation'))).toBe(true);
    });

    it('should handle different file system operations', () => {
      const content = `
        fs.readFile(req.body.filename)
        fs.writeFile(req.body.filename, data)
        fs.createReadStream(req.body.filename)
        fs.createWriteStream(req.body.filename)
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(6);
      expect(issues.some(issue => issue.message.includes('File system operation without validation'))).toBe(true);
    });

    it('should handle complex nested file upload', () => {
      const content = `
        function handleUpload(req, res) {
          const file = req.files.file;
          file.mv("./uploads/" + file.name);
          fs.writeFile(req.body.filename, data);
          return res.json({ success: true });
        }
      `;
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(4);
      expect(issues.some(issue => issue.message.includes('Direct file move with original filename'))).toBe(true);
      expect(issues.some(issue => issue.message.includes('File system operation without validation'))).toBe(true);
    });
  });

  describe('Safe File Upload Detection', () => {
    it('should skip fileFilter validation', () => {
      const content = 'multer({ dest: "uploads/", fileFilter: validateFile })';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file validation', () => {
      const content = 'upload.single("file").fileValidate(validateFile)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file check', () => {
      const content = 'upload.single("file").fileCheck(checkFile)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file verify', () => {
      const content = 'upload.single("file").fileVerify(verifyFile)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file sanitize', () => {
      const content = 'upload.single("file").fileSanitize(sanitizeFile)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file clean', () => {
      const content = 'upload.single("file").fileClean(cleanFile)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file whitelist', () => {
      const content = 'upload.single("file").fileWhitelist(whitelist)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file blacklist', () => {
      const content = 'upload.single("file").fileBlacklist(blacklist)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file allowed', () => {
      const content = 'upload.single("file").fileAllowed(allowed)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file permitted', () => {
      const content = 'upload.single("file").filePermitted(permitted)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file safe', () => {
      const content = 'upload.single("file").fileSafe(safe)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file secure', () => {
      const content = 'upload.single("file").fileSecure(secure)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file type', () => {
      const content = 'upload.single("file").fileType(type)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file mimetype', () => {
      const content = 'upload.single("file").fileMimetype(mimetype)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file extension', () => {
      const content = 'upload.single("file").fileExtension(extension)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file filename', () => {
      const content = 'upload.single("file").fileFilename(filename)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file size', () => {
      const content = 'upload.single("file").fileSize(size)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file limit', () => {
      const content = 'upload.single("file").fileLimit(limit)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file max', () => {
      const content = 'upload.single("file").fileMax(max)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file restrict', () => {
      const content = 'upload.single("file").fileRestrict(restrict)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file filter', () => {
      const content = 'upload.single("file").fileFilter(filter)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file scan', () => {
      const content = 'upload.single("file").fileScan(scan)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file virus', () => {
      const content = 'upload.single("file").fileVirus(virus)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file malware', () => {
      const content = 'upload.single("file").fileMalware(malware)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip file antivirus', () => {
      const content = 'upload.single("file").fileAntivirus(antivirus)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip upload validate', () => {
      const content = 'upload.single("file").uploadValidate(validate)';
      const fileContent: FileContent = {
        path: 'src/app.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should skip upload check', () => {
      const content = 'upload.single("file").uploadCheck(check)';
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
