import { DirectoryTraversalRule } from '../../rules/directory-traversal';
import { FileContent } from '../../types';

describe('DirectoryTraversalRule', () => {
  let rule: DirectoryTraversalRule;

  beforeEach(() => {
    rule = new DirectoryTraversalRule();
  });

  describe('check', () => {
    it('should detect unsafe file operations with user input', () => {
      const content: FileContent = {
        path: 'src/upload.ts',
        content: `
          const filePath = req.query.path;
          fs.readFile(filePath, (err, data) => {
            // Handle file
          });
        `,
        lines: ['const filePath = req.query.path;', 'fs.readFile(filePath, (err, data) => {', '  // Handle file', '});']
      };

      const issues = rule.check(content);
      expect(issues.length).toBeGreaterThan(0);
      expect(issues[0]?.rule).toBe('directory-traversal');
      expect(issues[0]?.severity).toBe('high');
    });

    it('should not flag safe path handling', () => {
      const content: FileContent = {
        path: 'src/upload.ts',
        content: `
          const filePath = req.query.path;
          const sanitizedPath = path.resolve(baseDir, filePath);
          fs.readFile(sanitizedPath, (err, data) => {
            // Handle file
          });
        `,
        lines: [
          'const filePath = req.query.path;',
          'const sanitizedPath = path.resolve(baseDir, filePath);',
          'fs.readFile(sanitizedPath, (err, data) => {',
          '  // Handle file',
          '});'
        ]
      };

      const issues = rule.check(content);
      expect(issues.length).toBe(0);
    });

    it('should detect path concatenation vulnerabilities', () => {
      const content: FileContent = {
        path: 'src/upload.ts',
        content: `
          const basePath = '/uploads/';
          const filePath = basePath + req.query.filename;
          fs.readFile(filePath, (err, data) => {
            // Handle file
          });
        `,
        lines: [
          'const basePath = \'/uploads/\';',
          'const filePath = basePath + req.query.filename;',
          'fs.readFile(filePath, (err, data) => {',
          '  // Handle file',
          '});'
        ]
      };

      const issues = rule.check(content);
      expect(issues.length).toBeGreaterThan(0);
      expect(issues[0]?.message).toContain('Path concatenation');
    });

    it('should detect template literal path vulnerabilities', () => {
      const content: FileContent = {
        path: 'src/upload.ts',
        content: `
          const basePath = '/uploads/';
          const filePath = \`\${basePath}\${req.query.filename}\`;
          fs.readFile(filePath, (err, data) => {
            // Handle file
          });
        `,
        lines: [
          'const basePath = \'/uploads/\';',
          'const filePath = `${basePath}${req.query.filename}`;',
          'fs.readFile(filePath, (err, data) => {',
          '  // Handle file',
          '});'
        ]
      };

      const issues = rule.check(content);
      expect(issues.length).toBeGreaterThan(0);
      expect(issues[0]?.message).toContain('Template literal path');
    });

    it('should not flag safe path handling with our sanitization', () => {
      const content: FileContent = {
        path: 'src/upload.ts',
        content: `
          const filePath = req.query.path;
          const sanitizedPath = filePath.replace(/\.\./g, '').replace(/\/+/g, '/');
          fs.readFile(sanitizedPath, (err, data) => {
            // Handle file
          });
        `,
        lines: [
          'const filePath = req.query.path;',
          'const sanitizedPath = filePath.replace(/\\.\\./g, \'\').replace(/\\/+/g, \'/\');',
          'fs.readFile(sanitizedPath, (err, data) => {',
          '  // Handle file',
          '});'
        ]
      };

      const issues = rule.check(content);
      expect(issues.length).toBe(0);
    });

    it('should ignore comments and test files', () => {
      const content: FileContent = {
        path: 'src/__tests__/upload.test.ts',
        content: `
          // This is a test file with vulnerable code
          const filePath = req.query.path;
          fs.readFile(filePath, (err, data) => {
            // Handle file
          });
        `,
        lines: [
          '// This is a test file with vulnerable code',
          'const filePath = req.query.path;',
          'fs.readFile(filePath, (err, data) => {',
          '  // Handle file',
          '});'
        ]
      };

      const issues = rule.check(content);
      expect(issues.length).toBe(0);
    });

    it('should ignore import statements', () => {
      const content: FileContent = {
        path: 'src/upload.ts',
        content: `
          import { readFile } from 'fs';
          import { resolve } from 'path';
        `,
        lines: [
          'import { readFile } from \'fs\';',
          'import { resolve } from \'path\';'
        ]
      };

      const issues = rule.check(content);
      expect(issues.length).toBe(0);
    });
  });
}); 