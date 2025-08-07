import { Reporter } from '../../reporter';
import { ScanResult } from '../../types';

describe('Reporter', () => {
  let reporter: Reporter;

  beforeEach(() => {
    reporter = new Reporter();
  });

  describe('truncateFilePath', () => {
    it('should sanitize directory traversal attempts', () => {
      const maliciousPath = '../../../etc/passwd';
      const result = reporter['truncateFilePath'](maliciousPath);
      expect(result).toBe('etc/passwd');
    });

    it('should handle multiple directory traversal attempts', () => {
      const maliciousPath = '../../../../../../etc/passwd';
      const result = reporter['truncateFilePath'](maliciousPath);
      expect(result).toBe('etc/passwd');
    });

    it('should handle mixed slashes', () => {
      const maliciousPath = '..\\..\\..\\etc\\passwd';
      const result = reporter['truncateFilePath'](maliciousPath);
      expect(result).toBe('etc/passwd');
    });

    it('should handle normal paths', () => {
      const normalPath = 'src/components/Button.tsx';
      const result = reporter['truncateFilePath'](normalPath);
      expect(result).toBe('src/components/Button.tsx');
    });

    it('should truncate long paths', () => {
      const longPath = 'src/very/deep/nested/directory/structure/with/many/levels/file.ts';
      const result = reporter['truncateFilePath'](longPath, 35);
      expect(result).toBe('src/.../file.ts');
    });

    it('should handle paths with multiple consecutive slashes', () => {
      const path = 'src//components///Button.tsx';
      const result = reporter['truncateFilePath'](path);
      expect(result).toBe('src/components/Button.tsx');
    });
  });

  describe('formatTable', () => {
    it('should format scan results with issues', () => {
      const result: ScanResult = {
        issues: [
          {
            rule: 'directory-traversal',
            severity: 'high',
            file: 'src/components/FileUpload.tsx',
            line: 42,
            column: 15,
            message: 'Potential directory traversal vulnerability',
            code: 'filePath = req.query.path',
            suggestion: 'Use path.resolve() and validate input'
          }
        ],
        filesScanned: 1,
        issuesFound: 1,
        summary: {
          critical: 0,
          high: 1,
          medium: 0,
          low: 0
        }
      };

      const output = reporter.formatTable(result);
      expect(output).toContain('directory-traversal');
      expect(output).toContain('HIGH');
      expect(output).toContain('src/components/FileUpload.tsx');
    });

    it('should format scan results without issues', () => {
      const result: ScanResult = {
        issues: [],
        filesScanned: 1,
        issuesFound: 0,
        summary: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        }
      };

      const output = reporter.formatTable(result);
      expect(output).toContain('No security issues found');
    });
  });
});