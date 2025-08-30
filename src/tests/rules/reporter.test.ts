import { Reporter } from '../../reporter';
import { ScanResult, SecurityIssue } from '../../types';

describe('Reporter', () => {
  let reporter: Reporter;

  beforeEach(() => {
    reporter = new Reporter();
  });

  describe('Rule Properties', () => {
    it('should be instantiable', () => {
      expect(reporter).toBeInstanceOf(Reporter);
    });
  });

  describe('Path Sanitization', () => {
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

    it('should handle paths with multiple consecutive slashes', () => {
      const path = 'src//components///Button.tsx';
      const result = reporter['truncateFilePath'](path);
      expect(result).toBe('src/components/Button.tsx');
    });

    it('should handle absolute paths', () => {
      const absolutePath = '/home/user/project/src/file.js';
      const result = reporter['truncateFilePath'](absolutePath);
      expect(result).toBe('home/user/project/src/file.js');
    });
  });

  describe('Path Truncation', () => {
    it('should truncate long paths', () => {
      const longPath = 'src/very/deep/nested/directory/structure/with/many/levels/file.ts';
      const result = reporter['truncateFilePath'](longPath, 35);
      expect(result).toBe('src/.../file.ts');
    });

    it('should not truncate short paths', () => {
      const shortPath = 'src/file.js';
      const result = reporter['truncateFilePath'](shortPath, 35);
      expect(result).toBe('src/file.js');
    });

    it('should handle paths with only two parts', () => {
      const twoPartPath = 'src/components/Button.tsx';
      const result = reporter['truncateFilePath'](twoPartPath, 20);
      // The method truncates this path because it's longer than maxLength (20)
      expect(result).toBe('src/.../Button.tsx');
    });

    it('should handle very long filenames', () => {
      const longFilename = 'src/very-long-filename-that-exceeds-maximum-length.ts';
      const result = reporter['truncateFilePath'](longFilename, 20);
      // For paths with 2 parts, the method returns the full path even if it's long
      expect(result).toBe('src/very-long-filename-that-exceeds-maximum-length.ts');
      expect(result.length).toBeGreaterThan(20);
    });
  });

  describe('Table Formatting', () => {
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
      expect(output).toContain('Potential directory traversal vulnerability');
    });

    it('should format scan results without issues', () => {
      const result: ScanResult = {
        issues: [],
        filesScanned: 5,
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
      expect(output).toContain('5 files');
    });

    it('should handle multiple issues with different severities', () => {
      const result: ScanResult = {
        issues: [
          {
            rule: 'xss-detection',
            severity: 'critical',
            file: 'src/components/UserInput.tsx',
            line: 15,
            column: 10,
            message: 'XSS vulnerability detected',
            code: 'innerHTML = userInput',
            suggestion: 'Use textContent instead'
          },
          {
            rule: 'sql-injection',
            severity: 'medium',
            file: 'src/database/query.ts',
            line: 25,
            column: 5,
            message: 'SQL injection risk',
            code: 'query = "SELECT * FROM " + table',
            suggestion: 'Use parameterized queries'
          }
        ],
        filesScanned: 2,
        issuesFound: 2,
        summary: {
          critical: 1,
          high: 0,
          medium: 1,
          low: 0
        }
      };

      const output = reporter.formatTable(result);
      expect(output).toContain('xss-detection');
      expect(output).toContain('sql-injection');
      expect(output).toContain('CRITICAL');
      expect(output).toContain('MEDIUM');
    });
  });

  describe('JSON Formatting', () => {
    it('should format scan results as JSON', () => {
      const result: ScanResult = {
        issues: [
          {
            rule: 'test-rule',
            severity: 'high',
            file: 'test.js',
            line: 1,
            column: 1,
            message: 'Test issue',
            code: 'test code',
            suggestion: 'Test suggestion'
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

      const output = reporter.formatJson(result);
      const parsed = JSON.parse(output);
      
      expect(parsed.issues).toHaveLength(1);
      expect(parsed.issues[0].rule).toBe('test-rule');
      expect(parsed.issues[0].severity).toBe('high');
      expect(parsed.filesScanned).toBe(1);
      expect(parsed.issuesFound).toBe(1);
    });

    it('should handle empty results in JSON', () => {
      const result: ScanResult = {
        issues: [],
        filesScanned: 0,
        issuesFound: 0,
        summary: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        }
      };

      const output = reporter.formatJson(result);
      const parsed = JSON.parse(output);
      
      expect(parsed.issues).toHaveLength(0);
      expect(parsed.filesScanned).toBe(0);
      expect(parsed.issuesFound).toBe(0);
    });
  });

  describe('SARIF Formatting', () => {
    it('should format scan results as SARIF', () => {
      const result: ScanResult = {
        issues: [
          {
            rule: 'test-rule',
            severity: 'high',
            file: 'test.js',
            line: 1,
            column: 1,
            message: 'Test issue',
            code: 'test code',
            suggestion: 'Test suggestion'
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

      const output = reporter.formatSarif(result);
      const parsed = JSON.parse(output);
      
      expect(parsed.$schema).toContain('sarif');
      expect(parsed.version).toBe('2.1.0');
      expect(parsed.runs).toHaveLength(1);
      expect(parsed.runs[0].tool.driver.name).toBe('Vibe-Guard');
      expect(parsed.runs[0].results).toHaveLength(1);
    });

    it('should handle empty results in SARIF', () => {
      const result: ScanResult = {
        issues: [],
        filesScanned: 0,
        issuesFound: 0,
        summary: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        }
      };

      const output = reporter.formatSarif(result);
      const parsed = JSON.parse(output);
      
      expect(parsed.runs[0].results).toHaveLength(0);
      expect(parsed.runs[0].invocations[0].executionSuccessful).toBe(true);
    });
  });

  describe('HTML Formatting', () => {
    it('should format scan results as HTML', () => {
      const result: ScanResult = {
        issues: [
          {
            rule: 'test-rule',
            severity: 'high',
            file: 'test.js',
            line: 1,
            column: 1,
            message: 'Test issue',
            code: 'test code',
            suggestion: 'Test suggestion'
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

      const output = reporter.formatHtml(result);
      
      expect(output).toContain('<!DOCTYPE html>');
      expect(output).toContain('Vibe-Guard Security Report');
      expect(output).toContain('test-rule');
      expect(output).toContain('Test issue');
      expect(output).toContain('test.js');
    });

    it('should handle empty results in HTML', () => {
      const result: ScanResult = {
        issues: [],
        filesScanned: 0,
        issuesFound: 0,
        summary: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        }
      };

      const output = reporter.formatHtml(result);
      
      expect(output).toContain('<!DOCTYPE html>');
      expect(output).toContain('Vibe-Guard Security Report');
      expect(output).toContain('No security issues found');
    });
  });

  describe('Issue Details Formatting', () => {
    it('should format individual issue details', () => {
      const issue: SecurityIssue = {
        rule: 'xss-detection',
        severity: 'critical',
        file: 'src/components/UserInput.tsx',
        line: 15,
        column: 10,
        message: 'XSS vulnerability detected',
        code: 'innerHTML = userInput',
        suggestion: 'Use textContent instead'
      };

      const output = reporter.formatIssueDetails(issue);
      
      expect(output).toContain('xss-detection');
      expect(output).toContain('CRITICAL');
      expect(output).toContain('src/components/UserInput.tsx:15:10');
      expect(output).toContain('XSS vulnerability detected');
      expect(output).toContain('innerHTML = userInput');
      expect(output).toContain('Use textContent instead');
    });
  });

  describe('Edge Cases', () => {
    it('should handle very long file paths', () => {
      const veryLongPath = 'src/very/deep/nested/directory/structure/with/many/levels/and/a/very/long/filename/that/exceeds/maximum/length/limit/file.ts';
      const result = reporter['truncateFilePath'](veryLongPath, 30);
      expect(result.length).toBeLessThanOrEqual(30);
      // For very long paths, it should start with "src/.../file.ts" format
      expect(result).toMatch(/^src\/\.\.\.\/file\.ts$/);
    });

    it('should handle empty file paths', () => {
      const emptyPath = '';
      const result = reporter['truncateFilePath'](emptyPath);
      expect(result).toBe('');
    });

    it('should handle paths with only dots', () => {
      const dotsPath = '....';
      const result = reporter['truncateFilePath'](dotsPath);
      expect(result).toBe('');
    });

    it('should handle paths with special characters', () => {
      const specialPath = 'src/components/Button (v2).tsx';
      const result = reporter['truncateFilePath'](specialPath);
      expect(result).toBe('src/components/Button (v2).tsx');
    });
  });

  describe('Severity Coloring', () => {
    it('should color critical severity', () => {
      const result = reporter['colorSeverity']('critical');
      expect(result).toContain('CRITICAL');
    });

    it('should color high severity', () => {
      const result = reporter['colorSeverity']('high');
      expect(result).toContain('HIGH');
    });

    it('should color medium severity', () => {
      const result = reporter['colorSeverity']('medium');
      expect(result).toContain('MEDIUM');
    });

    it('should color low severity', () => {
      const result = reporter['colorSeverity']('low');
      expect(result).toContain('LOW');
    });

    it('should handle unknown severity', () => {
      const result = reporter['colorSeverity']('unknown' as any);
      expect(result).toBe('UNKNOWN');
    });
  });
});