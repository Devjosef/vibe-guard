import { Reporter } from '../../reporter';
import { SecurityIssue, ScanResult, SeverityLevel } from '../../types';

const makeIssue = (rule: string, severity: SeverityLevel, file: string, line: number): SecurityIssue => ({
  rule, severity, file, line, column: 1, code: `${rule}-001`, message: `${rule} detected`, suggestion: ''
});

describe('Reporter', () => {
  let reporter: Reporter;

  beforeEach(() => {
    reporter = new Reporter();
  });

  describe('truncateFilePath', () => {
    it('leaves short paths unchanged', () => {
      expect(reporter['truncateFilePath']('/app.js')).toBe('app.js');
      expect(reporter['truncateFilePath']('src/component.ts')).toBe('src/component.ts');
    });

    it('truncates long paths with ellipsis', () => {
      const longPath = '/Users/joseff/projects/vibe-guard/src/scanner/fileScanner.ts';
      const result = reporter['truncateFilePath'](longPath);
      expect(result.length).toBeLessThanOrEqual(50);
      expect(result).toContain('...');
    });

    it('respects custom maxLength', () => {
      const result = reporter['truncateFilePath']('/a/very/long/path.js', 15);
      expect(result.length).toBeLessThanOrEqual(15);
      expect(result).toContain('...');
    });
  });

  describe('formatTable', () => {
    it('shows clean message for empty results', () => {
      const result: ScanResult = {
        issues: [],
        filesScanned: 5,
        issuesFound: 0,
        summary: { critical: 0, high: 0, medium: 0, low: 0 }
      };
      expect(reporter.formatTable(result)).toContain("No security issues found");
    });

    it('formats issues in table layout', () => {
      const result: ScanResult = {
        issues: [makeIssue('SQLI', 'high', '/app.js', 42)],
        filesScanned: 10,
        issuesFound: 1,
        summary: { critical: 0, high: 1, medium: 0, low: 0 }
      };
      const output = reporter.formatTable(result);
      expect(output).toContain('HIGH');
      expect(output).toContain('SQLI');
      expect(output).toContain('app.js:42');
      expect(output).toContain('Found 1 issues');
    });
  });

  describe('formatSarif', () => {
    it('produces valid SARIF v2.1.0', () => {
      const result: ScanResult = {
        issues: [makeIssue('SQLI', 'high', '/app.js', 42)],
        filesScanned: 10,
        issuesFound: 1,
        summary: { critical: 0, high: 1, medium: 0, low: 0 }
      };
      const sarif = reporter.formatSarif(result);
      const parsed = JSON.parse(sarif);
      expect(parsed.$schema).toContain('sarif-2.1.0');
      expect(parsed.version).toBe('2.1.0');
      expect(parsed.runs[0].results[0].ruleId).toBe('SQLI');
    });

    it('handles empty results', () => {
      const result: ScanResult = {
        issues: [],
        filesScanned: 0,
        issuesFound: 0,
        summary: { critical: 0, high: 0, medium: 0, low: 0 }
      };
      const sarif = reporter.formatSarif(result);
      const parsed = JSON.parse(sarif);
      expect(parsed.runs[0].results).toHaveLength(0);
    });
  });

  describe('formatHtml', () => {
    it('generates valid HTML structure', () => {
      const result: ScanResult = {
        issues: [makeIssue('SQLI', 'high', '/app.js', 42)],
        filesScanned: 1,
        issuesFound: 1,
        summary: { critical: 0, high: 1, medium: 0, low: 0 }
      };
      const html = reporter.formatHtml(result);
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('Vibe-Guard Security Scan Results');
      expect(html).toContain('SQLI');
      expect(html).toContain('app.js:42');
    });
  });
});
