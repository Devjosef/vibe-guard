export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';

export interface SecurityIssue {
  rule: string;
  severity: SeverityLevel;
  message: string;
  file: string;
  line: number;
  column: number;
  code: string;
  suggestion: string;
}

export interface ScanOptions {
  target: string;
  format: 'table' | 'json';
  verbose: boolean;
  exclude?: string[];
  include?: string[];
}

export interface RuleMatch {
  pattern: RegExp;
  message: string;
  severity: SeverityLevel;
  suggestion: string;
}

export interface FileContent {
  path: string;
  content: string;
  lines: string[];
}

export interface ScanResult {
  issues: SecurityIssue[];
  filesScanned: number;
  issuesFound: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface RuleConfig {
  enabled: boolean;
  severity?: SeverityLevel;
  patterns?: string[];
  excludePatterns?: string[];
}

export interface VibeGuardConfig {
  rules: Record<string, RuleConfig>;
  exclude: string[];
  include: string[];
  outputFormat: 'table' | 'json';
}

export abstract class BaseRule {
  abstract readonly name: string;
  abstract readonly description: string;
  abstract readonly severity: SeverityLevel;
  
  abstract check(fileContent: FileContent): SecurityIssue[];
  
  protected createIssue(
    file: string,
    line: number,
    column: number,
    code: string,
    message: string,
    suggestion: string,
    severity?: SeverityLevel
  ): SecurityIssue {
    return {
      rule: this.name,
      severity: severity || this.severity,
      message,
      file,
      line,
      column,
      code: code.trim(),
      suggestion
    };
  }
  
  protected findMatches(content: string, pattern: RegExp): Array<{
    match: RegExpMatchArray;
    line: number;
    column: number;
    lineContent: string;
  }> {
    const lines = content.split('\n');
    const matches: Array<{
      match: RegExpMatchArray;
      line: number;
      column: number;
      lineContent: string;
    }> = [];
    
    lines.forEach((lineContent, lineIndex) => {
      let match: RegExpMatchArray | null;
      const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
      
      while ((match = globalPattern.exec(lineContent)) !== null) {
        matches.push({
          match,
          line: lineIndex + 1,
          column: (match.index ?? 0) + 1,
          lineContent
        });
        
        if (!pattern.flags.includes('g')) break;
      }
    });
    
    return matches;
  }
} 