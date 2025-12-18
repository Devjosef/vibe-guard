import chalk from 'chalk';
import { SecurityIssue, ScanResult, SeverityLevel } from './types';

export class Reporter {
  formatTable(result: ScanResult): string {
    if (result.issues.length === 0) {
      return chalk.green(`✅ Clean: ${result.filesScanned} files scanned`);
    }

    const issues = result.issues.map((i: SecurityIssue) => 
      `${this.colorSeverity(i.severity)} ${i.rule.padEnd(25)} ${i.file}:${i.line} ${i.message}`
    ).join('\n');

    return `${chalk.red.bold(`Found ${result.issuesFound} issues in ${result.filesScanned} files`)}\n${issues}`;
  }

  formatJson(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }

  private colorSeverity(sev: SeverityLevel): string {
    switch(sev) {
      case 'critical': return chalk.red.bold('CRITICAL');
      case 'high': return chalk.red('HIGH');
      case 'medium': return chalk.yellow('MEDIUM');
      case 'low': return chalk.blue('LOW');
      default: return String(sev).toUpperCase();
    }
  }
}
