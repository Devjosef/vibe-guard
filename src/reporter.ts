const Table = require('cli-table3');
import chalk from 'chalk';
import { SecurityIssue, ScanResult, SeverityLevel } from './types';

export class Reporter {
  formatTable(result: ScanResult): string {
    if (result.issues.length === 0) {
      return this.formatSuccess(result);
    }

    const table = new Table({
      head: [
        chalk.bold('Rule'),
        chalk.bold('Severity'),
        chalk.bold('File'),
        chalk.bold('Line'),
        chalk.bold('Message')
      ],
      colWidths: [25, 12, 40, 8, 60],
      wordWrap: true
    });

    result.issues.forEach(issue => {
      table.push([
        issue.rule,
        this.colorSeverity(issue.severity),
        this.truncateFilePath(issue.file),
        issue.line.toString(),
        issue.message
      ]);
    });

    return this.formatHeader(result) + '\n\n' + table.toString() + '\n\n' + this.formatSummary(result);
  }

  formatJson(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }

  private formatSuccess(result: ScanResult): string {
    const header = chalk.green.bold('🛡️  Vibe-Guard Security Scan Complete');
    const summary = chalk.green(`✅ No security issues found in ${result.filesScanned} files`);
    
    return `${header}\n\n${summary}\n`;
  }

  private formatHeader(result: ScanResult): string {
    const title = chalk.red.bold('🚨 Vibe-Guard Security Issues Detected');
    const subtitle = chalk.yellow(`Found ${result.issuesFound} security issues in ${result.filesScanned} files`);
    
    return `${title}\n${subtitle}`;
  }

  private formatSummary(result: ScanResult): string {
    const { summary } = result;
    const parts: string[] = [];

    if (summary.critical > 0) {
      parts.push(chalk.red.bold(`${summary.critical} Critical`));
    }
    if (summary.high > 0) {
      parts.push(chalk.red(`${summary.high} High`));
    }
    if (summary.medium > 0) {
      parts.push(chalk.yellow(`${summary.medium} Medium`));
    }
    if (summary.low > 0) {
      parts.push(chalk.blue(`${summary.low} Low`));
    }

    const summaryText = parts.length > 0 ? parts.join(' | ') : 'No issues';
    
    return chalk.bold('Summary: ') + summaryText + '\n\n' + this.formatRecommendations();
  }

  private formatRecommendations(): string {
    return chalk.cyan.bold('💡 Recommendations:\n') +
      chalk.cyan('• Review and fix critical and high severity issues immediately\n') +
      chalk.cyan('• Consider implementing security linting in your CI/CD pipeline\n') +
      chalk.cyan('• Run Vibe-Guard regularly during development\n') +
      chalk.cyan('• Check our documentation for detailed fix suggestions');
  }

  private colorSeverity(severity: SeverityLevel): string {
    switch (severity) {
      case 'critical':
        return chalk.red.bold('CRITICAL');
      case 'high':
        return chalk.red('HIGH');
      case 'medium':
        return chalk.yellow('MEDIUM');
      case 'low':
        return chalk.blue('LOW');
      default:
        return String(severity).toUpperCase();
    }
  }

  private truncateFilePath(filePath: string, maxLength: number = 35): string {
    if (filePath.length <= maxLength) {
      return filePath;
    }
    
    const parts = filePath.split('/');
    if (parts.length <= 2) {
      return filePath;
    }
    
    // Show first and last parts with ... in between
    const first = parts[0];
    const last = parts[parts.length - 1];
    const truncated = `${first}/.../${last}`;
    
    if (truncated.length <= maxLength) {
      return truncated;
    }
    
    // If still too long, just truncate from the beginning
    return '...' + filePath.slice(-(maxLength - 3));
  }

  formatIssueDetails(issue: SecurityIssue): string {
    const header = chalk.red.bold(`\n🚨 ${issue.rule} (${this.colorSeverity(issue.severity)})`);
    const location = chalk.gray(`📍 ${issue.file}:${issue.line}:${issue.column}`);
    const message = chalk.white(`💬 ${issue.message}`);
    const code = chalk.gray(`📝 Code: ${issue.code}`);
    const suggestion = chalk.green(`💡 Suggestion: ${issue.suggestion}`);
    
    return `${header}\n${location}\n${message}\n${code}\n${suggestion}\n`;
  }
} 