import chalk from 'chalk';
import { SecurityIssue, ScanResult, SeverityLevel } from './types';

export class Reporter {
  formatTable(result: ScanResult): string {
    if (result.issues.length === 0) {
      return chalk.green(`Clean: ${result.filesScanned} files scanned`);
    }

    const issues = result.issues.map((i: SecurityIssue) => 
      `${this.colorSeverity(i.severity)} ${i.rule.padEnd(25)} ${this.truncateFilePath(i.file)}:${i.line} ${i.message}`
    ).join('\n');

    return `${chalk.red.bold(`Found ${result.issuesFound} issues in ${result.filesScanned} files`)}\n${issues}`;
  }

  formatJson(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }

  truncateFilePath(path: string, maxLength: number = 50): string {
    if (path.length <= maxLength) return path;
    const mid = Math.floor(maxLength / 2);
    return `${path.slice(0, mid)}...${path.slice(-mid)}`;
  }

  formatSarif(result: ScanResult): string {
    return JSON.stringify({
      $schema: "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
      version: "2.1.0",
      runs: [{
        tool: { 
          driver: { 
            name: "Vibe-Guard", 
            version: "1.2.1",
            informationUri: "https://github.com/Devjosef/vibe-guard"
          } 
        },
        results: result.issues.map(issue => ({
          ruleId: issue.rule,
          level: issue.severity.toUpperCase() as 'ERROR' | 'WARNING' | 'NOTE',
          message: { text: issue.message },
          locations: [{ 
            physicalLocation: { 
              artifactLocation: { uri: issue.file }, 
              region: { startLine: issue.line } 
            } 
          }]
        }))
      }]
    }, null, 2);
  }

  formatHtml(result: ScanResult): string {
    const issuesHtml = result.issues.map(issue => 
      `<div style="border-left: 4px solid ${this.getSeverityColor(issue.severity)}; padding: 10px; margin: 10px 0; background: #f8f9fa;">
        <h3 style="margin-top: 0; color: ${this.getSeverityColor(issue.severity)};">${issue.rule}</h3>
        <p><strong>File:</strong> ${this.truncateFilePath(issue.file)}:${issue.line}</p>
        <p>${issue.message}</p>
      </div>`
    ).join('');

    return `<!DOCTYPE html>
<html>
<head>
  <title>Vibe-Guard Security Scan Results</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; }
    h1 { color: #1e40af; }
    .summary { background: #f0f9ff; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <h1>🛡️ Vibe-Guard Security Scan</h1>
  <div class="summary">
    <h2>Scan Summary</h2>
    <p>Found <strong>${result.issuesFound}</strong> issues in <strong>${result.filesScanned}</strong> files</p>
  </div>
  ${issuesHtml}
</body>
</html>`;
  }

  formatIssueDetails(issue: SecurityIssue): string {
    return `${chalk.bold.yellow(issue.rule)} ${this.colorSeverity(issue.severity)}\n` +
           `${chalk.gray(`File: ${this.truncateFilePath(issue.file)}:${issue.line}`)}\n\n` +
           `${issue.message}`;
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

  private getSeverityColor(sev: SeverityLevel): string {
    switch(sev) {
      case 'critical': return '#dc3545';
      case 'high': return '#fd7e14';
      case 'medium': return '#ffc107';
      case 'low': return '#0d6efd';
      default: return '#6c757d';
    }
  }
}
