const Table = require('cli-table3');
import chalk from 'chalk';
import { SecurityIssue, ScanResult, SeverityLevel } from './types';

// Class for reporting the scan results
export class Reporter {
  // Formats the scan results as a table
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

  // Formats the scan results as a JSON string
  formatJson(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }

  // Formats the scan results as a SARIF string
  formatSarif(result: ScanResult): string {
    const sarif = {
      $schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Vibe-Guard",
              version: "1.1.3",
              informationUri: "https://github.com/Devjosef/vibe-guard",
              rules: this.generateSarifRules(result)
            }
          },
          results: this.generateSarifResults(result),
          invocations: [
            {
              executionSuccessful: true,
              toolExecutionNotifications: [
                {
                  descriptor: {
                    id: "vibe-guard-scan"
                  },
                  message: {
                    text: `Scanned ${result.filesScanned} files and found ${result.issuesFound} security issues`
                  }
                }
              ]
            }
          ]
        }
      ]
    };

    return JSON.stringify(sarif, null, 2);
  }

  // Formats the scan results as an HTML string
  formatHtml(result: ScanResult): string {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vibe-Guard Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 2rem;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #ff4757, #ff3838);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .summary {
            padding: 2rem;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .summary-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid;
        }
        
        .summary-card.critical { border-left-color: #dc3545; }
        .summary-card.high { border-left-color: #fd7e14; }
        .summary-card.medium { border-left-color: #ffc107; }
        .summary-card.low { border-left-color: #17a2b8; }
        
        .summary-card h3 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .summary-card.critical h3 { color: #dc3545; }
        .summary-card.high h3 { color: #fd7e14; }
        .summary-card.medium h3 { color: #ffc107; }
        .summary-card.low h3 { color: #17a2b8; }
        
        .issues {
            padding: 2rem;
        }
        
        .issue {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
        }
        
        .issue-header {
            padding: 1rem;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .issue-title {
            font-weight: 600;
            font-size: 1.1rem;
        }
        
        .severity {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity.critical { background: #dc3545; color: white; }
        .severity.high { background: #fd7e14; color: white; }
        .severity.medium { background: #ffc107; color: #212529; }
        .severity.low { background: #17a2b8; color: white; }
        
        .issue-content {
            padding: 1rem;
        }
        
        .issue-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .meta-item {
            background: #f8f9fa;
            padding: 0.75rem;
            border-radius: 4px;
        }
        
        .meta-label {
            font-size: 0.875rem;
            color: #6c757d;
            margin-bottom: 0.25rem;
        }
        
        .meta-value {
            font-weight: 600;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
        }
        
        .code-snippet {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 1rem;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
        }
        
        .suggestion {
            background: #e7f3ff;
            border: 1px solid #b3d9ff;
            border-radius: 4px;
            padding: 1rem;
            margin-top: 1rem;
        }
        
        .suggestion h4 {
            color: #0066cc;
            margin-bottom: 0.5rem;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 2rem;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #e9ecef;
        }
        
        @media (max-width: 768px) {
            body { padding: 1rem; }
            .header h1 { font-size: 2rem; }
            .issue-header { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>██ Vibe-Guard Security Report</h1>
            <p>Security scan completed on ${new Date().toLocaleDateString()}</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="summary-card critical">
                    <h3>${result.summary.critical}</h3>
                    <p>Critical Issues</p>
                </div>
                <div class="summary-card high">
                    <h3>${result.summary.high}</h3>
                    <p>High Issues</p>
                </div>
                <div class="summary-card medium">
                    <h3>${result.summary.medium}</h3>
                    <p>Medium Issues</p>
                </div>
                <div class="summary-card low">
                    <h3>${result.summary.low}</h3>
                    <p>Low Issues</p>
                </div>
            </div>
            <p style="margin-top: 1rem; color: #6c757d;">
                Scanned ${result.filesScanned} files and found ${result.issuesFound} security issues
            </p>
        </div>
        
        <div class="issues">
            <h2>Security Issues</h2>
            ${result.issues.length === 0 ? 
                '<div style="text-align: center; padding: 3rem; color: #28a745;"><h3>✅ No security issues found!</h3><p>Your code looks secure.</p></div>' :
                result.issues.map(issue => this.formatHtmlIssue(issue)).join('')
            }
        </div>
        
        <div class="footer">
            <p>Generated by Vibe-Guard v1.1.3 | <a href="https://github.com/Devjosef/vibe-guard">GitHub</a></p>
        </div>
    </div>
</body>
</html>`;

    return html;
  }

  // Generates the SARIF rules
  private generateSarifRules(result: ScanResult): any[] {
    const ruleNames = [...new Set(result.issues.map(issue => issue.rule))];
    return ruleNames.map(ruleName => ({
      id: ruleName,
      name: ruleName,
      shortDescription: {
        text: `Security rule: ${ruleName}`
      }
    }));
  }

  // Generates the SARIF results
  private generateSarifResults(result: ScanResult): any[] {
    return result.issues.map(issue => ({
      ruleId: issue.rule,
      level: this.mapSeverityToSarifLevel(issue.severity),
      message: {
        text: issue.message
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: issue.file
            },
            region: {
              startLine: issue.line,
              startColumn: issue.column
            }
          }
        }
      ],
      properties: {
        suggestion: issue.suggestion
      }
    }));
  }

  // Maps the severity to the SARIF level
  private mapSeverityToSarifLevel(severity: SeverityLevel): string {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'note';
      default:
        return 'note';
    }
  }

  // Formats the HTML issue
  private formatHtmlIssue(issue: SecurityIssue): string {
    return `
        <div class="issue">
            <div class="issue-header">
                <div class="issue-title">${this.escapeHtml(issue.rule)}</div>
                <div class="severity ${issue.severity}">${issue.severity.toUpperCase()}</div>
            </div>
            <div class="issue-content">
                <p><strong>${this.escapeHtml(issue.message)}</strong></p>
                
                <div class="issue-meta">
                    <div class="meta-item">
                        <div class="meta-label">File</div>
                        <div class="meta-value">${this.escapeHtml(issue.file)}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Line</div>
                        <div class="meta-value">${issue.line}:${issue.column}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Rule</div>
                        <div class="meta-value">${this.escapeHtml(issue.rule)}</div>
                    </div>
                </div>
                
                <div class="code-snippet">${this.escapeHtml(issue.code)}</div>
                
                <div class="suggestion">
                    <h4>💡 Suggestion</h4>
                    <p>${this.escapeHtml(issue.suggestion)}</p>
                </div>
            </div>
        </div>
    `;
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  private formatSuccess(result: ScanResult): string {
    const header = chalk.green.bold('╔══════════════════════════════════════════════════════════════════════════════╗');
    const title = chalk.green.bold('║                           VIBE-GUARD SECURITY SCAN COMPLETE                    ║');
    const subtitle = chalk.green.bold('║                                NO THREATS DETECTED                            ║');
    const summary = chalk.green(`║  ✅ No security issues found in ${result.filesScanned} files`);
    const footer = chalk.green.bold('╚══════════════════════════════════════════════════════════════════════════════╝');
    
    return `${header}\n${title}\n${subtitle}\n${summary.padEnd(75)} ║\n${footer}\n`;
  }

  private formatHeader(result: ScanResult): string {
    const header = chalk.red.bold('╔══════════════════════════════════════════════════════════════════════════════╗');
    const title = chalk.red.bold('║                        VIBE-GUARD SECURITY ISSUES DETECTED                     ║');
    const subtitle = chalk.yellow.bold(`║                           ${result.issuesFound} THREATS FOUND IN ${result.filesScanned} FILES                           ║`);
    const footer = chalk.red.bold('╚══════════════════════════════════════════════════════════════════════════════╝');
    
    return `${header}\n${title}\n${subtitle}\n${footer}\n`;
  }

  private formatSummary(result: ScanResult): string {
    const { summary } = result;
    const parts: string[] = [];

    if (summary.critical > 0) {
      parts.push(chalk.red.bold(`${summary.critical} CRITICAL`));
    }
    if (summary.high > 0) {
      parts.push(chalk.red(`${summary.high} HIGH`));
    }
    if (summary.medium > 0) {
      parts.push(chalk.yellow(`${summary.medium} MEDIUM`));
    }
    if (summary.low > 0) {
      parts.push(chalk.blue(`${summary.low} LOW`));
    }

    const summaryText = parts.length > 0 ? parts.join(' | ') : 'No issues';
    
    return chalk.bold('╔══════════════════════════════════════════════════════════════════════════════╗\n') +
           chalk.bold('║                                    SUMMARY                                    ║\n') +
           chalk.bold('║  ') + summaryText.padEnd(73) + chalk.bold('║\n') +
           chalk.bold('╚══════════════════════════════════════════════════════════════════════════════╝\n\n') +
           this.formatRecommendations();
  }

  private formatRecommendations(): string {
    return chalk.cyan.bold('╔══════════════════════════════════════════════════════════════════════════════╗\n') +
           chalk.cyan.bold('║                                RECOMMENDATIONS                               ║\n') +
           chalk.cyan.bold('║  • Review and fix critical and high severity issues immediately').padEnd(73) + chalk.cyan.bold('║\n') +
           chalk.cyan.bold('║  • Consider implementing security linting in your CI/CD pipeline').padEnd(73) + chalk.cyan.bold('║\n') +
           chalk.cyan.bold('║  • Run Vibe-Guard regularly during development').padEnd(73) + chalk.cyan.bold('║\n') +
           chalk.cyan.bold('║  • Check our documentation for detailed fix suggestions').padEnd(73) + chalk.cyan.bold('║\n') +
           chalk.cyan.bold('╚══════════════════════════════════════════════════════════════════════════════╝');
  }

  // Colors the severity
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

  // Truncates the file path
  private truncateFilePath(filePath: string, maxLength: number = 35): string {
    let sanitizedPath = filePath.replace(/\\+/g, '/').replace(/\\/g, '/').replace(/\/+/g, '/');
    sanitizedPath = sanitizedPath.replace(/\.\./g, '').replace(/\/+/g, '/');
    sanitizedPath = sanitizedPath.replace(/^\/+/, '');
    
    if (sanitizedPath.length <= maxLength) {
      return sanitizedPath;
    }
    
    const parts = sanitizedPath.split('/');
    if (parts.length <= 2) {
      return sanitizedPath;
    }
    
    const first = parts[0];
    const last = parts[parts.length - 1];
    const truncated = `${first}/.../${last}`;
    
    if (truncated.length <= maxLength) {
      return truncated;
    }
    
    return '...' + sanitizedPath.slice(-(maxLength - 3));
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