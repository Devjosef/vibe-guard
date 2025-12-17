import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Maps vibe-guard CLI output to VS Code diagnostics
interface VibeGuardIssue {
  rule: string;
  severity: string;
  file: string;
  line: number;
  message: string;
}

interface VibeGuardResult {
  issues: VibeGuardIssue[];
  summary: string;
}

export function activate(context: vscode.ExtensionContext) {
  let disposable = vscode.commands.registerCommand('vibe-guard.scan', runSecurityScan);
  context.subscriptions.push(disposable);
}

async function runSecurityScan() {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage('No workspace folder found');
    return;
  }

  await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: "Vibe-Guard Security Scan",
    cancellable: false
  }, async () => {
    try {
      const { stdout } = await execAsync('vibe-guard scan . --format json', {
        cwd: workspaceFolder.uri.fsPath
      });

      const results = parseVibeGuardOutput(stdout);
      await displayResults(results);
      vscode.window.showInformationMessage(`Scan complete: ${results.issues.length} issues`);
    } catch (error) {
      vscode.window.showErrorMessage(`Scan failed: ${error}`);
    }
  });
}

// JSON primary, table fallback for CLI output variations
function parseVibeGuardOutput(output: string): VibeGuardResult {
  try {
    const data = JSON.parse(output);
    return {
      issues: data.issues || data.vulnerabilities || [],
      summary: data.summary || 'Scan completed'
    };
  } catch {
    return parseTextOutput(output);
  }
}

// Parses vibe-guard table format (delimited rows)
function parseTextOutput(output: string): VibeGuardResult {
  const issues: VibeGuardIssue[] = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('│') && !line.includes('Rule')) {
      const parts = line.split('│').map(p => p.trim()).filter(Boolean);
      if (parts.length >= 5) {
        issues.push({
          rule: parts[0],
          severity: parts[1],
          file: parts[2],
          line: parseInt(parts[3]) || 0,
          message: parts[4]
        });
      }
    }
  }
  
  return { issues, summary: `Found ${issues.length} issues` };
}

async function displayResults(results: VibeGuardResult) {
  const diagnostics = vscode.languages.createDiagnosticCollection('vibe-guard');
  
  // Group by file to batch diagnostics
  const issuesByFile = new Map<string, VibeGuardIssue[]>();
  for (const issue of results.issues) {
    if (!issuesByFile.has(issue.file)) issuesByFile.set(issue.file, []);
    issuesByFile.get(issue.file)!.push(issue);
  }

  for (const [filePath, issues] of issuesByFile) {
    const fileDiagnostics: vscode.Diagnostic[] = issues.map(issue => {
      const range = new vscode.Range(issue.line - 1, 0, issue.line - 1, 100);
      return new vscode.Diagnostic(range, `[${issue.rule}] ${issue.message}`, getDiagnosticSeverity(issue.severity));
    });

    try {
      diagnostics.set(vscode.Uri.file(filePath), fileDiagnostics);
    } catch {}
  }

  showOutput(results);
}

// Critical / High=Error, Medium = Warning, else = Info
function getDiagnosticSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (severity.toLowerCase()) {
    case 'critical':
    case 'high': return vscode.DiagnosticSeverity.Error;
    case 'medium': return vscode.DiagnosticSeverity.Warning;
    default: return vscode.DiagnosticSeverity.Information;
  }
}

function showOutput(results: VibeGuardResult) {
  const output = vscode.window.createOutputChannel('Vibe-Guard');
  output.clear();
  output.appendLine('Vibe-Guard Results');
  output.appendLine('================');
  output.appendLine(results.summary);
  
  for (const issue of results.issues) {
    output.appendLine('');
    output.appendLine(`${issue.severity.toUpperCase()}: ${issue.file}:${issue.line}`);
    output.appendLine(`  ${issue.rule}: ${issue.message}`);
  }
  
  output.show();
}

export function deactivate() {}
