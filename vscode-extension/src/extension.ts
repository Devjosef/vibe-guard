import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

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
  console.log('Vibe-Guard extension is now active!');

  // Register the scan command
  let disposable = vscode.commands.registerCommand('vibe-guard.scan', async () => {
    await runSecurityScan();
  });

  context.subscriptions.push(disposable);
}

async function runSecurityScan(): Promise<void> {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage('No workspace folder found');
    return;
  }

  // Show progress
  await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: "Running Vibe-Guard Security Scan",
    cancellable: false
  }, async (progress) => {
    try {
      progress.report({ message: 'Starting scan...' });
      
      // Run vibe-guard scan
      const { stdout, stderr } = await execAsync('vibe-guard scan . --format json', {
        cwd: workspaceFolder.uri.fsPath
      });

      if (stderr) {
        console.error('Vibe-Guard stderr:', stderr);
      }

      progress.report({ message: 'Parsing results...' });
      
      // Parse the results
      const results = parseVibeGuardOutput(stdout);
      
      // Display results
      await displayResults(results);
      
      vscode.window.showInformationMessage(`Security scan complete: ${results.issues.length} issues found`);
      
    } catch (error) {
      console.error('Vibe-Guard scan error:', error);
      vscode.window.showErrorMessage(`Security scan failed: ${error}`);
    }
  });
}

function parseVibeGuardOutput(output: string): VibeGuardResult {
  try {
    // Try to parse JSON output
    const data = JSON.parse(output);
    return {
      issues: data.issues || data.vulnerabilities || [],
      summary: data.summary || 'Scan completed'
    };
  } catch (error) {
    // Fallback to parsing text output
    return parseTextOutput(output);
  }
}

function parseTextOutput(output: string): VibeGuardResult {
  const issues: VibeGuardIssue[] = [];
  const lines = output.split('\n');
  
  // Simple parsing of the table format
  for (const line of lines) {
    if (line.includes('│') && !line.includes('Rule')) {
      const parts = line.split('│').map(p => p.trim()).filter(p => p);
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
  
  return {
    issues,
    summary: `Found ${issues.length} security issues`
  };
}

async function displayResults(results: VibeGuardResult): Promise<void> {
  // Create diagnostics collection
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('vibe-guard');
  
  // Group issues by file
  const issuesByFile = new Map<string, VibeGuardIssue[]>();
  
  for (const issue of results.issues) {
    const filePath = issue.file;
    if (!issuesByFile.has(filePath)) {
      issuesByFile.set(filePath, []);
    }
    issuesByFile.get(filePath)!.push(issue);
  }
  
  // Create diagnostics for each file
  for (const [filePath, issues] of issuesByFile) {
    const diagnostics: vscode.Diagnostic[] = [];
    
    for (const issue of issues) {
      const range = new vscode.Range(
        new vscode.Position(issue.line - 1, 0),
        new vscode.Position(issue.line - 1, 100)
      );
      
      const severity = getDiagnosticSeverity(issue.severity);
      
      const diagnostic = new vscode.Diagnostic(
        range,
        `[${issue.rule}] ${issue.message}`,
        severity
      );
      
      diagnostic.source = 'Vibe-Guard';
      diagnostics.push(diagnostic);
    }
    
    // Add diagnostics to the collection
    try {
      const uri = vscode.Uri.file(filePath);
      diagnosticCollection.set(uri, diagnostics);
    } catch (error) {
      console.error(`Error creating URI for ${filePath}:`, error);
    }
  }
  
  // Show summary in output channel
  const outputChannel = vscode.window.createOutputChannel('Vibe-Guard');
  outputChannel.clear();
          outputChannel.appendLine('██ Vibe-Guard Security Scan Results');
  outputChannel.appendLine('=====================================');
  outputChannel.appendLine(results.summary);
  outputChannel.appendLine('');
  
  for (const issue of results.issues) {
    outputChannel.appendLine(`${issue.severity.toUpperCase()}: ${issue.file}:${issue.line}`);
    outputChannel.appendLine(`  ${issue.rule}: ${issue.message}`);
    outputChannel.appendLine('');
  }
  
  outputChannel.show();
}

function getDiagnosticSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (severity.toLowerCase()) {
    case 'critical':
      return vscode.DiagnosticSeverity.Error;
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    case 'low':
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

export function deactivate() {
  console.log('Vibe-Guard extension deactivated');
}
