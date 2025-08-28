import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { FileContent, SecurityIssue, ScanResult, BaseRule } from './types';

// Class for scanning the files for security issues
export class FileScanner {
  private readonly supportedExtensions = [
    '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
    '.py', '.php', '.rb', '.go', '.java', '.cs',
    '.cpp', '.c', '.h', '.hpp', '.rs', '.kt',
    '.swift', '.dart', '.scala', '.clj', '.hs',
    '.json', '.yaml', '.yml', '.xml', '.env',
    '.config', '.conf', '.ini', '.toml'
  ];

  // The patterns to exclude from the scan
  private readonly excludePatterns = [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/.git/**',
    '**/coverage/**',
    '**/*.min.js',
    '**/*.bundle.js',
    '**/vendor/**',
    '**/__pycache__/**',
    '**/*.pyc',
    '**/target/**',
    '**/bin/**',
    '**/obj/**'
  ];

  // The maximum file size to scan
  private readonly maxFileSize = 5 * 1024 * 1024;

  // The binary extensions to exclude
  private readonly binaryExtensions = [
    '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
    '.img', '.iso', '.dmg', '.pkg', '.deb', '.rpm',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt',
    '.sqlite', '.db', '.mdb', '.accdb',
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    '.class', '.jar', '.war', '.ear',
    '.o', '.obj', '.lib', '.a'
  ];

  // Scans a directory for security issues
  async scanDirectory(targetPath: string, rules: BaseRule[]): Promise<ScanResult> {
    const files = await this.findFiles(targetPath);
    const issues: SecurityIssue[] = [];
    let filesScanned = 0;
    let filesSkipped = 0;

    for (const filePath of files) {
      try {
        const fileContent = await this.readFile(filePath);
        if (fileContent) {
          filesScanned++;
          
          for (const rule of rules) {
            const ruleIssues = rule.check(fileContent);
            issues.push(...ruleIssues);
          }
        } else {
          filesSkipped++;
        }
      } catch (error) {
        console.warn(`Warning: Could not scan file ${filePath}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        filesSkipped++;
      }
    }

    if (filesSkipped > 0) {
      console.log(`📋 Skipped ${filesSkipped} files (binary, too large, or unreadable)`);
    }

    return this.createScanResult(issues, filesScanned);
  }

  // Scans a file for security issues
  async scanFile(filePath: string, rules: BaseRule[]): Promise<ScanResult> {
    const issues: SecurityIssue[] = [];
    let filesScanned = 0;

    try {
      const fileContent = await this.readFile(filePath);
      if (fileContent) {
        filesScanned = 1;
        
        for (const rule of rules) {
          const ruleIssues = rule.check(fileContent);
          issues.push(...ruleIssues);
        }
      } else {
        console.log(`📋 Skipped file: ${filePath} (binary, too large, or unreadable)`);
      }
    } catch (error) {
      throw new Error(`Could not scan file ${filePath}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    return this.createScanResult(issues, filesScanned);
  }

  // Finds the files to scan
  private async findFiles(targetPath: string): Promise<string[]> {
    const stats = await fs.promises.stat(targetPath);
    
    if (stats.isFile()) {
      return [targetPath];
    }

    if (!stats.isDirectory()) {
      throw new Error(`Target path is neither a file nor a directory: ${targetPath}`);
    }

    const pattern = path.join(targetPath, '**/*');
    const allFiles = glob.sync(pattern, {
      ignore: this.excludePatterns,
      nodir: true,
      absolute: true
    });

    return allFiles.filter((file: string) => this.isSupportedFile(file));
  }

  // Checks if the file is supported
  private isSupportedFile(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    
    if (this.binaryExtensions.includes(ext)) {
      return false;
    }
    
    return this.supportedExtensions.includes(ext);
  }

  // Reads the file content
  private async readFile(filePath: string): Promise<FileContent | null> {
    try {
      const stats = await fs.promises.stat(filePath);
      if (stats.size > this.maxFileSize) {
        console.warn(`Skipping large file: ${filePath} (${Math.round(stats.size / 1024 / 1024)}MB > 5MB limit)`);
        return null;
      }

      if (await this.isBinaryFile(filePath)) {
        return null;
      }

      const content = await fs.promises.readFile(filePath, 'utf-8');
      const lines = content.split('\n');
      
      return {
        path: filePath,
        content,
        lines
      };
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
        return null;
      }
      if (error instanceof Error && error.message.includes('invalid')) {
        return null;
      }
      throw error;
    }
  }

  // Checks if the file is a binary file
  private async isBinaryFile(filePath: string): Promise<boolean> {
    try {
      const fd = await fs.promises.open(filePath, 'r');
      const buffer = Buffer.alloc(512);
      const { bytesRead } = await fd.read(buffer, 0, 512, 0);
      await fd.close();

      if (bytesRead === 0) {
        return false;
      }

      for (let i = 0; i < bytesRead; i++) {
        if (buffer[i] === 0) {
          return true;
        }
      }

      let nonPrintable = 0;
      for (let i = 0; i < bytesRead; i++) {
        const byte = buffer[i];
        if (byte !== undefined) {
          if (byte < 32 && byte !== 9 && byte !== 10 && byte !== 13) {
            nonPrintable++;
          }
        }
      }

      return (nonPrintable / bytesRead) > 0.3;
    } catch {
      return false;
    }
  }

  // Creates the scan result
  private createScanResult(issues: SecurityIssue[], filesScanned: number): ScanResult {
    const summary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    issues.forEach(issue => {
      summary[issue.severity]++;
    });

    return {
      issues,
      filesScanned,
      issuesFound: issues.length,
      summary
    };
  }
} 