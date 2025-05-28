import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { FileContent, SecurityIssue, ScanResult, BaseRule } from './types';

export class FileScanner {
  private readonly supportedExtensions = [
    '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
    '.py', '.php', '.rb', '.go', '.java', '.cs',
    '.cpp', '.c', '.h', '.hpp', '.rs', '.kt',
    '.swift', '.dart', '.scala', '.clj', '.hs',
    '.json', '.yaml', '.yml', '.xml', '.env',
    '.config', '.conf', '.ini', '.toml'
  ];

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

  // File size limit: 5MB (prevents performance issues)
  private readonly maxFileSize = 5 * 1024 * 1024;

  // Binary file extensions to skip
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

  private isSupportedFile(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    
    // Skip binary files
    if (this.binaryExtensions.includes(ext)) {
      return false;
    }
    
    return this.supportedExtensions.includes(ext);
  }

  private async readFile(filePath: string): Promise<FileContent | null> {
    try {
      // Check file size first
      const stats = await fs.promises.stat(filePath);
      if (stats.size > this.maxFileSize) {
        console.warn(`Skipping large file: ${filePath} (${Math.round(stats.size / 1024 / 1024)}MB > 5MB limit)`);
        return null;
      }

      // Check if file is binary by reading first few bytes
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
      // Handle encoding errors (binary files read as text)
      if (error instanceof Error && error.message.includes('invalid')) {
        return null;
      }
      throw error;
    }
  }

  private async isBinaryFile(filePath: string): Promise<boolean> {
    try {
      // Read first 512 bytes to check for binary content
      const fd = await fs.promises.open(filePath, 'r');
      const buffer = Buffer.alloc(512);
      const { bytesRead } = await fd.read(buffer, 0, 512, 0);
      await fd.close();

      if (bytesRead === 0) {
        return false; // Empty file, treat as text
      }

      // Check for null bytes (common in binary files)
      for (let i = 0; i < bytesRead; i++) {
        if (buffer[i] === 0) {
          return true;
        }
      }

      // Check for high percentage of non-printable characters
      let nonPrintable = 0;
      for (let i = 0; i < bytesRead; i++) {
        const byte = buffer[i];
        if (byte !== undefined) {
          // Allow common text characters: printable ASCII, newlines, tabs
          if (byte < 32 && byte !== 9 && byte !== 10 && byte !== 13) {
            nonPrintable++;
          }
        }
      }

      // If more than 30% non-printable, consider it binary
      return (nonPrintable / bytesRead) > 0.3;
    } catch {
      // If we can't read the file, assume it's not binary
      return false;
    }
  }

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