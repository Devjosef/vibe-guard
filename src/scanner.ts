import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { FileContent, SecurityIssue, ScanResult, BaseRule } from './types';

export class FileScanner {
  // Supported langs/configs, ADD MORE IF NEEDED
  private readonly supportedExtensions = [
    '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
    '.py', '.php', '.rb', '.go', '.java', '.cs',
    '.cpp', '.c', '.h', '.hpp', '.rs', '.kt',
    '.swift', '.dart', '.scala', '.clj', '.hs',
    '.json', '.yaml', '.yml', '.xml', '.env',
    '.config', '.conf', '.ini', '.toml'
  ];

  // Common build/dependency exclusions
  private readonly excludePatterns = [
    '**/node_modules/**', '**/dist/**', '**/build/**',
    '**/.git/**', '**/coverage/**', '**/*.min.js',
    '**/*.bundle.js', '**/vendor/**', '**/__pycache__/**',
    '**/*.pyc', '**/target/**', '**/bin/**', '**/obj/**'
  ];

  // 5MB limit, can be adjusted. example: 10mb dockerfile = 10 * 1024 * 1024
  private readonly maxFileSize = 5 * 1024 * 1024;

  // Heuristics exclude binaries
  private readonly binaryExtensions = [
    '.exe', '.dll', '.so', '.dylib', '.bin',
    '.jpg', '.png', '.gif', '.pdf', '.zip',
    '.mp3', '.mp4', '.sqlite', '.db', '.ttf'
  ];

  // Unified scan file or directory
  async scan(targetPath: string, rules: BaseRule[]): Promise<ScanResult> {
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
            issues.push(...rule.check(fileContent));
          }
        } else {
          filesSkipped++;
        }
      } catch (error) {
        filesSkipped++;
      }
    }

    return this.createScanResult(issues, filesScanned);
  }

  private async findFiles(targetPath: string): Promise<string[]> {
    const stats = await fs.promises.stat(targetPath);
    
    if (stats.isFile()) return [targetPath];
    if (!stats.isDirectory()) throw new Error(`Not file/dir: ${targetPath}`);

    const pattern = path.join(targetPath, '**/*');
    return glob.sync(pattern, {
      ignore: this.excludePatterns,
      nodir: true,
      absolute: true
    }).filter(file => this.isSupportedFile(file));
  }

  private isSupportedFile(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return this.supportedExtensions.includes(ext) && 
           !this.binaryExtensions.includes(ext);
  }

  private async readFile(filePath: string): Promise<FileContent | null> {
    try {
      const stats = await fs.promises.stat(filePath);
      if (stats.size > this.maxFileSize || await this.isBinaryFile(filePath)) {
        return null;
      }

      const content = await fs.promises.readFile(filePath, 'utf-8');
      return {
        path: filePath,
        content,
        lines: content.split('\n')
      };
    } catch {
      return null;
    }
  }

  // Null bytes or non-printable = binary exact threshhold >30%
 private async isBinaryFile(filePath: string): Promise<boolean> {
  try {
    const fd = await fs.promises.open(filePath, 'r');
    const buffer = Buffer.alloc(512);
    const { bytesRead } = await fd.read(buffer, 0, 512, 0);
    await fd.close();

    if (bytesRead === 0) return false;

    // Typed array to guarantee numbers
    const data = new Uint8Array(buffer.buffer, buffer.byteOffset, bytesRead);
    let nonPrintable = 0;

    for (const byte of data) {
      if (byte === 0) return true;
      if (byte < 32 && byte !== 9 && byte !== 10 && byte !== 13) {
        nonPrintable++;
      }
    }

    return nonPrintable / data.length > 0.3;
  } catch {
    return false;
  }
}

  private createScanResult(issues: SecurityIssue[], filesScanned: number): ScanResult {
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    issues.forEach(issue => summary[issue.severity]++);
    
    return {
      issues,
      filesScanned,
      issuesFound: issues.length,
      summary
    };
  }
}
