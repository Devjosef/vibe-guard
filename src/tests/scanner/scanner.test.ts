import { FileScanner } from '../../scanner';
import * as fs from 'fs/promises';
import * as path from 'path';
import { mkdtempSync, rmSync } from 'fs';

describe('FileScanner', () => {
  let testDir: string;
  let scanner: FileScanner;

  beforeEach(() => {
    scanner = new FileScanner();
    testDir = mkdtempSync(path.join(process.cwd(), 'test-'));
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it('scans single file → filesScanned=1', async () => {
    const filePath = path.join(testDir, 'test.js');
    await fs.writeFile(filePath, 'console.log("test")');
    
    const result = await scanner.scan(filePath, []);
    expect(result.filesScanned).toBe(1);
    expect(result.issues).toHaveLength(0);
  });

  it('skips 6MB file → filesScanned=0', async () => {
    const filePath = path.join(testDir, 'large.js');
    const large = 'a'.repeat(6 * 1024 * 1024);  // 6MB
    await fs.writeFile(filePath, large);
    
    const result = await scanner.scan(filePath, []);
    expect(result.filesScanned).toBe(0);  // Size limit
  });

  it('scans 4MB file → filesScanned=1', async () => {
    const filePath = path.join(testDir, 'small.js');
    const small = 'a'.repeat(4 * 1024 * 1024);  // 4MB
    await fs.writeFile(filePath, small);
    
    const result = await scanner.scan(filePath, []);
    expect(result.filesScanned).toBe(1);
  });

  it('skips binaries by extension → .png/.exe', async () => {
    await fs.writeFile(path.join(testDir, 'image.png'), 'fake');
    await fs.writeFile(path.join(testDir, 'binary.exe'), 'fake');
    await fs.writeFile(path.join(testDir, 'test.js'), 'safe');
    
    const result = await scanner.scan(testDir, []);
    expect(result.filesScanned).toBe(1);  // Only test.js
  });

  it('excludes node_modules/dist', async () => {
    await fs.mkdir(path.join(testDir, 'src'), { recursive: true });
    await fs.mkdir(path.join(testDir, 'node_modules/pkg'), { recursive: true });
    await fs.mkdir(path.join(testDir, 'dist'), { recursive: true });
    
    await fs.writeFile(path.join(testDir, 'src/app.js'), 'safe');
    await fs.writeFile(path.join(testDir, 'node_modules/pkg/index.js'), 'skip');
    await fs.writeFile(path.join(testDir, 'dist/bundle.js'), 'skip');
    
    const result = await scanner.scan(testDir, []);
    expect(result.filesScanned).toBe(1);  // Only src/app.js
  });
});
