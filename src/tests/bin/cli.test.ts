import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { VERSION } from '../../types/version';

const cliPath = path.resolve(process.cwd(), 'dist/bin/vibe-guard.js');

describe('CLI', () => {
  it('shows the supported commands in help output', () => {
    const result = spawnSync(process.execPath, [cliPath, '--help'], { encoding: 'utf8' });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('start');
    expect(result.stdout).toContain('scan');
    expect(result.stdout).not.toContain('learn');
    expect(result.stdout).not.toContain('demo');
  });

  it('writes valid SARIF when scanning to an output file', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vibe-guard-cli-'));
    const target = path.join(directory, 'safe.js');
    const output = path.join(directory, 'report.sarif');
    fs.writeFileSync(target, 'const value = 1;\n');

    try {
      const result = spawnSync(
        process.execPath,
        [cliPath, 'scan', directory, '--format', 'sarif', '--output-file', output],
        { encoding: 'utf8' }
      );

      expect(result.status).toBe(0);
      expect(fs.existsSync(output)).toBe(true);
      const report = JSON.parse(fs.readFileSync(output, 'utf8')) as {
        version: string;
        runs: Array<{ tool: { driver: { version: string } } }>;
      };
      expect(report.version).toBe('2.1.0');
      expect(report.runs[0]?.tool.driver.version).toBe(VERSION);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('shows remediation guidance when a scan finds an issue', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vibe-guard-cli-'));
    const target = path.join(directory, 'unsafe.js');
    fs.writeFileSync(target, 'element.innerHTML = req.body.html;\n');

    try {
      const result = spawnSync(
        process.execPath,
        [cliPath, 'scan', directory],
        { encoding: 'utf8' }
      );

      expect(result.status).toBe(1);
      expect(result.stdout).toContain('Potential XSS vulnerability');
      expect(result.stdout).toContain('Remediation:');
      expect(result.stdout).toContain('textContent');
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
