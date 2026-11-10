import { UnpinnedSupplyChainDependenciesRule } from '../../rules/unpinned-supply-chain-dependencies';
import { FileContent } from '../../types';

describe('UnpinnedSupplyChainDependenciesRule', () => {
  const rule = new UnpinnedSupplyChainDependenciesRule();

  const check = (content: string): ReturnType<typeof rule.check> => {
    const fileContent: FileContent = {
      path: 'package.json',
      content,
      lines: content.split('\n')
    };
    return rule.check(fileContent);
  };

  it('detects floating registry versions and branch-based Git dependencies', () => {
    const issues = check(`{
  "dependencies": {
    "floating-lib": "latest",
    "branch-lib": "git+https://github.com/example/lib.git#main"
  }
}`);

    expect(issues).toHaveLength(2);
    expect(issues[0]?.message).toContain('floating version');
    expect(issues[1]?.message).toContain('immutable commit');
  });

  it('allows normal semver ranges and full Git commit references', () => {
    const issues = check(`{
  "dependencies": {
    "semver-lib": "^2.3.4",
    "pinned-lib": "git+https://github.com/example/lib.git#0123456789abcdef0123456789abcdef01234567"
  }
}`);

    expect(issues).toHaveLength(0);
  });

  it('does not inspect unrelated files', () => {
    const fileContent: FileContent = {
      path: 'src/config.ts',
      content: '"floating-lib": "latest"',
      lines: ['"floating-lib": "latest"']
    };

    expect(rule.check(fileContent)).toHaveLength(0);
  });
});
