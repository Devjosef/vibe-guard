import { BaseRule, FileContent, SecurityIssue } from '../types';

export class UnpinnedSupplyChainDependenciesRule extends BaseRule {
  readonly name = 'unpinned-supply-chain-dependencies';
  readonly description = 'Detects floating package versions and mutable Git dependency references';
  readonly severity = 'medium' as const;

  private readonly dependencyPattern = /["']([^"']+)["']\s*:\s*["']([^"']+)["']/g;
  private readonly floatingVersionPattern = /^(?:\*|latest|next|canary|beta)$/i;
  private readonly gitDependencyPattern = /^(?:git\+|git:\/\/|github:|gitlab:|bitbucket:)/i;
  private readonly immutableCommitPattern = /#[a-f0-9]{40}(?:$|[?#])/i;

  check(fileContent: FileContent): SecurityIssue[] {
    if (!/(?:^|[/\\])package\.json$/i.test(fileContent.path)) return [];

    const issues: SecurityIssue[] = [];
    let dependencySection = false;

    fileContent.lines.forEach((line, index) => {
      if (/^\s*"(?:dependencies|devDependencies|optionalDependencies|peerDependencies)"\s*:\s*\{/.test(line)) {
        dependencySection = true;
      } else if (dependencySection && /^\s*\}/.test(line)) {
        dependencySection = false;
      }

      if (!dependencySection) return;

      this.dependencyPattern.lastIndex = 0;
      const match = this.dependencyPattern.exec(line);
      if (!match) return;

      const packageName = match[1];
      const version = match[2];
      if (!packageName || !version) return;

      let message: string | undefined;
      let suggestion: string | undefined;

      if (this.floatingVersionPattern.test(version)) {
        message = `Dependency "${packageName}" uses a floating version "${version}"`;
        suggestion = 'Pin the dependency to a reviewed version and commit the package-manager lockfile.';
      } else if (this.gitDependencyPattern.test(version) && !this.immutableCommitPattern.test(version)) {
        message = `Git dependency "${packageName}" does not reference an immutable commit`;
        suggestion = 'Pin Git dependencies to a full commit SHA instead of a branch, tag, or default reference.';
      }

      if (message && suggestion) {
        issues.push(this.createIssue(fileContent.path, index + 1, match.index + 1, line, message, suggestion));
      }
    });

    return issues;
  }
}
