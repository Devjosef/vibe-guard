# Contributing to Vibe-Guard

Solo-maintained security scanner (1.1k npm downloads). Fork, test, PR.

## Setup
```bash git clone https://github.com/Devjosef/vibe-guard.git
cd vibe-guard
npm i
npm run build
node dist/bin/vibe-guard.js scan .
npm test 
```

## Add Rule
1. `src/rules/my-rule.ts` extending `BaseRule`
2. Export in `src/rules/index.ts`
3. Test it
4. Update README rule list

```typescript
export class MyRule extends BaseRule {
  readonly name = 'my-rule';
  readonly severity = 'medium' as const;

  check(file: FileContent): SecurityIssue[] {
    return this.findMatches(file.content, /bad-pattern/gi)
      .filter(m => !this.isCommentOrTest(m.lineContent, file.path))
      .map(m => this.createIssue(file.path, m.line, m.column, m.lineContent, 'Issue', 'Fix'));
  }
}
```

## Tests
- Positive: detects vuln
- Negative: ignores safe code/comments/tests
- `npm test`

## PR Rules
- Passes `npm run build && npm test && npm run lint`
- No redundant patterns
- Docs updated (README + SECURITY_RULES.md)
- Describe: what/why/tests

I review for perf/false positives. Small focused PRs preferred. No huge refactors.

Thanks.
