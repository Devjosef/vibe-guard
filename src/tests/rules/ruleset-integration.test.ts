import VibeGuard from '../../index';

describe('registered security rules', () => {
  it('includes the new AI and supply-chain detections', () => {
    const rules = new VibeGuard().getRules();
    const names = rules.map(rule => rule.name);

    expect(rules).toHaveLength(30);
    expect(names).toContain('exposed-secrets');
    expect(names).toContain('unsafe-llm-prompt-construction');
    expect(names).toContain('unpinned-supply-chain-dependencies');
  });
});
