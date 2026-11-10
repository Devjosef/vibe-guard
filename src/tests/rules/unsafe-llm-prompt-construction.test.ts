import { UnsafeLlmPromptConstructionRule } from '../../rules/unsafe-llm-prompt-construction';
import { FileContent } from '../../types';

describe('UnsafeLlmPromptConstructionRule', () => {
  const rule = new UnsafeLlmPromptConstructionRule();

  const check = (content: string): ReturnType<typeof rule.check> => {
    const fileContent: FileContent = {
      path: 'src/llm-client.ts',
      content,
      lines: content.split('\n')
    };
    return rule.check(fileContent);
  };

  it('detects request data interpolated into a prompt template', () => {
    const issues = check('const prompt = `Summarize this: ${req.body.prompt}`;');

    expect(issues).toHaveLength(1);
    expect(issues[0]?.severity).toBe('high');
    expect(issues[0]?.message).toContain('inserted directly');
  });

  it('detects user input concatenated into a system prompt', () => {
    expect(check('systemPrompt = "Follow these instructions: " + userInput;')).toHaveLength(1);
  });

  it('does not flag structured user messages or sanitized template values', () => {
    expect(check('client.messages.create({ messages: [{ role: "user", content: userInput }] });')).toHaveLength(0);
    expect(check('const prompt = `Summarize this: ${sanitize(userInput)}`;')).toHaveLength(0);
  });

  it('does not flag comments', () => {
    expect(check('// const prompt = `Summarize this: ${userInput}`;')).toHaveLength(0);
  });
});
