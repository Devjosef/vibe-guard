import { BaseRule, FileContent, SecurityIssue } from '../types';

export class UnsafeLlmPromptConstructionRule extends BaseRule {
  readonly name = 'unsafe-llm-prompt-construction';
  readonly description = 'Detects untrusted user input interpolated directly into LLM prompt templates';
  readonly severity = 'high' as const;

  private readonly unsafePromptPattern = new RegExp(
    String.raw`(?:\b(?:const|let|var)\s+)?\b(?:prompt|systemPrompt|systemMessage|instructions|template)\s*(?:\+?=)\s*(?:` +
      String.raw`[^;\n]*\$\{\s*(?:\b(?:req|request)\s*\.\s*(?:body|query|params)(?:\s*\.\s*[\w$]+)?|\b(?:userInput|userPrompt|untrustedInput|userMessage|inputText)\b)\s*\}[^;\n]*` +
      String.raw`|["'][^"'\n]*["']\s*\+\s*(?:\b(?:req|request)\s*\.\s*(?:body|query|params)(?:\s*\.\s*[\w$]+)?|\b(?:userInput|userPrompt|untrustedInput|userMessage|inputText)\b)` +
      String.raw`|\s*(?:\b(?:req|request)\s*\.\s*(?:body|query|params)(?:\s*\.\s*[\w$]+)?|\b(?:userInput|userPrompt|untrustedInput|userMessage|inputText)\b))`,
    'i'
  );

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    fileContent.lines.forEach((line, index) => {
      if (/^\s*(?:\/\/|#|\*|\/\*)/.test(line)) return;
      const match = this.unsafePromptPattern.exec(line);
      if (!match) return;

      const column = match.index + 1;
      issues.push(this.createIssue(
        fileContent.path,
        index + 1,
        column,
        line,
        'Untrusted input is inserted directly into an LLM prompt template',
        'Keep untrusted content separate from system instructions, use structured user messages, and apply explicit input handling.'
      ));
    });

    return issues;
  }
}
