import { BaseRule, FileContent, SecurityIssue } from '../types';

interface PromptInjectionContext {
  isInComment: boolean;
  isInString: boolean;
  isInTemplate: boolean;
  isInFunction: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
  aiFramework: string | undefined;
}

export class PromptInjectionDetectionRule extends BaseRule {
  readonly name = 'prompt-injection-detection';
  readonly description = 'Detects potential prompt injection vulnerabilities in AI systems with context-aware analysis';
  readonly severity = 'critical' as const;

  private readonly injectionPatterns = [
    // Direct prompt injection attempts
    { 
      pattern: /(?:prompt|input|query|message).*?(?:ignore|forget|system|assistant|user|previous|above|instructions)/gi, 
      type: 'Direct Prompt Injection',
      confidence: 0.85,
      validation: (text: string) => this.validateDirectInjection(text)
    },
    
    // Role confusion attacks
    { 
      pattern: /(?:you[_-]?are|act[_-]?as|pretend[_-]?to[_-]?be|behave[_-]?as|role[_-]?play).*?(?:system|assistant|user|admin|developer)/gi, 
      type: 'Role Confusion Attack',
      confidence: 0.9,
      validation: (text: string) => this.validateRoleConfusion(text)
    },
    
    // Instruction injection and override
    { 
      pattern: /(?:new[_-]?instructions?|override|replace|change|modify).*?(?:prompt|system|instructions|rules|guidelines)/gi, 
      type: 'Instruction Override',
      confidence: 0.8,
      validation: (text: string) => this.validateInstructionOverride(text)
    },
    
    // Jailbreak attempts
    { 
      pattern: /(?:jailbreak|bypass|circumvent|override|ignore).*?(?:safety|guardrails|filters|restrictions|limitations)/gi, 
      type: 'Jailbreak Attempt',
      confidence: 0.95,
      validation: (text: string) => this.validateJailbreak(text)
    },
    
    // System prompt leakage
    { 
      pattern: /(?:system|assistant|user|model).*?(?:prompt|instructions?|rules?|guidelines|configuration)/gi, 
      type: 'System Prompt Exposure',
      confidence: 0.7,
      validation: (text: string) => this.validateSystemExposure(text)
    },
    
    // Unsanitized user input in prompts
    { 
      pattern: /(?:prompt|input|query|message)\s*[:=]\s*['"`]?\$\{.*?\}/gi, 
      type: 'Unsanitized Prompt Input',
      confidence: 0.9,
      validation: (text: string) => this.validateUnsanitizedInput(text)
    },
    
    // Template injection in prompts
    { 
      pattern: /(?:prompt|input|query|message)\s*[:=]\s*['"`]?[^'"`]*\$\{.*?\}[^'"`]*['"`]?/gi, 
      type: 'Template Injection in Prompt',
      confidence: 0.85,
      validation: (text: string) => this.validateTemplateInjection(text)
    },
    
    // Context manipulation
    { 
      pattern: /(?:context|memory|history|conversation).*?(?:clear|reset|forget|ignore|delete)/gi, 
      type: 'Context Manipulation',
      confidence: 0.75,
      validation: (text: string) => this.validateContextManipulation(text)
    },
    
    // Output format manipulation
    { 
      pattern: /(?:output|response|answer|result).*?(?:format|structure|json|xml|html|markdown)/gi, 
      type: 'Output Format Manipulation',
      confidence: 0.6,
      validation: (text: string) => this.validateOutputManipulation(text)
    },
    
    // Privilege escalation attempts
    { 
      pattern: /(?:admin|root|superuser|privileged|elevated).*?(?:access|permissions|rights|capabilities)/gi, 
      type: 'Privilege Escalation Attempt',
      confidence: 0.8,
      validation: (text: string) => this.validatePrivilegeEscalation(text)
    }
  ];

  private readonly safePatterns = [
    /example/i,
    /demo/i,
    /test/i,
    /mock/i,
    /sample/i,
    /placeholder/i,
    /comment/i,
    /todo/i,
    /fixme/i,
    /development/i,
    /dev/i,
    /staging/i,
    /localhost/i,
    /sanitize/i,
    /validate/i,
    /escape/i,
    /filter/i,
    /secure/i,
    /safe/i,
    /protected/i,
    /defense/i,
    /guard/i,
    /prevent/i,
    /block/i,
    /restrict/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const aiFramework = this.detectAIFramework(fileContent.content);
    
    for (const { pattern, type, confidence, validation } of this.injectionPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework, aiFramework);
        
        // Skip if in safe context
        if (this.isSafeContext(context)) {
          continue;
        }
        
        // Validate the injection attempt
        if (!validation(matchedText)) {
          continue;
        }
        
        // Calculate final confidence based on context
        const finalConfidence = this.calculateConfidence(confidence, context);
        
        if (finalConfidence >= 0.5) {
          issues.push(this.createIssue(
            fileContent.path,
            line,
            column,
            lineContent,
            `Prompt injection detected: ${type} (confidence: ${Math.round(finalConfidence * 100)}%)`,
            this.generateSuggestion(type, context),
            finalConfidence >= 0.8 ? 'critical' : finalConfidence >= 0.6 ? 'high' : 'medium'
          ));
        }
      }
    }

    return issues;
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string, aiFramework?: string): PromptInjectionContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language),
      isInString: this.isInString(currentLine, column),
      isInTemplate: this.isInTemplate(currentLine, language),
      isInFunction: this.isInFunction(surroundingLines),
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(surroundingLines),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework,
      aiFramework
    };
  }

  private isSafeContext(context: PromptInjectionContext): boolean {
    // Safe if in comment
    if (context.isInComment) return true;
    
    // Safe if in test file
    if (context.isInTestFile) return true;
    
    // Safe if in documentation
    if (context.isInDocumentation) return true;
    
    // Safe if using security-related keywords
    if (this.safePatterns.some(pattern => pattern.test(context.surroundingCode))) {
      return true;
    }
    
    // Safe if in sanitization/validation context
    if (context.surroundingCode.includes('sanitize') || 
        context.surroundingCode.includes('validate') ||
        context.surroundingCode.includes('escape') ||
        context.surroundingCode.includes('filter')) {
      return true;
    }
    
    return false;
  }

  private detectLanguage(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase();
    const languageMap: Record<string, string> = {
      'js': 'javascript',
      'jsx': 'javascript',
      'ts': 'typescript',
      'tsx': 'typescript',
      'py': 'python',
      'php': 'php',
      'rb': 'ruby',
      'go': 'go',
      'java': 'java',
      'cs': 'csharp',
      'cpp': 'cpp',
      'c': 'c',
      'rs': 'rust',
      'kt': 'kotlin',
      'swift': 'swift',
      'dart': 'dart',
      'scala': 'scala',
      'clj': 'clojure',
      'hs': 'haskell'
    };
    return languageMap[ext || ''] || 'unknown';
  }

  private detectFramework(content: string, language: string): string | undefined {
    if (language === 'javascript' || language === 'typescript') {
      if (content.includes('express') || content.includes('app.get') || content.includes('app.post')) return 'express';
      if (content.includes('react') || content.includes('jsx') || content.includes('tsx')) return 'react';
      if (content.includes('vue') || content.includes('Vue.createApp')) return 'vue';
      if (content.includes('angular') || content.includes('@Component')) return 'angular';
    }
    if (language === 'python') {
      if (content.includes('flask') || content.includes('Flask')) return 'flask';
      if (content.includes('django') || content.includes('Django')) return 'django';
      if (content.includes('fastapi') || content.includes('FastAPI')) return 'fastapi';
    }
    return undefined;
  }

  private detectAIFramework(content: string): string | undefined {
    if (content.includes('openai') || content.includes('OpenAI')) return 'openai';
    if (content.includes('anthropic') || content.includes('Anthropic')) return 'anthropic';
    if (content.includes('langchain') || content.includes('LangChain')) return 'langchain';
    if (content.includes('llama') || content.includes('Llama')) return 'llama';
    if (content.includes('huggingface') || content.includes('transformers')) return 'huggingface';
    if (content.includes('tensorflow') || content.includes('tf.')) return 'tensorflow';
    if (content.includes('pytorch') || content.includes('torch.')) return 'pytorch';
    return undefined;
  }

  private isInComment(line: string, language: string): boolean {
    const trimmed = line.trim();
    if (language === 'javascript' || language === 'typescript') {
      return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
    }
    if (language === 'python') {
      return trimmed.startsWith('#');
    }
    if (language === 'php') {
      return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('#');
    }
    return false;
  }

  private isInString(line: string, column: number): boolean {
    const before = line.substring(0, column);
    const quotes = (before.match(/['"`]/g) || []).length;
    return quotes % 2 === 1;
  }

  private isInTemplate(line: string, language: string): boolean {
    return language === 'javascript' && line.includes('`') && line.includes('${');
  }

  private isInFunction(lines: string[]): boolean {
    return lines.some(line => line.includes('function') || line.includes('=>') || line.includes('def '));
  }

  private isInTestFile(filePath: string): boolean {
    return filePath.includes('test') || filePath.includes('spec') || filePath.includes('mock');
  }

  private isInDocumentation(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('@example') || 
      line.includes('@doc') || 
      line.includes('@description') ||
      line.includes('README') ||
      line.includes('documentation')
    );
  }

  private calculateConfidence(baseConfidence: number, context: PromptInjectionContext): number {
    let confidence = baseConfidence;
    
    // Reduce confidence for certain contexts
    if (context.isInTemplate) confidence *= 0.8;
    if (context.isInFunction) confidence *= 0.9;
    if (context.aiFramework) confidence *= 1.1; // Increase for AI frameworks
    
    return Math.min(confidence, 1.0);
  }

  // Validation methods for different injection types
  private validateDirectInjection(text: string): boolean {
    const injectionKeywords = ['ignore', 'forget', 'system', 'assistant', 'user', 'previous', 'above', 'instructions'];
    return injectionKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateRoleConfusion(text: string): boolean {
    const roleKeywords = ['you are', 'act as', 'pretend to be', 'behave as', 'role play'];
    const targetRoles = ['system', 'assistant', 'user', 'admin', 'developer'];
    return roleKeywords.some(role => text.toLowerCase().includes(role)) &&
           targetRoles.some(target => text.toLowerCase().includes(target));
  }

  private validateInstructionOverride(text: string): boolean {
    const overrideKeywords = ['new instructions', 'override', 'replace', 'change', 'modify'];
    const targetKeywords = ['prompt', 'system', 'instructions', 'rules', 'guidelines'];
    return overrideKeywords.some(override => text.toLowerCase().includes(override)) &&
           targetKeywords.some(target => text.toLowerCase().includes(target));
  }

  private validateJailbreak(text: string): boolean {
    const jailbreakKeywords = ['jailbreak', 'bypass', 'circumvent', 'override', 'ignore'];
    const safetyKeywords = ['safety', 'guardrails', 'filters', 'restrictions', 'limitations'];
    return jailbreakKeywords.some(jailbreak => text.toLowerCase().includes(jailbreak)) &&
           safetyKeywords.some(safety => text.toLowerCase().includes(safety));
  }

  private validateSystemExposure(text: string): boolean {
    const systemKeywords = ['system', 'assistant', 'user', 'model'];
    const exposureKeywords = ['prompt', 'instructions', 'rules', 'guidelines', 'configuration'];
    return systemKeywords.some(system => text.toLowerCase().includes(system)) &&
           exposureKeywords.some(exposure => text.toLowerCase().includes(exposure));
  }

  private validateUnsanitizedInput(text: string): boolean {
    return /\$\{.*?\}/.test(text) && (text.includes('prompt') || text.includes('input') || text.includes('query'));
  }

  private validateTemplateInjection(text: string): boolean {
    return /\$\{.*?\}/.test(text) && text.includes('${');
  }

  private validateContextManipulation(text: string): boolean {
    const contextKeywords = ['context', 'memory', 'history', 'conversation'];
    const manipulationKeywords = ['clear', 'reset', 'forget', 'ignore', 'delete'];
    return contextKeywords.some(context => text.toLowerCase().includes(context)) &&
           manipulationKeywords.some(manipulation => text.toLowerCase().includes(manipulation));
  }

  private validateOutputManipulation(text: string): boolean {
    const outputKeywords = ['output', 'response', 'answer', 'result'];
    const formatKeywords = ['format', 'structure', 'json', 'xml', 'html', 'markdown'];
    return outputKeywords.some(output => text.toLowerCase().includes(output)) &&
           formatKeywords.some(format => text.toLowerCase().includes(format));
  }

  private validatePrivilegeEscalation(text: string): boolean {
    const privilegeKeywords = ['admin', 'root', 'superuser', 'privileged', 'elevated'];
    const accessKeywords = ['access', 'permissions', 'rights', 'capabilities'];
    return privilegeKeywords.some(privilege => text.toLowerCase().includes(privilege)) &&
           accessKeywords.some(access => text.toLowerCase().includes(access));
  }

  private generateSuggestion(type: string, context: PromptInjectionContext): string {
    const suggestions = {
      'Direct Prompt Injection': 'Implement input sanitization and validation. Use allowlists for acceptable inputs and blocklists for malicious patterns.',
      'Role Confusion Attack': 'Validate user roles and implement proper access controls. Use role-based authentication and authorization.',
      'Instruction Override': 'Implement instruction validation and use secure prompt engineering techniques. Consider using prompt classifiers.',
      'Jailbreak Attempt': 'Implement safety filters and content moderation. Use red-teaming to identify and block jailbreak attempts.',
      'System Prompt Exposure': 'Protect system prompts and implement proper access controls. Use environment variables for sensitive configurations.',
      'Unsanitized Prompt Input': 'Sanitize all user inputs before using them in prompts. Use input validation and output encoding.',
      'Template Injection in Prompt': 'Use secure template engines and validate template variables. Implement proper input sanitization.',
      'Context Manipulation': 'Implement context validation and use secure session management. Monitor for unusual context changes.',
      'Output Format Manipulation': 'Validate output formats and implement proper response filtering. Use secure output encoding.',
      'Privilege Escalation Attempt': 'Implement proper authentication and authorization. Use role-based access controls and privilege separation.'
    };
    
    let suggestion = suggestions[type as keyof typeof suggestions] || 'Implement comprehensive input validation and output sanitization.';
    
    if (context.aiFramework) {
      suggestion += ` For ${context.aiFramework}, consider using framework-specific security features and prompt validation.`;
    }
    
    if (context.framework) {
      suggestion += ` For ${context.framework}, implement framework-specific input validation and security middleware.`;
    }
    
    return suggestion;
  }
}