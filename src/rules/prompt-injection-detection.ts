import { BaseRule, FileContent, SecurityIssue, SeverityLevel } from '../types';

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

interface InjectionPattern {
  pattern: RegExp;
  type: string;
  severity: SeverityLevel;
  description: string;
  validation: (text: string) => boolean;
}

export class PromptInjectionDetectionRule extends BaseRule {
  readonly name = 'prompt-injection-detection';
  readonly description = 'Detects potential prompt injection vulnerabilities in AI systems with context-aware analysis';
  readonly severity = 'critical' as const;

  private readonly injectionPatterns: InjectionPattern[] = [
    // Critical pattern: Most dangerous injection types
    { 
      pattern: /\b(?:prompt|input|query|message)\s*[:=]\s*['"`]?[^'"`]*(?:ignore|forget|system|assistant|user|previous|above|instructions)[^'"`]*['"`]?/gi, 
      type: 'Direct Prompt Injection',
      severity: 'critical',
      description: 'Direct attempt to override system instructions or context',
      validation: (text: string) => this.validateDirectInjection(text)
    },
    { 
      pattern: /\b(?:prompt|input|query|message)\s*[:=]\s*['"`]?[^'"`]*\$\{[^}]*\}[^'"`]*['"`]?/gi, 
      type: 'Unsanitized Prompt Input',
      severity: 'critical',
      description: 'User input directly interpolated into prompts without sanitization',
      validation: (text: string) => this.validateUnsanitizedInput(text)
    },
    { 
      pattern: /\b(?:prompt|input|query|message)\s*[:=]\s*['"`]?[^'"`]*(?:jailbreak|bypass|circumvent|override|ignore)[^'"`]*(?:safety|guardrails|filters|restrictions|limitations)[^'"`]*['"`]?/gi, 
      type: 'Jailbreak Attempt',
      severity: 'critical',
      description: 'Attempt to bypass safety measures and guardrails',
      validation: (text: string) => this.validateJailbreak(text)
    },
    { 
      pattern: /\b(?:prompt|input|query|message)\s*[:=]\s*['"`]?[^'"`]*(?:new[_-]?instructions?|override|replace|change|modify)[^'"`]*(?:prompt|system|instructions|rules|guidelines)[^'"`]*['"`]?/gi, 
      type: 'Instruction Override',
      severity: 'critical',
      description: 'Attempt to replace or modify system instructions',
      validation: (text: string) => this.validateInstructionOverride(text)
    },
    
    // High pattern: Dangerous but less critical
    { 
      pattern: /\b(?:prompt|input|query|message)\s*[:=]\s*['"`]?[^'"`]*(?:you[_-]?are|act[_-]?as|pretend[_-]?to[_-]?be|behave[_-]?as|role[_-]?play)[^'"`]*(?:system|assistant|user|admin|developer)[^'"`]*['"`]?/gi, 
      type: 'Role Confusion Attack',
      severity: 'high',
      description: 'Attempt to impersonate system roles or gain elevated privileges',
      validation: (text: string) => this.validateRoleConfusion(text)
    },
    { 
      pattern: /\b(?:prompt|input|query|message)\s*[:=]\s*['"`]?[^'"`]*(?:system|assistant|user|model)[^'"`]*(?:prompt|instructions?|rules?|guidelines|configuration)[^'"`]*['"`]?/gi, 
      type: 'System Prompt Exposure',
      severity: 'high',
      description: 'Attempt to extract or expose system prompts and configurations',
      validation: (text: string) => this.validateSystemExposure(text)
    },
    { 
      pattern: /\b(?:prompt|input|query|message)\s*[:=]\s*['"`]?[^'"`]*(?:admin|root|superuser|privileged|elevated)[^'"`]*(?:access|permissions|rights|capabilities)[^'"`]*['"`]?/gi, 
      type: 'Privilege Escalation Attempt',
      severity: 'high',
      description: 'Attempt to gain elevated privileges or administrative access',
      validation: (text: string) => this.validatePrivilegeEscalation(text)
    },
    
    // Medium pattern: Less critical but still concerning
    { 
      pattern: /\b(?:prompt|input|query|message)\s*[:=]\s*['"`]?[^'"`]*(?:context|memory|history|conversation)[^'"`]*(?:clear|reset|forget|ignore|delete)[^'"`]*['"`]?/gi, 
      type: 'Context Manipulation',
      severity: 'medium',
      description: 'Attempt to manipulate conversation context or memory',
      validation: (text: string) => this.validateContextManipulation(text)
    },
    { 
      pattern: /\b(?:completion|generate|llm_output|response)\s*[:=]\s*['"`]?[^'"`]*(?:output|response|answer|result)[^'"`]*(?:format|structure|json|xml|html|markdown)[^'"`]*['"`]?/gi, 
      type: 'Output Format Manipulation',
      severity: 'medium',
      description: 'Attempt to manipulate output format for data exfiltration',
      validation: (text: string) => this.validateOutputManipulation(text)
    },
    
    // String concatenation and format patterns
    { 
      pattern: /\b(?:prompt|input|query|message)\s*[:=]\s*['"`][^'"`]*['"`]\s*[+]\s*\w+/gi, 
      type: 'String Concatenation Injection',
      severity: 'critical',
      description: 'User input concatenated directly into prompts',
      validation: (text: string) => this.validateStringConcatenation(text)
    },
    { 
      pattern: /\bf["`][^`"]*\$\{[^}]*\}[^`"]*["`]/gi, 
      type: 'F-String Template Injection',
      severity: 'critical',
      description: 'Python f-string with user input interpolation',
      validation: (text: string) => this.validateFStringInjection(text)
    },
    { 
      pattern: /\b(?:prompt|input|query|message)\s*[:=]\s*['"`][^'"`]*\{[^}]*\}[^'"`]*['"`]\.format\(/gi, 
      type: 'Format String Injection',
      severity: 'critical',
      description: 'Python .format() with user input',
      validation: (text: string) => this.validateFormatStringInjection(text)
    },
    { 
      pattern: /\bString\.format\s*\(\s*['"`][^'"`]*\{[^}]*\}[^'"`]*['"`]/gi, 
      type: 'Java Format String Injection',
      severity: 'critical',
      description: 'Java String.format with user input',
      validation: (text: string) => this.validateJavaFormatInjection(text)
    },
    { 
      pattern: /\b\$\s*["`][^`"]*\{[^}]*\}[^`"]*["`]/gi, 
      type: 'C# String Interpolation Injection',
      severity: 'critical',
      description: 'C# string interpolation with user input',
      validation: (text: string) => this.validateCSharpInterpolation(text)
    }
  ];

  private readonly safePatterns = [
    /\bexample\b/i,
    /\bdemo\b/i,
    /\btest\b/i,
    /\bmock\b/i,
    /\bsample\b/i,
    /\bplaceholder\b/i,
    /\bcomment\b/i,
    /\btodo\b/i,
    /\bfixme\b/i,
    /\bdevelopment\b/i,
    /\bdev\b/i,
    /\bstaging\b/i,
    /\blocalhost\b/i,
    /\bsanitize\b/i,
    /\bvalidate\b/i,
    /\bescape\b/i,
    /\bfilter\b/i,
    /\bsecure\b/i,
    /\bsafe\b/i,
    /\bprotected\b/i,
    /\bdefense\b/i,
    /\bguard\b/i,
    /\bprevent\b/i,
    /\bblock\b/i,
    /\brestrict\b/i,
    /\bconsole\.log\b/i,
    /\bconsole\.warn\b/i,
    /\bconsole\.error\b/i,
    /\blogger\.(?:log|warn|error|info)\b/i,
    /\bprint\b/i,
    /\becho\b/i,
    /\bprintf\b/i,
    /\bSystem\.out\.println\b/i,
    /\bputs\b/i,
    /\bConsole\.WriteLine\b/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const aiFramework = this.detectAIFramework(fileContent.content);
    
    for (const { pattern, type, severity, description, validation } of this.injectionPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework, aiFramework);
        
        // Skips if in safe context (but not test files! We want to flag those with lower severity)
        if (this.isSafeContext(context) && !context.isInTestFile) {
          continue;
        }
        
        // Validates the injection attempt
        if (!validation(matchedText)) {
          continue;
        }
        
        // Determines final severity based on context
        const finalSeverity = this.determineSeverity(severity, context);
        
        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Prompt injection detected: ${type} - ${description}`,
          this.getRemediationMessage(type, context, finalSeverity),
          finalSeverity
        ));
      }
    }

    return issues;
  }

  private determineSeverity(baseSeverity: SeverityLevel, context: PromptInjectionContext): SeverityLevel {
    // Downgrades severity in test/documentation contexts instead of skipping
    if (context.isInTestFile || context.isInDocumentation) {
      switch (baseSeverity) {
        case 'critical': return 'high';
        case 'high': return 'medium';
        case 'medium': return 'low';
        case 'low': return 'low';
        default: return baseSeverity;
      }
    }
    
    // Downgrades in development contexts
    if (this.isDevelopmentContext(context)) {
      switch (baseSeverity) {
        case 'critical': return 'high';
        case 'high': return 'medium';
        case 'medium': return 'low';
        case 'low': return 'low';
        default: return baseSeverity;
      }
    }
    
    return baseSeverity;
  }

  private isDevelopmentContext(context: PromptInjectionContext): boolean {
    const devPatterns = [
      /\bdevelopment\b/i,
      /\bdev\b/i,
      /\bstaging\b/i,
      /\blocalhost\b/i,
      /\b127\.0\.0\.1\b/i,
      /\btest\b/i,
      /\bmock\b/i,
      /\bdebug\b/i,
      /\bNODE_ENV\s*=\s*['"`]development['"`]/i,
      /\bNODE_ENV\s*=\s*['"`]test['"`]/i,
      /\bDEBUG\s*=\s*true\b/i
    ];
    
    return devPatterns.some(pattern => pattern.test(context.surroundingCode));
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
    
    if (context.isInComment) return true;
    
    
    if (context.isInDocumentation && !context.isInTestFile) return true;
    
    
    if (this.safePatterns.some(pattern => pattern.test(context.surroundingCode))) {
      return true;
    }
    
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
      if (content.includes('next') || content.includes('Next.js')) return 'nextjs';
    }
    if (language === 'python') {
      if (content.includes('flask') || content.includes('Flask')) return 'flask';
      if (content.includes('django') || content.includes('Django')) return 'django';
      if (content.includes('fastapi') || content.includes('FastAPI')) return 'fastapi';
    }
    if (language === 'php') {
      if (content.includes('laravel') || content.includes('Laravel')) return 'laravel';
      if (content.includes('symfony') || content.includes('Symfony')) return 'symfony';
    }
    if (language === 'ruby') {
      if (content.includes('rails') || content.includes('Rails')) return 'rails';
    }
    if (language === 'java') {
      if (content.includes('spring') || content.includes('Spring')) return 'spring';
    }
    if (language === 'csharp') {
      if (content.includes('asp.net') || content.includes('ASP.NET')) return 'aspnet';
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
    if (content.includes('autogen') || content.includes('AutoGen')) return 'autogen';
    if (content.includes('llamaindex') || content.includes('LlamaIndex')) return 'llamaindex';
    if (content.includes('haystack') || content.includes('Haystack')) return 'haystack';
    if (content.includes('azure') && content.includes('openai')) return 'azure-openai';
    if (content.includes('vertex') && content.includes('ai')) return 'vertex-ai';
    if (content.includes('bedrock') || content.includes('Bedrock')) return 'bedrock';
    if (content.includes('cohere') || content.includes('Cohere')) return 'cohere';
    if (content.includes('replicate') || content.includes('Replicate')) return 'replicate';
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

  // Validation methods!
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

  private validateStringConcatenation(text: string): boolean {
    return text.includes('+') && (text.includes('prompt') || text.includes('input') || text.includes('query'));
  }

  private validateFStringInjection(text: string): boolean {
    return /\$\{.*?\}/.test(text) && text.includes('f"') || text.includes("f'");
  }

  private validateFormatStringInjection(text: string): boolean {
    return /\{[^}]*\}/.test(text) && text.includes('.format(');
  }

  private validateJavaFormatInjection(text: string): boolean {
    return /\{[^}]*\}/.test(text) && text.includes('String.format');
  }

  private validateCSharpInterpolation(text: string): boolean {
    return /\$\{[^}]*\}/.test(text) && text.includes('$"') || text.includes("$'");
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

  private getRemediationMessage(type: string, context: PromptInjectionContext, severity: SeverityLevel): string {
    const messages: Record<string, Record<string, string>> = {
      'Direct Prompt Injection': {
        'critical': 'CRITICAL: Implement strict input validation and sanitization. Use allowlists for acceptable inputs and blocklists for malicious patterns. Consider using structured API calls instead of free-form prompts.',
        'high': 'HIGH: Implement input sanitization and validation. Block common injection keywords and patterns.',
        'medium': 'MEDIUM: Review input validation and consider implementing prompt sanitization.',
        'low': 'LOW: Consider implementing input validation for better security.'
      },
      'Unsanitized Prompt Input': {
        'critical': 'CRITICAL: Never interpolate user input directly into prompts. Use parameterized prompts, input validation, and output encoding. Separate instructions from data using structured API calls.',
        'high': 'HIGH: Sanitize all user inputs before using them in prompts. Use input validation and output encoding.',
        'medium': 'MEDIUM: Consider using parameterized prompts instead of string interpolation.',
        'low': 'LOW: Review prompt construction for potential injection vulnerabilities.'
      },
      'Jailbreak Attempt': {
        'critical': 'CRITICAL: Implement comprehensive safety filters and content moderation. Use red-teaming to identify and block jailbreak attempts. Consider using multiple validation layers.',
        'high': 'HIGH: Implement safety filters and content moderation. Monitor for jailbreak patterns.',
        'medium': 'MEDIUM: Consider implementing safety filters for AI responses.',
        'low': 'LOW: Review AI safety measures and consider implementing filters.'
      },
      'Instruction Override': {
        'critical': 'CRITICAL: Implement instruction validation and use secure prompt engineering techniques. Use prompt classifiers and never allow user input to modify system instructions.',
        'high': 'HIGH: Validate instructions and use secure prompt engineering. Block instruction modification attempts.',
        'medium': 'MEDIUM: Consider implementing instruction validation.',
        'low': 'LOW: Review prompt engineering practices for security.'
      },
      'Role Confusion Attack': {
        'critical': 'CRITICAL: Implement role classification and filtering. Never allow users to impersonate system roles. Use role-based authentication and authorization.',
        'high': 'HIGH: Validate user roles and implement proper access controls. Filter role confusion attempts.',
        'medium': 'MEDIUM: Consider implementing role validation and filtering.',
        'low': 'LOW: Review role-based access controls.'
      },
      'System Prompt Exposure': {
        'critical': 'CRITICAL: Protect system prompts and implement proper access controls. Use environment variables for sensitive configurations. Never expose system prompts to users.',
        'high': 'HIGH: Protect system prompts and implement access controls. Use environment variables.',
        'medium': 'MEDIUM: Consider protecting system prompts and configurations.',
        'low': 'LOW: Review system prompt protection measures.'
      },
      'String Concatenation Injection': {
        'critical': 'CRITICAL: Never concatenate user input directly into prompts. Use parameterized prompts or structured API calls. Implement input validation and sanitization.',
        'high': 'HIGH: Avoid string concatenation with user input. Use parameterized approaches.',
        'medium': 'MEDIUM: Consider using parameterized prompts instead of concatenation.',
        'low': 'LOW: Review string concatenation practices in prompts.'
      },
      'F-String Template Injection': {
        'critical': 'CRITICAL: Never use f-strings with user input in prompts. Use parameterized prompts or structured API calls. Implement input validation.',
        'high': 'HIGH: Avoid f-strings with user input in prompts. Use safer alternatives.',
        'medium': 'MEDIUM: Consider using parameterized prompts instead of f-strings.',
        'low': 'LOW: Review f-string usage in prompts.'
      },
      'Format String Injection': {
        'critical': 'CRITICAL: Never use .format() with user input in prompts. Use parameterized prompts or structured API calls. Implement input validation.',
        'high': 'HIGH: Avoid .format() with user input in prompts. Use safer alternatives.',
        'medium': 'MEDIUM: Consider using parameterized prompts instead of .format().',
        'low': 'LOW: Review .format() usage in prompts.'
      },
      'Context Manipulation': {
        'critical': 'CRITICAL: Implement context validation and use secure session management. Prevent one user from overriding shared system context. Use session scoping.',
        'high': 'HIGH: Validate context changes and implement session management. Monitor for unusual context manipulation.',
        'medium': 'MEDIUM: Consider implementing context validation and session management.',
        'low': 'LOW: Review context management practices.'
      },
      'Output Format Manipulation': {
        'critical': 'CRITICAL: Validate output formats and implement proper response filtering. Use secure output encoding. Never allow users to control output format.',
        'high': 'HIGH: Validate output formats and implement response filtering. Use secure encoding.',
        'medium': 'MEDIUM: Consider implementing output format validation.',
        'low': 'LOW: Review output format handling.'
      },
      'Privilege Escalation Attempt': {
        'critical': 'CRITICAL: Implement proper authentication and authorization. Use role-based access controls and privilege separation. Never mix admin/system commands with user-generated inputs.',
        'high': 'HIGH: Implement proper authentication and authorization. Use role-based access controls.',
        'medium': 'MEDIUM: Consider implementing privilege separation and access controls.',
        'low': 'LOW: Review authentication and authorization practices.'
      }
    };
    
    let suggestion = messages[type]?.[severity] || 'Implement comprehensive input validation and output sanitization.';
    
    if (context.aiFramework) {
      suggestion += this.getAIFrameworkSpecificAdvice(context.aiFramework, type);
    }
    
    if (context.framework) {
      suggestion += this.getFrameworkSpecificAdvice(context.framework, type);
    }
    
    if (context.language) {
      suggestion += this.getLanguageSpecificAdvice(context.language, type);
    }
    
    return suggestion;
  }

  private getAIFrameworkSpecificAdvice(aiFramework: string, type: string): string {
    const advice: Record<string, Record<string, string>> = {
      'openai': {
        'Unsanitized Prompt Input': ' For OpenAI, use structured API calls with separate system and user messages. Implement input validation using OpenAI\'s content filtering.',
        'Jailbreak Attempt': ' For OpenAI, use the content filtering API and implement additional safety checks. Consider using function calling instead of free-form prompts.',
        'Role Confusion Attack': ' For OpenAI, use role-based message structure and implement user role validation.'
      },
      'anthropic': {
        'Unsanitized Prompt Input': ' For Anthropic, use Claude\'s structured input format and implement input validation. Use system prompts to define behavior boundaries.',
        'Jailbreak Attempt': ' For Anthropic, use Claude\'s safety features and implement additional content filtering. Consider using constitutional AI principles.'
      },
      'langchain': {
        'Unsanitized Prompt Input': ' For LangChain, use prompt templates with input validation. Implement prompt injection detection using LangChain\'s security features.',
        'Context Manipulation': ' For LangChain, use memory management and implement context validation. Use conversation buffers with proper scoping.'
      }
    };
    
    return advice[aiFramework]?.[type] || ` For ${aiFramework}, consider using framework-specific security features and input validation.`;
  }

  private getFrameworkSpecificAdvice(framework: string, type: string): string {
    const advice: Record<string, Record<string, string>> = {
      'express': {
        'Unsanitized Prompt Input': ' For Express, implement input validation middleware and use parameterized prompts. Consider using express-validator.',
        'String Concatenation Injection': ' For Express, avoid string concatenation in prompts. Use template engines with proper escaping.'
      },
      'flask': {
        'Unsanitized Prompt Input': ' For Flask, use Flask-WTF for form validation and implement input sanitization. Use parameterized prompts.',
        'F-String Template Injection': ' For Flask, avoid f-strings with user input. Use Jinja2 templates with proper escaping.'
      },
      'django': {
        'Unsanitized Prompt Input': ' For Django, use Django forms for validation and implement input sanitization. Use parameterized prompts.',
        'Format String Injection': ' For Django, avoid .format() with user input. Use Django templates with proper escaping.'
      }
    };
    
    return advice[framework]?.[type] || ` For ${framework}, implement framework-specific input validation and security middleware.`;
  }

  private getLanguageSpecificAdvice(language: string, type: string): string {
    const advice: Record<string, Record<string, string>> = {
      'python': {
        'F-String Template Injection': ' In Python, use parameterized prompts or structured API calls instead of f-strings with user input.',
        'Format String Injection': ' In Python, avoid .format() with user input. Use parameterized approaches or structured API calls.'
      },
      'javascript': {
        'String Concatenation Injection': ' In JavaScript, use template literals with proper escaping or parameterized prompts instead of string concatenation.',
        'Template Injection in Prompt': ' In JavaScript, use parameterized prompts or structured API calls instead of template literals with user input.'
      },
      'java': {
        'Java Format String Injection': ' In Java, use parameterized prompts or structured API calls instead of String.format with user input.',
        'String Concatenation Injection': ' In Java, use StringBuilder or parameterized approaches instead of string concatenation with user input.'
      },
      'csharp': {
        'C# String Interpolation Injection': ' In C#, use parameterized prompts or structured API calls instead of string interpolation with user input.',
        'String Concatenation Injection': ' In C#, use parameterized approaches or structured API calls instead of string concatenation with user input.'
      }
    };
    
    return advice[language]?.[type] || ` In ${language}, implement language-specific input validation and sanitization.`;
  }
}