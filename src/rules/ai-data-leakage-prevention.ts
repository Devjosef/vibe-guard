import { BaseRule, FileContent, SecurityIssue } from '../types';

interface DataLeakageContext {
  isInComment: boolean;
  isInString: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  isInDevelopment: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
  hasDataProtection: boolean;
  isProtectedEnvironment: boolean;
}

export class AiDataLeakagePreventionRule extends BaseRule {
  readonly name = 'ai-data-leakage-prevention';
  readonly description = 'Detects potential data leakage in AI systems and training data exposure with context-aware analysis';
  readonly severity = 'high' as const;

  private readonly leakagePatterns = [
    // Training data exposure: more specific patterns
    { 
      pattern: /(?:training[_-]?data|dataset|corpus)\s*[:=]\s*['"`]?[^'"`]*(?:expose|leak|public|unrestricted)['"`]?/gi, 
      type: 'Training Data Exposure',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateTrainingDataExposure(text)
    },
    { 
      pattern: /(?:sensitive|confidential|proprietary)\s*[:=]\s*['"`]?[^'"`]*(?:training|dataset|corpus)['"`]?/gi, 
      type: 'Sensitive Training Data',
      confidence: 0.85,
      severity: 'critical' as const,
      validation: (text: string) => this.validateSensitiveTrainingData(text)
    },
    
    // Model output containing sensitive data: more specific
    { 
      pattern: /(?:model|ai|llm)\s*[:=]\s*['"`]?[^'"`]*(?:output|response|generation)\s*[:=]\s*['"`]?[^'"`]*(?:sensitive|confidential|proprietary)['"`]?/gi, 
      type: 'Sensitive Data in AI Output',
      confidence: 0.8,
      severity: 'high' as const,
      validation: (text: string) => this.validateSensitiveOutput(text)
    },
    
    // Unfiltered AI responses: more specific
    { 
      pattern: /(?:ai|model|llm)\s*[:=]\s*['"`]?[^'"`]*(?:unfiltered|unrestricted|raw)\s*[:=]\s*['"`]?[^'"`]*(?:output|response)['"`]?/gi, 
      type: 'Unfiltered AI Output',
      confidence: 0.75,
      severity: 'high' as const,
      validation: (text: string) => this.validateUnfilteredOutput(text)
    },
    
    // Data classification bypass: more specific
    { 
      pattern: /(?:bypass|ignore|skip)\s*[:=]\s*['"`]?[^'"`]*(?:classification|label|sensitivity)['"`]?/gi, 
      type: 'Data Classification Bypass',
      confidence: 0.85,
      severity: 'high' as const,
      validation: (text: string) => this.validateClassificationBypass(text)
    },
    
    // AI model containing sensitive data: more specific
    { 
      pattern: /(?:model|weights|parameters)\s*[:=]\s*['"`]?[^'"`]*(?:contain|include|embed)\s*[:=]\s*['"`]?[^'"`]*(?:sensitive|confidential)['"`]?/gi, 
      type: 'Sensitive Data in Model',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateSensitiveModel(text)
    },
    
    // Unencrypted AI artifacts: more specific
    { 
      pattern: /(?:model|weights|artifacts)\s*[:=]\s*['"`]?[^'"`]*(?:unencrypted|plaintext|raw)['"`]?/gi, 
      type: 'Unencrypted AI Artifacts',
      confidence: 0.8,
      severity: 'high' as const,
      validation: (text: string) => this.validateUnencryptedArtifacts(text)
    },
    
    // Logging sensitive data: more specific
    { 
      pattern: /(?:log|console|print|echo)\s*[:=]\s*['"`]?[^'"`]*(?:sensitive|confidential|proprietary|personal)['"`]?/gi, 
      type: 'Sensitive Data Logging',
      confidence: 0.85,
      severity: 'high' as const,
      validation: (text: string) => this.validateSensitiveLogging(text)
    },
    
    // Data export without filtering: more specific
    { 
      pattern: /(?:export|save|write)\s*[:=]\s*['"`]?[^'"`]*(?:all|complete|full)\s*[:=]\s*['"`]?[^'"`]*(?:data|dataset)['"`]?/gi, 
      type: 'Unfiltered Data Export',
      confidence: 0.7,
      severity: 'medium' as const,
      validation: (text: string) => this.validateUnfilteredExport(text)
    },
    
    // API response without sanitization: more specific
    { 
      pattern: /(?:api|response|return)\s*[:=]\s*['"`]?[^'"`]*(?:raw|unfiltered|complete)\s*[:=]\s*['"`]?[^'"`]*(?:data|result)['"`]?/gi, 
      type: 'Unsanitized API Response',
      confidence: 0.75,
      severity: 'medium' as const,
      validation: (text: string) => this.validateUnsanitizedResponse(text)
    }
  ];

  private readonly falsePositivePatterns = [
    // Development and testing patterns
    /example/i,
    /demo/i,
    /test/i,
    /mock/i,
    /sample/i,
    /placeholder/i,
    /comment/i,
    /todo/i,
    /fixme/i,
    /\/\/.*/i,
    /#.*/i,
    /\/\*.*\*\//i,
    /<!--.*-->/i,
    /development/i,
    /dev/i,
    /staging/i,
    /localhost/i,
    
    // Documentation and tutorials
    /documentation/i,
    /docs?/i,
    /tutorial/i,
    /guide/i,
    /readme/i,
    /example[_-]?config/i,
    /sample[_-]?config/i,
    /\.md$/i,
    /\.rst$/i,
    /\.txt$/i,
    
    // Safe environments
    /sandbox/i,
    /isolated/i,
    /contained/i,
    /restricted/i,
    /safe[_-]?mode/i,
    /demo[_-]?mode/i,
    /test[_-]?environment/i,
    
    // Data protection patterns (likely safe)
    /encrypt/i,
    /protect/i,
    /secure/i,
    /filter/i,
    /sanitize/i,
    /anonymize/i,
    /mask/i,
    /redact/i,
    /dlp/i,
    /data[_-]?loss[_-]?prevention/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const hasDataProtection = this.hasDataProtection(fileContent.content);
    const isProtectedEnvironment = this.isProtectedEnvironment(fileContent.content);
    
    for (const { pattern, type, confidence, severity, validation } of this.leakagePatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework, hasDataProtection, isProtectedEnvironment);
        
        // Skip if in safe context
        if (this.isSafeContext(context)) {
          continue;
        }
        
        // Validate the data leakage issue
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
            `${severity.toUpperCase()}: ${type} detected (confidence: ${Math.round(finalConfidence * 100)}%): ${this.getLineContext(lineContent, column)}`,
            this.generateSuggestion(type, context),
            severity
          ));
        }
      }
    }

    return issues;
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string, hasDataProtection?: boolean, isProtectedEnvironment?: boolean): DataLeakageContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language),
      isInString: this.isInString(currentLine, column),
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(fileContent.path),
      isInDevelopment: this.isInDevelopment(surroundingLines),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework,
      hasDataProtection: hasDataProtection || false,
      isProtectedEnvironment: isProtectedEnvironment || false
    };
  }

  private isSafeContext(context: DataLeakageContext): boolean {
    // Safe if in comment
    if (context.isInComment) return true;
    
    // Safe if in test file
    if (context.isInTestFile) return true;
    
    // Safe if in documentation
    if (context.isInDocumentation) return true;
    
    // Safe if in development context
    if (context.isInDevelopment) return true;
    
    // Safe if using data protection keywords
    if (this.falsePositivePatterns.some(pattern => pattern.test(context.surroundingCode))) {
      return true;
    }
    
    // Safe if data protection measures are present
    if (context.hasDataProtection) return true;
    
    // Safe if in protected environment
    if (context.isProtectedEnvironment) return true;
    
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
      'cs': 'csharp'
    };
    return languageMap[ext || ''] || 'unknown';
  }

  private detectFramework(content: string, language: string): string | undefined {
    if (language === 'javascript' || language === 'typescript') {
      if (content.includes('openai') || content.includes('OpenAI')) return 'openai';
      if (content.includes('anthropic') || content.includes('Anthropic')) return 'anthropic';
      if (content.includes('langchain') || content.includes('LangChain')) return 'langchain';
      if (content.includes('transformers') || content.includes('Transformers')) return 'transformers';
    }
    if (language === 'python') {
      if (content.includes('openai') || content.includes('OpenAI')) return 'openai';
      if (content.includes('anthropic') || content.includes('Anthropic')) return 'anthropic';
      if (content.includes('langchain') || content.includes('LangChain')) return 'langchain';
      if (content.includes('transformers') || content.includes('Transformers')) return 'transformers';
      if (content.includes('pandas') || content.includes('Pandas')) return 'pandas';
      if (content.includes('numpy') || content.includes('NumPy')) return 'numpy';
    }
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

  private isInTestFile(filePath: string): boolean {
    return filePath.includes('test') || filePath.includes('spec') || filePath.includes('mock');
  }

  private isInDocumentation(filePath: string): boolean {
    const docPatterns = [
      /docs?\//i,
      /documentation/i,
      /examples?/i,
      /samples?/i,
      /tutorials?/i,
      /guides?/i,
      /readme/i,
      /\.md$/i,
      /\.rst$/i,
      /\.txt$/i
    ];
    return docPatterns.some(pattern => pattern.test(filePath));
  }

  private isInDevelopment(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('development') || 
      line.includes('dev') ||
      line.includes('staging') ||
      line.includes('localhost') ||
      line.includes('127.0.0.1') ||
      line.includes('NODE_ENV') ||
      line.includes('DEBUG')
    );
  }

  private hasDataProtection(content: string): boolean {
    const protectionPatterns = [
      /encrypt/i,
      /protect/i,
      /secure/i,
      /filter/i,
      /sanitize/i,
      /anonymize/i,
      /mask/i,
      /redact/i,
      /dlp/i,
      /data[_-]?loss[_-]?prevention/i,
      /privacy/i,
      /gdpr/i,
      /compliance/i
    ];
    return protectionPatterns.some(pattern => pattern.test(content));
  }

  private isProtectedEnvironment(content: string): boolean {
    const protectedPatterns = [
      /sandbox/i,
      /isolated/i,
      /contained/i,
      /restricted/i,
      /monitored/i,
      /audited/i,
      /logged/i,
      /safe/i,
      /protected/i
    ];
    return protectedPatterns.some(pattern => pattern.test(content));
  }

  private calculateConfidence(baseConfidence: number, context: DataLeakageContext): number {
    let confidence = baseConfidence;
    
    // Adjust confidence based on context
    if (context.hasDataProtection) confidence *= 0.6; // Reduce if data protection present
    if (context.isProtectedEnvironment) confidence *= 0.7; // Reduce if in protected environment
    if (context.framework) confidence *= 1.1; // Increase for known frameworks
    
    return Math.min(confidence, 1.0);
  }

  // Validation methods for different data leakage issues
  private validateTrainingDataExposure(text: string): boolean {
    const trainingKeywords = ['training', 'dataset', 'corpus'];
    const exposureKeywords = ['expose', 'leak', 'public', 'unrestricted'];
    return trainingKeywords.some(training => text.toLowerCase().includes(training)) &&
           exposureKeywords.some(exposure => text.toLowerCase().includes(exposure));
  }

  private validateSensitiveTrainingData(text: string): boolean {
    const sensitiveKeywords = ['sensitive', 'confidential', 'proprietary'];
    const trainingKeywords = ['training', 'dataset', 'corpus'];
    return sensitiveKeywords.some(sensitive => text.toLowerCase().includes(sensitive)) &&
           trainingKeywords.some(training => text.toLowerCase().includes(training));
  }

  private validateSensitiveOutput(text: string): boolean {
    const aiKeywords = ['model', 'ai', 'llm'];
    const outputKeywords = ['output', 'response', 'generation'];
    const sensitiveKeywords = ['sensitive', 'confidential', 'proprietary'];
    return aiKeywords.some(ai => text.toLowerCase().includes(ai)) &&
           outputKeywords.some(output => text.toLowerCase().includes(output)) &&
           sensitiveKeywords.some(sensitive => text.toLowerCase().includes(sensitive));
  }

  private validateUnfilteredOutput(text: string): boolean {
    const aiKeywords = ['ai', 'model', 'llm'];
    const unfilteredKeywords = ['unfiltered', 'unrestricted', 'raw'];
    const outputKeywords = ['output', 'response'];
    return aiKeywords.some(ai => text.toLowerCase().includes(ai)) &&
           unfilteredKeywords.some(unfiltered => text.toLowerCase().includes(unfiltered)) &&
           outputKeywords.some(output => text.toLowerCase().includes(output));
  }

  private validateClassificationBypass(text: string): boolean {
    const bypassKeywords = ['bypass', 'ignore', 'skip'];
    const classificationKeywords = ['classification', 'label', 'sensitivity'];
    return bypassKeywords.some(bypass => text.toLowerCase().includes(bypass)) &&
           classificationKeywords.some(classification => text.toLowerCase().includes(classification));
  }

  private validateSensitiveModel(text: string): boolean {
    const modelKeywords = ['model', 'weights', 'parameters'];
    const containKeywords = ['contain', 'include', 'embed'];
    const sensitiveKeywords = ['sensitive', 'confidential'];
    return modelKeywords.some(model => text.toLowerCase().includes(model)) &&
           containKeywords.some(contain => text.toLowerCase().includes(contain)) &&
           sensitiveKeywords.some(sensitive => text.toLowerCase().includes(sensitive));
  }

  private validateUnencryptedArtifacts(text: string): boolean {
    const artifactKeywords = ['model', 'weights', 'artifacts'];
    const unencryptedKeywords = ['unencrypted', 'plaintext', 'raw'];
    return artifactKeywords.some(artifact => text.toLowerCase().includes(artifact)) &&
           unencryptedKeywords.some(unencrypted => text.toLowerCase().includes(unencrypted));
  }

  private validateSensitiveLogging(text: string): boolean {
    const loggingKeywords = ['log', 'console', 'print', 'echo'];
    const sensitiveKeywords = ['sensitive', 'confidential', 'proprietary', 'personal'];
    return loggingKeywords.some(logging => text.toLowerCase().includes(logging)) &&
           sensitiveKeywords.some(sensitive => text.toLowerCase().includes(sensitive));
  }

  private validateUnfilteredExport(text: string): boolean {
    const exportKeywords = ['export', 'save', 'write'];
    const unfilteredKeywords = ['all', 'complete', 'full'];
    const dataKeywords = ['data', 'dataset'];
    return exportKeywords.some(exportKeyword => text.toLowerCase().includes(exportKeyword)) &&
           unfilteredKeywords.some(unfiltered => text.toLowerCase().includes(unfiltered)) &&
           dataKeywords.some(data => text.toLowerCase().includes(data));
  }

  private validateUnsanitizedResponse(text: string): boolean {
    const responseKeywords = ['api', 'response', 'return'];
    const unsanitizedKeywords = ['raw', 'unfiltered', 'complete'];
    const dataKeywords = ['data', 'result'];
    return responseKeywords.some(response => text.toLowerCase().includes(response)) &&
           unsanitizedKeywords.some(unsanitized => text.toLowerCase().includes(unsanitized)) &&
           dataKeywords.some(data => text.toLowerCase().includes(data));
  }

  private getLineContext(lineContent: string, column: number): string {
    const start = Math.max(0, column - 20);
    const end = Math.min(lineContent.length, column + 20);
    return lineContent.substring(start, end).trim();
  }

  private generateSuggestion(type: string, context: DataLeakageContext): string {
    const suggestions = {
      'Training Data Exposure': 'Implement data access controls and encryption for training data. Use secure data storage and access logging.',
      'Sensitive Training Data': 'Apply data classification and encryption to sensitive training data. Use secure data pipelines and access controls.',
      'Sensitive Data in AI Output': 'Implement output filtering and content moderation. Use data loss prevention (DLP) tools to detect and block sensitive data.',
      'Unfiltered AI Output': 'Implement content filtering and output sanitization. Use AI safety measures and content moderation.',
      'Data Classification Bypass': 'Enforce mandatory data classification. Implement automated classification and prevent bypass mechanisms.',
      'Sensitive Data in Model': 'Implement model security measures. Use model encryption and secure model deployment practices.',
      'Unencrypted AI Artifacts': 'Encrypt AI models and artifacts. Use secure model storage and transmission protocols.',
      'Sensitive Data Logging': 'Implement secure logging practices. Use log encryption and sensitive data masking.',
      'Unfiltered Data Export': 'Implement data export controls and filtering. Use data anonymization and access controls.',
      'Unsanitized API Response': 'Implement API response sanitization. Use content filtering and data validation.'
    };
    
    let suggestion = suggestions[type as keyof typeof suggestions] || 'Implement data loss prevention (DLP) policies. Use sensitivity labels, output filtering, and encryption for AI artifacts. Monitor AI outputs for sensitive data exposure.';
    
    if (context.framework) {
      suggestion += ` For ${context.framework}, consider using framework-specific data protection features.`;
      
      if (context.framework === 'openai') {
        suggestion += ' Use OpenAI content filtering and data handling best practices.';
      } else if (context.framework === 'anthropic') {
        suggestion += ' Use Anthropic safety features and data protection measures.';
      } else if (context.framework === 'langchain') {
        suggestion += ' Use LangChain data protection and output filtering capabilities.';
      } else if (context.framework === 'pandas') {
        suggestion += ' Use Pandas data anonymization and filtering functions.';
      }
    }
    
    return suggestion;
  }
}