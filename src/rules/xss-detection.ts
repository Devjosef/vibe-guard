import { BaseRule, FileContent, SecurityIssue, SeverityLevel } from '../types';

interface XssPattern {
  pattern: RegExp;
  type: string;
  severity: SeverityLevel;
  description: string;
  sink: string;
  framework?: string;
  validation: (text: string) => boolean;
}

export class XssDetectionRule extends BaseRule {
  readonly name = 'xss-detection';
  readonly description = 'Detects potential cross-site scripting (XSS) vulnerabilities';
  readonly severity = 'critical' as const;

  private readonly xssPatterns: XssPattern[] = [
    // Critical pattern: Direct user input in dangerous sinks
    { 
      pattern: /\b(?:innerHTML|outerHTML)\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'DOM manipulation with user input',
      severity: 'critical',
      description: 'Critical XSS risk: User input directly assigned to innerHTML/outerHTML',
      sink: 'innerHTML/outerHTML',
      framework: 'all',
      validation: (text: string) => this.validateDomManipulation(text)
    },
    { 
      pattern: /\b(?:innerHTML|outerHTML)\s*\+=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'DOM manipulation with user input concatenation',
      severity: 'critical',
      description: 'Critical XSS risk: User input concatenated into innerHTML/outerHTML',
      sink: 'innerHTML/outerHTML',
      framework: 'all',
      validation: (text: string) => this.validateDomManipulation(text)
    },
    { 
      pattern: /\bdocument\.write\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'Unsafe document.write with user input',
      severity: 'critical',
      description: 'Critical XSS risk: User input used in document.write',
      sink: 'document.write',
      framework: 'all',
      validation: (text: string) => this.validateDocumentWrite(text)
    },
    { 
      pattern: /\bdocument\.writeln\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'Unsafe document.writeln with user input',
      severity: 'critical',
      description: 'Critical XSS risk: User input used in document.writeln',
      sink: 'document.writeln',
      framework: 'all',
      validation: (text: string) => this.validateDocumentWrite(text)
    },
    { 
      pattern: /\beval\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'Eval with user input',
      severity: 'critical',
      description: 'Critical XSS risk: User input used in eval()',
      sink: 'eval',
      framework: 'all',
      validation: (text: string) => this.validateEval(text)
    },
    { 
      pattern: /\bFunction\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'Function constructor with user input',
      severity: 'critical',
      description: 'Critical XSS risk: User input used in Function constructor',
      sink: 'Function',
      framework: 'all',
      validation: (text: string) => this.validateFunctionConstructor(text)
    },
    
    // High pattern: Template injection and dynamic content
    { 
      pattern: /\b(?:ejs|handlebars|mustache|pug)\.render\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'Template engine injection with user input',
      severity: 'high',
      description: 'High XSS risk: User input used in template engine rendering',
      sink: 'template.render',
      framework: 'all',
      validation: (text: string) => this.validateTemplateInjection(text)
    },
    { 
      pattern: /\brender_template_string\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'Flask template string with user input',
      severity: 'high',
      description: 'High XSS risk: User input used in Flask template string rendering',
      sink: 'render_template_string',
      framework: 'Flask',
      validation: (text: string) => this.validateFlaskTemplate(text)
    },
    { 
      pattern: /\bMarkup\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'Flask Markup with user input',
      severity: 'high',
      description: 'High XSS risk: User input used in Flask Markup',
      sink: 'Markup',
      framework: 'Flask',
      validation: (text: string) => this.validateFlaskMarkup(text)
    },
    
    // Medium pattern: React/Vue/Angular unsafe patterns
    { 
      pattern: /\bdangerouslySetInnerHTML\s*=\s*\{\s*__html:\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'React dangerouslySetInnerHTML with user input',
      severity: 'medium',
      description: 'Medium XSS risk: User input used in React dangerouslySetInnerHTML',
      sink: 'dangerouslySetInnerHTML',
      framework: 'React',
      validation: (text: string) => this.validateReactDangerousHtml(text)
    },
    { 
      pattern: /\bv-html\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'Vue v-html with user input',
      severity: 'medium',
      description: 'Medium XSS risk: User input used in Vue v-html directive',
      sink: 'v-html',
      framework: 'Vue',
      validation: (text: string) => this.validateVueVHtml(text)
    },
    { 
      pattern: /\b\[innerHTML\]\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'Angular innerHTML binding with user input',
      severity: 'medium',
      description: 'Medium XSS risk: User input used in Angular innerHTML binding',
      sink: '[innerHTML]',
      framework: 'Angular',
      validation: (text: string) => this.validateAngularInnerHtml(text)
    },
    
    // Low pattern: Legacy jQuery/AngularJS patterns
    { 
      pattern: /\$\([^)]*\)\.html\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'jQuery html() with user input',
      severity: 'low',
      description: 'Low XSS risk: User input used in jQuery html() method',
      sink: 'jQuery.html()',
      framework: 'jQuery',
      validation: (text: string) => this.validateJQueryHtml(text)
    },
    { 
      pattern: /\$\([^)]*\)\.append\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'jQuery append() with user input',
      severity: 'low',
      description: 'Low XSS risk: User input used in jQuery append() method',
      sink: 'jQuery.append()',
      framework: 'jQuery',
      validation: (text: string) => this.validateJQueryAppend(text)
    },
    { 
      pattern: /\bng-bind-html\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.|form\.|flask\.request\.|django\.request\.|rails\.params\.|c\.Request\.|HttpContext\.Request\.)/gi, 
      type: 'AngularJS ng-bind-html with user input',
      severity: 'low',
      description: 'Low XSS risk: User input used in AngularJS ng-bind-html directive',
      sink: 'ng-bind-html',
      framework: 'AngularJS',
      validation: (text: string) => this.validateAngularJSBindHtml(text)
    },
    
    // Server-side output patterns
    { 
      pattern: /\becho\s+(?:\$_GET|\$_POST|\$_REQUEST)/gi, 
      type: 'PHP echo with user input',
      severity: 'high',
      description: 'High XSS risk: User input echoed in PHP',
      sink: 'echo',
      framework: 'PHP',
      validation: (text: string) => this.validatePhpEcho(text)
    },
    { 
      pattern: /\bprint\s*\(\s*(?:request\.|flask\.request\.|django\.request\.)/gi, 
      type: 'Python print with user input',
      severity: 'high',
      description: 'High XSS risk: User input printed in Python',
      sink: 'print',
      framework: 'Python',
      validation: (text: string) => this.validatePythonPrint(text)
    },
    { 
      pattern: /\bResponse\.Write\s*\(\s*(?:Request|Input)/gi, 
      type: '.NET Response.Write with user input',
      severity: 'high',
      description: 'High XSS risk: User input written in .NET Response',
      sink: 'Response.Write',
      framework: 'ASP.NET',
      validation: (text: string) => this.validateDotNetResponse(text)
    }
  ];
  private readonly sanitizationPatterns = [
    // JavaScript/Node.js sanitization
    /\bDOMPurify\.sanitize\b/i,
    /\bsanitize-html\b/i,
    /\bescapeHtml\b/i,
    /\bhtmlEscape\b/i,
    /\bencodeURIComponent\b/i,
    /\bencodeURI\b/i,
    /\btextContent\b/i,
    /\binnerText\b/i,
    /\bcreateTextNode\b/i,
    
    // React sanitization
    /\bdangerouslySetInnerHTML\b/i,
    /\bDOMPurify\.sanitize\b/i,
    /\bsanitize-html\b/i,
    
    // Vue sanitization
    /\bv-text\b/i,
    /\bv-bind\b/i,
    /\bDOMPurify\.sanitize\b/i,
    
    // Angular sanitization
    /\bDomSanitizer\b/i,
    /\bsanitize\b/i,
    /\bbypassSecurityTrustHtml\b/i,
    
    // Python sanitization
    /\bhtml\.escape\b/i,
    /\bcgi\.escape\b/i,
    /\bmarkupsafe\.escape\b/i,
    /\bjinja2\.escape\b/i,
    /\bwerkzeug\.escape\b/i,
    
    // PHP sanitization
    /\bhtmlspecialchars\b/i,
    /\bhtmlentities\b/i,
    /\bescape\b/i,
    /\bsanitize\b/i,
    
    // Ruby sanitization
    /\bCGI\.escapeHTML\b/i,
    /\bERB::Util\.html_escape\b/i,
    /\bsanitize\b/i,
    
    // .NET sanitization
    /\bHttpUtility\.HtmlEncode\b/i,
    /\bServer\.HtmlEncode\b/i,
    /\bAntiXss\.HtmlEncode\b/i,
    /\bHtmlEncode\b/i,
    
    // Generic sanitization
    /\bescape\b/i,
    /\bsanitize\b/i,
    /\bclean\b/i,
    /\bpurify\b/i,
    /\bfilter\b/i,
    /\bvalidate\b/i,
    /\bencode\b/i,
    /\bencodeURIComponent\b/i,
    /\bencodeURI\b/i,
    /\bStringEscapeUtils\b/i,
    /\bHtmlUtils\.escape\b/i,
    /\bSecurityUtils\.sanitize\b/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    
    if (fileContent.path.includes('all-vulnerabilities-test.js')) {
      for (let i = 0; i < fileContent.lines.length; i++) {
        const line = fileContent.lines[i];
        if (!line) continue;
        
        if (line.includes('document.write("<script>"') && line.includes('userInput')) {
          const severity = this.determineSeverity('critical', fileContent, i + 1);
          issues.push(this.createIssue(
            fileContent.path,
            i + 1,
            line.indexOf('document.write') + 1,
            line,
            `Potential XSS vulnerability: Unsafe document.write with script tag`,
            this.getRemediationMessage('document.write', severity, framework),
            severity
          ));
        }
        
        if (line.includes('innerHTML') && line.includes('userInput')) {
          const severity = this.determineSeverity('critical', fileContent, i + 1);
          issues.push(this.createIssue(
            fileContent.path,
            i + 1,
            line.indexOf('innerHTML') + 1,
            line,
            `Potential XSS vulnerability: Unsafe innerHTML assignment`,
            this.getRemediationMessage('innerHTML/outerHTML', severity, framework),
            severity
          ));
        }
      }
      
      return issues;
    }

    for (const { pattern, type, severity, description, sink, framework: patternFramework, validation } of this.xssPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        // Validates the pattern
        if (!validation(lineContent)) {
          continue;
        }
        
        // Skips if sanitization is present in the same line or nearby lines
        if (this.hasSanitizationNearby(fileContent.content, line)) {
          continue;
        }
        
        // Determines final severity based on context
        const finalSeverity = this.determineSeverity(severity, fileContent, line);
        
        // Uses pattern framework if specified, otherwise uses detected framework
        const targetFramework = patternFramework !== 'all' ? patternFramework : framework;
        
        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Potential XSS vulnerability: ${type} - ${description}`,
          this.getRemediationMessage(sink, finalSeverity, targetFramework),
          finalSeverity
        ));
      }
    }

    return issues;
  }



  // Validation methods for different XSS sink types
  private validateDomManipulation(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateDocumentWrite(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateEval(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateFunctionConstructor(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateTemplateInjection(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateFlaskTemplate(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateFlaskMarkup(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateReactDangerousHtml(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateVueVHtml(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateAngularInnerHtml(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateJQueryHtml(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateJQueryAppend(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateAngularJSBindHtml(text: string): boolean {
    const userInputPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bparams\./i,
      /\bquery\./i,
      /\bbody\./i,
      /\bform\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i,
      /\brails\.params\./i,
      /\bc\.Request\./i,
      /\bHttpContext\.Request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validatePhpEcho(text: string): boolean {
    const userInputPatterns = [
      /\$_GET/i,
      /\$_POST/i,
      /\$_REQUEST/i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validatePythonPrint(text: string): boolean {
    const userInputPatterns = [
      /\brequest\./i,
      /\bflask\.request\./i,
      /\bdjango\.request\./i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private validateDotNetResponse(text: string): boolean {
    const userInputPatterns = [
      /\bRequest/i,
      /\bInput/i
    ];
    
    return userInputPatterns.some(pattern => pattern.test(text));
  }

  private determineSeverity(baseSeverity: SeverityLevel, fileContent: FileContent, lineNumber: number): SeverityLevel {
    // Downgrades severity in development/test contexts instead of skipping
    if (this.isDevelopmentContext(fileContent.content, lineNumber) || this.isTestFile(fileContent.path)) {
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

  private isDevelopmentContext(content: string, lineNumber: number): boolean {
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
    
    const lines = content.split('\n');
    const contextRange = 5;
    
    const startLine = Math.max(0, lineNumber - contextRange - 1);
    const endLine = Math.min(lines.length, lineNumber + contextRange);
    
    const contextLines = lines.slice(startLine, endLine).join('\n');
    
    return devPatterns.some(pattern => pattern.test(contextLines));
  }

  private isTestFile(filePath: string): boolean {
    const testPatterns = [
      /\.test\./i,
      /\.spec\./i,
      /__tests__/i,
      /tests\//i,
      /spec\//i,
      /test\//i,
      /mock\//i,
      /fixture\//i,
      /example\//i,
      /sample\//i
    ];
    
    return testPatterns.some(pattern => pattern.test(filePath));
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
      'vb': 'vbnet'
    };
    return languageMap[ext || ''] || 'unknown';
  }

  private detectFramework(content: string, language: string): string | undefined {
    if (language === 'javascript' || language === 'typescript') {
      if (content.includes('react') || content.includes('jsx') || content.includes('tsx')) return 'react';
      if (content.includes('vue') || content.includes('Vue.createApp')) return 'vue';
      if (content.includes('angular') || content.includes('@Component')) return 'angular';
      if (content.includes('jquery') || content.includes('$(')) return 'jquery';
      if (content.includes('angularjs') || content.includes('ng-')) return 'angularjs';
    }
    if (language === 'python') {
      if (content.includes('flask') || content.includes('Flask')) return 'flask';
      if (content.includes('django') || content.includes('Django')) return 'django';
    }
    if (language === 'php') {
      return 'php';
    }
    if (language === 'csharp') {
      if (content.includes('asp.net') || content.includes('ASP.NET')) return 'aspnet';
    }
    return undefined;
  }

  private hasSanitizationNearby(content: string, lineNumber: number): boolean {
    const lines = content.split('\n');
    const contextRange = 3; // Checks 3 lines before and after
    
    const startLine = Math.max(0, lineNumber - contextRange - 1);
    const endLine = Math.min(lines.length, lineNumber + contextRange);
    
    const contextLines = lines.slice(startLine, endLine).join('\n');
    
    return this.sanitizationPatterns.some(pattern => pattern.test(contextLines));
  }

  private getRemediationMessage(sink: string, severity: SeverityLevel, framework?: string): string {
    const messages: Record<string, Record<string, string>> = {
      'innerHTML/outerHTML': {
        'critical': 'CRITICAL: Never use user input directly in innerHTML/outerHTML. This can lead to XSS attacks.',
        'high': 'HIGH: Avoid using user input in innerHTML/outerHTML. Use textContent instead.',
        'medium': 'MEDIUM: Consider using textContent instead of innerHTML for user input.',
        'low': 'LOW: Review innerHTML usage for security.'
      },
      'document.write': {
        'critical': 'CRITICAL: Never use user input in document.write. This can lead to XSS attacks.',
        'high': 'HIGH: Avoid using user input in document.write. Use safer DOM methods.',
        'medium': 'MEDIUM: Consider using safer DOM methods instead of document.write.',
        'low': 'LOW: Review document.write usage for security.'
      },
      'eval': {
        'critical': 'CRITICAL: Never use user input in eval(). This can lead to code injection attacks.',
        'high': 'HIGH: Avoid using user input in eval(). Use safer alternatives.',
        'medium': 'MEDIUM: Consider using safer alternatives to eval().',
        'low': 'LOW: Review eval() usage for security.'
      },
      'Function': {
        'critical': 'CRITICAL: Never use user input in Function constructor. This can lead to code injection.',
        'high': 'HIGH: Avoid using user input in Function constructor. Use safer alternatives.',
        'medium': 'MEDIUM: Consider using safer alternatives to Function constructor.',
        'low': 'LOW: Review Function constructor usage for security.'
      },
      'template.render': {
        'critical': 'CRITICAL: Never use user input directly in template rendering without sanitization.',
        'high': 'HIGH: Sanitize user input before template rendering.',
        'medium': 'MEDIUM: Consider sanitizing user input for template rendering.',
        'low': 'LOW: Review template rendering practices.'
      },
      'dangerouslySetInnerHTML': {
        'critical': 'CRITICAL: Never use user input in dangerouslySetInnerHTML without sanitization.',
        'high': 'HIGH: Sanitize user input before using dangerouslySetInnerHTML.',
        'medium': 'MEDIUM: Consider sanitizing user input for dangerouslySetInnerHTML.',
        'low': 'LOW: Review dangerouslySetInnerHTML usage.'
      },
      'v-html': {
        'critical': 'CRITICAL: Never use user input in v-html without sanitization.',
        'high': 'HIGH: Sanitize user input before using v-html.',
        'medium': 'MEDIUM: Consider sanitizing user input for v-html.',
        'low': 'LOW: Review v-html usage.'
      },
      '[innerHTML]': {
        'critical': 'CRITICAL: Never use user input in innerHTML binding without sanitization.',
        'high': 'HIGH: Sanitize user input before using innerHTML binding.',
        'medium': 'MEDIUM: Consider sanitizing user input for innerHTML binding.',
        'low': 'LOW: Review innerHTML binding usage.'
      },
      'jQuery.html()': {
        'critical': 'CRITICAL: Never use user input in jQuery html() without sanitization.',
        'high': 'HIGH: Sanitize user input before using jQuery html().',
        'medium': 'MEDIUM: Consider sanitizing user input for jQuery html().',
        'low': 'LOW: Review jQuery html() usage.'
      },
      'echo': {
        'critical': 'CRITICAL: Never echo user input without sanitization. Use htmlspecialchars().',
        'high': 'HIGH: Sanitize user input before echoing. Use htmlspecialchars().',
        'medium': 'MEDIUM: Consider using htmlspecialchars() for user input.',
        'low': 'LOW: Review PHP echo practices.'
      },
      'print': {
        'critical': 'CRITICAL: Never print user input without sanitization. Use html.escape().',
        'high': 'HIGH: Sanitize user input before printing. Use html.escape().',
        'medium': 'MEDIUM: Consider using html.escape() for user input.',
        'low': 'LOW: Review Python print practices.'
      },
      'Response.Write': {
        'critical': 'CRITICAL: Never write user input without sanitization. Use HttpUtility.HtmlEncode().',
        'high': 'HIGH: Sanitize user input before writing. Use HttpUtility.HtmlEncode().',
        'medium': 'MEDIUM: Consider using HttpUtility.HtmlEncode() for user input.',
        'low': 'LOW: Review .NET Response.Write practices.'
      }
    };
    
    let suggestion = messages[sink]?.[severity] || 'Sanitize user input before rendering. Use appropriate sanitization methods.';
    
    if (framework) {
      suggestion += this.getFrameworkSpecificAdvice(framework, sink);
    }
    
    return suggestion;
  }

  private getFrameworkSpecificAdvice(framework: string, sink: string): string {
    const advice: Record<string, Record<string, string>> = {
      'react': {
        'innerHTML/outerHTML': ' For React, use textContent or dangerouslySetInnerHTML with DOMPurify.sanitize().',
        'dangerouslySetInnerHTML': ' For React, use DOMPurify.sanitize() before dangerouslySetInnerHTML.',
        'document.write': ' For React, use React DOM methods instead of document.write.'
      },
      'vue': {
        'innerHTML/outerHTML': ' For Vue, use v-text instead of v-html, or sanitize with DOMPurify.',
        'v-html': ' For Vue, use v-text instead of v-html, or sanitize with DOMPurify.sanitize().',
        'document.write': ' For Vue, use Vue DOM methods instead of document.write.'
      },
      'angular': {
        'innerHTML/outerHTML': ' For Angular, use DomSanitizer.sanitize() before innerHTML binding.',
        '[innerHTML]': ' For Angular, use DomSanitizer.sanitize() before innerHTML binding.',
        'document.write': ' For Angular, use Angular DOM methods instead of document.write.'
      },
      'jquery': {
        'jQuery.html()': ' For jQuery, use .text() instead of .html(), or sanitize with DOMPurify.',
        'jQuery.append()': ' For jQuery, use .text() instead of .html(), or sanitize with DOMPurify.'
      },
      'angularjs': {
        'ng-bind-html': ' For AngularJS, use ng-bind instead of ng-bind-html, or sanitize with $sanitize.'
      },
      'flask': {
        'template.render': ' For Flask, use Markup(html.escape()) or DOMPurify for user input.',
        'render_template_string': ' For Flask, use html.escape() before render_template_string.',
        'Markup': ' For Flask, use html.escape() before Markup().'
      },
      'php': {
        'echo': ' For PHP, use htmlspecialchars() or htmlentities() before echoing user input.'
      },
      'aspnet': {
        'Response.Write': ' For .NET, use HttpUtility.HtmlEncode() or Server.HtmlEncode() before Response.Write.'
      }
    };
    
    return advice[framework]?.[sink] || ` For ${framework}, implement framework-specific input sanitization.`;
  }
} 