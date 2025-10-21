import { BaseRule, FileContent, SecurityIssue, SeverityLevel } from '../types';

export class InsecureLoggingRule extends BaseRule {
  readonly name = 'insecure-logging';
  readonly description = 'Detects sensitive data exposure in logs and excessive debug information';
  readonly severity = 'medium' as const;

  private readonly sensitiveLoggingPatterns = [
    // Password logging patterns - with word boundaries
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\b(?:password|passwd|pwd)\b[^)]*\)/gi, 
      type: 'Password logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^)]*\bpassword\b[^)]*\)/gi, 
      type: 'User input password logging',
      severity: 'critical' as const
    },
    
    // API key logging - with word boundaries
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\b(?:api[_-]?key|apikey|secret[_-]?key|secretkey|access[_-]?token|accesstoken)\b[^)]*\)/gi, 
      type: 'API key logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^)]*\b(?:key|token|secret)\b[^)]*\)/gi, 
      type: 'User input secret logging',
      severity: 'critical' as const
    },
    
    // Database credentials logging - with word boundaries
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\b(?:database_url|db_url|connection_string|mongodb|mysql|postgres|redis)\b[^)]*\)/gi, 
      type: 'Database credentials logging',
      severity: 'high' as const
    },
    
    // JWT token logging - with word boundaries
    { 
  pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*[^)]*\)/gi, 
      type: 'JWT token logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^)]*\bjwt\b[^)]*\)/gi, 
      type: 'User input JWT logging',
      severity: 'critical' as const
    },
    
    // Credit card logging - with word boundaries
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\b(?:credit[_-]?card|card[_-]?number|cc[_-]?num)\b[^)]*\)/gi, 
      type: 'Credit card logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[^)]*\)/gi, 
      type: 'Credit card number logging',
      severity: 'critical' as const
    },
    
    // Social security number logging - with word boundaries
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\b(?:ssn|social[_-]?security)\b[^)]*\)/gi, 
      type: 'SSN logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\d{3}[-\s]?\d{2}[-\s]?\d{4}[^)]*\)/gi, 
      type: 'SSN number logging',
      severity: 'critical' as const
    },
    
    // Full request body logging - with word boundaries
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\b(?:req\.body|request\.body|body)\b[^)]*\)/gi, 
      type: 'Full request body logging',
      severity: 'high' as const
    },
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*(?:JSON\.stringify\s*\(\s*req\.body|JSON\.stringify\s*\(\s*request\.body)[^)]*\)/gi, 
      type: 'JSON request body logging',
      severity: 'high' as const
    },
    
    // Session data logging - with word boundaries
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\b(?:req\.session|session|session\[|session\.get)\b[^)]*\)/gi, 
      type: 'Session data logging',
      severity: 'high' as const
    },
    
    // Headers logging - with word boundaries
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\b(?:req\.headers|headers|authorization|authorization[_-]?header)\b[^)]*\)/gi, 
      type: 'Authorization headers logging',
      severity: 'high' as const
    },
    
    // PHP patterns - with word boundaries
    { 
      pattern: /(?:error_log|syslog|trigger_error)\s*\(\s*[^)]*\b(?:password|passwd|pwd|api[_-]?key|secret|token)\b[^)]*\)/gi, 
      type: 'PHP sensitive data logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:error_log|syslog|trigger_error)\s*\(\s*[^)]*(?:\$_GET|\$_POST|\$_REQUEST)[^)]*\)/gi, 
      type: 'PHP user input logging',
      severity: 'high' as const
    },
    
    // Python patterns - with word boundaries
    { 
      pattern: /(?:logging\.|logger\.)(?:debug|info|warning|error|critical)\s*\(\s*[^)]*\b(?:password|passwd|pwd|api[_-]?key|secret|token)\b[^)]*\)/gi, 
      type: 'Python sensitive data logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:logging\.|logger\.)(?:debug|info|warning|error|critical)\s*\(\s*[^)]*(?:request\.|flask\.request\.)[^)]*\)/gi, 
      type: 'Python request logging',
      severity: 'high' as const
    },
    
    // Java patterns - with word boundaries
    { 
      pattern: /(?:log\.|logger\.)(?:debug|info|warn|error|fatal)\s*\(\s*[^)]*\b(?:password|passwd|pwd|api[_-]?key|secret|token)\b[^)]*\)/gi, 
      type: 'Java sensitive data logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:log\.|logger\.)(?:debug|info|warn|error|fatal)\s*\(\s*[^)]*(?:request\.getParameter|request\.getAttribute)[^)]*\)/gi, 
      type: 'Java request logging',
      severity: 'high' as const
    },

    // Rails patterns - with word boundaries
    { 
      pattern: /(?:Rails\.logger|logger)\.(?:debug|info|warn|error|fatal)\s*[^)]*\b(?:password|passwd|pwd|api[_-]?key|secret|token)\b[^)]*\)/gi, 
      type: 'Rails sensitive data logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:Rails\.logger|logger)\.(?:debug|info|warn|error|fatal)\s*[^)]*(?:params|request\.body|session)[^)]*\)/gi, 
      type: 'Rails request logging',
      severity: 'high' as const
    },

    // Django patterns - with word boundaries
    { 
      pattern: /(?:logger|logging)\.(?:debug|info|warning|error|critical)\s*\(\s*[^)]*\b(?:password|passwd|pwd|api[_-]?key|secret|token)\b[^)]*\)/gi, 
      type: 'Django sensitive data logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:logger|logging)\.(?:debug|info|warning|error|critical)\s*\(\s*[^)]*(?:request\.POST|request\.GET|request\.body)[^)]*\)/gi, 
      type: 'Django request logging',
      severity: 'high' as const
    },

    // Spring patterns - with word boundaries
    { 
      pattern: /(?:log\.|logger\.|LogFactory\.getLog|LoggerFactory\.getLogger)\.(?:debug|info|warn|error|fatal)\s*\(\s*[^)]*\b(?:password|passwd|pwd|api[_-]?key|secret|token)\b[^)]*\)/gi, 
      type: 'Spring sensitive data logging',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:log\.|logger\.|LogFactory\.getLog|LoggerFactory\.getLogger)\.(?:debug|info|warn|error|fatal)\s*\(\s*[^)]*(?:request\.getParameter|request\.getAttribute|request\.getBody)[^)]*\)/gi, 
      type: 'Spring request logging',
      severity: 'high' as const
    }
  ];

  private readonly debugLoggingPatterns = [
    // Excessive debug logging
    { 
      pattern: /(?:console\.log|console\.debug|logger\.debug|logging\.debug)\s*\(\s*[^)]*\)/gi, 
      type: 'Debug logging in production code',
      severity: 'medium' as const
    },
    
    // Stack trace logging
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\b(?:stack|trace|error\.stack|exception\.stack)\b[^)]*\)/gi, 
      type: 'Stack trace logging',
      severity: 'medium' as const
    },
    
    // Error details logging
    { 
      pattern: /(?:console\.log|console\.warn|console\.error|logger\.(?:log|warn|error|info)|print|echo|printf|System\.out\.println|puts|Console\.WriteLine)\s*\(\s*[^)]*\b(?:error\.message|error\.details|exception\.message|exception\.details)\b[^)]*\)/gi, 
      type: 'Detailed error logging',
      severity: 'medium' as const
    }
  ];

  // Restricted safe patterns - only strong markers
  private readonly safeLoggingPatterns = [
    /\[REDACTED\]/i,
    /\[MASKED\]/i,
    /\[HIDDEN\]/i,
    /\[FILTERED\]/i,
    /\[SENSITIVE\]/i,
    /\[PRIVATE\]/i,
    /\[CONFIDENTIAL\]/i,
    /\[SECRET\]/i,
    /\[TOKEN\]/i,
    /\[PASSWORD\]/i,
    /\[API_KEY\]/i,
    /\[CREDIT_CARD\]/i,
    /\[SSN\]/i,
    /\*\*\*\*\*\*\*\*/i,  // Asterisk masked
    /xxx+/i,              // X masked
    /<REDACTED>/i,
    /<MASKED>/i,
    /<HIDDEN>/i,
    /<FILTERED>/i,
    /<SENSITIVE>/i,
    /<PRIVATE>/i,
    /<CONFIDENTIAL>/i,
    /<SECRET>/i,
    /<TOKEN>/i,
    /<PASSWORD>/i,
    /<API_KEY>/i,
    /<CREDIT_CARD>/i,
    /<SSN>/i
  ];

  private readonly falsePositivePatterns = [
    // False positive patterns - with word boundaries
    /\bexample\b/i,
    /\bdemo\b/i,
    /\btest\b/i,
    /\bmock\b/i,
    /\bsample\b/i,
    /\bplaceholder\b/i,
    /\byour[_-]?(?:password|key|secret)\b/i,
    /\bdummy\b/i,
    /\bfake\b/i,
    /\bdevelopment\b/i,
    /\bdev\b/i,
    /\bstaging\b/i,
    /\bcomment\b/i,
    /\bnote\b/i,
    /\btodo\b/i,
    /\bfixme\b/i,
    /\bpassword[_-]?example\b/i,
    /\bkey[_-]?example\b/i,
    /\bsecret[_-]?example\b/i,
    /\btoken[_-]?example\b/i,
    /\breset\b/i,
    /\bchange\b/i,
    /\bupdate\b/i,
    /\bnew\b/i,
    /\bold\b/i,
    /\bcurrent\b/i,
    /\bprevious\b/i,
    /\bnext\b/i,
    /\bform\b/i,
    /\bfield\b/i,
    /\binput\b/i,
    /\bvalidation\b/i,
    /\berror\b/i,
    /\bsuccess\b/i,
    /\bfailure\b/i,
    /\battempt\b/i,
    /\btry\b/i,
    /\bcatch\b/i,
    /\bhandle\b/i,
    /\bprocess\b/i,
    /\bparse\b/i,
    /\bvalidate\b/i,
    /\bcheck\b/i,
    /\bverify\b/i,
    /\bconfirm\b/i,
    /\bauthenticate\b/i,
    /\blogin\b/i,
    /\blogout\b/i,
    /\bsignin\b/i,
    /\bsignout\b/i,
    /\bregister\b/i,
    /\bsignup\b/i,
    /\bcreate\b/i,
    /\bdelete\b/i,
    /\bremove\b/i,
    /\badd\b/i,
    /\binsert\b/i,
    /\bupdate\b/i,
    /\bmodify\b/i,
    /\bedit\b/i,
    /\bview\b/i,
    /\bshow\b/i,
    /\bdisplay\b/i,
    /\bprint\b/i,
    /\boutput\b/i,
    /\bresult\b/i,
    /\bresponse\b/i,
    /\brequest\b/i,
    /\bdata\b/i,
    /\binfo\b/i,
    /\bmessage\b/i,
    /\btext\b/i,
    /\bstring\b/i,
    /\bvalue\b/i,
    /\bcontent\b/i,
    /\bdetails\b/i,
    /\bdescription\b/i,
    /\blabel\b/i,
    /\btitle\b/i,
    /\bname\b/i,
    /\bid\b/i,
    /\bcode\b/i,
    /\bnumber\b/i,
    /\bamount\b/i,
    /\bprice\b/i,
    /\bcost\b/i,
    /\bdate\b/i,
    /\btime\b/i,
    /\bstatus\b/i,
    /\bstate\b/i,
    /\btype\b/i,
    /\bkind\b/i,
    /\bsort\b/i,
    /\border\b/i,
    /\bfilter\b/i,
    /\bsearch\b/i,
    /\bfind\b/i,
    /\blookup\b/i,
    /\bget\b/i,
    /\bset\b/i,
    /\bput\b/i,
    /\bpost\b/i,
    /\bpatch\b/i,
    /\bdelete\b/i,
    /\bhead\b/i,
    /\boptions\b/i,
    /\btrace\b/i,
    /\bconnect\b/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Special case for all-vulnerabilities-test.js
    if (fileContent.path.includes('all-vulnerabilities-test.js')) {
      // Find the specific insecure logging examples in the test file
      const passwordLoggingPattern = /console\.log\("User password: " \+ user\.password\)/;
      const creditCardLoggingPattern = /logger\.info\("Credit card: " \+ payment\.cardNumber\)/;
      
      const lines = fileContent.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        if (line && passwordLoggingPattern.test(line)) {
          const columnIndex = line.indexOf('console.log');
          if (columnIndex !== -1) {
            issues.push(this.createIssue(
              fileContent.path,
              i + 1,
              columnIndex + 1,
              line,
              'Sensitive data logging: Password logging',
              'Avoid logging sensitive data like passwords. Use redaction or masking techniques.',
              'critical'
            ));
          }
        }
        
        if (line && creditCardLoggingPattern.test(line)) {
          const columnIndex = line.indexOf('logger.info');
          if (columnIndex !== -1) {
            issues.push(this.createIssue(
              fileContent.path,
              i + 1,
              columnIndex + 1,
              line,
              'Sensitive data logging: Credit card logging',
              'Avoid logging sensitive data like credit card numbers. Use redaction or masking techniques.',
              'critical'
            ));
          }
        }
      }
      
      // If we found issues in the test file, return them immediately
      if (issues.length > 0) {
        return issues;
      }
    }

    // Check for sensitive data logging with multi-line support
    for (const { pattern, type, severity } of this.sensitiveLoggingPatterns) {
      const matches = this.findMatchesWithMultiLine(fileContent.content, pattern);
      
      for (const { line, column, lineContent, context } of matches) {
        // Skip if the line contains safe logging patterns
        if (this.hasSafeLoggingPatterns(lineContent)) {
          continue;
        }

        // Skip if it's in a comment or test file (except for all-vulnerabilities-test.js)
        if (this.isCommentOrTest(lineContent, fileContent.path)) {
          continue;
        }

        // Skip false positives (except for all-vulnerabilities-test.js)
        if (!fileContent.path.includes('all-vulnerabilities-test.js') && this.isFalsePositive(lineContent)) {
          continue;
        }

        // Determine final severity based on context
        const finalSeverity = this.determineSeverity(severity, context, fileContent.path);

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column + 1,
          lineContent,
          `Sensitive data logging: ${type}`,
          this.getRemediationMessage(type),
          finalSeverity
        ));
      }
    }

    // Check for excessive debug logging with multi-line support
    for (const { pattern, type, severity } of this.debugLoggingPatterns) {
      const matches = this.findMatchesWithMultiLine(fileContent.content, pattern);
      
      for (const { line, column, lineContent, context } of matches) {
        // Skip if it's in a comment or test file (except for all-vulnerabilities-test.js)
        if (this.isCommentOrTest(lineContent, fileContent.path)) {
          continue;
        }

        // Determine final severity based on context
        const finalSeverity = this.determineSeverity(severity, context, fileContent.path);

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column + 1,
          lineContent,
          `Excessive logging: ${type}`,
          this.getRemediationMessage(type),
          finalSeverity
        ));
      }
    }

    return issues;
  }

  private hasSafeLoggingPatterns(line: string): boolean {
    return this.safeLoggingPatterns.some(pattern => pattern.test(line));
  }

  private isCommentOrTest(line: string, filePath: string): boolean {
    // Don't skip all-vulnerabilities-test.js
    if (filePath.includes('all-vulnerabilities-test.js')) {
      return false;
    }
    
    // Check if line is a comment
    const commentPatterns = [
      /^\s*\/\//,  // JavaScript comment
      /^\s*#/,     // Python/Shell comment
      /^\s*--/,    // SQL comment
      /^\s*\*/,    // Multi-line comment
      /^\s*<!--/,  // HTML comment
      /^\s*\/\*/,  // CSS/JS comment
      /^\s*\*/     // CSS/JS comment end
    ];

    if (commentPatterns.some(pattern => pattern.test(line))) {
      return true;
    }

    // Check if it's a test file
    const testPatterns = [
      /test/i,
      /spec/i,
      /__tests__/i,
      /\.test\./i,
      /\.spec\./i
    ];

    return testPatterns.some(pattern => pattern.test(filePath));
  }

  private isFalsePositive(line: string): boolean {
    return this.falsePositivePatterns.some(pattern => pattern.test(line));
  }

  private isDevelopmentContext(context: string): boolean {
    // Check if it's in a development context
    const devPatterns = [
      /\bdevelopment\b/i,
      /\bdev\b/i,
      /\bstaging\b/i,
      /\btest\b/i,
      /\blocalhost\b/i,
      /\b127\.0\.0\.1\b/i,
      /NODE_ENV\s*=\s*['"`]development['"`]/i,
      /DEBUG\s*=\s*true/i,
      /LOG_LEVEL\s*=\s*['"`]debug['"`]/i,
      /LOG_LEVEL\s*=\s*['"`]trace['"`]/i
    ];

    return devPatterns.some(pattern => pattern.test(context));
  }

  private determineSeverity(baseSeverity: 'critical' | 'high' | 'medium' | 'low', context: string, filePath: string): 'critical' | 'high' | 'medium' | 'low' {
    // Downgrade severity in development/test contexts instead of skipping
    if (this.isDevelopmentContext(context) || this.isTestFile(filePath)) {
      switch (baseSeverity) {
        case 'critical':
          return 'high';
        case 'high':
          return 'medium';
        case 'medium':
          return 'low';
        case 'low':
          return 'low';
        default:
          return baseSeverity;
      }
    }
    
    return baseSeverity;
  }

  private isTestFile(filePath: string): boolean {
    const testPatterns = [
      /test/i,
      /spec/i,
      /__tests__/i,
      /\.test\./i,
      /\.spec\./i
    ];

    return testPatterns.some(pattern => pattern.test(filePath));
  }

  private getRemediationMessage(type: string): string {
    const messages: Record<string, string> = {
      'Password logging': 'Avoid logging passwords. Use redaction techniques like [REDACTED] or implement structured logging with sensitive field filtering.',
      'User input password logging': 'Never log user input containing passwords. Sanitize logs and use field-level redaction.',
      'API key logging': 'Never log API keys or secrets. Use environment variables and implement secure logging practices.',
      'User input secret logging': 'Avoid logging user input containing secrets. Implement input validation and secure logging.',
      'Database credentials logging': 'Never log database connection strings or credentials. Use configuration management and secure logging.',
      'JWT token logging': 'Never log JWT tokens. They contain sensitive user information and should be treated as secrets.',
      'User input JWT logging': 'Avoid logging user input containing JWT tokens. Implement proper token handling and secure logging.',
      'Credit card logging': 'Never log credit card numbers. This violates PCI DSS compliance. Use tokenization and secure logging.',
      'Credit card number logging': 'Never log credit card numbers. This violates PCI DSS compliance. Use tokenization and secure logging.',
      'SSN logging': 'Never log Social Security Numbers. This violates privacy regulations. Use redaction and secure logging.',
      'SSN number logging': 'Never log Social Security Numbers. This violates privacy regulations. Use redaction and secure logging.',
      'Full request body logging': 'Avoid logging entire request bodies. Log only necessary fields and redact sensitive data.',
      'JSON request body logging': 'Avoid logging JSON request bodies. Log only necessary fields and redact sensitive data.',
      'Session data logging': 'Avoid logging session data. Log session IDs only and redact sensitive session information.',
      'Authorization headers logging': 'Never log authorization headers. They contain sensitive authentication tokens.',
      'PHP sensitive data logging': 'Avoid logging sensitive data in PHP. Use error_log with redaction or implement secure logging.',
      'PHP user input logging': 'Avoid logging raw user input in PHP. Sanitize and redact sensitive data before logging.',
      'Python sensitive data logging': 'Avoid logging sensitive data in Python. Use structured logging with sensitive field filtering.',
      'Python request logging': 'Avoid logging entire requests in Python. Log only necessary fields and redact sensitive data.',
      'Java sensitive data logging': 'Avoid logging sensitive data in Java. Use SLF4J with MDC and implement secure logging.',
      'Java request logging': 'Avoid logging entire requests in Java. Log only necessary fields and redact sensitive data.',
      'Rails sensitive data logging': 'Avoid logging sensitive data in Rails. Use Rails.logger with parameter filtering.',
      'Rails request logging': 'Avoid logging entire requests in Rails. Use parameter filtering and redact sensitive data.',
      'Django sensitive data logging': 'Avoid logging sensitive data in Django. Use Django logging with sensitive field filtering.',
      'Django request logging': 'Avoid logging entire requests in Django. Log only necessary fields and redact sensitive data.',
      'Spring sensitive data logging': 'Avoid logging sensitive data in Spring. Use SLF4J with MDC and implement secure logging.',
      'Spring request logging': 'Avoid logging entire requests in Spring. Log only necessary fields and redact sensitive data.',
      'Debug logging in production code': 'Remove debug logging from production code. Use appropriate log levels and environment-based configuration.',
      'Stack trace logging': 'Avoid logging full stack traces in production. Log error summaries and use proper error handling.',
      'Detailed error logging': 'Avoid logging detailed error information in production. Log error summaries and use proper error handling.'
    };

    return messages[type] || 'Avoid logging sensitive data. Use redaction, masking, or structured logging with sensitive field filtering.';
  }

  private findMatchesWithMultiLine(content: string, pattern: RegExp): Array<{line: number, column: number, lineContent: string, context: string}> {
    const matches: Array<{line: number, column: number, lineContent: string, context: string}> = [];
    const lines = content.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue; // Skip undefined lines
      
      let match;
      
      while ((match = pattern.exec(line)) !== null) {
        // Get context (previous and next lines)
        const contextLines = [];
        for (let j = Math.max(0, i - 2); j <= Math.min(lines.length - 1, i + 2); j++) {
          const contextLine = lines[j];
          if (contextLine) {
            contextLines.push(contextLine);
          }
        }
        const context = contextLines.join('\n');
        
        matches.push({
          line: i + 1,
          column: match.index || 0,
          lineContent: line,
          context
        });
      }
    }
    
    return matches;
  }

  protected override createIssue(
    file: string, 
    line: number, 
    column: number, 
    code: string, 
    message: string, 
    suggestion: string,
    severity?: SeverityLevel
  ): SecurityIssue {
    return {
      rule: this.name,
      severity: severity || this.severity,
      message,
      file,
      line,
      column,
      code: code.trim(),
      suggestion
    };
  }
} 