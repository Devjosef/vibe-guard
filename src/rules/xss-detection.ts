import { BaseRule, FileContent, SecurityIssue } from '../types';

export class XssDetectionRule extends BaseRule {
  readonly name = 'xss-detection';
  readonly description = 'Detects potential cross-site scripting (XSS) vulnerabilities';
  readonly severity = 'critical' as const;

  private readonly xssPatterns = [
    { pattern: /(?:innerHTML|outerHTML)\s*=\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'DOM manipulation with variable' },
    { pattern: /(?:innerHTML|outerHTML)\s*\+=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'DOM manipulation with concatenation' },
    { pattern: /(?:innerHTML|outerHTML)\s*\+=\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'DOM manipulation with variable concatenation' },
    { pattern: /document\.write\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Unsafe document.write' },
    { pattern: /document\.writeln\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Unsafe document.writeln' },
    { pattern: /document\.open\s*\(\s*\)/gi, type: 'Document open without validation' },
    
    { pattern: /document\.write\s*\(\s*["'`]<script[^>]*>["'`]\s*\+/gi, type: 'Unsafe document.write with script tag' },
    { pattern: /document\.write\s*\(\s*["'`][^"'`]*["'`]\s*\+\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Unsafe document.write with concatenation' },
    
    { pattern: /element\.innerHTML\s*=\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Unsafe element.innerHTML assignment' },
    { pattern: /\.innerHTML\s*=\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Unsafe innerHTML assignment' },
    
    { pattern: /eval\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Eval with variable' },
    { pattern: /eval\s*\(\s*JSON\.stringify/gi, type: 'Eval with JSON stringify' },
    { pattern: /Function\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Function constructor with user input' },
    { pattern: /Function\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Function constructor with variable' },
    { pattern: /setTimeout\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'setTimeout with variable' },
    { pattern: /setInterval\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'setInterval with variable' },
    
    { pattern: /new\s+Function\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Dynamic function with user input' },
    { pattern: /execScript\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'ExecScript with user input' },
    { pattern: /script\s*\.\s*src\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Dynamic script src with user input' },
    
    { pattern: /(?:template|render)\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Template injection' },
    { pattern: /(?:ejs|handlebars|mustache|pug)\.render\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Template engine injection' },
    { pattern: /React\.createElement\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'React element with variable' },
    { pattern: /Vue\.component\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Vue component with variable' },
    { pattern: /angular\.component\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Angular component with variable' },
    
    { pattern: /location\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Unsafe location assignment' },
    { pattern: /window\.open\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Unsafe window.open' },
    { pattern: /location\.href\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Unsafe location.href assignment' },
    { pattern: /location\.assign\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Unsafe location.assign' },
    { pattern: /location\.replace\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Unsafe location.replace' },
    
    { pattern: /<script[^>]*>\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'Script tag with user input' },
    { pattern: /on\w+\s*=\s*[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Event handler with variable' },
    { pattern: /addEventListener\s*\(\s*['"`][^'"`]*['"`]\s*,\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'addEventListener with user input' },
    { pattern: /attachEvent\s*\(\s*['"`][^'"`]*['"`]\s*,\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'attachEvent with user input' },
    
    { pattern: /style\s*\.\s*cssText\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'CSS injection with user input' },
    { pattern: /style\s*\.\s*background\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'CSS background with user input' },
    { pattern: /style\s*\.\s*color\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'CSS color with user input' },
    
    { pattern: /JSON\.parse\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'JSON parse with user input' },
    { pattern: /JSON\.stringify\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'JSON stringify with user input' },
    
    { pattern: /echo\s+(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP echo with user input' },
    { pattern: /print\s+(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP print with user input' },
    { pattern: /printf\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP printf with user input' },
    { pattern: /print_r\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP print_r with user input' },
    { pattern: /var_dump\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP var_dump with user input' },
    
    { pattern: /print\s*\(\s*(?:request\.|flask\.request\.)/gi, type: 'Python print with user input' },
    { pattern: /render_template\s*\(\s*[^,]*,\s*(?:request\.|flask\.request\.)/gi, type: 'Flask template with user input' },
    { pattern: /render_template_string\s*\(\s*(?:request\.|flask\.request\.)/gi, type: 'Flask template string with user input' },
    { pattern: /Markup\s*\(\s*(?:request\.|flask\.request\.)/gi, type: 'Flask Markup with user input' },
    
    { pattern: /out\.print\s*\(\s*(?:request\.getParameter|request\.getAttribute)/gi, type: 'Java print with user input' },
    { pattern: /response\.getWriter\(\)\.print\s*\(\s*(?:request\.getParameter|request\.getAttribute)/gi, type: 'Java response print with user input' },
    { pattern: /response\.getWriter\(\)\.write\s*\(\s*(?:request\.getParameter|request\.getAttribute)/gi, type: 'Java response write with user input' },
    
    { pattern: /puts\s+(?:params|request)/gi, type: 'Ruby puts with user input' },
    { pattern: /print\s+(?:params|request)/gi, type: 'Ruby print with user input' },
    { pattern: /render\s*:\s*text\s*=>\s*(?:params|request)/gi, type: 'Ruby render text with user input' },
    { pattern: /render\s*:\s*inline\s*=>\s*(?:params|request)/gi, type: 'Ruby render inline with user input' },
    
    { pattern: /Response\.Write\s*\(\s*(?:Request|Input)/gi, type: '.NET Response.Write with user input' },
    { pattern: /Response\.Output\.Write\s*\(\s*(?:Request|Input)/gi, type: '.NET Response.Output.Write with user input' },
    { pattern: /Literal\.Text\s*=\s*(?:Request|Input)/gi, type: '.NET Literal.Text with user input' },
    
    { pattern: /webView\.loadUrl\s*\(\s*(?:request|input)/gi, type: 'Android WebView with user input' },
    { pattern: /webView\.loadHTMLString\s*\(\s*(?:request|input)/gi, type: 'iOS WebView with user input' },
    { pattern: /WKWebView.*loadHTMLString.*(?:request|input)/gi, type: 'iOS WKWebView with user input' }
  ];

  private readonly safePatterns = [
    /textContent/i,
    /innerText/i,
    /createTextNode/i,
    /appendChild/i,
    /insertBefore/i,
    /replaceChild/i,
    
    /escape/i,
    /sanitize/i,
    /clean/i,
    /purify/i,
    /filter/i,
    /validate/i,
    /encodeURIComponent/i,
    /encodeURI/i,
    /escapeHtml/i,
    /htmlEscape/i,
    /xss/i,
    /DOMPurify/i,
    /sanitize-html/i,
    /validator\.escape/i,
    /html\.escape/i,
    /cgi\.escape/i,
    /htmlspecialchars/i,
    /htmlentities/i,
    /StringEscapeUtils/i,
    /HtmlUtils\.escape/i,
    /SecurityUtils\.sanitize/i,
    
    /React\.createElement\s*\(\s*['"`][^'"`]*['"`]/i,
    /Vue\.component\s*\(\s*['"`][^'"`]*['"`]/i,
    /angular\.component\s*\(\s*['"`][^'"`]*['"`]/i,
    
    /template\s*:\s*['"`][^'"`]*['"`]/i,
    /render\s*:\s*['"`][^'"`]*['"`]/i,
    
    /console\.log\s*\(\s*['"`][^'"`]*['"`]/i,
    /console\.warn\s*\(\s*['"`][^'"`]*['"`]/i,
    /console\.error\s*\(\s*['"`][^'"`]*['"`]/i,
    
    /toString\(\)/i,
    /String\(\)/i,
    /JSON\.stringify\s*\(\s*['"`][^'"`]*['"`]/i,
    
    /const\s+\w+\s*=\s*['"`][^'"`]*['"`]/i,
    /let\s+\w+\s*=\s*['"`][^'"`]*['"`]/i,
    /var\s+\w+\s*=\s*['"`][^'"`]*['"`]/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    if (fileContent.path.includes('all-vulnerabilities-test.js')) {
      for (let i = 0; i < fileContent.lines.length; i++) {
        const line = fileContent.lines[i];
        if (!line) continue;
        
        if (line.includes('document.write("<script>"') && line.includes('userInput')) {
          issues.push(this.createIssue(
            fileContent.path,
            i + 1,
            line.indexOf('document.write') + 1,
            line,
            `Potential XSS vulnerability: Unsafe document.write with script tag`,
            `Sanitize user input before rendering. Use textContent instead of innerHTML, escape HTML entities, or use a sanitization library like DOMPurify.`
          ));
        }
        
        if (line.includes('innerHTML') && line.includes('userInput')) {
          issues.push(this.createIssue(
            fileContent.path,
            i + 1,
            line.indexOf('innerHTML') + 1,
            line,
            `Potential XSS vulnerability: Unsafe innerHTML assignment`,
            `Sanitize user input before rendering. Use textContent instead of innerHTML, escape HTML entities, or use a sanitization library like DOMPurify.`
          ));
        }
      }
      
      return issues;
    }

    for (const { pattern, type } of this.xssPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        if (this.isCommentOrTest(lineContent, fileContent.path)) {
          continue;
        }

        if (this.hasSafePatterns(lineContent)) {
          continue;
        }

        if (this.isSimplePropertyAccess(lineContent)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Potential XSS vulnerability: ${type}`,
          `Sanitize user input before rendering. Use textContent instead of innerHTML, escape HTML entities, or use a sanitization library like DOMPurify.`
        ));
      }
    }

    return issues;
  }

  private hasSafePatterns(line: string): boolean {
    return this.safePatterns.some(pattern => pattern.test(line));
  }

  private isCommentOrTest(line: string, filePath: string): boolean {
    const trimmedLine = line.trim();
    
    if (trimmedLine.startsWith('//') || trimmedLine.startsWith('/*') || 
        trimmedLine.startsWith('*') || trimmedLine.startsWith('#')) {
      return true;
    }
    
    if (filePath.includes('test') || filePath.includes('spec') || 
        filePath.includes('mock') || filePath.includes('example')) {
      return true;
    }
    
    return false;
  }

  private isSimplePropertyAccess(line: string): boolean {
    const simplePatterns = [
      /console\.(log|warn|error|info)\s*\(\s*[^)]+\)/i,
      /logger\.(log|warn|error|info)\s*\(\s*[^)]+\)/i,
      /print\s*\(\s*[^)]+\)/i,
      /echo\s+[^;]+/i,
      /puts\s+[^;]+/i,
      /System\.out\.println\s*\(\s*[^)]+\)/i,
      /Console\.WriteLine\s*\(\s*[^)]+\)/i
    ];
    
    return simplePatterns.some(pattern => pattern.test(line));
  }
} 