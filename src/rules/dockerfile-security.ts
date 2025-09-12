import { BaseRule, FileContent, SecurityIssue, SeverityLevel } from '../types';

interface DockerfilePattern {
  pattern: RegExp;
  type: string;
  severity: SeverityLevel;
  description: string;
  suggestion: string;
  context?: {
    requiresUser?: boolean;
    requiresFrom?: boolean;
    requiresWorkdir?: boolean;
  };
}

interface DockerfileContext {
  hasUserDirective: boolean;
  hasFromDirective: boolean;
  hasWorkdirDirective: boolean;
  baseImage: string;
  isMultiStage: boolean;
  stageCount: number;
  hasSecurityLabels: boolean;
  exposedPorts: string[];
  hasHealthcheck: boolean;
  hasNonRootUser: boolean;
  hasDockerignore: boolean;
  hasMaintainerLabel: boolean;
  runCommandCount: number;
  copyCommandCount: number;
  userDirectiveOrder: number[];
  hasExcessiveLayers: boolean;
  hasPublicPorts: boolean;
}

export class DockerfileSecurityRule extends BaseRule {
  readonly name = 'dockerfile-security';
  readonly description = 'Detects common Dockerfile security vulnerabilities and misconfigurations';
  readonly severity = 'high' as const;

  private readonly dockerfilePatterns: DockerfilePattern[] = [
    {
      pattern: /^FROM\s+([^\s]+)(?!@sha256:)/gm,
      type: 'Missing Image Digest',
      severity: 'high',
      description: 'Image reference without @sha256 digest can lead to supply chain attacks',
      suggestion: 'Use pinned digest: FROM node:18.17.0-alpine@sha256:abc123...'
    },
    {
      pattern: /^FROM\s+([^\s:]+):latest/gm,
      type: 'Latest Tag Usage',
      severity: 'high',
      description: 'Using latest tag can lead to unpredictable builds and security vulnerabilities',
      suggestion: 'Use specific version tags (e.g., node:18.17.0-alpine instead of node:latest)'
    },
    {
      pattern: /^USER\s+root/gm,
      type: 'Root User Execution',
      severity: 'critical',
      description: 'Running container as root user creates security risks',
      suggestion: 'Create and use a non-root user: RUN adduser --disabled-password --gecos "" appuser && USER appuser'
    },
    {
      pattern: /^EXPOSE\s+(\d+)/gm,
      type: 'Port Exposure',
      severity: 'medium',
      description: 'Exposed ports without justification or security context',
      suggestion: 'Only expose necessary ports and consider using non-standard ports for internal services'
    },
    {
      pattern: /^RUN\s+.*(?:apt-get|yum|apk)\s+install.*(?:-y|--yes)/gm,
      type: 'Package Installation',
      severity: 'medium',
      description: 'Package installation without cleanup can increase image size and attack surface',
      suggestion: 'Clean up package caches and pin versions: RUN apt-get update && apt-get install -y package=1.2.3 && rm -rf /var/lib/apt/lists/*'
    },
    {
      pattern: /^COPY\s+.*\s+\/$/gm,
      type: 'Copy to Root',
      severity: 'high',
      description: 'Copying files to root directory can lead to permission issues',
      suggestion: 'Copy to specific directories and set appropriate ownership'
    },
    {
      pattern: /^ADD\s+/gm,
      type: 'ADD Directive Usage',
      severity: 'medium',
      description: 'ADD directive can extract archives and download from URLs, creating security risks',
      suggestion: 'Use COPY for local files, download and verify external resources separately. Add .dockerignore to prevent leaks'
    },
    {
      pattern: /^ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)\s*=/gmi,
      type: 'Sensitive Environment Variables',
      severity: 'critical',
      description: 'Sensitive data in environment variables can be exposed',
      suggestion: 'Use Docker secrets or external secret management systems'
    },
    {
      pattern: /^RUN\s+.*(?:curl|wget)\s+.*(?!--checksum|--hash)/gm,
      type: 'Insecure Download',
      severity: 'high',
      description: 'Downloads without checksum validation can lead to supply chain attacks',
      suggestion: 'Validate checksums: RUN curl -L --checksum sha256:abc123... https://example.com/file'
    },
    {
      pattern: /^RUN\s+(?!.*&&).*$/gm,
      type: 'Unchained RUN Commands',
      severity: 'medium',
      description: 'RUN commands without && chaining can hide failures and create security risks',
      suggestion: 'Chain commands with &&: RUN apt-get update && apt-get install -y package && rm -rf /var/lib/apt/lists/*'
    },
    {
      pattern: /^HEALTHCHECK\s+NONE/gm,
      type: 'Disabled Healthcheck',
      severity: 'medium',
      description: 'Healthcheck disabled or set to NONE',
      suggestion: 'Enable healthcheck: HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD curl -f http://localhost:3000/health || exit 1'
    },
    {
      pattern: /^FROM\s+(?:ubuntu|debian|centos|rhel)(?!.*alpine)/gm,
      type: 'Large Base Image',
      severity: 'low',
      description: 'Using large base images increases attack surface and image size',
      suggestion: 'Consider minimal variants: alpine, distroless, or scratch for smaller, more secure images'
    }
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    if (!this.isDockerfile(fileContent.path)) {
      return issues;
    }

    const context = this.analyzeDockerfileContext(fileContent.content);
    
    for (const { pattern, type, severity, description, suggestion } of this.dockerfilePatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        if (this.shouldSkipMatch(type, context)) {
          continue;
        }
        
        const finalSeverity = this.determineSeverity(severity, context, type);
        const enhancedSuggestion = this.enhanceSuggestion(suggestion, context, type);
        
        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `${type}: ${description}`,
          enhancedSuggestion,
          finalSeverity
        ));
      }
    }

    const missingPractices = this.checkMissingPractices(context);
    issues.push(...missingPractices);

    return issues;
  }

  private isDockerfile(filePath: string): boolean {
    const lowerPath = filePath.toLowerCase();
    return lowerPath.includes('dockerfile') || 
           lowerPath.endsWith('docker-compose.yml') || 
           lowerPath.endsWith('docker-compose.yaml') ||
           lowerPath.endsWith('.dockerfile');
  }

  private analyzeDockerfileContext(content: string): DockerfileContext {
    const runMatches = content.match(/^RUN\s+/gm) || [];
    const copyMatches = content.match(/^COPY\s+/gm) || [];
    
    return {
      hasUserDirective: /^USER\s+/m.test(content),
      hasFromDirective: /^FROM\s+/m.test(content),
      hasWorkdirDirective: /^WORKDIR\s+/m.test(content),
      baseImage: this.extractBaseImage(content),
      isMultiStage: (content.match(/^FROM\s+/gm) || []).length > 1,
      stageCount: (content.match(/^FROM\s+/gm) || []).length,
      hasSecurityLabels: /LABEL\s+.*security/m.test(content),
      exposedPorts: this.extractExposedPorts(content),
      hasHealthcheck: /^HEALTHCHECK/m.test(content),
      hasNonRootUser: /^USER\s+(?!root\b)/m.test(content),
      hasDockerignore: this.checkDockerignoreExists(),
      hasMaintainerLabel: /LABEL\s+.*maintainer/m.test(content),
      runCommandCount: runMatches.length,
      copyCommandCount: copyMatches.length,
      userDirectiveOrder: this.extractUserDirectiveOrder(content),
      hasExcessiveLayers: runMatches.length > 10 || copyMatches.length > 5,
      hasPublicPorts: this.hasPublicPorts(content)
    };
  }

  private extractBaseImage(content: string): string {
    const fromMatch = content.match(/^FROM\s+([^\s]+)/m);
    return fromMatch?.[1] ?? 'unknown';
  }

  private extractExposedPorts(content: string): string[] {
    const exposeMatches = content.match(/^EXPOSE\s+([^\n]+)/gm);
    if (!exposeMatches) return [];
    
    return exposeMatches.map(match => {
      const portMatch = match.match(/^EXPOSE\s+(.+)/);
      return portMatch?.[1]?.trim() ?? '';
    }).filter(port => port.length > 0);
  }

  private checkDockerignoreExists(): boolean {
    return false;
  }

  private extractUserDirectiveOrder(content: string): number[] {
    const lines = content.split('\n');
    const userLines: number[] = [];
    
    lines.forEach((line, index) => {
      if (/^USER\s+/m.test(line)) {
        userLines.push(index + 1);
      }
    });
    
    return userLines;
  }

  private hasPublicPorts(content: string): boolean {
    const publicPorts = ['80', '443', '8080', '3000', '5000'];
    const exposedPorts = this.extractExposedPorts(content);
    
    return exposedPorts.some(port => 
      publicPorts.some(publicPort => port.includes(publicPort))
    );
  }

  private shouldSkipMatch(type: string, context: DockerfileContext): boolean {
    if (type === 'Root User Execution' && context.hasNonRootUser) {
      return true;
    }
    
    if (type === 'Latest Tag Usage' && context.isMultiStage) {
      return false;
    }
    
    return false;
  }

  private determineSeverity(baseSeverity: SeverityLevel, context: DockerfileContext, type: string): SeverityLevel {
    if (type === 'Root User Execution' && !context.hasNonRootUser) {
      return 'critical';
    }
    
    if (type === 'Latest Tag Usage' && context.baseImage.includes('latest')) {
      return 'high';
    }
    
    if (type === 'Sensitive Environment Variables') {
      return 'critical';
    }
    
    if (type === 'Port Exposure' && context.hasPublicPorts) {
      return 'high';
    }
    
    if (type === 'Missing Image Digest' && !context.isMultiStage) {
      return 'high';
    }
    
    if (type === 'Insecure Download') {
      return 'high';
    }
    
    return baseSeverity;
  }

  private enhanceSuggestion(baseSuggestion: string, context: DockerfileContext, type: string): string {
    let suggestion = baseSuggestion;
    
    if (type === 'Root User Execution') {
      suggestion += '\n\n**Complete fix example:**\n```dockerfile\nRUN adduser --disabled-password --gecos "" appuser \\\n    && chown -R appuser:appuser /app \\\n    && USER appuser\n```';
    }
    
    if (type === 'Latest Tag Usage') {
      suggestion += `\n\n**Current base image:** ${context.baseImage}`;
      suggestion += '\n**Recommended:** Use specific version tags for reproducible builds';
    }
    
    if (type === 'Port Exposure' && context.exposedPorts.length > 0) {
      suggestion += `\n\n**Currently exposed ports:** ${context.exposedPorts.join(', ')}`;
      if (context.hasPublicPorts) {
        suggestion += '\n**⚠️ Critical:** Public ports (80, 443, 8080) exposed - document services behind ports';
      }
      suggestion += '\n**Consider:** Only expose necessary ports and use non-standard ports for internal services';
    }
    
    if (type === 'Missing Image Digest') {
      suggestion += '\n\n**Security benefit:** Pinned digests prevent supply chain attacks and ensure immutable images';
      suggestion += '\n**Example:** FROM node:18.17.0-alpine@sha256:abc123def456...';
    }
    
    if (type === 'Package Installation') {
      suggestion += '\n\n**Additional security:** Pin package versions to prevent supply chain attacks';
      suggestion += '\n**Example:** RUN apt-get update && apt-get install -y package=1.2.3 && rm -rf /var/lib/apt/lists/*';
    }
    
    if (type === 'ADD Directive Usage') {
      suggestion += '\n\n**Security risk:** ADD can extract archives and download from URLs';
      suggestion += '\n**Solution:** Use COPY for local files, download and verify external resources separately';
      suggestion += '\n**Also add:** .dockerignore file to prevent sensitive file leaks';
    }
    
    if (type === 'Unchained RUN Commands') {
      suggestion += '\n\n**Security risk:** Unchained commands can hide failures and create inconsistent states';
      suggestion += '\n**Best practice:** Always chain with && to ensure commands fail fast';
    }
    
    if (type === 'Large Base Image') {
      suggestion += '\n\n**Security benefit:** Minimal images reduce attack surface and image size';
      suggestion += '\n**Alternatives:** alpine, distroless, or scratch for production workloads';
    }
    
    return suggestion;
  }

  private checkMissingPractices(context: DockerfileContext): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    if (!context.hasUserDirective && !context.hasNonRootUser) {
      issues.push(this.createIssue(
        'Dockerfile',
        1,
        1,
        'FROM ...',
        'Missing non-root user: Container runs as root by default',
        'Add a non-root user: RUN adduser --disabled-password --gecos "" appuser && USER appuser',
        'high'
      ));
    }
    
    if (!context.hasWorkdirDirective) {
      issues.push(this.createIssue(
        'Dockerfile',
        1,
        1,
        'FROM ...',
        'Missing WORKDIR: Defaults to / which can cause permission issues',
        'Add WORKDIR: WORKDIR /app to set a specific working directory',
        'medium'
      ));
    }
    
    if (!context.hasSecurityLabels) {
      issues.push(this.createIssue(
        'Dockerfile',
        1,
        1,
        'FROM ...',
        'Missing security labels: No security metadata provided',
        'Add security labels: LABEL security.scan="enabled" security.level="high"',
        'medium'
      ));
    }
    
    if (!context.hasMaintainerLabel) {
      issues.push(this.createIssue(
        'Dockerfile',
        1,
        1,
        'FROM ...',
        'Missing maintainer label: No responsible contact information',
        'Add maintainer: LABEL maintainer="your-email@example.com"',
        'low'
      ));
    }
    
    if (!context.hasHealthcheck) {
      issues.push(this.createIssue(
        'Dockerfile',
        1,
        1,
        'FROM ...',
        'Missing healthcheck: No container health monitoring',
        'Add healthcheck: HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD curl -f http://localhost:3000/health || exit 1',
        'medium'
      ));
    }
    
    if (context.hasExcessiveLayers) {
      issues.push(this.createIssue(
        'Dockerfile',
        1,
        1,
        'RUN/COPY ...',
        'Excessive layers: Too many RUN/COPY commands create large, insecure images',
        `Combine commands: ${context.runCommandCount} RUN commands and ${context.copyCommandCount} COPY commands detected. Use multi-line RUN with && chaining`,
        'medium'
      ));
    }
    
    if (context.exposedPorts.length > 3) {
      const severity = context.hasPublicPorts ? 'high' : 'medium';
      issues.push(this.createIssue(
        'Dockerfile',
        1,
        1,
        'EXPOSE ...',
        'Excessive port exposure: Too many ports exposed',
        `Consider reducing exposed ports. Currently exposing: ${context.exposedPorts.join(', ')}${context.hasPublicPorts ? ' (includes public ports)' : ''}`,
        severity
      ));
    }
    
    if (!context.hasDockerignore) {
      issues.push(this.createIssue(
        'Dockerfile',
        1,
        1,
        'FROM ...',
        'Missing .dockerignore: Risk of including sensitive files in build context',
        'Create .dockerignore file to exclude sensitive files, node_modules, .git, etc.',
        'medium'
      ));
    }
    
    return issues;
  }

}
