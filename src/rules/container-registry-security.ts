import { BaseRule, FileContent, SecurityIssue, SeverityLevel } from '../types';

interface RegistryPattern {
  pattern: RegExp;
  type: string;
  severity: SeverityLevel;
  description: string;
  suggestion: string;
  context?: {
    requiresSignature?: boolean;
    requiresDigest?: boolean;
    requiresPullSecrets?: boolean;
  };
}

interface RegistryContext {
  hasImagePullSecrets: boolean;
  hasImageDigest: boolean;
  hasImageSignature: boolean;
  hasImagePullPolicy: boolean;
  registryType: string;
  imageName: string;
  imageTag: string;
  hasInsecureRegistry: boolean;
  hasPublicRegistry: boolean;
  hasPrivateRegistry: boolean;
  hasImageScanning: boolean;
  hasImageSigning: boolean;
  pullPolicyType: string;
  hasTrivyScanning: boolean;
  hasCosignSigning: boolean;
  hasVulnerabilityScanning: boolean;
  registryUrls: string[];
  imageReferences: string[];
}

export class ContainerRegistrySecurityRule extends BaseRule {
  readonly name = 'container-registry-security';
  readonly description = 'Detects container registry security misconfigurations and vulnerabilities';
  readonly severity = 'medium' as const;

  private readonly registryPatterns: RegistryPattern[] = [
    {
      pattern: /image:\s*([^:]+):latest/gm,
      type: 'Latest Tag Usage',
      severity: 'high',
      description: 'Using latest tag can lead to unpredictable deployments',
      suggestion: 'Use specific version tags (e.g., nginx:1.21.6 instead of nginx:latest)'
    },
    {
      pattern: /image:\s*([^:]+):([^\s]+)(?!@sha256:)(?!@sha512:)/gm,
      type: 'Missing Image Digest',
      severity: 'high',
      description: 'Image reference without @sha256 digest can lead to supply chain attacks',
      suggestion: 'Use pinned digest: image@sha256:abc123... for immutable references'
    },
    {
      pattern: /image:\s*([^:]+):([^\s]+)@sha256:([a-f0-9]{64})/gm,
      type: 'Image Digest Present',
      severity: 'low',
      description: 'Image digest provides immutable reference - good practice',
      suggestion: 'Good practice: Image digest ensures consistent deployments'
    },
    {
      pattern: /image:\s*([^:]+):([^\s]+)(?!@sha256:)(?!@sha512:)/gm,
      type: 'Missing Image Signature',
      severity: 'medium',
      description: 'Image without signature verification',
      suggestion: 'Use signed images and verify signatures in CI/CD pipeline'
    },
    {
      pattern: /image:\s*([^:]+):([^\s]+)(?!@sha256:)(?!@sha512:)/gm,
      type: 'Insecure Image Pull',
      severity: 'high',
      description: 'Image pull without authentication or verification',
      suggestion: 'Use imagePullSecrets and verify image integrity'
    },
    {
      pattern: /image:\s*([^:]+):([^\s]+)(?!@sha256:)(?!@sha512:)/gm,
      type: 'Public Registry Usage',
      severity: 'medium',
      description: 'Using public registry (Docker Hub, GCR, etc.) without verification',
      suggestion: 'Use private registry or verify public images before deployment'
    },
    {
      pattern: /image:\s*([^:]+):([^\s]+)(?!@sha256:)(?!@sha512:)/gm,
      type: 'Missing Image Scanning',
      severity: 'medium',
      description: 'No vulnerability scanning detected in workflow',
      suggestion: 'Implement image vulnerability scanning in CI/CD pipeline'
    },
    {
      pattern: /imagePullPolicy:\s*Always/gm,
      type: 'Always Pull Policy',
      severity: 'low',
      description: 'Always pulling images can slow deployments and increase security risk',
      suggestion: 'Use IfNotPresent or specific version tags with IfNotPresent policy'
    },
    {
      pattern: /insecure-registry|http:/gm,
      type: 'Insecure Registry',
      severity: 'critical',
      description: 'Using insecure registry over HTTP',
      suggestion: 'Use HTTPS registry endpoints for secure communication'
    }
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    if (!this.isContainerFile(fileContent.path)) {
      return issues;
    }

    const context = this.analyzeRegistryContext(fileContent.content);
    
    for (const { pattern, type, severity, description, suggestion } of this.registryPatterns) {
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

  private isContainerFile(filePath: string): boolean {
    const lowerPath = filePath.toLowerCase();
    return lowerPath.includes('dockerfile') || 
           lowerPath.endsWith('docker-compose.yml') || 
           lowerPath.endsWith('docker-compose.yaml') ||
           lowerPath.endsWith('.dockerfile') ||
           lowerPath.endsWith('.yaml') ||
           lowerPath.endsWith('.yml') ||
           lowerPath.includes('k8s') ||
           lowerPath.includes('kubernetes') ||
           lowerPath.includes('deployment') ||
           lowerPath.includes('service') ||
           lowerPath.includes('pod');
  }

  private analyzeRegistryContext(content: string): RegistryContext {
    return {
      hasImagePullSecrets: /imagePullSecrets:/m.test(content),
      hasImageDigest: /@sha256:|@sha512:/m.test(content),
      hasImageSignature: /@sha256:|@sha512:/m.test(content),
      hasImagePullPolicy: /imagePullPolicy:/m.test(content),
      registryType: this.extractRegistryType(content),
      imageName: this.extractImageName(content),
      imageTag: this.extractImageTag(content),
      hasInsecureRegistry: /insecure-registry|http:/m.test(content),
      hasPublicRegistry: /docker\.io|gcr\.io|quay\.io|registry\.k8s\.io/m.test(content),
      hasPrivateRegistry: /\.local|\.internal|private/m.test(content),
      hasImageScanning: /scan|vulnerability|security/m.test(content),
      hasImageSigning: /sign|signature|cosign/m.test(content),
      pullPolicyType: this.extractPullPolicyType(content),
      hasTrivyScanning: /trivy|aquasec/m.test(content),
      hasCosignSigning: /cosign|signature/m.test(content),
      hasVulnerabilityScanning: /vulnerability|scan|security/m.test(content),
      registryUrls: this.extractRegistryUrls(content),
      imageReferences: this.extractImageReferences(content)
    };
  }

  private extractRegistryType(content: string): string {
    if (/docker\.io/m.test(content)) return 'docker-hub';
    if (/gcr\.io/m.test(content)) return 'gcr';
    if (/quay\.io/m.test(content)) return 'quay';
    if (/registry\.k8s\.io/m.test(content)) return 'k8s-registry';
    if (/\.local|\.internal/m.test(content)) return 'private';
    return 'unknown';
  }

  private extractImageName(content: string): string {
    const imageMatch = content.match(/image:\s*([^:]+):/m);
    return imageMatch?.[1] ?? 'unknown';
  }

  private extractImageTag(content: string): string {
    const tagMatch = content.match(/image:\s*[^:]+:([^\s@]+)/m);
    return tagMatch?.[1] ?? 'latest';
  }

  private extractPullPolicyType(content: string): string {
    const policyMatch = content.match(/imagePullPolicy:\s*(\w+)/m);
    return policyMatch?.[1] ?? 'unknown';
  }

  private extractRegistryUrls(content: string): string[] {
    const urlMatches = content.match(/(?:registry|repository):\s*([^\s\n]+)/gm);
    if (!urlMatches) return [];
    
    return urlMatches.map(match => {
      const urlMatch = match.match(/(?:registry|repository):\s*(.+)/);
      return urlMatch?.[1]?.trim() ?? '';
    }).filter(url => url.length > 0);
  }

  private extractImageReferences(content: string): string[] {
    const imageMatches = content.match(/image:\s*([^\s\n]+)/gm);
    if (!imageMatches) return [];
    
    return imageMatches.map(match => {
      const imageMatch = match.match(/image:\s*(.+)/);
      return imageMatch?.[1]?.trim() ?? '';
    }).filter(image => image.length > 0);
  }

  private shouldSkipMatch(type: string, context: RegistryContext): boolean {
    if (type === 'Missing Image Digest' && context.hasImageDigest) {
      return true;
    }
    
    if (type === 'Missing Image Signature' && context.hasImageSignature) {
      return true;
    }
    
    return false;
  }

  private determineSeverity(baseSeverity: SeverityLevel, context: RegistryContext, type: string): SeverityLevel {
    if (type === 'Missing Image Digest' && !context.hasImageDigest) {
      return 'high';
    }
    
    if (type === 'Insecure Registry' && context.hasInsecureRegistry) {
      return 'critical';
    }
    
    if (type === 'Public Registry Usage' && context.hasPublicRegistry && !context.hasVulnerabilityScanning) {
      return 'high';
    }
    
    if (type === 'Latest Tag Usage' && context.hasPublicRegistry) {
      return 'high';
    }
    
    if (type === 'Missing Image Scanning' && context.hasPublicRegistry) {
      return 'high';
    }
    
    if (type === 'Insecure Image Pull' && context.hasPrivateRegistry && !context.hasImagePullSecrets) {
      return 'critical';
    }
    
    return baseSeverity;
  }

  private enhanceSuggestion(baseSuggestion: string, context: RegistryContext, type: string): string {
    let suggestion = baseSuggestion;
    
    if (type === 'Missing Image Digest') {
      suggestion += '\n\n**Complete secure image reference example:**\n```yaml\nimage: nginx@sha256:abc123def456...\nimagePullPolicy: IfNotPresent\nimagePullSecrets:\n  - name: registry-secret\n```';
      suggestion += '\n\n**Security benefit:** Pinned digests prevent supply chain attacks and ensure immutable images';
    }
    
    if (type === 'Latest Image Tag') {
      suggestion += `\n\n**Current image:** ${context.imageName}:${context.imageTag}`;
      suggestion += '\n**Recommended:** Use specific version tags for reproducible deployments';
      suggestion += '\n**Example:** Replace `nginx:latest` with `nginx:1.21.6`';
    }
    
    if (type === 'Missing Image Scanning') {
      suggestion += '\n\n**Implement image scanning with Trivy:**\n```yaml\n# In CI/CD pipeline\n- name: Scan image\n  run: |\n    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\\n      aquasec/trivy image ${IMAGE_NAME}:${IMAGE_TAG}\n```';
      suggestion += '\n\n**Alternative tools:** Snyk, Clair, or built-in registry scanning';
    }
    
    if (type === 'Insecure Image Pull') {
      suggestion += '\n\n**Secure image pull configuration:**\n```yaml\nimagePullSecrets:\n  - name: registry-secret\nimagePullPolicy: IfNotPresent\n```';
      suggestion += '\n\n**For private registries:** Always use imagePullSecrets for authentication';
    }
    
    if (type === 'Public Registry Usage') {
      suggestion += `\n\n**Registry type detected:** ${context.registryType}`;
      suggestion += '\n**Security risk:** Public registries can be compromised or contain malicious images';
      suggestion += '\n**Solution:** Use private registry or verify public images before deployment';
    }
    
    if (type === 'Missing Image Signature') {
      suggestion += '\n\n**Implement image signing with cosign:**\n```bash\n# Sign image\ncosign sign --key cosign.key ${IMAGE_NAME}:${IMAGE_TAG}\n\n# Verify signature\ncosign verify --key cosign.pub ${IMAGE_NAME}:${IMAGE_TAG}\n```';
      suggestion += '\n\n**Security benefit:** Image signatures ensure integrity and authenticity';
    }
    
    if (type === 'Insecure Registry') {
      suggestion += '\n\n**Security risk:** HTTP registries are vulnerable to man-in-the-middle attacks';
      suggestion += '\n**Solution:** Use HTTPS registry endpoints for secure communication';
      suggestion += '\n**Example:** Replace `http://registry.example.com` with `https://registry.example.com`';
    }
    
    if (type === 'Always Pull Policy') {
      suggestion += '\n\n**Current pull policy:** ' + context.pullPolicyType;
      suggestion += '\n**Security risk:** Always pulling can slow deployments and increase attack surface';
      suggestion += '\n**Recommended:** Use `IfNotPresent` with specific version tags';
    }
    
    return suggestion;
  }

  private checkMissingPractices(context: RegistryContext): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    if (!context.hasImagePullSecrets && context.hasPrivateRegistry) {
      issues.push(this.createIssue(
        'Container Manifest',
        1,
        1,
        'image: ...',
        'Missing image pull secrets: Cannot authenticate with private registry',
        'Add imagePullSecrets to authenticate with private registry:\n```yaml\nimagePullSecrets:\n  - name: registry-secret\n```',
        'high'
      ));
    }
    
    if (!context.hasImageDigest && context.imageReferences.length > 0) {
      issues.push(this.createIssue(
        'Container Manifest',
        1,
        1,
        'image: ...',
        'Missing image digest: Image references are mutable',
        'Use image digest for immutable references: image@sha256:abc123...\n**Security benefit:** Prevents supply chain attacks',
        'high'
      ));
    }
    
    if (!context.hasVulnerabilityScanning && context.hasPublicRegistry) {
      issues.push(this.createIssue(
        'Container Manifest',
        1,
        1,
        'image: ...',
        'Missing image scanning: No vulnerability assessment for public registry images',
        'Implement image vulnerability scanning in CI/CD pipeline:\n```yaml\n# Trivy scanning\n- name: Scan image\n  run: docker run --rm aquasec/trivy image ${IMAGE_NAME}:${IMAGE_TAG}\n```',
        'high'
      ));
    }
    
    if (!context.hasImageSigning && context.hasPublicRegistry) {
      issues.push(this.createIssue(
        'Container Manifest',
        1,
        1,
        'image: ...',
        'Missing image signing: No integrity verification for public registry images',
        'Implement image signing and verification in CI/CD pipeline:\n```bash\n# Sign with cosign\ncosign sign --key cosign.key ${IMAGE_NAME}:${IMAGE_TAG}\n```',
        'medium'
      ));
    }
    
    if (!context.hasImagePullPolicy && context.imageReferences.length > 0) {
      issues.push(this.createIssue(
        'Container Manifest',
        1,
        1,
        'image: ...',
        'Missing image pull policy: No pull policy specified',
        'Add imagePullPolicy for better control:\n```yaml\nimagePullPolicy: IfNotPresent\n```',
        'low'
      ));
    }
    
    if (context.hasInsecureRegistry) {
      issues.push(this.createIssue(
        'Container Manifest',
        1,
        1,
        'registry: ...',
        'Insecure registry detected: Using HTTP instead of HTTPS',
        'Use HTTPS registry endpoints for secure communication:\n```yaml\n# Replace http:// with https://\nregistry: https://registry.example.com\n```',
        'critical'
      ));
    }
    
    return issues;
  }

}
