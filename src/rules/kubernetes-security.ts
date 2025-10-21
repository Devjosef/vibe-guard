import { BaseRule, FileContent, SecurityIssue, SeverityLevel } from '../types';

interface KubernetesPattern {
  pattern: RegExp;
  type: string;
  severity: SeverityLevel;
  description: string;
  suggestion: string;
  context?: {
    requiresSecurityContext?: boolean;
    requiresResources?: boolean;
    requiresServiceAccount?: boolean;
  };
}

interface KubernetesContext {
  hasSecurityContext: boolean;
  hasResourceLimits: boolean;
  hasResourceRequests: boolean;
  hasServiceAccount: boolean;
  hasNonRootUser: boolean;
  hasReadOnlyRootFilesystem: boolean;
  hasPrivilegedMode: boolean;
  hasHostNetwork: boolean;
  hasHostPID: boolean;
  hasHostIPC: boolean;
  hasCapabilities: boolean;
  hasNetworkPolicies: boolean;
  hasPodSecurityPolicy: boolean;
  hasRBAC: boolean;
  resourceType: string;
  namespace: string;
  hasImagePullSecrets: boolean;
  hasImagePullPolicy: boolean;
  hasAutomountServiceAccountToken: boolean;
  hasHostPathVolumes: boolean;
  hasSeccompProfile: boolean;
  hasAppArmorProfile: boolean;
  hasSELinuxOptions: boolean;
  hasReadinessProbe: boolean;
  hasLivenessProbe: boolean;
  hasStartupProbe: boolean;
  hasResourceQuotas: boolean;
  hasLimitRanges: boolean;
  hasPodDisruptionBudget: boolean;
}

export class KubernetesSecurityRule extends BaseRule {
  readonly name = 'kubernetes-security';
  readonly description = 'Detects Kubernetes security misconfigurations and vulnerabilities';
  readonly severity = 'high' as const;

  private readonly kubernetesPatterns: KubernetesPattern[] = [
    {
      pattern: /privileged:\s*true/gm,
      type: 'Privileged Container',
      severity: 'critical',
      description: 'Container running in privileged mode has full host access',
      suggestion: 'Remove privileged: true and use specific capabilities if needed'
    },
    {
      pattern: /hostNetwork:\s*true/gm,
      type: 'Host Namespace Sharing',
      severity: 'high',
      description: 'Container shares host network namespace - breaks isolation',
      suggestion: 'Use hostNetwork: false and configure proper network policies'
    },
    {
      pattern: /hostPID:\s*true/gm,
      type: 'Host Namespace Sharing',
      severity: 'high',
      description: 'Container shares host PID namespace - breaks isolation',
      suggestion: 'Use hostPID: false to isolate process namespace'
    },
    {
      pattern: /hostIPC:\s*true/gm,
      type: 'Host Namespace Sharing',
      severity: 'high',
      description: 'Container shares host IPC namespace - breaks isolation',
      suggestion: 'Use hostIPC: false to isolate IPC namespace'
    },
    {
      pattern: /runAsUser:\s*0/gm,
      type: 'Root User Execution',
      severity: 'critical',
      description: 'Container running as root user (UID 0)',
      suggestion: 'Set runAsUser to non-zero value (e.g., 1000)'
    },
    {
      pattern: /runAsNonRoot:\s*false/gm,
      type: 'Non-Root Disabled',
      severity: 'critical',
      description: 'Non-root user enforcement explicitly disabled',
      suggestion: 'Set runAsNonRoot: true to enforce non-root execution'
    },
    {
      pattern: /readOnlyRootFilesystem:\s*false/gm,
      type: 'Writable Root Filesystem',
      severity: 'medium',
      description: 'Container has writable root filesystem - allows tampering',
      suggestion: 'Set readOnlyRootFilesystem: true and use emptyDir volumes for writable data'
    },
    {
      pattern: /allowPrivilegeEscalation:\s*true/gm,
      type: 'Privilege Escalation Allowed',
      severity: 'high',
      description: 'Container can escalate privileges',
      suggestion: 'Set allowPrivilegeEscalation: false'
    },
    {
      pattern: /add:\s*\[[^\]]*['"]SYS_ADMIN['"][^\]]*\]/gm,
      type: 'Dangerous Capabilities',
      severity: 'critical',
      description: 'Container has SYS_ADMIN capability - dangerous kernel-level access',
      suggestion: 'Remove SYS_ADMIN capability and use minimal required capabilities'
    },
    {
      pattern: /add:\s*\[[^\]]*['"]NET_ADMIN['"][^\]]*\]/gm,
      type: 'Dangerous Capabilities',
      severity: 'high',
      description: 'Container has NET_ADMIN capability - dangerous kernel-level access',
      suggestion: 'Remove NET_ADMIN capability unless absolutely necessary'
    },
    {
      pattern: /add:\s*\[[^\]]*['"](?:SYS_TIME|SYS_MODULE|SYS_RAWIO|SYS_PTRACE)['"][^\]]*\]/gm,
      type: 'Dangerous Capabilities',
      severity: 'high',
      description: 'Container has dangerous capabilities - kernel-level access',
      suggestion: 'Remove dangerous capabilities and use minimal required capabilities'
    },
    {
      pattern: /image:\s*([^:]+):latest/gm,
      type: 'Latest Image Tag',
      severity: 'medium',
      description: 'Using latest image tag can lead to unpredictable deployments',
      suggestion: 'Use specific version tags (e.g., nginx:1.21.6 instead of nginx:latest)'
    },
    {
      pattern: /imagePullPolicy:\s*Always/gm,
      type: 'Always Pull Policy',
      severity: 'low',
      description: 'Always pulling images increases deployment overhead and security risks',
      suggestion: 'Use IfNotPresent or specific version tags with IfNotPresent policy'
    },
    {
      pattern: /automountServiceAccountToken:\s*true/gm,
      type: 'Service Account Token Mounting',
      severity: 'medium',
      description: 'Service account token automatically mounted - potential privilege escalation',
      suggestion: 'Set automountServiceAccountToken: false unless explicitly needed'
    },
    {
      pattern: /^\s*path:\s*\/var\/lib/gm,
      type: 'Host Path Volume',
      severity: 'high',
      description: 'Host path volume mounted - potential host filesystem access',
      suggestion: 'Avoid hostPath volumes or use read-only mounts with specific paths'
    }
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    if (!this.isKubernetesManifest(fileContent.path)) {
      return issues;
    }

    const context = this.analyzeKubernetesContext(fileContent.content);
    
    for (const { pattern, type, severity, description, suggestion } of this.kubernetesPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        if (this.shouldSkipMatch(type, context, lineContent, fileContent.content)) {
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

  private isKubernetesManifest(filePath: string): boolean {
    const lowerPath = filePath.toLowerCase();
    return lowerPath.includes('k8s') ||
           lowerPath.includes('kubernetes') ||
           lowerPath.includes('deployment') ||
           lowerPath.includes('service') ||
           lowerPath.includes('pod') ||
           lowerPath.includes('namespace') ||
           (lowerPath.endsWith('.yaml') && (lowerPath.includes('k8s') || lowerPath.includes('kubernetes'))) ||
           (lowerPath.endsWith('.yml') && (lowerPath.includes('k8s') || lowerPath.includes('kubernetes')));
  }

  private analyzeKubernetesContext(content: string): KubernetesContext {
    return {
      hasSecurityContext: /securityContext:/m.test(content),
      hasResourceLimits: /limits:/m.test(content),
      hasResourceRequests: /requests:/m.test(content),
      hasServiceAccount: /serviceAccount:/m.test(content),
      hasNonRootUser: /runAsNonRoot:\s*true/m.test(content),
      hasReadOnlyRootFilesystem: /readOnlyRootFilesystem:\s*true/m.test(content),
      hasPrivilegedMode: /privileged:\s*true/m.test(content),
      hasHostNetwork: /hostNetwork:\s*true/m.test(content),
      hasHostPID: /hostPID:\s*true/m.test(content),
      hasHostIPC: /hostIPC:\s*true/m.test(content),
      hasCapabilities: /capabilities:/m.test(content),
      hasNetworkPolicies: /kind:\s*NetworkPolicy/m.test(content),
      hasPodSecurityPolicy: /kind:\s*PodSecurityPolicy/m.test(content),
      hasRBAC: /kind:\s*(Role|ClusterRole|RoleBinding|ClusterRoleBinding)/m.test(content),
      resourceType: this.extractResourceType(content),
      namespace: this.extractNamespace(content),
      hasImagePullSecrets: /imagePullSecrets:/m.test(content),
      hasImagePullPolicy: /imagePullPolicy:/m.test(content),
      hasAutomountServiceAccountToken: /automountServiceAccountToken:/m.test(content),
      hasHostPathVolumes: /hostPath:/m.test(content),
      hasSeccompProfile: /seccompProfile:/m.test(content),
      hasAppArmorProfile: /appArmorProfile:/m.test(content),
      hasSELinuxOptions: /seLinuxOptions:/m.test(content),
      hasReadinessProbe: /readinessProbe:/m.test(content),
      hasLivenessProbe: /livenessProbe:/m.test(content),
      hasStartupProbe: /startupProbe:/m.test(content),
      hasResourceQuotas: /kind:\s*ResourceQuota/m.test(content),
      hasLimitRanges: /kind:\s*LimitRange/m.test(content),
      hasPodDisruptionBudget: /kind:\s*PodDisruptionBudget/m.test(content)
    };
  }

  private extractResourceType(content: string): string {
    const kindMatch = content.match(/kind:\s*(\w+)/m);
    return kindMatch?.[1] ?? 'unknown';
  }

  private extractNamespace(content: string): string {
    const namespaceMatch = content.match(/namespace:\s*(\w+)/m);
    return namespaceMatch?.[1] ?? 'default';
  }

  private shouldSkipMatch(type: string, context: KubernetesContext, lineContent: string, fullContent: string): boolean {
    if (type === 'Root User Execution') {
      const lines = fullContent.split('\n');
      const currentLineIndex = lines.findIndex(line => line.trim() === lineContent.trim());
      
      if (currentLineIndex >= 0) {
        let securityContextStart = -1;
        for (let i = currentLineIndex; i >= 0; i--) {
          if (lines[i]?.includes('securityContext:')) {
            securityContextStart = i;
            break;
          }
        }
        
        let securityContextEnd = lines.length;
        if (securityContextStart >= 0) {
          for (let i = securityContextStart + 1; i < lines.length; i++) {
            const line = lines[i];
            if (line && line.trim() && !line.startsWith(' ') && !line.startsWith('\t')) {
              securityContextEnd = i;
              break;
            }
          }
        }
        
        if (securityContextStart >= 0 && securityContextEnd > securityContextStart) {
          const securityContextBlock = lines.slice(securityContextStart, securityContextEnd).join('\n');
          if (securityContextBlock.includes('runAsNonRoot: true')) {
            return true;
          }
        }
      }
    }
    
    if (type === 'Privilege Escalation Allowed' && context.hasSecurityContext) {
      return false;
    }
    
    return false;
  }

  private determineSeverity(baseSeverity: SeverityLevel, context: KubernetesContext, type: string): SeverityLevel {
    if (type === 'Privileged Container' && context.hasPrivilegedMode) {
      return 'critical';
    }
    
    if (type === 'Root User Execution' && !context.hasNonRootUser) {
      return 'critical';
    }
    
    if (type === 'Dangerous Capabilities' && context.hasCapabilities) {
      return 'critical';
    }
    
    if (type === 'Host Namespace Sharing' && (context.hasHostNetwork || context.hasHostPID || context.hasHostIPC)) {
      return 'high';
    }
    
    if (type === 'Privilege Escalation Allowed' && !context.hasSecurityContext) {
      return 'high';
    }
    
    if (type === 'Non-Root Disabled' && !context.hasNonRootUser) {
      return 'critical';
    }
    
    if (type === 'Host Path Volume' && context.hasHostPathVolumes) {
      return 'high';
    }
    
    return baseSeverity;
  }

  private enhanceSuggestion(baseSuggestion: string, context: KubernetesContext, type: string): string {
    let suggestion = baseSuggestion;
    
    if (type === 'Root User Execution') {
      suggestion += '\n\n**Complete secure security context example:**\n```yaml\nsecurityContext:\n  runAsNonRoot: true\n  runAsUser: 1000\n  runAsGroup: 1000\n  readOnlyRootFilesystem: true\n  allowPrivilegeEscalation: false\n  capabilities:\n    drop: ["ALL"]\n```';
    }
    
    if (type === 'Privileged Container') {
      suggestion += '\n\n**Alternative approach with specific capabilities:**\n```yaml\nsecurityContext:\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # Only add specific capabilities needed\n    drop: ["ALL"]\n  runAsNonRoot: true\n  readOnlyRootFilesystem: true\n```';
    }
    
    if (type === 'Host Namespace Sharing') {
      suggestion += '\n\n**Secure namespace isolation:**\n```yaml\nspec:\n  hostNetwork: false\n  hostPID: false\n  hostIPC: false\n  securityContext:\n    runAsNonRoot: true\n    runAsUser: 1000\n```';
    }
    
    if (type === 'Dangerous Capabilities') {
      suggestion += '\n\n**Capabilities restriction example:**\n```yaml\nsecurityContext:\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # Only add what you need\n    drop: ["ALL"]  # Drop all by default\n```';
    }
    
    if (type === 'Writable Root Filesystem') {
      suggestion += '\n\n**Read-only filesystem with writable volumes:**\n```yaml\nsecurityContext:\n  readOnlyRootFilesystem: true\nvolumes:\n- name: tmp-volume\n  emptyDir: {}\n- name: cache-volume\n  emptyDir: {}\n```';
    }
    
    if (type === 'Latest Image Tag') {
      suggestion += `\n\n**Current resource type:** ${context.resourceType}`;
      suggestion += '\n**Recommended:** Use specific version tags for reproducible deployments';
      suggestion += '\n**Example:** Replace `nginx:latest` with `nginx:1.21.6`';
    }
    
    if (type === 'Service Account Token Mounting') {
      suggestion += '\n\n**Disable automatic token mounting:**\n```yaml\nspec:\n  automountServiceAccountToken: false\n  serviceAccountName: my-service-account\n```';
    }
    
    if (type === 'Host Path Volume') {
      suggestion += '\n\n**Secure volume alternatives:**\n```yaml\n# Use emptyDir instead of hostPath\nvolumes:\n- name: app-data\n  emptyDir: {}\n\n# If hostPath is required, use read-only\n- name: host-data\n  hostPath:\n    path: /var/lib/app\n    type: DirectoryOrCreate\n  readOnly: true\n```';
    }
    
    return suggestion;
  }

  private checkMissingPractices(context: KubernetesContext): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    if (context.resourceType === 'unknown') {
      return issues;
    }
    
    if (!context.hasSecurityContext) {
      issues.push(this.createIssue(
        'Kubernetes Manifest',
        1,
        1,
        'apiVersion: ...',
        'Missing security context: No security constraints defined - default insecure baseline',
        'Add security context with non-root user and read-only filesystem:\n```yaml\nsecurityContext:\n  runAsNonRoot: true\n  runAsUser: 1000\n  readOnlyRootFilesystem: true\n  allowPrivilegeEscalation: false\n```',
        'high'
      ));
    }
    
    if (!context.hasResourceLimits) {
      issues.push(this.createIssue(
        'Kubernetes Manifest',
        1,
        1,
        'apiVersion: ...',
        'Missing resource limits: No resource constraints defined - risk of denial-of-service',
        'Add resource limits to prevent resource exhaustion attacks:\n```yaml\nresources:\n  requests:\n    cpu: "100m"\n    memory: "128Mi"\n  limits:\n    cpu: "500m"\n    memory: "512Mi"\n```',
        'medium'
      ));
    }
    
    if (!context.hasServiceAccount && (context.resourceType === 'Pod' || context.resourceType === 'Deployment')) {
      issues.push(this.createIssue(
        'Kubernetes Manifest',
        1,
        1,
        'apiVersion: ...',
        'Missing service account: Using overly-permissive default service account',
        'Create dedicated service account with minimal permissions:\n```yaml\nspec:\n  serviceAccountName: my-service-account\n  automountServiceAccountToken: false\n```',
        'medium'
      ));
    }
    
    if (!context.hasNetworkPolicies) {
      issues.push(this.createIssue(
        'Kubernetes Manifest',
        1,
        1,
        'apiVersion: ...',
        'Missing network policies: All pods have unrestricted network access',
        'Implement network policies to restrict pod-to-pod communication:\n```yaml\nkind: NetworkPolicy\nspec:\n  podSelector: {}\n  policyTypes: ["Ingress", "Egress"]\n```',
        'medium'
      ));
    }
    
    if (!context.hasRBAC && (context.resourceType === 'Pod' || context.resourceType === 'Deployment')) {
      issues.push(this.createIssue(
        'Kubernetes Manifest',
        1,
        1,
        'apiVersion: ...',
        'Missing RBAC: No role-based access control enforcement',
        'Implement RBAC with least privilege principle:\n```yaml\nkind: Role\nrules:\n- apiGroups: [""]\n  resources: ["pods"]\n  verbs: ["get", "list"]\n```',
        'medium'
      ));
    }
    
    if (!context.hasReadinessProbe && !context.hasLivenessProbe && (context.resourceType === 'Pod' || context.resourceType === 'Deployment')) {
      issues.push(this.createIssue(
        'Kubernetes Manifest',
        1,
        1,
        'apiVersion: ...',
        'Missing health checks: No readiness or liveness probes defined',
        'Add health checks for better reliability:\n```yaml\nlivenessProbe:\n  httpGet:\n    path: /health\n    port: 8080\n  initialDelaySeconds: 30\nreadinessProbe:\n  httpGet:\n    path: /ready\n    port: 8080\n```',
        'low'
      ));
    }
    
    if (!context.hasResourceQuotas && context.namespace !== 'default') {
      issues.push(this.createIssue(
        'Kubernetes Manifest',
        1,
        1,
        'apiVersion: ...',
        'Missing resource quotas: No namespace-level resource constraints',
        'Implement resource quotas to prevent resource exhaustion:\n```yaml\nkind: ResourceQuota\nspec:\n  hard:\n    requests.cpu: "2"\n    requests.memory: 4Gi\n    limits.cpu: "4"\n    limits.memory: 8Gi\n```',
        'low'
      ));
    }
    
    if (!context.hasLimitRanges && context.namespace !== 'default') {
      issues.push(this.createIssue(
        'Kubernetes Manifest',
        1,
        1,
        'apiVersion: ...',
        'Missing limit ranges: No default resource limits for pods',
        'Implement limit ranges for default resource constraints:\n```yaml\nkind: LimitRange\nspec:\n  limits:\n  - default:\n      cpu: "500m"\n      memory: "512Mi"\n    type: Container\n```',
        'low'
      ));
    }
    
    return issues;
  }

}
