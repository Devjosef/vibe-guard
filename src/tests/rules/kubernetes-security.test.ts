import { KubernetesSecurityRule } from '../../rules/kubernetes-security';
import { FileContent } from '../../types';

describe('KubernetesSecurityRule', () => {
  let rule: KubernetesSecurityRule;

  beforeEach(() => {
    rule = new KubernetesSecurityRule();
  });

  describe('Rule Properties', () => {
    it('should have correct basic properties', () => {
      expect(rule.name).toBe('kubernetes-security');
      expect(rule.description).toBe('Detects Kubernetes security misconfigurations and vulnerabilities');
      expect(rule.severity).toBe('high');
    });
  });

  describe('Core Functionality', () => {
    it('should detect privileged container', () => {
      const content = 'privileged: true';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const privilegedIssues = issues.filter(issue => issue.message.includes('Privileged Container'));
      expect(privilegedIssues).toHaveLength(1);
      expect(privilegedIssues[0]?.severity).toBe('critical');
      expect(privilegedIssues[0]?.message).toContain('Privileged Container');
    });

    it('should detect host namespace sharing', () => {
      const content = 'hostNetwork: true';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const hostIssues = issues.filter(issue => issue.message.includes('Host Namespace Sharing'));
      expect(hostIssues).toHaveLength(1);
      expect(hostIssues[0]?.severity).toBe('high');
      expect(hostIssues[0]?.message).toContain('Host Namespace Sharing');
    });

    it('should detect root user execution', () => {
      const content = 'runAsUser: 0';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const rootIssues = issues.filter(issue => issue.message.includes('Root User Execution'));
      expect(rootIssues).toHaveLength(1);
      expect(rootIssues[0]?.severity).toBe('critical');
      expect(rootIssues[0]?.message).toContain('Root User Execution');
    });

    it('should detect non-root disabled', () => {
      const content = 'runAsNonRoot: false';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const nonRootIssues = issues.filter(issue => issue.message.includes('Non-Root Disabled'));
      expect(nonRootIssues).toHaveLength(1);
      expect(nonRootIssues[0]?.severity).toBe('critical');
      expect(nonRootIssues[0]?.message).toContain('Non-Root Disabled');
    });

    it('should detect writable root filesystem', () => {
      const content = 'readOnlyRootFilesystem: false';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const filesystemIssues = issues.filter(issue => issue.message.includes('Writable Root Filesystem'));
      expect(filesystemIssues).toHaveLength(1);
      expect(filesystemIssues[0]?.severity).toBe('medium');
      expect(filesystemIssues[0]?.message).toContain('Writable Root Filesystem');
    });

    it('should detect privilege escalation allowed', () => {
      const content = 'allowPrivilegeEscalation: true';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const privilegeEscalationIssues = issues.filter(issue => issue.message.includes('Privilege Escalation Allowed'));
      expect(privilegeEscalationIssues).toHaveLength(1);
      expect(privilegeEscalationIssues[0]?.severity).toBe('high');
      expect(privilegeEscalationIssues[0]?.message).toContain('Privilege Escalation Allowed');
    });

    it('should detect dangerous capabilities', () => {
      const content = 'capabilities:\n  add: ["SYS_ADMIN"]';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const capabilityIssues = issues.filter(issue => issue.message.includes('Dangerous Capabilities'));
      expect(capabilityIssues).toHaveLength(1);
      expect(capabilityIssues[0]?.severity).toBe('critical');
      expect(capabilityIssues[0]?.message).toContain('Dangerous Capabilities');
    });

    it('should detect latest image tag', () => {
      const content = 'image: nginx:latest';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const latestTagIssues = issues.filter(issue => issue.message.includes('Latest Image Tag'));
      expect(latestTagIssues).toHaveLength(1);
      expect(latestTagIssues[0]?.severity).toBe('medium');
      expect(latestTagIssues[0]?.message).toContain('Latest Image Tag');
    });

    it('should detect always pull policy', () => {
      const content = 'imagePullPolicy: Always';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const alwaysPullIssues = issues.filter(issue => issue.message.includes('Always Pull Policy'));
      expect(alwaysPullIssues).toHaveLength(1);
      expect(alwaysPullIssues[0]?.severity).toBe('low');
      expect(alwaysPullIssues[0]?.message).toContain('Always Pull Policy');
    });

    it('should detect service account token mounting', () => {
      const content = 'automountServiceAccountToken: true';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const serviceAccountIssues = issues.filter(issue => issue.message.includes('Service Account Token Mounting'));
      expect(serviceAccountIssues).toHaveLength(1);
      expect(serviceAccountIssues[0]?.severity).toBe('medium');
      expect(serviceAccountIssues[0]?.message).toContain('Service Account Token Mounting');
    });

    it('should detect host path volume', () => {
      const content = 'hostPath:\n  path: /var/lib/data';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const hostPathIssues = issues.filter(issue => issue.message.includes('Host Path Volume'));
      expect(hostPathIssues).toHaveLength(1);
      expect(hostPathIssues[0]?.severity).toBe('high');
      expect(hostPathIssues[0]?.message).toContain('Host Path Volume');
    });
  });

  describe('Context-Aware Behavior', () => {
    it('should escalate severity for privileged container with context', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    securityContext:
      privileged: true
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const privilegedIssues = issues.filter(issue => issue.message.includes('Privileged Container'));
      expect(privilegedIssues).toHaveLength(1);
      expect(privilegedIssues[0]?.severity).toBe('critical');
    });

    it('should escalate severity for root user without non-root enforcement', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    securityContext:
      runAsUser: 0
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const rootIssues = issues.filter(issue => issue.message.includes('Root User Execution'));
      expect(rootIssues).toHaveLength(1);
      expect(rootIssues[0]?.severity).toBe('critical');
    });

    it('should escalate severity for host namespace sharing', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const hostIssues = issues.filter(issue => issue.message.includes('Host Namespace Sharing'));
      expect(hostIssues).toHaveLength(3);
      expect(hostIssues.every(issue => issue.severity === 'high')).toBe(true);
    });

    it('should provide enhanced suggestions for root user execution', () => {
      const content = 'runAsUser: 0';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const rootIssues = issues.filter(issue => issue.message.includes('Root User Execution'));
      expect(rootIssues).toHaveLength(1);
      expect(rootIssues[0]?.suggestion).toContain('runAsNonRoot: true');
      expect(rootIssues[0]?.suggestion).toContain('runAsUser: 1000');
      expect(rootIssues[0]?.suggestion).toContain('readOnlyRootFilesystem: true');
    });

    it('should provide enhanced suggestions for privileged container', () => {
      const content = 'privileged: true';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const privilegedIssues = issues.filter(issue => issue.message.includes('Privileged Container'));
      expect(privilegedIssues).toHaveLength(1);
      expect(privilegedIssues[0]?.suggestion).toContain('capabilities:');
      expect(privilegedIssues[0]?.suggestion).toContain('add: ["NET_BIND_SERVICE"]');
      expect(privilegedIssues[0]?.suggestion).toContain('drop: ["ALL"]');
    });

    it('should provide enhanced suggestions for dangerous capabilities', () => {
      const content = 'capabilities:\n  add: ["SYS_ADMIN"]';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const capabilityIssues = issues.filter(issue => issue.message.includes('Dangerous Capabilities'));
      expect(capabilityIssues).toHaveLength(1);
      expect(capabilityIssues[0]?.suggestion).toContain('capabilities:');
      expect(capabilityIssues[0]?.suggestion).toContain('add: ["NET_BIND_SERVICE"]');
      expect(capabilityIssues[0]?.suggestion).toContain('drop: ["ALL"]');
    });

    it('should provide enhanced suggestions for writable root filesystem', () => {
      const content = 'readOnlyRootFilesystem: false';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const filesystemIssues = issues.filter(issue => issue.message.includes('Writable Root Filesystem'));
      expect(filesystemIssues).toHaveLength(1);
      expect(filesystemIssues[0]?.suggestion).toContain('readOnlyRootFilesystem: true');
      expect(filesystemIssues[0]?.suggestion).toContain('emptyDir: {}');
    });
  });

  describe('Missing Best Practices', () => {
    it('should detect missing security context', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    image: nginx:1.21.6
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const missingContextIssues = issues.filter(issue => issue.message.includes('Missing security context'));
      expect(missingContextIssues).toHaveLength(1);
      expect(missingContextIssues[0]?.severity).toBe('high');
    });

    it('should detect missing resource limits', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    image: nginx:1.21.6
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const missingLimitsIssues = issues.filter(issue => issue.message.includes('Missing resource limits'));
      expect(missingLimitsIssues).toHaveLength(1);
      expect(missingLimitsIssues[0]?.severity).toBe('medium');
    });

    it('should detect missing service account for pods', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    image: nginx:1.21.6
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const missingSAIssues = issues.filter(issue => issue.message.includes('Missing service account'));
      expect(missingSAIssues).toHaveLength(1);
      expect(missingSAIssues[0]?.severity).toBe('medium');
    });

    it('should detect missing network policies', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    image: nginx:1.21.6
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const missingNPIssues = issues.filter(issue => issue.message.includes('Missing network policies'));
      expect(missingNPIssues).toHaveLength(1);
      expect(missingNPIssues[0]?.severity).toBe('medium');
    });

    it('should detect missing RBAC for deployments', () => {
      const content = `
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: test
        image: nginx:1.21.6
`;
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const missingRBACIssues = issues.filter(issue => issue.message.includes('Missing RBAC'));
      expect(missingRBACIssues).toHaveLength(1);
      expect(missingRBACIssues[0]?.severity).toBe('medium');
    });

    it('should detect missing health checks', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    image: nginx:1.21.6
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const missingHealthIssues = issues.filter(issue => issue.message.includes('Missing health checks'));
      expect(missingHealthIssues).toHaveLength(1);
      expect(missingHealthIssues[0]?.severity).toBe('low');
    });
  });

  describe('Edge Cases', () => {
    it('should handle complex Kubernetes manifests', () => {
      const content = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: complex-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: complex-app
  template:
    metadata:
      labels:
        app: complex-app
    spec:
      serviceAccountName: complex-app-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      containers:
      - name: web
        image: nginx:latest
        securityContext:
          privileged: true
          runAsUser: 0
          allowPrivilegeEscalation: true
          capabilities:
            add: ["SYS_ADMIN", "NET_ADMIN"]
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 80
        readinessProbe:
          httpGet:
            path: /ready
            port: 80
      - name: redis
        image: redis:latest
        securityContext:
          runAsNonRoot: false
        resources:
          requests:
            memory: "32Mi"
            cpu: "100m"
          limits:
            memory: "64Mi"
            cpu: "200m"
      volumes:
      - name: host-data
        hostPath:
          path: /var/lib/data
      - name: config
        configMap:
          name: app-config
`;
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      
      // Should detect multiple issues
      const privilegedIssues = issues.filter(issue => issue.message.includes('Privileged Container'));
      const rootIssues = issues.filter(issue => issue.message.includes('Root User Execution'));
      const capabilityIssues = issues.filter(issue => issue.message.includes('Dangerous Capabilities'));
      const latestTagIssues = issues.filter(issue => issue.message.includes('Latest Image Tag'));
      const hostPathIssues = issues.filter(issue => issue.message.includes('Host Path Volume'));
      
      expect(privilegedIssues).toHaveLength(1);
      expect(rootIssues).toHaveLength(1);
      expect(capabilityIssues).toHaveLength(2); // SYS_ADMIN and NET_ADMIN both detected
      expect(latestTagIssues).toHaveLength(2);
      expect(hostPathIssues).toHaveLength(1);
    });

    it('should handle empty content', () => {
      const content = '';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should handle content with only comments', () => {
      const content = '# This is a comment\n# Another comment';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should handle different resource types', () => {
      const content = `
apiVersion: v1
kind: Service
metadata:
  name: test-service
spec:
  selector:
    app: test
  ports:
  - port: 80
    targetPort: 8080
`;
      const fileContent: FileContent = {
        path: 'k8s-service.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      // Services don't have containers, so should have fewer issues
      expect(issues.length).toBeLessThan(10);
    });
  });

  describe('False Positive Prevention', () => {
    it('should NOT detect issues in non-Kubernetes files', () => {
      const content = 'privileged: true';
      const fileContent: FileContent = {
        path: 'docker-compose.yml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should NOT detect root user when non-root is enforced', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    securityContext:
      runAsUser: 0
      runAsNonRoot: true
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const rootIssues = issues.filter(issue => issue.message.includes('Root User Execution'));
      expect(rootIssues).toHaveLength(0);
    });

    it('should NOT detect issues when using non-root user', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    securityContext:
      runAsUser: 1000
      runAsNonRoot: true
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const rootIssues = issues.filter(issue => issue.message.includes('Root User Execution'));
      const nonRootIssues = issues.filter(issue => issue.message.includes('Non-Root Disabled'));
      expect(rootIssues).toHaveLength(0);
      expect(nonRootIssues).toHaveLength(0);
    });

    it('should NOT detect issues when using read-only root filesystem', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    securityContext:
      readOnlyRootFilesystem: true
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const filesystemIssues = issues.filter(issue => issue.message.includes('Writable Root Filesystem'));
      expect(filesystemIssues).toHaveLength(0);
    });

    it('should NOT detect issues when privilege escalation is disabled', () => {
      const content = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    securityContext:
      allowPrivilegeEscalation: false
`;
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const privilegeEscalationIssues = issues.filter(issue => issue.message.includes('Privilege Escalation Allowed'));
      expect(privilegeEscalationIssues).toHaveLength(0);
    });

    it('should NOT detect issues when using specific image tags', () => {
      const content = 'image: nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const latestTagIssues = issues.filter(issue => issue.message.includes('Latest Image Tag'));
      expect(latestTagIssues).toHaveLength(0);
    });

    it('should NOT detect issues when using IfNotPresent pull policy', () => {
      const content = 'imagePullPolicy: IfNotPresent';
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const alwaysPullIssues = issues.filter(issue => issue.message.includes('Always Pull Policy'));
      expect(alwaysPullIssues).toHaveLength(0);
    });
  });

  describe('Performance', () => {
    it('should handle large Kubernetes manifests efficiently', () => {
      const largeContent = Array(100).fill('  - name: test\n    value: "test"').join('\n');
      const vulnerableLine = '        privileged: true';
      const content = largeContent + '\n' + vulnerableLine + '\n' + largeContent;
      
      const fileContent: FileContent = {
        path: 'k8s-pod.yaml',
        content,
        lines: content.split('\n')
      };

      const startTime = Date.now();
      const issues = rule.check(fileContent);
      const endTime = Date.now();

      const privilegedIssues = issues.filter(issue => issue.message.includes('Privileged Container'));
      expect(privilegedIssues).toHaveLength(1);
      expect(endTime - startTime).toBeLessThan(1000); // 1 second timeout
    });
  });
});
