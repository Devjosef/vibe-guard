import { ContainerRegistrySecurityRule } from '../../rules/container-registry-security';
import { FileContent } from '../../types';

describe('ContainerRegistrySecurityRule', () => {
  let rule: ContainerRegistrySecurityRule;

  beforeEach(() => {
    rule = new ContainerRegistrySecurityRule();
  });

  describe('Rule Properties', () => {
    it('should have correct basic properties', () => {
      expect(rule.name).toBe('container-registry-security');
      expect(rule.description).toBe('Detects container registry security misconfigurations and vulnerabilities');
      expect(rule.severity).toBe('medium');
    });
  });

  describe('Core Functionality', () => {
    it('should detect latest image tag usage', () => {
      const content = 'image: nginx:latest';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const latestTagIssues = issues.filter(issue => issue.message.includes('Latest Tag Usage'));
      expect(latestTagIssues).toHaveLength(1);
      expect(latestTagIssues[0]?.severity).toBe('high');
    });

    it('should detect missing image digest', () => {
      const content = 'image: nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const digestIssues = issues.filter(issue => issue.message.includes('Missing Image Digest'));
      expect(digestIssues).toHaveLength(1);
      expect(digestIssues[0]?.severity).toBe('high');
    });

    it('should detect insecure image pull', () => {
      const content = 'image: http://insecure-registry.com/nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const insecurePullIssues = issues.filter(issue => issue.message.includes('Insecure Image Pull'));
      expect(insecurePullIssues).toHaveLength(1);
      expect(insecurePullIssues[0]?.severity).toBe('high');
    });

    it('should detect public registry usage', () => {
      const content = 'image: docker.io/nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const publicRegistryIssues = issues.filter(issue => issue.message.includes('Public Registry Usage'));
      expect(publicRegistryIssues).toHaveLength(1);
      expect(publicRegistryIssues[0]?.severity).toBe('high');
    });

    it('should detect always pull policy', () => {
      const content = 'imagePullPolicy: Always';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0]?.severity).toBe('low');
      expect(issues[0]?.message).toContain('Always Pull Policy');
    });

    it('should detect insecure registry usage', () => {
      const content = 'image: insecure-registry.com/nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const insecureRegistryIssues = issues.filter(issue => issue.message.includes('Insecure Registry'));
      expect(insecureRegistryIssues).toHaveLength(1);
      expect(insecureRegistryIssues[0]?.severity).toBe('critical');
    });
  });

  describe('Context-Aware Behavior', () => {
    it('should escalate severity for public registry without scanning', () => {
      const content = 'image: docker.io/nginx:latest';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const latestTagIssues = issues.filter(issue => issue.message.includes('Latest Tag Usage'));
      expect(latestTagIssues).toHaveLength(1);
      expect(latestTagIssues[0]?.severity).toBe('high');
    });

    it('should escalate severity for missing image scanning on public registries', () => {
      const content = 'image: docker.io/nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const missingScanningIssues = issues.filter(issue => issue.message.includes('Missing Image Scanning'));
      expect(missingScanningIssues).toHaveLength(1);
      expect(missingScanningIssues[0]?.severity).toBe('high');
    });

    it('should escalate severity for private registry without pull secrets', () => {
      const content = 'image: private-registry.com/nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const missingSecretsIssues = issues.filter(issue => issue.message.includes('Missing image pull secrets'));
      expect(missingSecretsIssues).toHaveLength(1);
      expect(missingSecretsIssues[0]?.severity).toBe('high');
    });

    it('should provide enhanced suggestions for secure image usage', () => {
      const content = 'image: nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const digestIssues = issues.filter(issue => issue.message.includes('Missing Image Digest'));
      expect(digestIssues).toHaveLength(1);
      expect(digestIssues[0]?.suggestion).toContain('nginx@sha256:abc123def456');
      expect(digestIssues[0]?.suggestion).toContain('imagePullPolicy: IfNotPresent');
    });

    it('should provide Trivy scanning suggestions', () => {
      const content = 'image: docker.io/nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const scanningIssues = issues.filter(issue => issue.message.includes('Missing Image Scanning'));
      expect(scanningIssues).toHaveLength(1);
      expect(scanningIssues[0]?.suggestion).toContain('trivy image');
      expect(scanningIssues[0]?.suggestion).toContain('vulnerability scanning');
    });

    it('should provide Cosign signing suggestions', () => {
      const content = 'image: docker.io/nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const signingIssues = issues.filter(issue => issue.message.includes('Missing Image Signature'));
      expect(signingIssues).toHaveLength(1);
      expect(signingIssues[0]?.suggestion).toContain('cosign sign');
      expect(signingIssues[0]?.suggestion).toContain('image signing');
    });
  });

  describe('Edge Cases', () => {
    it('should handle multiple image references in same file', () => {
      const content = `
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:latest
      - name: redis
        image: redis:latest
`;
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const latestTagIssues = issues.filter(issue => issue.message.includes('Latest Tag Usage'));
      expect(latestTagIssues).toHaveLength(2);
    });

    it('should handle image references in different contexts', () => {
      const content = `
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:1.21.6
        imagePullPolicy: Always
      initContainers:
      - name: init
        image: busybox:latest
`;
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
    });

    it('should handle empty content', () => {
      const content = '';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should handle content with only comments', () => {
      const content = '# This is a comment\n# Another comment';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(0);
    });

    it('should handle complex YAML structures', () => {
      const content = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: complex-app
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
      containers:
      - name: web
        image: nginx:latest
        ports:
        - containerPort: 80
        env:
        - name: ENV_VAR
          value: "test"
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
`;
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
    });
  });

  describe('False Positive Prevention', () => {
    it('should NOT detect issues in non-Kubernetes files', () => {
      const content = 'image: nginx:latest';
      const fileContent: FileContent = {
        path: 'docker-compose.yml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
    });

    it('should NOT detect issues when using image digest', () => {
      const content = 'image: nginx@sha256:abc123def456789';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const digestIssues = issues.filter(issue => issue.message.includes('Missing Image Digest'));
      const latestTagIssues = issues.filter(issue => issue.message.includes('Latest Image Tag'));
      expect(digestIssues).toHaveLength(0);
      expect(latestTagIssues).toHaveLength(0);
    });

    it('should NOT detect issues when using specific version tags', () => {
      const content = 'image: nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
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
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const alwaysPullIssues = issues.filter(issue => issue.message.includes('Always Pull Policy'));
      expect(alwaysPullIssues).toHaveLength(0);
    });

    it('should NOT detect issues when using secure registry', () => {
      const content = 'image: secure-registry.com/nginx:1.21.6';
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      const insecureRegistryIssues = issues.filter(issue => issue.message.includes('Insecure Registry'));
      expect(insecureRegistryIssues).toHaveLength(0);
    });
  });

  describe('Performance', () => {
    it('should handle large Kubernetes manifests efficiently', () => {
      const largeContent = Array(100).fill('  - name: test\n    value: "test"').join('\n');
      const vulnerableLine = '        image: nginx:latest';
      const content = largeContent + '\n' + vulnerableLine + '\n' + largeContent;
      
      const fileContent: FileContent = {
        path: 'k8s-deployment.yaml',
        content,
        lines: content.split('\n')
      };

      const startTime = Date.now();
      const issues = rule.check(fileContent);
      const endTime = Date.now();

      expect(issues.length).toBeGreaterThan(0);
      expect(endTime - startTime).toBeLessThan(1000);
    });
  });
});
