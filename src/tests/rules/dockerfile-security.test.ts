import { DockerfileSecurityRule } from '../../rules/dockerfile-security';
import { FileContent } from '../../types';

describe('DockerfileSecurityRule', () => {
  let rule: DockerfileSecurityRule;

  beforeEach(() => {
    rule = new DockerfileSecurityRule();
  });

  describe('Rule Properties', () => {
    it('should have correct basic properties', () => {
      expect(rule.name).toBe('dockerfile-security');
      expect(rule.description).toBe('Detects common Dockerfile security vulnerabilities and misconfigurations');
      expect(rule.severity).toBe('high');
    });
  });

  describe('Core Functionality', () => {
    it('should detect privileged container execution', () => {
      const content = 'FROM ubuntu:22.04\nRUN apt-get update\nUSER root';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const rootIssues = issues.filter(issue => issue.message.includes('Root User Execution'));
      expect(rootIssues).toHaveLength(1);
      expect(rootIssues[0]?.severity).toBe('critical');
    });

    it('should detect latest tag usage', () => {
      const content = 'FROM nginx:latest\nCOPY . /usr/share/nginx/html';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const latestTagIssues = issues.filter(issue => issue.message.includes('Latest Tag Usage'));
      expect(latestTagIssues).toHaveLength(1);
      expect(latestTagIssues[0]?.severity).toBe('high');
    });

    it('should detect exposed ports without justification', () => {
      const content = 'FROM nginx:1.21.6\nEXPOSE 80 443 8080 9000';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const portIssues = issues.filter(issue => issue.message.includes('Port Exposure'));
      expect(portIssues).toHaveLength(1);
      expect(portIssues[0]?.severity).toBe('high');
    });

    it('should detect insecure package installation', () => {
      const content = 'FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const packageIssues = issues.filter(issue => issue.message.includes('Package Installation'));
      expect(packageIssues).toHaveLength(1);
      expect(packageIssues[0]?.severity).toBe('medium');
    });

    it('should detect ADD directive usage', () => {
      const content = 'FROM nginx:1.21.6\nADD . /usr/share/nginx/html';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const addIssues = issues.filter(issue => issue.message.includes('ADD Directive Usage'));
      expect(addIssues).toHaveLength(1);
      expect(addIssues[0]?.severity).toBe('medium');
    });

    it('should detect missing image digest', () => {
      const content = 'FROM nginx:1.21.6\nCOPY . /usr/share/nginx/html';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const digestIssues = issues.filter(issue => issue.message.includes('Missing Image Digest'));
      expect(digestIssues).toHaveLength(1);
      expect(digestIssues[0]?.severity).toBe('high');
    });

    it('should detect insecure download without checksum', () => {
      const content = 'FROM ubuntu:22.04\nRUN curl -O http://example.com/file.tar.gz';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const downloadIssues = issues.filter(issue => issue.message.includes('Insecure Download'));
      expect(downloadIssues).toHaveLength(1);
      expect(downloadIssues[0]?.severity).toBe('high');
    });

    it('should detect unchained RUN commands', () => {
      const content = 'FROM ubuntu:22.04\nRUN apt-get update\nRUN apt-get install -y curl';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const runIssues = issues.filter(issue => issue.message.includes('Unchained RUN Commands'));
      expect(runIssues).toHaveLength(2);
      expect(runIssues[0]?.severity).toBe('medium');
    });

    it('should detect disabled healthcheck', () => {
      const content = 'FROM nginx:1.21.6\nHEALTHCHECK NONE';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const healthcheckIssues = issues.filter(issue => issue.message.includes('Disabled Healthcheck'));
      expect(healthcheckIssues).toHaveLength(1);
      expect(healthcheckIssues[0]?.severity).toBe('medium');
    });

    it('should detect large base image', () => {
      const content = 'FROM ubuntu:22.04\nCOPY . /app';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const largeImageIssues = issues.filter(issue => issue.message.includes('Large Base Image'));
      expect(largeImageIssues).toHaveLength(1);
      expect(largeImageIssues[0]?.severity).toBe('low');
    });
  });

  describe('Context-Aware Behavior', () => {
    it('should escalate severity for public ports', () => {
      const content = 'FROM nginx:1.21.6\nEXPOSE 80 443 8080 9000 3000 5000';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const portIssues = issues.filter(issue => issue.message.includes('Port Exposure'));
      expect(portIssues).toHaveLength(1);
      expect(portIssues[0]?.severity).toBe('high');
    });

    it('should provide enhanced suggestions for package installation', () => {
      const content = 'FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
      const packageIssues = issues.filter(issue => issue.message.includes('Package Installation'));
      expect(packageIssues).toHaveLength(1);
      expect(packageIssues[0]?.suggestion).toContain('Pin package versions');
      expect(packageIssues[0]?.suggestion).toContain('apt-get install -y package=1.2.3');
    });

    it('should detect missing .dockerignore', () => {
      const content = 'FROM nginx:1.21.6\nCOPY . /usr/share/nginx/html';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const missingPractices = issues.filter(issue => issue.message.includes('Missing .dockerignore'));
      expect(missingPractices).toHaveLength(1);
      expect(missingPractices[0]?.severity).toBe('medium');
    });

    it('should detect missing WORKDIR', () => {
      const content = 'FROM nginx:1.21.6\nCOPY . /usr/share/nginx/html';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const missingPractices = issues.filter(issue => issue.message.includes('Missing WORKDIR'));
      expect(missingPractices).toHaveLength(1);
      expect(missingPractices[0]?.severity).toBe('medium');
    });

    it('should detect missing maintainer label', () => {
      const content = 'FROM nginx:1.21.6\nCOPY . /usr/share/nginx/html';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const missingPractices = issues.filter(issue => issue.message.includes('Missing maintainer label'));
      expect(missingPractices).toHaveLength(1);
      expect(missingPractices[0]?.severity).toBe('low');
    });
  });

  describe('Edge Cases', () => {
    it('should handle multi-stage builds correctly', () => {
      const content = `
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM nginx:1.21.6
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
`;
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
    });

    it('should handle empty Dockerfile', () => {
      const content = '';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
    });

    it('should handle Dockerfile with only comments', () => {
      const content = '# This is a comment\n# Another comment';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
    });

    it('should handle complex RUN commands with proper chaining', () => {
      const content = 'FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const unchainedIssues = issues.filter(issue => issue.message.includes('Unchained RUN Commands'));
      expect(unchainedIssues).toHaveLength(0);
    });
  });

  describe('False Positive Prevention', () => {
    it('should NOT detect issues in non-Dockerfile files', () => {
      const content = 'FROM nginx:latest\nUSER root';
      const fileContent: FileContent = {
        path: 'docker-compose.yml',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      expect(issues.length).toBeGreaterThan(0);
    });

    it('should NOT detect issues when using specific image tags', () => {
      const content = 'FROM nginx:1.21.6@sha256:abc123def456\nCOPY . /usr/share/nginx/html';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const latestTagIssues = issues.filter(issue => issue.message.includes('Latest Tag Usage'));
      const digestIssues = issues.filter(issue => issue.message.includes('Missing Image Digest'));
      expect(latestTagIssues).toHaveLength(0);
      expect(digestIssues).toHaveLength(1);
    });

    it('should NOT detect issues when using COPY instead of ADD', () => {
      const content = 'FROM nginx:1.21.6\nCOPY . /usr/share/nginx/html';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const addIssues = issues.filter(issue => issue.message.includes('ADD Directive Usage'));
      expect(addIssues).toHaveLength(0);
    });

    it('should NOT detect issues when using non-root user', () => {
      const content = 'FROM nginx:1.21.6\nUSER nginx\nCOPY . /usr/share/nginx/html';
      const fileContent: FileContent = {
        path: 'Dockerfile',
        content,
        lines: content.split('\n')
      };

      const issues = rule.check(fileContent);
      const rootIssues = issues.filter(issue => issue.message.includes('Root User Execution'));
      expect(rootIssues).toHaveLength(0);
    });
  });

  describe('Performance', () => {
    it('should handle large Dockerfiles efficiently', () => {
      const largeContent = Array(100).fill('RUN echo "test"').join('\n');
      const vulnerableLine = 'FROM nginx:latest';
      const content = largeContent + '\n' + vulnerableLine + '\n' + largeContent;
      
      const fileContent: FileContent = {
        path: 'Dockerfile',
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
