import * as fs from 'fs';
import * as path from 'path';
import { FileScanner } from './scanner';
import { Reporter } from './reporter';
import { ScanOptions, ScanResult, BaseRule } from './types';
import { ConfigLoader } from './config';
import { ExposedSecretsRule } from './rules/exposed-secrets';
import { MissingAuthenticationRule } from './rules/missing-authentication';
import { OpenCorsRule } from './rules/open-cors';
import { HardcodedSensitiveDataRule } from './rules/hardcoded-sensitive-data';
import { InsecureHttpRule } from './rules/insecure-http';
import { SqlInjectionRule } from './rules/sql-injection';
import { UnvalidatedInputRule } from './rules/unvalidated-input';
import { DirectoryTraversalRule } from './rules/directory-traversal';
import { InsecureDependenciesRule } from './rules/insecure-dependencies';
import { MissingSecurityHeadersRule } from './rules/missing-security-headers';
import { XssDetectionRule } from './rules/xss-detection';
import { CsrfProtectionRule } from './rules/csrf-protection';
import { InsecureDeserializationRule } from './rules/insecure-deserialization';
import { BrokenAccessControlRule } from './rules/broken-access-control';
import { InsecureFileUploadRule } from './rules/insecure-file-upload';
import { InsecureRandomGenerationRule } from './rules/insecure-random-generation';
import { InsecureLoggingRule } from './rules/insecure-logging';
import { InsecureSessionManagementRule } from './rules/insecure-session-management';
import { InsecureErrorHandlingRule } from './rules/insecure-error-handling';
import { InsecureConfigurationRule } from './rules/insecure-configuration';
import { PromptInjectionDetectionRule } from './rules/prompt-injection-detection';
import { AiGeneratedCodeValidationRule } from './rules/ai-generated-code-validation';
import { AiAgentAccessControlRule } from './rules/ai-agent-access-control';
import { AiDataLeakagePreventionRule } from './rules/ai-data-leakage-prevention';
import { McpServerSecurityRule } from './rules/mcp-server-security';
import { KubernetesSecurityRule } from './rules/kubernetes-security';
import { DockerfileSecurityRule } from './rules/dockerfile-security';
import { ContainerRegistrySecurityRule } from './rules/container-registry-security';

export class VibeGuard {
  private readonly scanner = new FileScanner();
  private readonly reporter = new Reporter();
  private readonly rules: BaseRule[];

  constructor() {
    this.rules = [
      new ExposedSecretsRule(),
      new MissingAuthenticationRule(),
      new OpenCorsRule(),
      new HardcodedSensitiveDataRule(),
      new InsecureHttpRule(),
      new SqlInjectionRule(),
      new UnvalidatedInputRule(),
      new DirectoryTraversalRule(),
      new InsecureDependenciesRule(),
      new MissingSecurityHeadersRule(),
      new XssDetectionRule(),
      new CsrfProtectionRule(),
      new InsecureDeserializationRule(),
      new BrokenAccessControlRule(),
      new InsecureFileUploadRule(),
      new InsecureRandomGenerationRule(),
      new InsecureLoggingRule(),
      new InsecureSessionManagementRule(),
      new InsecureErrorHandlingRule(),
      new InsecureConfigurationRule(),
      new PromptInjectionDetectionRule(),
      new AiGeneratedCodeValidationRule(),
      new AiAgentAccessControlRule(),
      new AiDataLeakagePreventionRule(),
      new McpServerSecurityRule(),
      new KubernetesSecurityRule(),
      new DockerfileSecurityRule(),
      new ContainerRegistrySecurityRule()
    ];
  }

  async scan(options: ScanOptions): Promise<ScanResult> {
    const config = ConfigLoader.loadConfig(options.target);
    const mergedOptions = ConfigLoader.mergeConfig(config, options);
    const targetPath = path.resolve(mergedOptions.target);
    
    if (!fs.existsSync(targetPath)) {
      throw new Error(`Target path does not exist: ${targetPath}`);
    }

    return this.scanner.scan(targetPath, this.rules);
  }

  formatResults(result: ScanResult, format: string = 'table'): string {
  if (format === 'json') {
    return this.reporter.formatJson(result);
  }
  return this.reporter.formatTable(result); 
}

  async scanAndFormat(options: ScanOptions): Promise<string> {
    const result = await this.scan(options);
    return this.formatResults(result, options.format);
  }

  getRules(): BaseRule[] {
    return [...this.rules];
  }

  getRuleByName(name: string): BaseRule | undefined {
    return this.rules.find(rule => rule.name === name);
  }

  generateConfig(): string {
    return ConfigLoader.generateSampleConfig();
  }

  createConfigFile(): void {
    const configPath = path.join(process.cwd(), 'vibe-guard.json');
    if (fs.existsSync(configPath)) return;
    fs.writeFileSync(configPath, ConfigLoader.generateSampleConfig());
  }
}

export default VibeGuard;
