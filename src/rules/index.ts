import { BaseRule } from '../types';
import { ExposedSecretsRule } from './exposed-secrets';
import { MissingAuthenticationRule } from './missing-authentication';
import { OpenCorsRule } from './open-cors';
import { HardcodedSensitiveDataRule } from './hardcoded-sensitive-data';
import { InsecureHttpRule } from './insecure-http';
import { SqlInjectionRule } from './sql-injection';
import { UnvalidatedInputRule } from './unvalidated-input';
import { DirectoryTraversalRule } from './directory-traversal';
import { InsecureDependenciesRule } from './insecure-dependencies';
import { MissingSecurityHeadersRule } from './missing-security-headers';
import { XssDetectionRule } from './xss-detection';
import { CsrfProtectionRule } from './csrf-protection';
import { InsecureDeserializationRule } from './insecure-deserialization';
import { BrokenAccessControlRule } from './broken-access-control';
import { InsecureFileUploadRule } from './insecure-file-upload';
import { InsecureRandomGenerationRule } from './insecure-random-generation';
import { InsecureLoggingRule } from './insecure-logging';
import { InsecureSessionManagementRule } from './insecure-session-management';
import { InsecureErrorHandlingRule } from './insecure-error-handling';
import { InsecureConfigurationRule } from './insecure-configuration';
import { AiGeneratedCodeValidationRule } from './ai-generated-code-validation';
import { AiAgentAccessControlRule } from './ai-agent-access-control';
import { AiDataLeakagePreventionRule } from './ai-data-leakage-prevention';
import { McpServerSecurityRule } from './mcp-server-security';
import { PromptInjectionDetectionRule } from './prompt-injection-detection';

export function getAllRules(): BaseRule[] {
  return [
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
    new AiGeneratedCodeValidationRule(),
    new AiAgentAccessControlRule(),
    new AiDataLeakagePreventionRule(),
    new McpServerSecurityRule(),
    new PromptInjectionDetectionRule(),
  ];
}

export {
  ExposedSecretsRule,
  MissingAuthenticationRule,
  OpenCorsRule,
  HardcodedSensitiveDataRule,
  InsecureHttpRule,
  SqlInjectionRule,
  UnvalidatedInputRule,
  DirectoryTraversalRule,
  InsecureDependenciesRule,
  MissingSecurityHeadersRule,
  XssDetectionRule,
  CsrfProtectionRule,
  InsecureDeserializationRule,
  BrokenAccessControlRule,
  InsecureFileUploadRule,
  InsecureRandomGenerationRule,
  InsecureLoggingRule,
  InsecureSessionManagementRule,
  InsecureErrorHandlingRule,
  InsecureConfigurationRule,
  AiGeneratedCodeValidationRule,
  AiAgentAccessControlRule,
  AiDataLeakagePreventionRule,
  McpServerSecurityRule,
  PromptInjectionDetectionRule,
};

export * from '../types'; 