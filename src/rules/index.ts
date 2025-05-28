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
  // Export additional rules here as they are created
};

export * from '../types'; 