/**
 * Security finding types
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface CWEReference {
  id: string;
  name: string;
  description?: string;
  mitigations?: string[];
}

export interface OWASPReference {
  id: string;
  name: string;
  description?: string;
}

export interface Remediation {
  summary: string;
  steps: string[];
  priority?: 'immediate' | 'short-term' | 'medium-term';
}

export interface SecurityFinding {
  id: string;
  type: string;
  severity: Severity;
  title: string;
  description: string;
  filePath: string;
  lineNumber?: number;
  columnNumber?: number;
  codeSnippet?: string;

  // AI analysis
  aiReasoning: string;
  confidence: number; // 0-100
  exploitScenario?: string;

  // Research backing
  cwes: CWEReference[];
  owasp: OWASPReference[];

  // Remediation
  remediation: Remediation;
}

export interface DependencyVulnerability {
  packageName: string;
  version: string;
  severity: Severity;
  title: string;
  description: string;
  cveIds: string[];
  patchedVersion?: string;
  url?: string;
}

export interface ScanResult {
  findings: SecurityFinding[];
  dependencyVulnerabilities: DependencyVulnerability[];
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    vulnerableDependencies: number;
  };
  scanDuration: number;
}
