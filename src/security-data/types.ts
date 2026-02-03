/**
 * Types for security data APIs
 */

export interface CWEData {
  id: string;
  name: string;
  description: string;
  extendedDescription?: string;
  mitigations: string[];
  detectionMethods: string[];
  examples: string[];
  relatedWeaknesses: string[];
  applicablePlatforms: string[];
}

export interface OWASPCategory {
  id: string;
  name: string;
  description: string;
  year: number;
  rank: number;
}

export interface NpmAuditVulnerability {
  name: string;
  severity: 'info' | 'low' | 'moderate' | 'high' | 'critical';
  isDirect: boolean;
  via: string[];
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable: boolean | {
    name: string;
    version: string;
    isSemVerMajor: boolean;
  };
}

export interface NpmAuditResult {
  auditReportVersion: number;
  vulnerabilities: Record<string, NpmAuditVulnerability>;
  metadata: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
      total: number;
    };
    dependencies: {
      prod: number;
      dev: number;
      optional: number;
      peer: number;
      peerOptional: number;
      total: number;
    };
  };
}
