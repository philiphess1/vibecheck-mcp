/**
 * npm audit integration
 *
 * Runs npm audit to check for dependency vulnerabilities
 * using the GitHub Advisory Database
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { join } from 'path';
import type { DependencyVulnerability, Severity } from '../types/index.js';
import type { NpmAuditResult, NpmAuditVulnerability } from '../security-data/types.js';

const execAsync = promisify(exec);

/**
 * Map npm severity to our severity type
 */
function mapSeverity(npmSeverity: NpmAuditVulnerability['severity']): Severity {
  switch (npmSeverity) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    case 'info':
      return 'info';
    default:
      return 'low';
  }
}

/**
 * Transform npm audit results to our format
 */
function transformAuditResult(result: NpmAuditResult): DependencyVulnerability[] {
  const vulnerabilities: DependencyVulnerability[] = [];

  for (const [name, vuln] of Object.entries(result.vulnerabilities)) {
    // Get fix information
    let patchedVersion: string | undefined;
    if (typeof vuln.fixAvailable === 'object' && vuln.fixAvailable) {
      patchedVersion = vuln.fixAvailable.version;
    }

    // Get vulnerability description from via field
    const description = Array.isArray(vuln.via)
      ? vuln.via.filter((v) => typeof v === 'string').join(', ') || `Vulnerability in ${name}`
      : `Vulnerability in ${name}`;

    vulnerabilities.push({
      packageName: name,
      version: vuln.range,
      severity: mapSeverity(vuln.severity),
      title: `${vuln.severity.toUpperCase()}: ${name}`,
      description,
      cveIds: [], // npm audit doesn't directly expose CVE IDs in this format
      patchedVersion,
    });
  }

  return vulnerabilities;
}

export interface NpmAuditOptions {
  /**
   * Include devDependencies in the audit
   */
  includeDevDependencies?: boolean;

  /**
   * Timeout in milliseconds (default: 60000)
   */
  timeout?: number;
}

export interface NpmAuditResponse {
  vulnerabilities: DependencyVulnerability[];
  summary: {
    info: number;
    low: number;
    moderate: number;
    high: number;
    critical: number;
    total: number;
  };
  error?: string;
}

/**
 * Run npm audit on a directory
 *
 * @param path - Path to directory containing package.json and package-lock.json
 * @param options - Audit options
 */
export async function runNpmAudit(
  path: string,
  options: NpmAuditOptions = {}
): Promise<NpmAuditResponse> {
  const { includeDevDependencies = false, timeout = 60000 } = options;

  // Check for package-lock.json
  const hasPackageLock = existsSync(join(path, 'package-lock.json'));
  const hasYarnLock = existsSync(join(path, 'yarn.lock'));
  const hasPnpmLock = existsSync(join(path, 'pnpm-lock.yaml'));

  if (!hasPackageLock && !hasYarnLock && !hasPnpmLock) {
    return {
      vulnerabilities: [],
      summary: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
      error: 'No lock file found. Run npm install, yarn install, or pnpm install first.',
    };
  }

  // Build command
  let command = 'npm audit --json';
  if (!includeDevDependencies) {
    command += ' --omit=dev';
  }

  try {
    // npm audit returns non-zero exit code if vulnerabilities found
    // so we need to handle both success and "error" cases
    const { stdout, stderr } = await execAsync(command, {
      cwd: path,
      timeout,
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large outputs
    });

    if (stderr && !stdout) {
      return {
        vulnerabilities: [],
        summary: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
        error: stderr,
      };
    }

    const result: NpmAuditResult = JSON.parse(stdout);
    const vulnerabilities = transformAuditResult(result);

    return {
      vulnerabilities,
      summary: {
        info: result.metadata.vulnerabilities.info,
        low: result.metadata.vulnerabilities.low,
        moderate: result.metadata.vulnerabilities.moderate,
        high: result.metadata.vulnerabilities.high,
        critical: result.metadata.vulnerabilities.critical,
        total: result.metadata.vulnerabilities.total,
      },
    };
  } catch (error) {
    // npm audit exits with code 1 when vulnerabilities are found
    // but we can still parse the output
    if (error && typeof error === 'object' && 'stdout' in error) {
      const execError = error as { stdout: string; stderr: string };
      if (execError.stdout) {
        try {
          const result: NpmAuditResult = JSON.parse(execError.stdout);
          const vulnerabilities = transformAuditResult(result);

          return {
            vulnerabilities,
            summary: {
              info: result.metadata.vulnerabilities.info,
              low: result.metadata.vulnerabilities.low,
              moderate: result.metadata.vulnerabilities.moderate,
              high: result.metadata.vulnerabilities.high,
              critical: result.metadata.vulnerabilities.critical,
              total: result.metadata.vulnerabilities.total,
            },
          };
        } catch {
          // Fall through to error handling
        }
      }
    }

    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      vulnerabilities: [],
      summary: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
      error: `npm audit failed: ${errorMessage}`,
    };
  }
}

/**
 * Quick check if npm audit is available
 */
export async function isNpmAvailable(): Promise<boolean> {
  try {
    await execAsync('npm --version', { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}
