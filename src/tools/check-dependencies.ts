/**
 * check_dependencies MCP Tool
 *
 * Quick dependency vulnerability scan using npm audit.
 * Does not require AI analysis.
 */

import { z } from 'zod';
import { runNpmAudit, isNpmAvailable, type NpmAuditResponse } from '../core/npm-audit.js';

// Input schema
export const checkDependenciesSchema = z.object({
  path: z.string().describe('Path to directory containing package.json and package-lock.json'),
  includeDevDependencies: z.boolean().optional()
    .describe('Include devDependencies in scan (default: false)'),
});

export type CheckDependenciesInput = z.infer<typeof checkDependenciesSchema>;

// Output type
export interface CheckDependenciesResult {
  vulnerabilities: NpmAuditResponse['vulnerabilities'];
  summary: NpmAuditResponse['summary'];
  error?: string;
  npmAvailable: boolean;
}

/**
 * Execute check_dependencies tool
 */
export async function executeCheckDependencies(
  input: CheckDependenciesInput
): Promise<CheckDependenciesResult> {
  // Check if npm is available
  const npmAvailable = await isNpmAvailable();
  if (!npmAvailable) {
    return {
      vulnerabilities: [],
      summary: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
      error: 'npm is not available. Please install Node.js/npm.',
      npmAvailable: false,
    };
  }

  // Run npm audit
  const result = await runNpmAudit(input.path, {
    includeDevDependencies: input.includeDevDependencies,
  });

  return {
    vulnerabilities: result.vulnerabilities,
    summary: result.summary,
    error: result.error,
    npmAvailable: true,
  };
}
