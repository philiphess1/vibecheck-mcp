/**
 * scan_codebase MCP Tool
 *
 * Identifies security-relevant files and checks dependencies for vulnerabilities.
 * Returns hotspots categorized by security risk + npm audit results.
 *
 * The AI analysis is done by Claude Code itself, not by this MCP.
 */

import { z } from 'zod';
import type {
  ParsedFile,
  HotspotCategory,
  DependencyVulnerability,
  ProjectContext,
  SecurityHotspot,
  HotspotAnalysis,
} from '../types/index.js';
import {
  readFilesFromPath,
  parseFileInputs,
  getPackageJson,
  collectSecurityHotspots,
  filterHotspots,
  runNpmAudit,
} from '../core/index.js';
import { fetchCWE, COMMON_CWES } from '../security-data/index.js';

// Input schema
export const scanCodebaseSchema = z.object({
  path: z.string().optional().describe('Absolute path to repository/directory to scan'),
  files: z.array(z.object({
    path: z.string(),
    content: z.string(),
  })).optional().describe('Provide file contents directly'),
  categories: z.array(z.enum([
    'auth', 'api', 'database-rules', 'secrets-env', 'dependencies', 'data-flow',
  ])).optional().describe('Limit to specific categories (default: all)'),
  severityThreshold: z.enum(['critical', 'high', 'medium', 'low']).optional()
    .describe('Only return findings at or above this severity'),
});

export type ScanCodebaseInput = z.infer<typeof scanCodebaseSchema>;

// Output types
export interface HotspotFile {
  path: string;
  content: string;
  size: number;
}

export interface CategoryHotspot {
  category: HotspotCategory;
  priority: 'critical' | 'high' | 'medium';
  reason: string;
  files: HotspotFile[];
  relevantCWEs: string[];
}

export interface ScanCodebaseResult {
  hotspots: CategoryHotspot[];
  dependencyVulnerabilities: DependencyVulnerability[];
  projectContext: ProjectContext;
  summary: {
    totalFiles: number;
    securityRelevantFiles: number;
    skippedFiles: number;
    hotspotCategories: number;
    vulnerableDependencies: number;
  };
  scanDuration: number;
}

// CWEs relevant to each category
const CATEGORY_CWES: Record<HotspotCategory, string[]> = {
  auth: [COMMON_CWES.BROKEN_AUTH, COMMON_CWES.MISSING_AUTH, '384', '613'],
  api: [COMMON_CWES.MISSING_AUTH, COMMON_CWES.SQL_INJECTION, COMMON_CWES.SSRF, '20'],
  'database-rules': ['284', '285', COMMON_CWES.MISSING_AUTH],
  'secrets-env': [COMMON_CWES.HARDCODED_CREDENTIALS, '540', COMMON_CWES.SENSITIVE_DATA_EXPOSURE],
  dependencies: ['1035', '1104'],
  'data-flow': [COMMON_CWES.SQL_INJECTION, COMMON_CWES.COMMAND_INJECTION, COMMON_CWES.XSS, COMMON_CWES.PATH_TRAVERSAL],
};

/**
 * Detect project context from files
 */
function detectProjectContext(files: ParsedFile[]): ProjectContext {
  const packageJson = getPackageJson(files);
  const deps = packageJson && typeof packageJson === 'object' && 'dependencies' in packageJson
    ? (packageJson as { dependencies?: Record<string, string> }).dependencies || {}
    : {};

  return {
    hasPackageJson: !!packageJson,
    hasPackageLock: files.some((f) =>
      f.path.includes('package-lock.json') ||
      f.path.includes('yarn.lock') ||
      f.path.includes('pnpm-lock.yaml')
    ),
    framework:
      'next' in deps ? 'nextjs' :
      'express' in deps ? 'express' :
      '@nestjs/core' in deps ? 'nestjs' :
      'fastify' in deps ? 'fastify' :
      'react' in deps ? 'react' :
      undefined,
    database:
      'firebase' in deps || '@firebase/app' in deps ? 'firebase' :
      '@supabase/supabase-js' in deps ? 'supabase' :
      'mongodb' in deps || 'mongoose' in deps ? 'mongodb' :
      'pg' in deps || '@prisma/client' in deps ? 'postgresql' :
      'mysql2' in deps ? 'mysql' :
      undefined,
    authProvider:
      '@clerk/nextjs' in deps ? 'clerk' :
      'auth0' in deps || '@auth0/nextjs-auth0' in deps ? 'auth0' :
      'next-auth' in deps ? 'nextauth' :
      'firebase' in deps ? 'firebase' :
      '@supabase/supabase-js' in deps ? 'supabase' :
      undefined,
    isTypeScript: files.some((f) => f.extension === '.ts' || f.extension === '.tsx'),
  };
}

/**
 * Transform hotspot to output format with file contents
 */
function transformHotspot(hotspot: SecurityHotspot): CategoryHotspot {
  return {
    category: hotspot.category,
    priority: hotspot.priority,
    reason: hotspot.reason,
    files: hotspot.files.map((f) => ({
      path: f.path,
      content: f.content,
      size: f.size,
    })),
    relevantCWEs: CATEGORY_CWES[hotspot.category].map((id) => `CWE-${id}`),
  };
}

/**
 * Execute scan_codebase tool
 */
export async function executeScanCodebase(
  input: ScanCodebaseInput
): Promise<ScanCodebaseResult> {
  const startTime = Date.now();

  // Get files
  let files: ParsedFile[];
  let basePath: string | undefined;

  if (input.path) {
    files = readFilesFromPath(input.path);
    basePath = input.path;
  } else if (input.files && input.files.length > 0) {
    files = parseFileInputs(input.files);
  } else {
    throw new Error('Either path or files must be provided');
  }

  if (files.length === 0) {
    throw new Error('No files found to scan');
  }

  // Detect project context
  const projectContext = detectProjectContext(files);

  // Collect hotspots
  let analysis = collectSecurityHotspots(files);

  // Filter by categories if specified
  if (input.categories && input.categories.length > 0) {
    analysis = filterHotspots(analysis, input.categories);
  }

  // Run npm audit if we have a path and package-lock
  let dependencyVulnerabilities: DependencyVulnerability[] = [];
  if (basePath && projectContext.hasPackageLock) {
    const auditResult = await runNpmAudit(basePath);
    if (!auditResult.error) {
      dependencyVulnerabilities = auditResult.vulnerabilities;
    }
  }

  // Transform hotspots to output format
  const hotspots = analysis.hotspots.map(transformHotspot);

  return {
    hotspots,
    dependencyVulnerabilities,
    projectContext,
    summary: {
      totalFiles: analysis.totalFiles,
      securityRelevantFiles: analysis.securityRelevantFiles,
      skippedFiles: analysis.skippedFiles.length,
      hotspotCategories: hotspots.length,
      vulnerableDependencies: dependencyVulnerabilities.length,
    },
    scanDuration: Date.now() - startTime,
  };
}
