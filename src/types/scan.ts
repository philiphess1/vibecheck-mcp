/**
 * Scan configuration and input types
 */

import type { HotspotCategory } from './hotspot.js';
import type { Severity } from './finding.js';

export interface FileInput {
  path: string;
  content: string;
}

export interface ScanOptions {
  // Input source - one of these required
  path?: string;
  files?: FileInput[];

  // Filtering
  categories?: HotspotCategory[];
  severityThreshold?: Severity;

  // Options
  includeDevDependencies?: boolean;
}

export interface ProjectContext {
  hasPackageJson: boolean;
  hasPackageLock: boolean;
  framework?: 'nextjs' | 'react' | 'express' | 'nestjs' | 'fastify';
  database?: 'firebase' | 'supabase' | 'mongodb' | 'postgresql' | 'mysql';
  authProvider?: 'clerk' | 'auth0' | 'nextauth' | 'firebase' | 'supabase';
  isTypeScript: boolean;
}
