/**
 * Hotspot categorization types
 */

export type HotspotCategory =
  | 'auth'
  | 'api'
  | 'database-rules'
  | 'secrets-env'
  | 'dependencies'
  | 'data-flow';

export type HotspotPriority = 'critical' | 'high' | 'medium';

export interface ParsedFile {
  path: string;
  content: string;
  size: number;
  extension: string;
}

export interface SecurityHotspot {
  category: HotspotCategory;
  files: ParsedFile[];
  priority: HotspotPriority;
  reason: string;
}

export interface HotspotAnalysis {
  hotspots: SecurityHotspot[];
  skippedFiles: string[];
  totalFiles: number;
  securityRelevantFiles: number;
}

export interface CategoryPattern {
  category: HotspotCategory;
  priority: HotspotPriority;
  pathPatterns: RegExp[];
  contentPatterns: RegExp[];
  description: string;
}

export interface SkipPattern {
  name: string;
  pattern: RegExp;
  reason: string;
}
