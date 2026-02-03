/**
 * Hotspot Collector
 *
 * Categorizes files by security relevance without using AI.
 * This is a local, deterministic step that identifies which
 * files should be sent for AI analysis.
 */

import type {
  ParsedFile,
  HotspotCategory,
  HotspotPriority,
  SecurityHotspot,
  HotspotAnalysis,
  CategoryPattern,
  SkipPattern,
} from '../types/index.js';

/**
 * Patterns for each security category
 */
export const CATEGORY_PATTERNS: CategoryPattern[] = [
  {
    category: 'auth',
    priority: 'critical',
    description: 'Authentication, authorization, and session management',
    pathPatterns: [
      /auth/i,
      /login/i,
      /session/i,
      /middleware/i,
      /guard/i,
      /passport/i,
      /oauth/i,
      /jwt/i,
      /token/i,
    ],
    contentPatterns: [
      /verifyToken/i,
      /getServerSession/i,
      /useSession/i,
      /signIn/i,
      /signOut/i,
      /authenticate/i,
      /authorize/i,
      /isAuthenticated/i,
      /currentUser/i,
      /getUser/i,
      /requireAuth/i,
      /checkPermission/i,
      /bcrypt/i,
      /argon2/i,
      /password/i,
      /credential/i,
    ],
  },
  {
    category: 'api',
    priority: 'critical',
    description: 'API routes and endpoints',
    pathPatterns: [
      /\/api\//i,
      /routes?\//i,
      /controllers?\//i,
      /handlers?\//i,
      /endpoints?\//i,
    ],
    contentPatterns: [
      /NextRequest/i,
      /NextResponse/i,
      /Request\s*,/i,
      /Response\s*\)/i,
      /express\(\)/i,
      /app\.(get|post|put|patch|delete)/i,
      /router\.(get|post|put|patch|delete)/i,
      /createServerAction/i,
      /unstable_cache/i,
    ],
  },
  {
    category: 'database-rules',
    priority: 'critical',
    description: 'Database security rules and schemas',
    pathPatterns: [
      /firestore\.rules/i,
      /storage\.rules/i,
      /database\.rules/i,
      /\.prisma$/i,
      /schema\./i,
    ],
    contentPatterns: [
      /allow\s+(read|write|create|update|delete)/i,
      /rules_version/i,
      /@@map/i,
      /createClient/i,
      /supabase/i,
      /RLS/i,
    ],
  },
  {
    category: 'secrets-env',
    priority: 'high',
    description: 'Environment variables and secrets',
    pathPatterns: [
      /\.env/i,
      /config\./i,
      /secrets?\./i,
      /credentials?\./i,
    ],
    contentPatterns: [
      /process\.env/i,
      /import\.meta\.env/i,
      /NEXT_PUBLIC_/i,
      /VITE_/i,
      /REACT_APP_/i,
      /API_KEY/i,
      /SECRET/i,
      /PASSWORD/i,
      /TOKEN/i,
      /PRIVATE_KEY/i,
      /DATABASE_URL/i,
      /MONGODB_URI/i,
      /REDIS_URL/i,
    ],
  },
  {
    category: 'dependencies',
    priority: 'high',
    description: 'Package dependencies',
    pathPatterns: [
      /package\.json$/i,
    ],
    contentPatterns: [],
  },
  {
    category: 'data-flow',
    priority: 'medium',
    description: 'User input handling and data flow',
    pathPatterns: [],
    contentPatterns: [
      /req\.body/i,
      /req\.query/i,
      /req\.params/i,
      /request\.json\(\)/i,
      /formData/i,
      /searchParams/i,
      /useSearchParams/i,
      /params\./i,
      /dangerouslySetInnerHTML/i,
      /innerHTML/i,
      /eval\(/i,
      /new Function\(/i,
      /exec\(/i,
      /spawn\(/i,
      /child_process/i,
    ],
  },
];

/**
 * Patterns for files to skip entirely
 */
export const SKIP_PATTERNS: SkipPattern[] = [
  { name: 'node_modules', pattern: /node_modules/i, reason: 'Third-party dependencies' },
  { name: 'dist', pattern: /\/dist\//i, reason: 'Build output' },
  { name: 'build', pattern: /\/build\//i, reason: 'Build output' },
  { name: '.next', pattern: /\/\.next\//i, reason: 'Next.js build output' },
  { name: 'coverage', pattern: /\/coverage\//i, reason: 'Test coverage' },
  { name: 'test files', pattern: /\.(test|spec)\.(ts|tsx|js|jsx)$/i, reason: 'Test files' },
  { name: '__tests__', pattern: /__tests__/i, reason: 'Test directory' },
  { name: 'storybook', pattern: /\.stories\.(ts|tsx|js|jsx)$/i, reason: 'Storybook files' },
  { name: 'type declarations', pattern: /\.d\.ts$/i, reason: 'Type declarations only' },
  { name: 'CSS', pattern: /\.(css|scss|sass|less)$/i, reason: 'Stylesheets' },
  { name: 'images', pattern: /\.(png|jpg|jpeg|gif|svg|ico|webp)$/i, reason: 'Images' },
  { name: 'fonts', pattern: /\.(woff|woff2|ttf|eot|otf)$/i, reason: 'Fonts' },
  { name: 'markdown', pattern: /\.(md|mdx)$/i, reason: 'Documentation' },
  { name: 'UI components', pattern: /components\/ui\//i, reason: 'UI component library' },
  { name: 'public assets', pattern: /\/public\//i, reason: 'Static assets' },
  { name: 'lock files', pattern: /(package-lock|yarn\.lock|pnpm-lock)/i, reason: 'Lock files' },
];

/**
 * Check if a file should be skipped
 */
export function shouldSkipFile(file: ParsedFile): SkipPattern | null {
  for (const pattern of SKIP_PATTERNS) {
    if (pattern.pattern.test(file.path)) {
      return pattern;
    }
  }
  return null;
}

/**
 * Categorize a single file
 */
export function categorizeFile(file: ParsedFile): HotspotCategory[] {
  const categories: HotspotCategory[] = [];

  for (const pattern of CATEGORY_PATTERNS) {
    // Check path patterns
    const pathMatch = pattern.pathPatterns.some((p) => p.test(file.path));

    // Check content patterns
    const contentMatch = pattern.contentPatterns.some((p) => p.test(file.content));

    if (pathMatch || contentMatch) {
      categories.push(pattern.category);
    }
  }

  return categories;
}

/**
 * Get priority for a category
 */
function getCategoryPriority(category: HotspotCategory): HotspotPriority {
  const pattern = CATEGORY_PATTERNS.find((p) => p.category === category);
  return pattern?.priority || 'medium';
}

/**
 * Get description for a category
 */
function getCategoryDescription(category: HotspotCategory): string {
  const pattern = CATEGORY_PATTERNS.find((p) => p.category === category);
  return pattern?.description || category;
}

/**
 * Collect security hotspots from files
 */
export function collectSecurityHotspots(files: ParsedFile[]): HotspotAnalysis {
  const hotspotMap = new Map<HotspotCategory, ParsedFile[]>();
  const skippedFiles: string[] = [];

  for (const file of files) {
    // Check if file should be skipped
    const skipReason = shouldSkipFile(file);
    if (skipReason) {
      skippedFiles.push(file.path);
      continue;
    }

    // Categorize file
    const categories = categorizeFile(file);

    for (const category of categories) {
      if (!hotspotMap.has(category)) {
        hotspotMap.set(category, []);
      }
      hotspotMap.get(category)!.push(file);
    }
  }

  // Build hotspot list
  const hotspots: SecurityHotspot[] = [];

  for (const [category, categoryFiles] of hotspotMap) {
    hotspots.push({
      category,
      files: categoryFiles,
      priority: getCategoryPriority(category),
      reason: getCategoryDescription(category),
    });
  }

  // Sort by priority
  const priorityOrder: Record<HotspotPriority, number> = {
    critical: 0,
    high: 1,
    medium: 2,
  };

  hotspots.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  // Count security-relevant files (unique)
  const securityRelevantSet = new Set<string>();
  for (const hotspot of hotspots) {
    for (const file of hotspot.files) {
      securityRelevantSet.add(file.path);
    }
  }

  return {
    hotspots,
    skippedFiles,
    totalFiles: files.length,
    securityRelevantFiles: securityRelevantSet.size,
  };
}

/**
 * Filter hotspots by category
 */
export function filterHotspots(
  analysis: HotspotAnalysis,
  categories: HotspotCategory[]
): HotspotAnalysis {
  const categorySet = new Set(categories);

  return {
    ...analysis,
    hotspots: analysis.hotspots.filter((h) => categorySet.has(h.category)),
  };
}
