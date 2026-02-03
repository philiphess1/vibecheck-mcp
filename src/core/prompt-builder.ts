/**
 * Prompt Builder
 *
 * Builds expert security analysis prompts for each hotspot category.
 * Uses live CWE data to provide up-to-date context.
 */

import type {
  HotspotCategory,
  SecurityHotspot,
  ProjectContext,
  ParsedFile,
} from '../types/index.js';
import { fetchCWEs, COMMON_CWES } from '../security-data/cwe-api.js';
import { FINDING_TO_OWASP, getOWASPCategory } from '../security-data/owasp.js';

/**
 * Category-specific expertise and focus areas
 */
const CATEGORY_EXPERTISE: Record<HotspotCategory, {
  role: string;
  focus: string[];
  cwes: string[];
}> = {
  auth: {
    role: 'authentication and authorization security expert',
    focus: [
      'Missing or bypassed authentication checks',
      'Weak session management',
      'Insecure password handling',
      'JWT vulnerabilities',
      'OAuth/OIDC misconfigurations',
      'Privilege escalation paths',
      'IDOR vulnerabilities',
    ],
    cwes: [COMMON_CWES.BROKEN_AUTH, COMMON_CWES.MISSING_AUTH, '384', '613'],
  },
  api: {
    role: 'API security expert',
    focus: [
      'Missing authentication on endpoints',
      'Broken object-level authorization',
      'Mass assignment vulnerabilities',
      'Rate limiting and resource consumption',
      'Input validation issues',
      'Injection vulnerabilities',
      'SSRF in fetch/request calls',
    ],
    cwes: [COMMON_CWES.MISSING_AUTH, COMMON_CWES.SQL_INJECTION, COMMON_CWES.SSRF, '20'],
  },
  'database-rules': {
    role: 'database security rules expert',
    focus: [
      'Overly permissive read/write rules',
      'Missing authentication requirements',
      'Data validation in rules',
      'Cross-user data access',
      'Admin access patterns',
      'RLS policy gaps',
    ],
    cwes: ['284', '285', COMMON_CWES.MISSING_AUTH],
  },
  'secrets-env': {
    role: 'secrets and configuration security expert',
    focus: [
      'Hardcoded credentials and API keys',
      'Secrets in client-side code',
      'Exposed environment variables',
      'Insecure default configurations',
      'Missing encryption for sensitive data',
    ],
    cwes: [COMMON_CWES.HARDCODED_CREDENTIALS, '540', COMMON_CWES.SENSITIVE_DATA_EXPOSURE],
  },
  dependencies: {
    role: 'software supply chain security expert',
    focus: [
      'Known vulnerable packages',
      'Typosquatting packages',
      'Malware in dependencies',
      'Outdated packages with security issues',
      'Dependency confusion risks',
    ],
    cwes: ['1035', '1104'],
  },
  'data-flow': {
    role: 'application security expert specializing in data flow',
    focus: [
      'SQL injection in queries',
      'Command injection in exec/spawn calls',
      'XSS in dangerouslySetInnerHTML',
      'Path traversal in file operations',
      'Unsafe deserialization',
      'Template injection',
    ],
    cwes: [
      COMMON_CWES.SQL_INJECTION,
      COMMON_CWES.COMMAND_INJECTION,
      COMMON_CWES.XSS,
      COMMON_CWES.PATH_TRAVERSAL,
    ],
  },
};

/**
 * Truncate file content to fit in prompt
 */
function truncateContent(content: string, maxChars: number = 8000): string {
  if (content.length <= maxChars) {
    return content;
  }
  return content.slice(0, maxChars) + '\n... [truncated]';
}

/**
 * Format files for the prompt
 */
function formatFilesForPrompt(files: ParsedFile[]): string {
  const parts: string[] = [];

  // Sort by size, smaller first
  const sorted = [...files].sort((a, b) => a.size - b.size);

  let totalChars = 0;
  const maxTotalChars = 100000;

  for (const file of sorted) {
    if (totalChars > maxTotalChars) {
      parts.push(`\n... and ${sorted.length - parts.length} more files (truncated for size)`);
      break;
    }

    const content = truncateContent(file.content);
    parts.push(`\n### File: ${file.path}\n\`\`\`${file.extension.slice(1) || 'text'}\n${content}\n\`\`\``);
    totalChars += content.length;
  }

  return parts.join('\n');
}

/**
 * Build the system prompt for a category
 */
export async function buildSystemPrompt(
  category: HotspotCategory,
  projectContext?: ProjectContext
): Promise<string> {
  const expertise = CATEGORY_EXPERTISE[category];

  // Fetch CWE details
  const cweData = await fetchCWEs(expertise.cwes);

  // Build CWE context
  let cweContext = '';
  for (const [id, data] of cweData) {
    cweContext += `\n${id} - ${data.name}: ${data.description.slice(0, 300)}`;
    if (data.mitigations.length > 0) {
      cweContext += `\nMitigations: ${data.mitigations.slice(0, 2).join('; ')}`;
    }
  }

  // Get OWASP categories for this type
  const owaspIds = FINDING_TO_OWASP[category] || [];
  const owaspContext = owaspIds
    .map((id) => {
      const cat = getOWASPCategory(id);
      return cat ? `${cat.id} - ${cat.name}` : id;
    })
    .join('\n');

  // Build project-specific context
  let projectSpecific = '';
  if (projectContext) {
    if (projectContext.framework) {
      projectSpecific += `\nFramework: ${projectContext.framework}`;
    }
    if (projectContext.database) {
      projectSpecific += `\nDatabase: ${projectContext.database}`;
    }
    if (projectContext.authProvider) {
      projectSpecific += `\nAuth Provider: ${projectContext.authProvider}`;
    }
  }

  return `You are a ${expertise.role} performing a security code review.

Your focus areas for this analysis:
${expertise.focus.map((f) => `- ${f}`).join('\n')}

Relevant CWEs:
${cweContext || 'No specific CWEs loaded'}

Relevant OWASP Categories:
${owaspContext || 'No specific OWASP categories'}
${projectSpecific ? `\nProject Context:${projectSpecific}` : ''}

IMPORTANT INSTRUCTIONS:
1. Only report REAL vulnerabilities you can identify in the code
2. Provide specific file paths and line numbers when possible
3. Explain the vulnerability and how it could be exploited
4. Rate severity as: critical, high, medium, or low
5. Provide confidence score 0-100 based on how certain you are
6. Include remediation steps

DO NOT:
- Report hypothetical issues without evidence in the code
- Flag safe patterns as vulnerabilities (e.g., Firebase apiKey in client code is SAFE)
- Generate false positives

Respond with a JSON object matching this structure:
{
  "findings": [
    {
      "type": "string (e.g., missing-auth, sql-injection, hardcoded-secret)",
      "severity": "critical|high|medium|low",
      "title": "Brief title",
      "description": "Detailed description",
      "filePath": "path/to/file.ts",
      "lineNumber": 42,
      "codeSnippet": "relevant code",
      "aiReasoning": "Why this is a vulnerability and how it could be exploited",
      "confidence": 85,
      "remediation": {
        "summary": "How to fix",
        "steps": ["Step 1", "Step 2"]
      }
    }
  ],
  "summary": "Overall security assessment for this category"
}

If no vulnerabilities are found, return: { "findings": [], "summary": "No vulnerabilities found" }`;
}

/**
 * Build the user prompt with file contents
 */
export function buildUserPrompt(hotspot: SecurityHotspot): string {
  const filesContent = formatFilesForPrompt(hotspot.files);

  return `Analyze these ${hotspot.category} files for security vulnerabilities:

${filesContent}

Respond with a JSON object containing your findings.`;
}

/**
 * Parse the AI response
 */
export interface AISecurityResponse {
  findings: Array<{
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
    filePath: string;
    lineNumber?: number;
    codeSnippet?: string;
    aiReasoning: string;
    confidence: number;
    remediation: {
      summary: string;
      steps: string[];
    };
  }>;
  summary: string;
}

export function parseAIResponse(response: string): AISecurityResponse {
  // Try to extract JSON from the response
  const jsonMatch = response.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    return { findings: [], summary: 'Could not parse AI response' };
  }

  try {
    const parsed = JSON.parse(jsonMatch[0]);
    return {
      findings: Array.isArray(parsed.findings) ? parsed.findings : [],
      summary: parsed.summary || 'Analysis complete',
    };
  } catch {
    return { findings: [], summary: 'Could not parse AI response as JSON' };
  }
}

/**
 * Build prompts for all hotspots
 */
export async function buildAllPrompts(
  hotspots: SecurityHotspot[],
  projectContext?: ProjectContext
): Promise<Map<HotspotCategory, { systemPrompt: string; userPrompt: string }>> {
  const prompts = new Map<HotspotCategory, { systemPrompt: string; userPrompt: string }>();

  for (const hotspot of hotspots) {
    const systemPrompt = await buildSystemPrompt(hotspot.category, projectContext);
    const userPrompt = buildUserPrompt(hotspot);
    prompts.set(hotspot.category, { systemPrompt, userPrompt });
  }

  return prompts;
}
