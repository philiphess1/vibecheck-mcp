/**
 * MITRE CWE REST API Client
 * https://cwe-api.mitre.org/api/v1/
 *
 * No authentication required, free to use
 */

import type { CWEData } from './types.js';

const CWE_API_BASE = 'https://cwe-api.mitre.org/api/v1';

// Cache CWE data to avoid repeated API calls
const cweCache = new Map<string, CWEData>();

interface CWEApiResponse {
  ID: string;
  Name: string;
  Description?: string;
  Extended_Description?: string;
  Potential_Mitigations?: {
    Mitigation: Array<{
      Description: string;
    }>;
  };
  Detection_Methods?: {
    Detection_Method: Array<{
      Description: string;
    }>;
  };
  Demonstrative_Examples?: {
    Demonstrative_Example: Array<{
      Body_Text: string;
    }>;
  };
  Related_Weaknesses?: {
    Related_Weakness: Array<{
      CWE_ID: string;
    }>;
  };
  Applicable_Platforms?: {
    Language?: Array<{ Name: string }>;
    Technology?: Array<{ Name: string }>;
  };
}

function transformCWEResponse(data: CWEApiResponse): CWEData {
  const mitigations: string[] = [];
  if (data.Potential_Mitigations?.Mitigation) {
    for (const m of data.Potential_Mitigations.Mitigation) {
      if (m.Description) {
        mitigations.push(m.Description);
      }
    }
  }

  const detectionMethods: string[] = [];
  if (data.Detection_Methods?.Detection_Method) {
    for (const d of data.Detection_Methods.Detection_Method) {
      if (d.Description) {
        detectionMethods.push(d.Description);
      }
    }
  }

  const examples: string[] = [];
  if (data.Demonstrative_Examples?.Demonstrative_Example) {
    for (const e of data.Demonstrative_Examples.Demonstrative_Example) {
      if (e.Body_Text) {
        examples.push(e.Body_Text);
      }
    }
  }

  const relatedWeaknesses: string[] = [];
  if (data.Related_Weaknesses?.Related_Weakness) {
    for (const r of data.Related_Weaknesses.Related_Weakness) {
      if (r.CWE_ID) {
        relatedWeaknesses.push(`CWE-${r.CWE_ID}`);
      }
    }
  }

  const applicablePlatforms: string[] = [];
  if (data.Applicable_Platforms?.Language) {
    for (const l of data.Applicable_Platforms.Language) {
      if (l.Name) applicablePlatforms.push(l.Name);
    }
  }
  if (data.Applicable_Platforms?.Technology) {
    for (const t of data.Applicable_Platforms.Technology) {
      if (t.Name) applicablePlatforms.push(t.Name);
    }
  }

  return {
    id: `CWE-${data.ID}`,
    name: data.Name,
    description: data.Description || '',
    extendedDescription: data.Extended_Description,
    mitigations,
    detectionMethods,
    examples,
    relatedWeaknesses,
    applicablePlatforms,
  };
}

/**
 * Fetch CWE details by ID
 * @param cweId - CWE ID (e.g., "79" or "CWE-79")
 */
export async function fetchCWE(cweId: string): Promise<CWEData | null> {
  // Normalize ID
  const id = cweId.replace(/^CWE-/i, '');
  const cacheKey = `CWE-${id}`;

  // Check cache first
  if (cweCache.has(cacheKey)) {
    return cweCache.get(cacheKey)!;
  }

  try {
    const response = await fetch(`${CWE_API_BASE}/cwe/${id}`);

    if (!response.ok) {
      if (response.status === 404) {
        return null;
      }
      throw new Error(`CWE API error: ${response.status}`);
    }

    const data = await response.json() as CWEApiResponse;
    const cweData = transformCWEResponse(data);

    // Cache the result
    cweCache.set(cacheKey, cweData);

    return cweData;
  } catch (error) {
    console.error(`Failed to fetch CWE-${id}:`, error);
    return null;
  }
}

/**
 * Fetch multiple CWEs in parallel
 */
export async function fetchCWEs(cweIds: string[]): Promise<Map<string, CWEData>> {
  const results = new Map<string, CWEData>();

  const fetchPromises = cweIds.map(async (id) => {
    const data = await fetchCWE(id);
    if (data) {
      results.set(data.id, data);
    }
  });

  await Promise.all(fetchPromises);
  return results;
}

/**
 * Get a brief description for a CWE (for use in prompts)
 */
export async function getCWESummary(cweId: string): Promise<string> {
  const cwe = await fetchCWE(cweId);
  if (!cwe) {
    return `CWE-${cweId.replace(/^CWE-/i, '')}`;
  }
  return `${cwe.id}: ${cwe.name} - ${cwe.description.slice(0, 200)}...`;
}

// Common CWEs for security scanning
export const COMMON_CWES = {
  XSS: '79',
  SQL_INJECTION: '89',
  COMMAND_INJECTION: '78',
  PATH_TRAVERSAL: '22',
  HARDCODED_CREDENTIALS: '798',
  MISSING_AUTH: '862',
  BROKEN_AUTH: '287',
  SSRF: '918',
  INSECURE_DESERIALIZATION: '502',
  SENSITIVE_DATA_EXPOSURE: '200',
  INSUFFICIENT_LOGGING: '778',
  IMPROPER_INPUT_VALIDATION: '20',
};
