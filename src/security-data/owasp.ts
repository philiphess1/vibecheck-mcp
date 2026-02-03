/**
 * OWASP Top 10 Data
 *
 * Since OWASP doesn't have a formal API, we maintain a minimal
 * static mapping that we can update periodically.
 *
 * Last updated: 2023 (OWASP Top 10 Web + API Security)
 */

import type { OWASPCategory } from './types.js';

// OWASP Top 10 Web Application Security Risks (2021)
export const OWASP_TOP_10_WEB: OWASPCategory[] = [
  {
    id: 'A01:2021',
    name: 'Broken Access Control',
    description: 'Failures related to access control that allows users to act outside their intended permissions.',
    year: 2021,
    rank: 1,
  },
  {
    id: 'A02:2021',
    name: 'Cryptographic Failures',
    description: 'Failures related to cryptography which often lead to exposure of sensitive data.',
    year: 2021,
    rank: 2,
  },
  {
    id: 'A03:2021',
    name: 'Injection',
    description: 'Injection flaws such as SQL, NoSQL, OS, and LDAP injection occur when untrusted data is sent to an interpreter.',
    year: 2021,
    rank: 3,
  },
  {
    id: 'A04:2021',
    name: 'Insecure Design',
    description: 'Missing or ineffective security controls, often from missing threat modeling during design.',
    year: 2021,
    rank: 4,
  },
  {
    id: 'A05:2021',
    name: 'Security Misconfiguration',
    description: 'Missing or incorrect security hardening, insecure default configurations, or verbose error messages.',
    year: 2021,
    rank: 5,
  },
  {
    id: 'A06:2021',
    name: 'Vulnerable and Outdated Components',
    description: 'Using components with known vulnerabilities or unsupported/outdated software.',
    year: 2021,
    rank: 6,
  },
  {
    id: 'A07:2021',
    name: 'Identification and Authentication Failures',
    description: 'Failures in confirming user identity, authentication, and session management.',
    year: 2021,
    rank: 7,
  },
  {
    id: 'A08:2021',
    name: 'Software and Data Integrity Failures',
    description: 'Code and infrastructure that does not protect against integrity violations.',
    year: 2021,
    rank: 8,
  },
  {
    id: 'A09:2021',
    name: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging, detection, monitoring, and active response.',
    year: 2021,
    rank: 9,
  },
  {
    id: 'A10:2021',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.',
    year: 2021,
    rank: 10,
  },
];

// OWASP API Security Top 10 (2023)
export const OWASP_API_TOP_10: OWASPCategory[] = [
  {
    id: 'API1:2023',
    name: 'Broken Object Level Authorization',
    description: 'APIs expose endpoints that handle object identifiers, creating attack surface for object level access control issues.',
    year: 2023,
    rank: 1,
  },
  {
    id: 'API2:2023',
    name: 'Broken Authentication',
    description: 'Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.',
    year: 2023,
    rank: 2,
  },
  {
    id: 'API3:2023',
    name: 'Broken Object Property Level Authorization',
    description: 'Lack of or improper authorization validation at object property level leading to information exposure or manipulation.',
    year: 2023,
    rank: 3,
  },
  {
    id: 'API4:2023',
    name: 'Unrestricted Resource Consumption',
    description: 'API requests consume resources such as network bandwidth, CPU, memory, and storage without proper limits.',
    year: 2023,
    rank: 4,
  },
  {
    id: 'API5:2023',
    name: 'Broken Function Level Authorization',
    description: 'Complex access control policies with different hierarchies, groups, and roles create authorization flaws.',
    year: 2023,
    rank: 5,
  },
  {
    id: 'API6:2023',
    name: 'Unrestricted Access to Sensitive Business Flows',
    description: 'APIs vulnerable to abuse through excessive access to certain business flows, harming the business.',
    year: 2023,
    rank: 6,
  },
  {
    id: 'API7:2023',
    name: 'Server Side Request Forgery',
    description: 'SSRF can occur when an API fetches a remote resource without validating the user-supplied URI.',
    year: 2023,
    rank: 7,
  },
  {
    id: 'API8:2023',
    name: 'Security Misconfiguration',
    description: 'Complex and customizable API configurations can lead to insecure default settings and misconfigurations.',
    year: 2023,
    rank: 8,
  },
  {
    id: 'API9:2023',
    name: 'Improper Inventory Management',
    description: 'APIs tend to expose more endpoints than traditional web applications, making proper documentation important.',
    year: 2023,
    rank: 9,
  },
  {
    id: 'API10:2023',
    name: 'Unsafe Consumption of APIs',
    description: 'Developers tend to trust data received from third-party APIs more than user input, adopting weaker security standards.',
    year: 2023,
    rank: 10,
  },
];

/**
 * Get OWASP category by ID
 */
export function getOWASPCategory(id: string): OWASPCategory | undefined {
  const allCategories = [...OWASP_TOP_10_WEB, ...OWASP_API_TOP_10];
  return allCategories.find((c) => c.id === id);
}

/**
 * Get all OWASP categories relevant to a topic
 */
export function getRelevantOWASP(topic: string): OWASPCategory[] {
  const topicLower = topic.toLowerCase();
  const allCategories = [...OWASP_TOP_10_WEB, ...OWASP_API_TOP_10];

  return allCategories.filter((c) =>
    c.name.toLowerCase().includes(topicLower) ||
    c.description.toLowerCase().includes(topicLower)
  );
}

/**
 * Map security finding types to OWASP categories
 */
export const FINDING_TO_OWASP: Record<string, string[]> = {
  'missing-auth': ['A01:2021', 'API1:2023', 'API5:2023'],
  'broken-auth': ['A07:2021', 'API2:2023'],
  'sql-injection': ['A03:2021'],
  'command-injection': ['A03:2021'],
  'xss': ['A03:2021'],
  'ssrf': ['A10:2021', 'API7:2023'],
  'hardcoded-secret': ['A02:2021'],
  'exposed-env': ['A02:2021', 'A05:2021'],
  'insecure-config': ['A05:2021', 'API8:2023'],
  'vulnerable-dependency': ['A06:2021'],
  'missing-rate-limit': ['API4:2023'],
  'data-exposure': ['API3:2023'],
};
