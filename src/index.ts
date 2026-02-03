#!/usr/bin/env node
/**
 * VibeCheck MCP Server
 *
 * AI-powered security audit tool with real-time vulnerability data.
 *
 * Tools:
 * - scan_codebase: Full security analysis with AI
 * - check_dependencies: Quick npm audit scan
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import {
  scanCodebaseSchema,
  executeScanCodebase,
  checkDependenciesSchema,
  executeCheckDependencies,
} from './tools/index.js';

// Create server
const server = new Server(
  {
    name: 'vibecheck',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'scan_codebase',
        description: `AI-powered security audit with real-time vulnerability database lookups.

Analyzes code for:
- Authentication and authorization issues
- API security vulnerabilities
- Database security rules
- Exposed secrets and environment variables
- Dependency vulnerabilities (via npm audit)
- Data flow and injection vulnerabilities

Returns findings with:
- Severity ratings (critical, high, medium, low)
- AI reasoning and confidence scores
- CWE and OWASP references
- Remediation steps`,
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to repository/directory to scan',
            },
            files: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  path: { type: 'string' },
                  content: { type: 'string' },
                },
                required: ['path', 'content'],
              },
              description: 'Provide file contents directly (alternative to path)',
            },
            categories: {
              type: 'array',
              items: {
                type: 'string',
                enum: ['auth', 'api', 'database-rules', 'secrets-env', 'dependencies', 'data-flow'],
              },
              description: 'Limit scan to specific categories (default: all)',
            },
            severityThreshold: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low'],
              description: 'Only return findings at or above this severity',
            },
          },
        },
      },
      {
        name: 'check_dependencies',
        description: `Run npm audit to check dependencies for known vulnerabilities.

Uses the GitHub Advisory Database (same as npm audit).
Returns known CVEs, severity levels, and patched versions.

Requirements:
- npm must be installed
- Directory must contain package-lock.json (or yarn.lock/pnpm-lock.yaml)`,
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Path to directory containing package.json and package-lock.json',
            },
            includeDevDependencies: {
              type: 'boolean',
              description: 'Include devDependencies in scan (default: false)',
            },
          },
          required: ['path'],
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    if (name === 'scan_codebase') {
      const input = scanCodebaseSchema.parse(args);
      const result = await executeScanCodebase(input);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    }

    if (name === 'check_dependencies') {
      const input = checkDependenciesSchema.parse(args);
      const result = await executeCheckDependencies(input);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    }

    throw new Error(`Unknown tool: ${name}`);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ error: errorMessage }, null, 2),
        },
      ],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('VibeCheck MCP Server running');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
