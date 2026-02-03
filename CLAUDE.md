# VibeCheck MCP Server

AI-powered security audit MCP server. Analyzes codebases for vulnerabilities using real-time CWE data and npm audit.

## Quick Start

```bash
npm install
npm run build
```

## Tools

1. **scan_codebase** - Full AI security analysis
2. **check_dependencies** - Quick npm audit

## Architecture

```
src/
├── index.ts          # MCP server entry
├── tools/            # Tool implementations
├── core/             # Analysis logic
├── security-data/    # CWE/OWASP APIs
└── types/            # TypeScript types
```

## Key Files

- `core/hotspot-collector.ts` - Categorizes files by security risk
- `core/prompt-builder.ts` - Builds AI prompts with CWE context
- `core/npm-audit.ts` - Runs npm audit for dependency checks
- `security-data/cwe-api.ts` - MITRE CWE REST API client

## Data Flow

1. Read files from path or accept content
2. Collect hotspots (categorize by security relevance)
3. Run npm audit for dependencies
4. Build prompts with live CWE data
5. Use MCP sampling for AI analysis
6. Return structured findings
