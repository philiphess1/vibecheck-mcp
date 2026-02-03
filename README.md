# VibeCheck MCP Server

AI-powered security audit tool for codebases. Analyzes code for vulnerabilities using real-time data from MITRE CWE and npm audit.

## Features

- **AI-Powered Analysis**: Uses MCP sampling to analyze code with Claude
- **Real-Time CWE Data**: Fetches vulnerability definitions from MITRE's CWE API
- **Dependency Scanning**: Uses npm audit for package vulnerability checks
- **Zero Configuration**: No API keys required to get started

## Installation

### Claude Code (Recommended)

```bash
/plugin marketplace add philiphess1/vibecheck-mcp
/plugin install vibecheck@vibecheck
```

### Manual Installation

Add to your Claude Desktop config (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vibecheck": {
      "command": "npx",
      "args": ["-y", "vibecheck-audit-mcp"]
    }
  }
}
```

### From Source

```bash
git clone https://github.com/philiphess1/vibecheck-mcp.git
cd vibecheck-mcp
npm install && npm run build
```

## Tools

### scan_codebase

Full AI-powered security audit with real-time vulnerability data.

**Analyzes:**
- Authentication and authorization issues
- API security vulnerabilities
- Database security rules
- Exposed secrets and environment variables
- Dependency vulnerabilities (via npm audit)
- Data flow and injection vulnerabilities

**Input:**
```json
{
  "path": "/path/to/codebase",
  "categories": ["auth", "api", "secrets-env"],
  "severityThreshold": "medium"
}
```

Or provide files directly:
```json
{
  "files": [
    { "path": "src/auth.ts", "content": "..." }
  ]
}
```

**Categories:**
- `auth` - Authentication, sessions, middleware
- `api` - API routes, endpoints
- `database-rules` - Firebase/Supabase rules, Prisma schemas
- `secrets-env` - Environment variables, config files
- `dependencies` - package.json vulnerabilities
- `data-flow` - User input handling, injection points

### check_dependencies

Quick dependency-only scan using npm audit.

**Input:**
```json
{
  "path": "/path/to/project",
  "includeDevDependencies": false
}
```

**Requirements:**
- npm installed
- `package-lock.json` in the project

## Data Sources

| Source | Purpose | Auth Required |
|--------|---------|---------------|
| MITRE CWE API | Vulnerability definitions | No |
| npm audit | Package CVEs | No |
| OWASP | Security categories | No (bundled) |

## Development

```bash
# Build
npm run build

# Watch mode
npm run dev

# Run directly
npm start
```

## How It Works

1. **File Reading**: Reads files from the specified path or accepts file contents directly
2. **Hotspot Collection**: Categorizes files by security relevance (auth, api, secrets, etc.)
3. **Dependency Audit**: Runs `npm audit` if package-lock.json exists
4. **AI Analysis**: Uses MCP sampling to analyze each category with expert prompts
5. **CWE Enrichment**: Fetches relevant CWE definitions from MITRE API
6. **Results**: Returns structured findings with severity, CWE/OWASP refs, and remediation steps

## Output Format

```json
{
  "findings": [
    {
      "id": "uuid",
      "type": "hardcoded-secret",
      "severity": "critical",
      "title": "Hardcoded API Key",
      "description": "...",
      "filePath": "src/config.ts",
      "lineNumber": 42,
      "codeSnippet": "const API_KEY = 'sk-...'",
      "aiReasoning": "...",
      "confidence": 95,
      "cwes": [{ "id": "CWE-798", "name": "..." }],
      "owasp": [{ "id": "A02:2021", "name": "..." }],
      "remediation": {
        "summary": "Use environment variables",
        "steps": ["..."]
      }
    }
  ],
  "dependencyVulnerabilities": [...],
  "summary": {
    "totalFindings": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0,
    "vulnerableDependencies": 3
  },
  "scanDuration": 12500
}
```

## License

MIT
