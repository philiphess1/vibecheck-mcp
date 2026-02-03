/**
 * File system reader for scanning codebases
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, extname, relative } from 'path';
import type { ParsedFile } from '../types/index.js';

// File extensions to include
const CODE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.json', '.yaml', '.yml',
  '.env', '.env.local', '.env.development', '.env.production',
  '.prisma', '.graphql', '.gql',
  '.rules', // Firebase rules
  '.sql',
  '.py', '.rb', '.go', '.java', '.rs', '.php',
]);

// Directories to skip
const SKIP_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'out',
  'coverage',
  '.turbo',
  '.cache',
  '__pycache__',
  'vendor',
  '.idea',
  '.vscode',
]);

// Files to skip
const SKIP_FILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  '.DS_Store',
]);

// Max file size to read (1MB)
const MAX_FILE_SIZE = 1024 * 1024;

/**
 * Check if a file should be included in the scan
 */
function shouldIncludeFile(filePath: string, size: number): boolean {
  const ext = extname(filePath).toLowerCase();
  const fileName = filePath.split('/').pop() || '';

  // Skip if in skip list
  if (SKIP_FILES.has(fileName)) {
    return false;
  }

  // Skip if too large
  if (size > MAX_FILE_SIZE) {
    return false;
  }

  // Include if extension matches or is a dotfile config
  if (CODE_EXTENSIONS.has(ext)) {
    return true;
  }

  // Include certain dotfiles
  if (fileName.startsWith('.env') || fileName === '.gitignore') {
    return true;
  }

  // Include files without extension if they look like config
  if (!ext && (
    fileName.includes('config') ||
    fileName.includes('rc') ||
    fileName === 'Dockerfile' ||
    fileName === 'Makefile'
  )) {
    return true;
  }

  return false;
}

/**
 * Recursively read all files in a directory
 */
function readDirectoryRecursive(
  dirPath: string,
  basePath: string,
  files: ParsedFile[],
  maxFiles: number = 500
): void {
  if (files.length >= maxFiles) {
    return;
  }

  const entries = readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    if (files.length >= maxFiles) {
      break;
    }

    const fullPath = join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (!SKIP_DIRECTORIES.has(entry.name)) {
        readDirectoryRecursive(fullPath, basePath, files, maxFiles);
      }
    } else if (entry.isFile()) {
      try {
        const stats = statSync(fullPath);

        if (shouldIncludeFile(fullPath, stats.size)) {
          const content = readFileSync(fullPath, 'utf-8');
          const relativePath = relative(basePath, fullPath);

          files.push({
            path: relativePath,
            content,
            size: stats.size,
            extension: extname(fullPath).toLowerCase(),
          });
        }
      } catch {
        // Skip files we can't read
      }
    }
  }
}

/**
 * Read all files from a directory path
 */
export function readFilesFromPath(path: string): ParsedFile[] {
  if (!existsSync(path)) {
    throw new Error(`Path does not exist: ${path}`);
  }

  const stats = statSync(path);

  if (stats.isFile()) {
    // Single file
    const content = readFileSync(path, 'utf-8');
    return [{
      path: path.split('/').pop() || path,
      content,
      size: stats.size,
      extension: extname(path).toLowerCase(),
    }];
  }

  if (stats.isDirectory()) {
    const files: ParsedFile[] = [];
    readDirectoryRecursive(path, path, files);
    return files;
  }

  throw new Error(`Path is neither a file nor a directory: ${path}`);
}

/**
 * Convert file input objects to ParsedFile format
 */
export function parseFileInputs(files: Array<{ path: string; content: string }>): ParsedFile[] {
  return files.map((f) => ({
    path: f.path,
    content: f.content,
    size: f.content.length,
    extension: extname(f.path).toLowerCase(),
  }));
}

/**
 * Get package.json content from files
 */
export function getPackageJson(files: ParsedFile[]): object | null {
  const packageJsonFile = files.find((f) =>
    f.path === 'package.json' || f.path.endsWith('/package.json')
  );

  if (!packageJsonFile) {
    return null;
  }

  try {
    return JSON.parse(packageJsonFile.content);
  } catch {
    return null;
  }
}

/**
 * Check if project has package-lock.json
 */
export function hasPackageLock(files: ParsedFile[]): boolean {
  return files.some((f) =>
    f.path === 'package-lock.json' ||
    f.path.endsWith('/package-lock.json') ||
    f.path === 'yarn.lock' ||
    f.path.endsWith('/yarn.lock') ||
    f.path === 'pnpm-lock.yaml' ||
    f.path.endsWith('/pnpm-lock.yaml')
  );
}
