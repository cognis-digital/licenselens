import { existsSync, readFileSync, mkdirSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { promisify } from 'util';
import { createWriteStream } from 'stream';

// ============================================================================
// Core Types & Interfaces
// ============================================================================

export interface LicenseInfo {
  name: string;
  spdxId?: string;
  url?: string;
  text?: string;
  aliases: string[];
}

export interface PackageMetadata {
  name: string;
  version: string;
  license?: string | LicenseInfo;
  licenses?: (string | LicenseInfo)[];
  homepage?: string;
  repository?: string;
  bugs?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

export interface SBOMEntry {
  name: string;
  version: string;
  license: LicenseInfo;
  type: 'direct' | 'transitive';
  path?: string[]; // How deep in the dependency tree
}

export interface SBOMDocument {
  spdxVersion: string;
  documentName: string;
  documentNamespace: string;
  dataLicense: string;
  creators: string[];
  created: string;
  name: string;
  version: string;
  packages: SBOMEntry[];
}

export interface GeneratorOptions {
  rootDir?: string;
  recursive?: boolean;
  depthLimit?: number;
  outputFormat?: 'json' | 'csv' | 'text';
  outputPath?: string;
  includeDevDeps?: boolean;
  includePeerDeps?: boolean;
  includeOptionalDeps?: boolean;
  cacheDir?: string;
}

// ============================================================================
// License Database & Resolution
// ============================================================================

const LICENSE_DB: Record<string, LicenseInfo> = {
  'MIT': { name: 'MIT', spdxId: 'MIT', aliases: ['mit'], url: 'https://opensource.org/licenses/MIT' },
  'Apache-2.0': { name: 'Apache 2.0', spdxId: 'Apache-2.0', aliases: ['apache-2.0', 'apache2'], url: 'https://www.apache.org/licenses/LICENSE-2.0' },
  'BSD-3-Clause': { name: 'BSD 3-Clause', spdxId: 'BSD-3-Clause', aliases: ['bsd-3-clause', 'bsd3'], url: 'https://opensource.org/licenses/BSD-3-Clause' },
  'ISC': { name: 'ISC', spdxId: 'ISC', aliases: ['isc'], url: 'https://opensource.org/licenses/ISC' },
  'GPL-3.0-only': { name: 'GPL 3.0', spdxId: 'GPL-3.0-only', aliases: ['gpl-3.0', 'gplv3'], url: 'https://www.gnu.org/licenses/gpl-3.0.html' },
  'LGPL-2.1-only': { name: 'LGPL 2.1', spdxId: 'LGPL-2.1-only', aliases: ['lgpl-2.1', 'lgplv2'], url: 'https://www.gnu.org/licenses/lgpl-2.1.html' },
};

function normalizeLicenseName(name: string): string {
  return name.toUpperCase().replace(/-/g, '').replace(/\s/g, '');
}

function resolveLicense(license: string | LicenseInfo | undefined): LicenseInfo {
  if (typeof license === 'string') {
    const normalized = normalizeLicenseName(license);
    
    // Check exact match first
    for (const [key, info] of Object.entries(LICENSE_DB)) {
      if (normalizeLicenseName(key) === normalized) {
        return info;
      }
    }

    // Try partial matching with common aliases
    const knownAliases: Record<string, string> = {
      'mit': 'MIT',
      'apache2': 'Apache-2.0',
      'bsd3': 'BSD-3-Clause',
      'gplv3': 'GPL-3.0-only',
      'lgplv2': 'LGPL-2.1-only',
    };

    const matched = knownAliases[normalized];
    if (matched) {
      return LICENSE_DB[matched] || { name: license, spdxId: normalized, aliases: [normalized] };
    }

    // Return unknown license with minimal info
    return { 
      name: license, 
      spdxId: `UNKNOWN-${normalizeLicenseName(license).toUpperCase()}`,
      aliases: [license],
      text: 'Unknown or custom license. Check package.json for details.'
    };
  }

  if (license) {
    // Already a LicenseInfo object
    return license;
  }

  return { name: 'UNLICENSED', spdxId: 'NOASSERTION', aliases: [] };
}

// ============================================================================
// Package.json Parser
// ============================================================================

interface ParsedPackageJson extends PackageMetadata {
  _resolved?: string;
  _integrity?: string;
}

function parsePackageJson(content: string): ParsedPackageJson {
  try {
    return JSON.parse(content) as ParsedPackageJson;
  } catch (error) {
    throw new Error(`Invalid package.json at ${content.slice(0, 100)}...`);
  }
}

function extractDependencies(pkg: ParsedPackageJson): Record<string, string> {
  const deps: Record<string, string> = {};

  if (pkg.dependencies) {
    Object.assign(deps, pkg.dependencies);
  }
  
  if (pkg.devDependencies && this.options.includeDevDeps) {
    Object.assign(deps, pkg.devDependencies);
  }

  if (pkg.peerDependencies && this.options.includePeerDeps) {
    Object.assign(deps, pkg.peerDependencies);
  }

  if (pkg.optionalDependencies && this.options.includeOptionalDeps) {
    Object.assign(deps, pkg.optionalDependencies);
  }

  return deps;
}

// ============================================================================
// SBOM Generator Class
// ============================================================================

export class SBOMGenerator {
  private options: Required<GeneratorOptions>;
  private cacheDir: string;
  private resolvedLicenses: Map<string, LicenseInfo> = new Map();

  constructor(options: GeneratorOptions = {}) {
    this.options = {
      rootDir: process.cwd(),
      recursive: true,
      depthLimit: Infinity,
      outputFormat: 'json',
      outputPath: undefined,
      includeDevDeps: false,
      includePeerDeps: false,
      includeOptionalDeps: false,
      cacheDir: join(process.cwd(), '.licenselens-cache'),
    };

    // Ensure cache directory exists
    if (!existsSync(this.cacheDir)) {
      mkdirSync(this.cacheDir, { recursive: true });
    }
  }

  private getCacheKey(name: string, version: string): string {
    return `${name}@${version}`;
  }

  private async getCachedLicense(cacheKey: string): Promise<LicenseInfo | undefined> {
    const cacheFile = join(this.cacheDir, `${cacheKey}.json`);
    
    if (existsSync(cacheFile)) {
      try {
        return JSON.parse(readFileSync(cacheFile, 'utf-8'));
      } catch {
        // Corrupt cache file, treat as missing
      }
    }

    return undefined;
  }

  private async setCachedLicense(cacheKey: string, license: LicenseInfo): Promise<void> {
    const cacheFile = join(this.cacheDir, `${cacheKey}.json`);
    await promisify(createWriteStream)(cacheFile).end(JSON.stringify(license));
  }

  private getOrCreateCachedLicense(name: string, version: string, baseLicense: LicenseInfo): Promise<LicenseInfo> {
    const cacheKey = this.getCacheKey(name, version);
    
    return this.getCachedLicense(cacheKey)
      .then(cached => cached || baseLicense)
      .then(license => {
        // Always update cache with resolved license (includes fetched text if any)
        return this.setCachedLicense(cacheKey, license).then(() => license);
      });
  }

  private async resolvePackageLicenses(pkg: ParsedPackageJson): Promise<SBOMEntry[]> {
    const entries: SBOMEntry[] = [];

    // Handle single license field
    if (pkg.license) {
      let resolved = resolveLicense(pkg.license);
      
      // Try to fetch full text from URL if available and not in cache
      if (resolved.url && !resolved.text) {
        try {
          const response = await fetch(resolved.url, { 
            headers: { 'Accept': 'application/json' } 
          });
          
          if (response.ok) {
            const text = await response.text();
            resolved = { ...resolved, text };
            
            // Cache the license with fetched text
            const cacheKey = this.getCacheKey(pkg.name || 'unknown', pkg.version);
            await this.setCachedLicense(cacheKey, resolved);
          } else {
            resolved = { 
              ...resolved, 
              text: `Network error fetching from ${resolved.url}` 
            };
          }
        } catch (error) {
          resolved.text = `Error fetching license text: ${(error as Error).message}`;
        }
      }

      entries.push({
        name: pkg.name || 'root',
        version: pkg.version,
        license: resolved,
        type: 'direct',
        path: [],
      });
    }

    // Handle licenses array
    if (pkg.licenses && Array.isArray(pkg.licenses)) {
      for (const lic of pkg.licenses) {
        let resolved = resolveLicense(lic);
        
        // Fetch text from URL if available
        if (resolved.url && !resolved.text) {
          try {
            const response = await fetch(resolved.url, { 
              headers: { 'Accept': 'application/json' } 
            });
            
            if (response.ok) {
              const text = await response.text();
              resolved = { ...resolved, text };
              
              const cacheKey = this.getCacheKey(pkg.name || 'unknown', pkg.version);
              await this.setCachedLicense(cacheKey, resolved);
            } else {
              resolved = { 
                ...resolved, 
                text: `Network error fetching from ${resolved.url}` 
              };
            }
          } catch (error) {
            resolved.text = `Error fetching license text: ${(error as Error).message}`;
          }
        }

        entries.push({
          name: pkg.name || 'root',
          version: pkg.version,
          license: resolved,
          type: 'direct',
          path: [],
        });
      }
    }

    return entries;
  }

  private async resolveDependencies(
    pkgPath: string,
    pkgData: ParsedPackageJson,
    depth: number = 0,
    parentDeps?: Record<string, string>,
    visitedPaths: Set<string> = new Set()
  ): Promise<SBOMEntry[]> {
    if (depth > this.options.depthLimit) {
      return [];
    }

    const entries: SBOMEntry[] = [];

    // Resolve licenses for direct dependencies
    const deps = extractDependencies(pkgData);
    
    for (const [depName, depVersion] of Object.entries(deps)) {
      // Skip if already visited at same or deeper level to avoid loops
      const pathKey = `${pkgPath}:${depth}`;
      if (visitedPaths.has(pathKey)) {
        continue;
      }

      visitedPaths.add(pathKey);

      // Try to resolve from cache first, then fetch
      let license: LicenseInfo;
      
      const cacheKey = this.getCacheKey(depName, depVersion);
      const cachedLicense = await this.getCachedLicense(cacheKey);
      
      if (cachedLicense) {
        license = cachedLicense;
      } else {
        // Use base license from DB or resolve unknown
        let baseLicense = LICENSE_DB[depName] || 
                        { name: depName, spdxId: 'UNKNOWN', aliases: [depName], text: 'Unknown' };
        
        if (cachedLicense) {
          license = cachedLicense;
        } else {
          // Fetch from npm registry for more accurate info
          try {
            const url = `https://registry.npmjs.org/${encodeURIComponent(depName)}/${encodeURIComponent(depVersion)}`;
            const response = await fetch(url, { headers: { 'Accept': 'application/json' } });
            
            if (response.ok) {
              const data = await response.json();
              
              // Extract license from registry response
              let resolvedLicense: LicenseInfo | undefined;
              
              if (data.license && typeof data.license === 'string') {
                resolvedLicense = resolveLicense(data.license);
              } else if (Array.isArray(data.licenses)) {
                for (const lic of data.licenses) {
                  if (lic.name) {
                    resolvedLicense = resolveLicense(lic.name);
                    break;
                  }
                }
              }

              // If we got a license, cache it
              if (resolvedLicense) {
                await this.setCachedLicense(cacheKey, resolvedLicense);
                license = resolvedLicense;
              } else {
                // Use base license as fallback
                license = baseLicense;
              }
            } else {
              license = baseLicense;
            }
          } catch (error) {
            console.warn(`Error fetching ${depName}@${depVersion} from registry: ${(error as Error).message}`);
            license = baseLicense;
          }
        }
      }

      entries.push({
        name: depName,
        version: depVersion,
        license: license,
        type: 'transitive',
        path: [...(parentDeps || []), pkgPath],
      });
    }

    // Recursively resolve nested packages if recursive mode is enabled
    if (this.options.recursive && depth < this.options.depthLimit - 1) {
      const nestedPkgPath = join(pkgPath, 'node_modules', depName);
      
      for (const [depName, depVersion] of Object.entries(deps)) {
        // Only recurse into packages that have their own package.json
        if (!existsSync(join(nestedPkgPath, 'package.json'))) {
          continue;
        }

        const nestedContent = readFileSync(join(nestedPkgPath, 'package.json'), 'utf-8');
        const nestedPkg = parsePackageJson(nestedContent);
        
        // Avoid infinite loops by tracking visited paths
        if (visitedPaths.has(`${nestedPkgPath}:${depth + 1}`)) {
          continue;
        }

        visitedPaths.add(`${nestedPkgPath}:${depth + 1}`);

        const nestedEntries = await this.resolveDependencies(
          nestedPkgPath,
          nestedPkg,
          depth + 1,
          [...(parentDeps || []), pkgPath],
          new Set(visitedPaths)
        );

        entries.push(...nestedEntries);
      }
    }

    return entries;
  }

  private async generateSBOM(rootDir: string): Promise<SBOMDocument> {
    const startTime = Date.now();
    const rootPkgPath = join(rootDir, 'package.json');

    // Parse root package.json
    let rootContent: string;
    
    if (existsSync(rootPkgPath)) {
      rootContent = readFileSync(rootPkgPath, 'utf-8');
    } else {
      throw new Error(`Root package.json not found at ${rootPkgPath}`);
    }

    const rootPkg = parsePackageJson(rootContent);

    // Resolve all dependencies recursively
    const allEntries: SBOMEntry[] = [];
    
    await this.resolveDependencies(
      '',
      rootPkg,
      0,
      undefined,
      new Set()
    ).then(entries => {
      allEntries.push(...entries);
    });

    // Sort entries for consistent output
    allEntries.sort((a, b) => {
      if (a.name !== b.name) return a.name.localeCompare(b.name);
      return a.version.localeCompare(b.version);
    });

    const endTime