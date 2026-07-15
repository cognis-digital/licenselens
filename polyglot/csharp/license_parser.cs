// <summary>
// Licenselens - Dependency License & SBOM Gate
// </summary>
// <author>Qwen</author>
// <date>2024</date>

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Licenselens.Core;

public static partial class LicenseParser
{
    private static readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromMinutes(5) };
    
    public record DependencyWithLicense(
        string Name,
        string Version,
        string? LicenseId,
        string? LicenseUrl,
        bool IsDirect,
        int Depth);

    public record LicenseSummary(
        int TotalDependencies,
        int WithKnownLicenses,
        int WithUnknownLicenses,
        int WithConflicts,
        int WithNoLicense,
        List<string> UnknownLicenses,
        List<string> ConflictDescriptions);

    public class SBOMResult
    {
        public List<DependencyWithLicense> Dependencies { get; } = new();
        public LicenseSummary Summary { get; set; } = null!;
        public bool HasConflicts => Summary.ConflictDescriptions.Count > 0;
        public bool HasUnknownLicenses => Summary.UnknownLicenses.Any();
    }

    // SPDX license identifier database (subset of common licenses)
    private static readonly Dictionary<string, string> _knownLicenses = new(StringComparer.OrdinalIgnoreCase)
    {
        { "MIT", "https://opensource.org/licenses/MIT" },
        { "MIT-0", "https://github.com/aws/mit-0" },
        { "Apache-2.0", "https://www.apache.org/licenses/LICENSE-2.0" },
        { "Apache-2.0", "https://spdx.org/licenses/Apache-2.0" },
        { "BSD-3-Clause", "https://opensource.org/licenses/BSD-3-Clause" },
        { "BSD-2-Clause", "https://opensource.org/licenses/BSD-2-Clause" },
        { "ISC", "https://opensource.org/licenses/ISC" },
        { "GPL-3.0-only", "https://www.gnu.org/licenses/gpl-3.0.html" },
        { "GPL-3.0-or-later", "https://www.gnu.org/licenses/gpl-3.0.html" },
        { "LGPL-2.1-only", "https://www.gnu.org/licenses/lgpl-2.1.html" },
        { "MPL-2.0", "https://opensource.org/licenses/MPL-2.0" },
        { "EPL-2.0", "https://www.eclipse.org/legal/epl-2.0" },
        { "EPL-1.0", "https://www.eclipse.org/org/documents/epic1.0.html" },
        { "Unlicense", "https://unlicense.org/" },
        { "CC0-1.0", "https://creativecommons.org/publicdomain/zero/1.0/" },
        { "WTFPL", "https://www.wtfpl.net/" },
    };

    public static async Task<SBOMResult> ParseAsync(
        string manifestPath,
        string? lockFilePath = null,
        CancellationToken cancellationToken = default)
    {
        var result = new SBOMResult();
        
        // Detect package manager from manifest path
        var (packageManager, dependencies) = await DetectPackageManager(manifestPath);
        
        if (dependencies == null)
            return result;

        // Resolve transitive dependencies
        var resolved = await ResolveTransitiveDependencies(
            dependencies, 
            lockFilePath ?? "",
            packageManager,
            cancellationToken);

        // Build summary
        result.Summary = BuildSummary(resolved);
        
        // Add all to results (mark direct vs transitive)
        foreach (var dep in resolved)
        {
            if (!result.Dependencies.Any(d => d.Name == dep.Name && 
                string.Equals(d.Version, dep.Version, StringComparison.OrdinalIgnoreCase)))
            {
                result.Dependencies.Add(dep);
            }
        }

        return result;
    }

    private static async Task<(string PackageManager, List<PackageInfo>? Dependencies)> DetectPackageManager(
        string manifestPath)
    {
        var lower = Path.GetFullPath(manifestPath).ToLowerInvariant();
        
        // npm/yarn
        if (lower.EndsWith(".json") && 
            File.Exists(Path.Combine(Path.GetDirectoryName(manifestPath) ?? "", "package.json")))
        {
            return ("npm", await ParseNpmManifest(manifestPath));
        }

        // Cargo.toml
        if (lower.EndsWith("cargo.toml"))
        {
            return ("cargo", await ParseCargoToml(manifestPath));
        }

        // Gemfile.lock
        if (lower.EndsWith("gemfile.lock"))
        {
            return ("bundler", await ParseGemfileLock(manifestPath));
        }

        // requirements.txt / pip freeze
        if (lower.EndsWith(".txt") && 
            File.Exists(Path.Combine(Path.GetDirectoryName(manifestPath) ?? "", "requirements.txt")))
        {
            return ("pip", await ParsePipFreeze(manifestPath));
        }

        // go.mod
        if (lower.EndsWith("go.mod"))
        {
            return ("go", await ParseGoMod(manifestPath));
        }

        // pom.xml / maven
        if (lower.EndsWith(".xml") && 
            File.Exists(Path.Combine(Path.GetDirectoryName(manifestPath) ?? "", "pom.xml")))
        {
            return ("maven", await ParseMavenPom(manifestPath));
        }

        // .NET csproj + NuGet packages.config
        if (lower.EndsWith("csproj"))
        {
            var lockFile = Path.Combine(Path.GetDirectoryName(manifestPath) ?? "", "packages.lock.json");
            return ("nuget", await ParseNuGetCsProj(manifestPath, lockFile));
        }

        // Default: try to read as JSON (npm-style) or plain text
        if (lower.EndsWith(".json"))
        {
            return ("generic-json", await TryParseGenericJson(manifestPath));
        }

        // Plain text - assume pip/requirements style
        return ("pip", await ParsePipFreeze(manifestPath));
    }

    private static async Task<List<PackageInfo>> ParseNpmManifest(string manifestPath)
    {
        var content = await File.ReadAllTextAsync(manifestPath);
        var doc = JsonDocument.Parse(content);
        
        var deps = new List<PackageInfo>();
        
        // Direct dependencies from package.json
        if (doc.RootElement.TryGetProperty("dependencies", out var depObj))
        {
            foreach (var pair in depObj.EnumerateObject())
            {
                deps.Add(new PackageInfo(
                    name: pair.Name,
                    version: pair.Value.GetString(),
                    isDirect: true));
            }
        }

        // Transitive from package-lock.json if available
        var lockPath = Path.Combine(Path.GetDirectoryName(manifestPath) ?? "", "package-lock.json");
        if (File.Exists(lockPath))
        {
            var lockContent = await File.ReadAllTextAsync(lockPath);
            return ParseNpmLock(lockContent, deps);
        }

        return deps;
    }

    private static async Task<List<PackageInfo>> ParseNpmLock(string lockContent, List<PackageInfo> directDeps)
    {
        var doc = JsonDocument.Parse(lockContent);
        
        // Extract from "packages" field (npm v7+)
        if (doc.RootElement.TryGetProperty("packages", out var packagesObj))
        {
            foreach (var pair in packagesObj.EnumerateObject())
            {
                var pathParts = pair.Key.Split('/');
                var name = pathParts[0];
                
                // Find matching direct dependency to mark as transitive
                var isDirect = directDeps.Any(d => d.Name == name);
                
                if (pair.Value.TryGetProperty("version", out var verElem))
                {
                    var version = verElem.GetString();
                    
                    // Try to extract license from "license" field
                    string? licenseId = null;
                    if (pair.Value.TryGetProperty("license", out var licElem) && 
                        licElem.TryGetProperty("id", out var licIdElem))
                    {
                        licenseId = licIdElem.GetString();
                    }

                    directDeps.Add(new PackageInfo(
                        name: name,
                        version: version,
                        isDirect: isDirect));
                }
            }
        }

        return directDeps;
    }

    private static async Task<List<PackageInfo>> ParseCargoToml(string manifestPath)
    {
        var content = await File.ReadAllTextAsync(manifestPath);
        
        // Simple TOML parsing for dependencies section
        var deps = new List<PackageInfo>();
        
        // Look for [[dependencies]] sections
        var inDependencies = false;
        foreach (var line in content.Split('\n'))
        {
            if (line.Trim().StartsWith("[[dependencies]]"))
                inDependencies = true;
            
            if (inDependencies && !line.StartsWith("["))
            {
                // Parse: name = "version" or name = { version = "x", ... }
                var equalsIndex = line.IndexOf('=');
                if (equalsIndex > 0)
                {
                    var namePart = line.Substring(0, equalsIndex).Trim();
                    var valuePart = line.Substring(equalsIndex + 1).Trim();

                    string? version = null;
                    string? licenseId = null;

                    // Check for inline table with version and license
                    if (valuePart.StartsWith('{'))
                    {
                        var inner = valuePart.TrimStart('{').TrimEnd('}');
                        
                        if (inner.Contains("version"))
                        {
                            var verStart = inner.IndexOf('"') + 1;
                            var verEnd = inner.IndexOf('"', verStart);
                            version = inner.Substring(verStart, verEnd - verStart).Trim();
                        }

                        if (inner.Contains("license"))
                        {
                            var licStart = inner.IndexOf('"') + 1;
                            var licEnd = inner.IndexOf('"', licStart);
                            licenseId = inner.Substring(licStart, licEnd - licStart).Trim();
                        }
                    }
                    else if (valuePart.StartsWith("\"") && valuePart.EndsWith("\""))
                    {
                        version = valuePart.Trim('"');
                    }

                    deps.Add(new PackageInfo(
                        name: namePart.Trim('"'),
                        version: version,
                        isDirect: true,
                        licenseId: licenseId));
                }
            }
        }

        return deps;
    }

    private static async Task<List<PackageInfo>> ParseGemfileLock(string manifestPath)
    {
        var content = await File.ReadAllTextAsync(manifestPath);
        
        // Ruby gems are typically in Gemfile.lock under "PLATFORMS" or "DEPENDENCIES"
        var deps = new List<PackageInfo>();

        // Simple regex-based extraction for common formats
        var gemPattern = @"(\w+)[\s]*=\s*\"?([^"\s]+)\"?" + 
                        @"(?:\s*,\s*platform:\s*[\"\']([^\"\']+)[\"\'])?" + 
                        @"(?:\s*,\s*specs:\s*\[([^\]]+)\])?" + 
                        @"(?:\s*,\s*require:\s*([^\,]+))?" + 
                        @"(?:\s*,\s*license:\s*\"?([^"\s]+)\"?)?" + 
                        @".*";

        foreach (Match match in Regex.Matches(content, gemPattern, RegexOptions.Multiline | RegexOptions.IgnoreCase))
        {
            var name = match.Groups[1].Value.Trim();
            var version = match.Groups[2].Success ? match.Groups[2].Value.Trim() : null;
            var licenseId = match.Groups[6].Success ? match.Groups[6].Value.Trim() : null;

            deps.Add(new PackageInfo(
                name: name,
                version: version,
                isDirect: true,
                licenseId: licenseId));
        }

        return deps;
    }

    private static async Task<List<PackageInfo>> ParsePipFreeze(string manifestPath)
    {
        var content = await File.ReadAllTextAsync(manifestPath);
        
        // Format: package==version or package>=version
        var deps = new List<PackageInfo>();
        
        foreach (var line in content.Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line) || 
                line.StartsWith("#") || 
                !line.Contains("=="))
                continue;

            var parts = line.Split(new[] { "==", ">=", "<=" }, StringSplitOptions.None);
            if (parts.Length < 2)
                continue;

            var name = parts[0].Trim();
            var version = parts[1].Trim().Replace("\"", "").Replace("'", "");

            // Try to extract license from line or metadata
            string? licenseId = null;
            
            deps.Add(new PackageInfo(
                name: name,
                version: version,
                isDirect: true));
        }

        return deps;
    }

    private static async Task<List<PackageInfo>> ParseGoMod(string manifestPath)
    {
        var content = await File.ReadAllTextAsync(manifestPath);
        
        // Format: module path v1.2.3
        var deps = new List<PackageInfo>();
        
        foreach (var line in content.Split('\n'))
        {
            if (!line.StartsWith("require "))
                continue;

            var rest = line.Substring(8).Trim();
            
            // Parse: module/path v1.2.3
            var parts = rest.Split(' ');
            if (parts.Length >= 2)
            {
                var name = parts[0].Trim();
                var version = parts[1].Trim().Replace("\"", "");

                deps.Add(new PackageInfo(
                    name: name,
                    version: version,
                    isDirect: true));
            }
        }

        return deps;
    }

    private static async Task<List<PackageInfo>> ParseMavenPom(string manifestPath)
    {
        var content = await File.ReadAllTextAsync(manifestPath);
        
        // Simple XML parsing for Maven dependencies
        var deps = new List<PackageInfo>();
        
        var inDependencies = false;
        foreach (var line in content.Split('\n'))
        {
            if (line.Contains("<dependencies>"))
                inDependencies = true;
            
            if (inDependencies)
            {
                // Look for dependency element with groupId, artifactId, version
                var startTag = line.IndexOf("<dependency>") + 12;
                var endTag = line.LastIndexOf("</dependency>") + 13;

                if (startTag > 0 && endTag > startTag)
                {
                    // Extract attributes from opening tag
                    var depLine = line.Substring(startTag, endTag - startTag);
                    
                    string? groupId = null;
                    string? artifactId = null;
                    string? version = null;

                    if (depLine.Contains("<groupId>"))
                        groupId = ExtractText(depLine, "<groupId>", "</groupId>");
                    if (depLine.Contains("<artifactId>") && !depLine.Contains("<version>"))
                        artifactId = ExtractText(depLine, "<artifactId>", "</artifactId>");
                    if (depLine.Contains("<version>"))
                        version = ExtractText(depLine, "<version>", "</version>");

                    // Construct package name
                    var packageName = $"{groupId?.Replace('.', '_') ?? ""}_{artifactId}";
                    
                    deps.Add(new PackageInfo(
                        name: packageName,
                        version: version,
                        isDirect: true));
                }
            }
        }

        return deps;
    }

    private static string ExtractText(string text, string startTag, string endTag)
    {
        var start = text.IndexOf(startTag) + start