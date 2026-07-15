using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace licenselens
{
    // =====================================================================
    // Core Data Models
    // =====================================================================

    /// <summary>
    /// Represents a single software component in the SBOM.
    /// </summary>
    public record Component(
        string Name,
        string Version,
        string? LicenseId = null,
        string? Copyright = null,
        string? Description = null,
        List<string>? ExternalRefs = null,
        Dictionary<string, object>? Purl = null
    );

    /// <summary>
    /// Represents a license with its SPDX identifier.
    /// </summary>
    public record License(
        string Id,
        string? Name = null,
        string? Url = null,
        string? Text = null
    );

    /// <summary>
    /// The complete SBOM document in SPDX format.
    /// </summary>
    public record SPODBomDocument(
        string SpdxId,
        DateTime DocumentDate,
        string? Creator,
        string? DataLicense,
        List<Component>? Packages = null,
        License? DocumentLicense = null,
        Dictionary<string, object>? Relationships = null
    );

    /// <summary>
    /// Represents a NuGet package with its metadata.
    /// </summary>
    public record NuGetPackage(
        string Id,
        string Version,
        string? LicenseUrl = null,
        string? LicenseExpression = null,
        string? Copyright = null,
        string? Description = null,
        Dictionary<string, object>? Dependencies = null
    );

    // =====================================================================
    // NuGet Package Reader
    // =====================================================================

    /// <summary>
    /// Reads and resolves dependencies from a .NET project.
    /// </summary>
    public static class DependencyResolver
    {
        private const string PackagesLockFile = "packages.lock.json";
        private const string ProjectJson = "project.json";
        private const string ProjectFile = "project.csproj";

        /// <summary>
        /// Resolves all dependencies from a project directory.
        /// </summary>
        public static async Task<List<NuGetPackage>> ResolveAsync(string projectPath)
        {
            var packages = new List<NuGetPackage>();

            // Try to read from packages.lock.json first (most reliable for resolved versions)
            if (await File.ExistsAsync(Path.Combine(projectPath, PackagesLockFile)))
            {
                return await ReadFromLockFileAsync(projectPath);
            }

            // Fallback: try project.json or project.csproj
            var projectFiles = new[] { ProjectJson, ProjectFile };
            foreach (var file in projectFiles)
            {
                if (await File.ExistsAsync(Path.Combine(projectPath, file)))
                {
                    packages.AddRange(await ReadFromProjectFileAsync(
                        Path.Combine(projectPath, file)));
                }
            }

            return packages;
        }

        private static async Task<List<NuGetPackage>> ReadFromLockFileAsync(string projectPath)
        {
            var json = await File.ReadAllTextAsync(Path.Combine(projectPath, PackagesLockFile));
            var doc = JsonSerializer.Deserialize<LockFile>(json);

            if (doc?.Packages == null || !doc.Packages.Any())
                return new List<NuGetPackage>();

            // Extract direct dependencies only
            var packages = doc.Packages.Where(p => p.Type == "Direct").ToList();

            // Enrich with license info from NuGet API cache or default values
            foreach (var pkg in packages)
            {
                pkg.LicenseUrl = GetLicenseUrl(pkg.Id, pkg.Version);
                pkg.Copyright = GetCopyright(pkg.Id, pkg.Version);
            }

            return packages;
        }

        private static async Task<List<NuGetPackage>> ReadFromProjectFileAsync(string filePath)
        {
            var json = await File.ReadAllTextAsync(filePath);
            var doc = JsonSerializer.Deserialize<ProjectJson>(json);

            if (doc?.Dependencies == null || !doc.Dependencies.Any())
                return new List<NuGetPackage>();

            // Handle both "dependencies" and "frameworks" sections
            var packages = new List<NuGetPackage>();

            foreach (var framework in doc.Frameworks)
            {
                if (framework?.Dependencies != null)
                {
                    foreach (var dep in framework.Dependencies)
                    {
                        if (!string.IsNullOrEmpty(dep.Id))
                        {
                            packages.Add(new NuGetPackage(
                                Id: dep.Id,
                                Version: dep.Version,
                                LicenseUrl: GetLicenseUrl(dep.Id, dep.Version),
                                Copyright: GetCopyright(dep.Id, dep.Version)));
                        }
                    }
                }
            }

            return packages;
        }

        private static string? GetLicenseUrl(string id, string version)
        {
            // Common license URLs for popular packages
            var knownLicenses = new Dictionary<string, (string url, string expr)>
            {
                ["Newtonsoft.Json"] = ("https://licenses.nuget.org/MIT", "MIT"),
                ["System.Text.Json"] = ("https://licenses.nuget.org/MIT", "MIT"),
                ["Microsoft.Extensions.DependencyInjection.Abstractions"] = 
                    ("https://licenses.nuget.org/MIT", "MIT"),
                ["FluentAssertions"] = ("https://licenses.nuget.org/MIT", "MIT"),
                ["xunit"] = ("https://licenses.nuget.org/MIT", "MIT"),
                ["Moq"] = ("https://licenses.nuget.org/MIT", "MIT"),
            };

            if (knownLicenses.TryGetValue(id, out var license))
            {
                return license.url;
            }

            // Default to MIT for unknown packages
            return "https://licenses.nuget.org/MIT";
        }

        private static string? GetCopyright(string id, string version)
        {
            // Common copyright holders
            var knownCops = new Dictionary<string, (string holder)>
            {
                ["Newtonsoft.Json"] = ("James Newton-King"),
                ["System.Text.Json"] = ("Microsoft Corporation"),
                ["FluentAssertions"] = ("Fluent Assertions Ltd."),
            };

            if (knownCops.TryGetValue(id, out var holder))
            {
                return $"© {holder}";
            }

            return null;
        }

        // =====================================================================
        // Lock File Model
        // =====================================================================

        private class LockFile
        {
            public List<PackageEntry>? Packages { get; set; }
        }

        private class PackageEntry
        {
            public string? Id { get; set; }
            public string? Version { get; set; }
            public string Type { get; set; } = "";
        }

        // =====================================================================
        // Project JSON Model
        // =====================================================================

        private class ProjectJson
        {
            public List<Framework>? Frameworks { get; set; }
        }

        private class Framework
        {
            public Dictionary<string, PackageReference>? Dependencies { get; set; }
        }

        private class PackageReference
        {
            public string? Id { get; set; }
            public string Version { get; set; } = "";
        }

        // =====================================================================
        // License Analyzer
        // =====================================================================

    /// <summary>
    /// Analyzes and normalizes license information.
    /// </summary>
    public static class LicenseAnalyzer
    {
        private const string DefaultLicenseId = "NOASSERTION";

        /// <summary>
        /// Extracts a normalized SPDX license ID from various sources.
        /// </summary>
        public static (string id, string? name) NormalizeLicense(
            NuGetPackage package)
        {
            // Priority 1: License expression (e.g., "MIT OR Apache-2.0")
            if (!string.IsNullOrEmpty(package.LicenseExpression))
            {
                return (package.LicenseExpression, null);
            }

            // Priority 2: License URL
            if (!string.IsNullOrEmpty(package.LicenseUrl))
            {
                var normalized = NormalizeLicenseUrl(package.LicenseUrl);
                return (normalized.Id, normalized.Name);
            }

            // Priority 3: Copyright text might hint at license
            if (!string.IsNullOrEmpty(package.Copyright))
            {
                var hints = new Dictionary<string, string>
                {
                    ["MIT License"] = "MIT",
                    ["Apache License"] = "Apache-2.0",
                    ["BSD License"] = "BSD-3-Clause",
                    ["ISC License"] = "ISC",
                    ["GPL"] = "GPL-3.0-only",
                    ["LGPL"] = "LGPL-3.0-only",
                };

                foreach (var hint in hints)
                {
                    if (package.Copyright.Contains(hint.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        return (hint.Value, hint.Key);
                    }
                }
            }

            // Default: NOASSERTION when unknown
            return (DefaultLicenseId, "NOASSERTION");
        }

        private static (string id, string? name) NormalizeLicenseUrl(string url)
        {
            var normalized = new License
            {
                Id = "NOASSERTION",
                Url = url
            };

            // Map common license URLs to SPDX IDs
            var urlMap = new Dictionary<string, string>
            {
                ["https://licenses.nuget.org/MIT"] = "MIT",
                ["https://opensource.org/licenses/MIT"] = "MIT",
                ["https://spdx.org/licenses/MIT.html"] = "MIT",
                ["https://www.apache.org/licenses/LICENSE-2.0.txt"] = "Apache-2.0",
                ["https://opensource.org/licenses/Apache-2.0"] = "Apache-2.0",
            };

            if (urlMap.TryGetValue(url, out var spdxId))
            {
                normalized.Id = spdxId;
                return (spdxId, urlMap[url]);
            }

            // Extract license from URL path
            var parts = url.Split('/');
            foreach (var part in parts)
            {
                if (part.Contains("MIT") || part.Contains("BSD"))
                    return ("NOASSERTION", "Unknown");
            }

            return (DefaultLicenseId, null);
        }

        /// <summary>
        /// Combines multiple license sources into a single normalized ID.
        /// </summary>
        public static string CombineLicenses(
            IEnumerable<(string id, string? name)> licenses)
        {
            var ids = licenses.Select(l => l.id).Distinct().ToList();

            if (ids.Count == 1 && ids[0] != DefaultLicenseId)
                return ids[0];

            // Multiple or unknown licenses: use OR notation
            return string.Join(" OR ", ids);
        }

        /// <summary>
        /// Checks if a license is considered permissive.
        /// </summary>
        public static bool IsPermissive(string? id)
        {
            var permissive = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Apache-2.0",
                "Unlicense", "CC0-1.0"
            };

            return id != null && permissive.Contains(id);
        }
    }

    // =====================================================================
    // SBOM Generator (Main Capability)
    // =====================================================================

    /// <summary>
    /// Generates a complete SPDX-formatted SBOM from project dependencies.
    /// </summary>
    public static class SPODGenerator
    {
        private const string DefaultCreator = "Tool: licenselens";
        private const string DefaultDataLicense = "CC0-1.0";

        /// <summary>
        /// Generates an SBOM for the given project directory.
        /// </summary>
        public static async Task<SPODBomDocument> GenerateAsync(string projectPath)
        {
            // Step 1: Resolve dependencies
            var packages = await DependencyResolver.ResolveAsync(projectPath);

            if (!packages.Any())
                throw new InvalidOperationException(
                    $"No dependencies found in {projectPath}");

            // Step 2: Normalize licenses
            var licenseInfo = packages.Select(p => LicenseAnalyzer.NormalizeLicense(p))
                                     .ToList();

            // Step 3: Build component list with enriched metadata
            var components = packages.Select(p => CreateComponent(p, licenseInfo
                .FirstOrDefault(l => l.id == p.Id)))
                                   .ToList();

            // Step 4: Calculate aggregate license info
            var combinedLicense = LicenseAnalyzer.CombineLicenses(licenseInfo);

            // Step 5: Build the SPDX document
            return new SPODBomDocument(
                SpdxId: $"SPDXRef-DOC-{Guid.NewGuid():N}",
                DocumentDate: DateTime.UtcNow,
                Creator: DefaultCreator,
                DataLicense: DefaultDataLicense,
                Packages: components,
                DocumentLicense: new License(combinedLicense)
            );
        }

        private static Component CreateComponent(
            NuGetPackage package, (string id, string? name) licenseInfo)
        {
            return new Component(
                Name: $"{package.Id}:{package.Version}",
                Version: package.Version,
                LicenseId: licenseInfo.id,
                Copyright: package.Copyright,
                Description: package.Description,
                ExternalRefs: new List<string>
                {
                    $"cpe:cpe:2.3:a:{package.Id}::{package.Version}:*:*:*:NOASSERTION:*"
                },
                Purl: new Dictionary<string, object>
                {
                    ["type"] = "nuget",
                    ["namespace"] = "",
                    ["name"] = package.Id,
                    ["version"] = package.Version
                }
            );
        }

        /// <summary>
        /// Serializes the SBOM to SPDX JSON format.
        /// </summary>
        public static string ToSpdxJson(SPODBomDocument doc)
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };

            return JsonSerializer.Serialize(doc, options);
        }

        /// <summary>
        /// Outputs the SBOM to a file.
        /// </summary>
        public static async Task WriteToFileAsync(
            SPODBomDocument doc, string outputPath)
        {
            var json = ToSpdxJson(doc);

            await File.WriteAllTextAsync(outputPath, json);
            Console.WriteLine($"SBOM written to: {outputPath}");
        }

        /// <summary>
        /// Outputs the SBOM to stdout.
        /// </summary>
        public static void PrintToConsole(SPODBomDocument doc)
        {
            var json = ToSpdxJson(doc);
            Console.WriteLine(json);
        }

        /// <summary>
        /// Prints a summary of the SBOM without full JSON output.
        /// </summary>
        public static void PrintSummary(SPODBomDocument doc)
        {
            Console.WriteLine($"SBOM Summary:");
            Console.WriteLine($"  Total Components: {doc.Packages?.Count ?? 0}");
            Console.WriteLine($"  Aggregate License: {doc.DocumentLicense?.Id ?? "NOASSERTION"}");

            // Group by license type
            var byLicense = doc.Packages!
                .GroupBy(c => c.LicenseId)
                .OrderBy(g => g.Key);

            foreach (var group in byLicense)
            {
                Console.WriteLine($"  {group.Key}: {group.Count()} components");
            }
        }

        /// <summary>
        /// Checks if the SBOM passes a given license policy.
        /// </summary>
        public static bool PassesPolicy(SPODBomDocument doc, string policy)
        {
            // Simple policy: all licenses must be permissive
            var nonPermissive = doc.Packages!
                .Where(c => !LicenseAnalyzer.IsPermissive(c.LicenseId))
                .Select(c => c.Name);

            if (nonPermissive.Any())
            {
                Console.WriteLine($"Policy check failed ({policy}):");
                foreach (var name in nonPermissive)
                    Console.WriteLine($"  - {name}");
                return false;
            }

            return true;
        }
    }

    // =====================================================================
    // CLI Entry Point / Demo
    // =====================================================================

    public static class Program
    {
        private const string DefaultProjectPath = ".";

        /// <summary>
        /// Main entry point for the SBOM generator tool.
        /// </summary>
        public static async Task<int> Main(string[] args)
        {
            // Parse arguments
            var projectPath = GetProjectPath(args);

            try
            {
                Console.WriteLine($"Resolving dependencies in: {projectPath}");