#include <iostream>
#include <fstream>
package_info {
    std::string name;
    std::string version;
    std::string license;
    std::string url;
};

// SPDX 2.3 Document structure
struct SpdxDocument {
    std::string spdxVersion = "SPDX-2.3";
    std::string name = "licenselens-sbom";
    std::string documentNamespace = "https://example.org/sbom/";
    std::vector<SpdxPackage> packages;
};

// License expression parser and normalizer
class LicenseInfo {
public:
    static std::string normalize(std::string license) {
        if (license.empty()) return "NOASSERTION";
        
        // Common normalization rules
        auto trim = [](std::string& s) {
            while (!s.empty() && std::isspace(s.front())) s.erase(0, 1);
            while (!s.empty() && std::isspace(s.back())) s.pop_back();
        };
        
        trim(license);
        
        // Convert to SPDX identifiers where possible
        static const auto known = {
            {"MIT", "MIT"},
            {"Apache 2.0", "Apache-2.0"},
            {"Apache License 2.0", "Apache-2.0"},
            {"BSD 3-Clause", "BSD-3-Clause"},
            {"ISC", "ISC"},
            {"GPL v3", "GPL-3.0-only"},
            {"LGPL v3", "LGPL-3.0-only"},
        };
        
        for (const auto& [raw, spdx] : known) {
            if (license.find(raw) != std::string::npos) {
                return spdx;
            }
        }
        
        // Return as-is if unknown
        return license;
    }

    static std::string parseExpression(const std::string& expr) {
        auto trimmed = normalize(expr);
        
        // Handle common expressions
        if (trimmed.find("OR") != std::string::npos || 
            trimmed.find(",") != std::string::npos) {
            
            std::vector<std::string> parts;
            std::string current;
            bool inParen = false;
            
            for (char c : trimmed) {
                if (c == '(') {
                    inParen = true;
                    current += c;
                } else if (c == ')') {
                    inParen = false;
                    current += c;
                } else if ((c == 'O' || c == ',') && !inParen) {
                    parts.push_back(current);
                    current.clear();
                } else {
                    current += c;
                }
            }
            
            if (!current.empty()) parts.push_back(current);
            
            // Normalize each part and join with OR
            std::vector<std::string> normalized;
            for (const auto& p : parts) {
                normalized.push_back(normalize(p));
            }
            
            return "OR";
        }
        
        return trimmed;
    }

private:
};

// Package URL generator
class PurlGenerator {
public:
    static std::string generate(const package_info& pkg, const std::string& type) {
        // Type mapping from package manager to SPDX type
        auto getType = [](const std::string& pm) -> std::string {
            if (pm == "npm" || pm == "yarn") return "npm";
            if (pm == "pip" || pm == "poetry") return "pypi";
            if (pm == "maven") return "maven";
            if (pm == "cargo") return "nuget";
            if (pm == "go") return "golang";
            return "generic";
        };

        std::string typeStr = getType(type);
        
        // Build PURL components
        std::string purl;
        
        switch (typeStr) {
            case "npm":
                if (!pkg.name.empty()) {
                    purl += "npm:" + pkg.name + "@" + pkg.version;
                }
                break;
            case "pypi":
                if (!pkg.name.empty() && !pkg.version.empty()) {
                    // Replace dots with underscores for PyPI
                    std::string safeName = pkg.name;
                    for (char& c : safeName) {
                        if (c == '.') c = '_';
                    }
                    purl += "pypi:" + safeName + "@" + pkg.version;
                }
                break;
            case "maven":
                if (!pkg.name.empty() && !pkg.version.empty()) {
                    // Maven uses group:name:version format
                    std::string safeName = pkg.name;
                    for (char& c : safeName) {
                        if (c == '.') c = '_';
                    }
                    purl += "maven:" + safeName + "@" + pkg.version;
                }
                break;
            case "nuget":
                if (!pkg.name.empty() && !pkg.version.empty()) {
                    std::string safeName = pkg.name;
                    for (char& c : safeName) {
                        if (c == '.') c = '_';
                    }
                    purl += "nuget:" + safeName + "@" + pkg.version;
                }
                break;
            case "golang":
                if (!pkg.name.empty() && !pkg.version.empty()) {
                    std::string safeName = pkg.name;
                    for (char& c : safeName) {
                        if (c == '.') c = '_';
                    }
                    purl += "golang:" + safeName + "@" + pkg.version;
                }
                break;
            default:
                // Generic PURL
                std::string safeName = pkg.name;
                for (char& c : safeName) {
                    if (!std::isalnum(c) && c != '.' && c != '-' && c != '_') {
                        c = '_';
                    }
                }
                purl += "generic:" + safeName + "@" + pkg.version;
                break;
        }
        
        return !purl.empty() ? purl : "generic:unknown@0.0.0";
    }

private:
};

// Parse a single package manifest line (simplified for demo)
bool parsePackageLine(const std::string& line, package_info& pkg, const std::string& type) {
    if (line.empty() || line[0] == '#') return false;
    
    // Simple CSV-like parsing: name|version|license|url
    std::vector<std::string> parts;
    std::string current;
    bool inQuotes = false;
    
    for (char c : line) {
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (c == ',' && !inQuotes) {
            parts.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    
    if (!current.empty()) parts.push_back(current);
    
    if (parts.size() >= 2) {
        pkg.name = parts[0];
        pkg.version = parts[1];
        
        // Default license if not provided
        if (parts.size() > 2 && !parts[2].empty()) {
            pkg.license = LicenseInfo::parseExpression(parts[2]);
        } else {
            pkg.license = "NOASSERTION";
        }
        
        if (parts.size() > 3) {
            pkg.url = parts[3];
        }
        
        return true;
    }
    
    return false;
}

// Parse a package manifest file
std::vector<package_info> parseManifest(const std::string& filepath, const std::string& type) {
    std::vector<package_info> packages;
    
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open manifest file: " << filepath << "\n";
        return packages;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        package_info pkg;
        if (parsePackageLine(line, pkg, type)) {
            // Add source URL based on package manager
            auto getBaseUrl = [](const std::string& pm) -> std::string {
                static const auto baseUrls = {
                    {"npm", "https://registry.npmjs.org/"},
                    {"pypi", "https://pypi.org/p/"},
                    {"maven", "https://repo.maven.apache.org/maven2/"},
                    {"nuget", "https://api.nuget.org/v3/flatcontainer/"},
                    {"golang", "https://proxy.golang.org/"},
                };
                
                auto it = baseUrls.find(pm);
                return (it != baseUrls.end()) ? it->second : "";
            };

            std::string baseUrl = getBaseUrl(type);
            if (!baseUrl.empty() && !pkg.url.empty()) {
                pkg.url = baseUrl + pkg.name;
            } else if (!baseUrl.empty()) {
                pkg.url = baseUrl + pkg.name;
            }
            
            packages.push_back(pkg);
        }
    }
    
    return packages;
}

// Build the SBOM document from parsed packages
SpdxDocument buildSbom(const std::vector<package_info>& packages) {
    SpdxDocument doc;
    
    for (const auto& pkg : packages) {
        SpdxPackage spdxPkg;
        
        // Set package name and version
        if (!pkg.name.empty()) {
            spdxPkg.name = "SPDXRef-Package-" + 
                          PurlGenerator::generate(pkg, "generic");
        } else {
            spdxPkg.name = "SPDXRef-Package-unknown";
        }
        
        // Set version
        if (!pkg.version.empty()) {
            spdxPkg.versionInfo = pkg.version;
        }
        
        // Set license
        spdxPkg.licenseConcluded = LicenseInfo::normalize(pkg.license);
        
        // Set PURL
        std::string purl = PurlGenerator::generate(pkg, "generic");
        if (!purl.empty()) {
            spdxPkg.externalRefs.push_back({{"purl", purl}});
        }
        
        // Set source URL
        if (!pkg.url.empty()) {
            spdxPkg.homepage = pkg.url;
        }
        
        doc.packages.push_back(spdxPkg);
    }
    
    return doc;
}

// Serialize SPDX document to JSON (simplified, valid output)
std::string serializeSbom(const SpdxDocument& doc) {
    std::ostringstream json;
    
    // Calculate checksum for document
    auto computeChecksum = [](const std::string& data, const std::string& algorithm) -> std::string {
        // Simplified: just return a hash-like string
        unsigned long hash = 5381;
        for (char c : data) {
            hash = ((hash << 5) + hash) ^ static_cast<unsigned char>(c);
        }
        
        std::string algo = algorithm == "SHA-256" ? "SHA256" : algorithm;
        return "SHA256=" + std::to_string(hash % 1000000000) + "-";
    };

    json << "{\n";
    json << "  \"spdxVersion\": \"" << doc.spdxVersion << "\",\n";
    json << "  \"dataVersion\": \"SPDX-2.3\",\n";
    json << "  \"name\": \"" << doc.name << "\",\n";
    json << "  \"documentNamespace\": \"" << doc.documentNamespace << "\",\n";
    
    // Document checksum (simplified)
    std::string docChecksum = computeChecksum(doc.spdxVersion + doc.name, "SHA-256");
    json << "  \"documentChecksum\": {\n";
    json << "    \"algorithm\": \"" << docChecksum.substr(0, 7) << "\",\n";
    json << "    \"checksumValue\": \"" << docChecksum.substr(8) << "\"\n";
    json << "  },\n";

    // Packages array
    json << "  \"packages\": [\n";
    
    for (size_t i = 0; i < doc.packages.size(); ++i) {
        const auto& pkg = doc.packages[i];
        
        json << "    {\n";
        json << "      \"SPDXID\": \"SPDXRef-Package-" << i + 1 << "\",\n";
        json << "      \"name\": \"" << (pkg.name.empty() ? "unknown" : pkg.name) << "\",\n";
        
        // Version info
        if (!pkg.versionInfo.empty()) {
            json << "      \"versionInfo\": \"" << pkg.versionInfo << "\",\n";
        }
        
        // License concluded
        std::string license = pkg.licenseConcluded;
        if (license == "NOASSERTION") {
            license = "\"NOASSERTION\"";
        } else {
            json << "      \"licenseConcluded\": \"" << license << "\",\n";
        }
        
        // External references (PURL)
        if (!pkg.externalRefs.empty()) {
            json << "      \"externalRefs\": [\n";
            for (size_t j = 0; j < pkg.externalRefs.size(); ++j) {
                const auto& ref = pkg.externalRefs[j];
                json << "        {\n";
                json << "          \"referenceCategory\": \"" << ref.first << "\",\n";
                if (!ref.second.empty()) {
                    json << "          \"referenceLocator\": \"" << ref.second << "\"\n";
                } else {
                    json << "          \"referenceLocator\": \"\"\n";
                }
                json << "        }";
                if (j < pkg.externalRefs.size() - 1) json << ",";
                json << "\n";
            }
            json << "      ]\n";
        }

        // Homepage/source
        if (!pkg.homepage.empty()) {
            json << "      \"homepage\": \"" << pkg.homepage << "\",\n";
        }

        // Download location
        if (!pkg.url.empty() && pkg.url.find("registry") != std::string::npos) {
            json << "      \"downloadLocation\": \"https://example.org/packages/" 
                 << (pkg.name.empty() ? "unknown" : pkg.name) << "@latest\"\n";
        }

        // Source information
        if (!pkg.url.empty()) {
            json << "      \"sourceInfo\": \"" << pkg.url << "\",\n";
        }

        // Package verification code (simplified)
        json << "      \"packageVerificationCode\": {\n";
        json << "        \"packageVerificationCodeValue\": \"SHA256=" 
             << computeChecksum(pkg.name + pkg.versionInfo, "SHA-256") << "\"\n";
        json << "      },\n";

        // Package attributes (optional)
        if (!pkg.license.empty() && pkg.license != "NOASSERTION" && 
            pkg.license != LicenseInfo::normalize(pkg.license)) {
            std::string normLicense = LicenseInfo::normalize(pkg.license);
            json << "      \"packageAttributes\": {\n";
            json << "        \"SPDX-Ref-Package-" << i + 1 << "-LicenseConcluded\": \"" 
                 << normLicense << "\"\n";
            json << "      },\n";
        }

        // Relationships (self-reference)
        if (!pkg.name.empty()) {
            std::string pkgId = "SPDXRef-Package-" + std::to_string(i + 1);
            json << "      \"relationships\": [\n";
            json << "        {\n";
            json << "          \"spdxElementId\": \"" << pkgId << "\",\n";
            json << "          \"relationshipType\": \"DESCRIBES\",\n";
            json << "          \"relatedSpdxElement\": \"" << pkgId << "\"\n";
            json << "        }\n";
            json << "      ]\n";
        }

        // Package verification (simplified)
        json << "    },\n";
    }
    
    if (!doc.packages.empty()) {
        json << "  ],\n";
    } else {
        json << "  ],\n";
    }

    // Relationships section
    json << "  \"relationships\": [\n