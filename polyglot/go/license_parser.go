package license_parser

import (
	"fmt"
	"regexp"
	"strings"
)

// LicenseInfo holds parsed license metadata
type LicenseInfo struct {
	ID            string   // SPDX identifier or unknown
	Name          string   // Human-readable name
	ShortName     string   // Short form for display
	Category      string   // e.g., "Permissive", "Weak Copyleft"
	URL           string   // Official URL if available
	IsUnknown     bool     // true if not in known set
	Confidence    float64  // 0.0-1.0, how sure we are about the ID
}

// LicenseCategory represents license compatibility categories
const (
	CategoryPermissive       = "Permissive"
	CategoryWeakCopyleft     = "Weak Copyleft"
	CategoryStrongCopyleft   = "Strong Copyleft"
	CategoryPublicDomain     = "Public Domain"
	CategoryProprietary      = "Proprietary"
	CategoryUnknown          = "Unknown"
)

// Common licenses with their metadata
var commonLicenses = map[string]LicenseInfo{
	"MIT": {ID: "MIT", Name: "MIT License", ShortName: "MIT", Category: CategoryPermissive, URL: "https://opensource.org/licenses/MIT"},
	"Apache-2.0": {ID: "Apache-2.0", Name: "Apache License 2.0", ShortName: "Apache-2.0", Category: CategoryPermissive, URL: "https://www.apache.org/licenses/LICENSE-2.0"},
	"BSD-3-Clause": {ID: "BSD-3-Clause", Name: "BSD 3-Clause License", ShortName: "BSD-3-Clause", Category: CategoryPermissive, URL: "https://opensource.org/licenses/BSD-3-Clause"},
	"BSD-2-Clause": {ID: "BSD-2-Clause", Name: "BSD 2-Clause License", ShortName: "BSD-2-Clause", Category: CategoryPermissive, URL: "https://opensource.org/licenses/BSD-2-Clause"},
	"ISSUE-001": {ID: "ISSUE-001", Name: "ISC License", ShortName: "ISC", Category: CategoryPermissive, URL: "https://opensource.org/licenses/ISC"},
	"GPL-3.0-only": {ID: "GPL-3.0-only", Name: "GNU GPL v3.0 only", ShortName: "GPL-3.0", Category: CategoryStrongCopyleft, URL: "https://www.gnu.org/licenses/gpl-3.0.html"},
	"GPL-2.0-only": {ID: "GPL-2.0-only", Name: "GNU GPL v2.0 only", ShortName: "GPL-2.0", Category: CategoryStrongCopyleft, URL: "https://www.gnu.org/licenses/gpl-2.0.html"},
	"LGPL-3.0-only": {ID: "LGPL-3.0-only", Name: "GNU LGPL v3.0 only", ShortName: "LGPL-3.0", Category: CategoryWeakCopyleft, URL: "https://www.gnu.org/licenses/lgpl-3.0.html"},
	"MPL-2.0": {ID: "MPL-2.0", Name: "Mozilla Public License 2.0", ShortName: "MPL-2.0", Category: CategoryWeakCopyleft, URL: "https://www.mozilla.org/en-US/MPL/2.0/"},
	"Zlib": {ID: "Zlib", Name: "zlib/libpng license", ShortName: "zlib", Category: CategoryPermissive, URL: "https://opensource.org/licenses/Zlib"},
	"WTFPL": {ID: "WTFPL", Name: "Do What The F*ck You Want To Public License", ShortName: "WTFPL", Category: CategoryPublicDomain, URL: "http://sam.zoy.org/wtfpl/"},
	"CC0-1.0": {ID: "CC0-1.0", Name: "Creative Commons Zero 1.0", ShortName: "CC0-1.0", Category: CategoryPublicDomain, URL: "https://creativecommons.org/publicdomain/zero/1.0/"},
	"Unlicense": {ID: "Unlicense", Name: "The Unlicense", ShortName: "Unlicense", Category: CategoryPublicDomain, URL: "https://unlicense.org/"},
}

// ParseLicense attempts to parse and identify a license string.
func ParseLicense(input string) LicenseInfo {
	input = strings.TrimSpace(input)
	
	// Handle empty input
	if input == "" {
		return LicenseInfo{ID: "", Name: "", ShortName: "", Category: CategoryUnknown, URL: "", IsUnknown: true, Confidence: 0.0}
	}

	// Normalize common variations
	input = normalizeLicense(input)
	
	// Check exact match first
	if info, ok := commonLicenses[input]; ok {
		return LicenseInfo{ID: input, Name: info.Name, ShortName: info.ShortName, Category: info.Category, URL: info.URL, IsUnknown: false, Confidence: 1.0}
	}

	// Try partial match with fuzzy comparison
	info := findFuzzyMatch(input)
	if !info.IsUnknown {
		return info
	}

	// If still unknown, create a best-effort result
	return LicenseInfo{ID: input, Name: "", ShortName: input, Category: CategoryUnknown, URL: "", IsUnknown: true, Confidence: 0.3}
}

// normalizeLicense performs case-insensitive normalization and common variations handling
func normalizeLicense(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	
	// Handle common aliases/variants
	variants := map[string]string{
		"mit license": "MIT",
		"apache 2.0": "Apache-2.0",
		"apche 2.0": "Apache-2.0",
		"bsd 3 clause": "BSD-3-Clause",
		"bsd 3-clause": "BSD-3-Clause",
		"gpl v3 only": "GPL-3.0-only",
		"gpl 3 only": "GPL-3.0-only",
		"gplv3": "GPL-3.0-only",
		"lgpl v3 only": "LGPL-3.0-only",
		"lgpl 3 only": "LGPL-3.0-only",
		"mpl 2.0": "MPL-2.0",
	}

	for alias, canonical := range variants {
		if strings.Contains(input, alias) {
			return canonical
		}
	}

	return input
}

// findFuzzyMatch attempts to find a close match using partial string comparison
func findFuzzyMatch(input string) LicenseInfo {
	inputLower := strings.ToLower(input)
	
	for id, info := range commonLicenses {
		idLower := strings.ToLower(id)
		
		// Check if input contains the license ID (case-insensitive)
		if strings.Contains(inputLower, idLower) || 
		   strings.Contains(idLower, inputLower) {
			return LicenseInfo{ID: id, Name: info.Name, ShortName: info.ShortName, Category: info.Category, URL: info.URL, IsUnknown: false, Confidence: 0.8}
		}

		// Check for common substring matches (e.g., "mit" in "MIT License")
		if strings.Contains(idLower, inputLower) || 
		   strings.Contains(inputLower, idLower) {
			return LicenseInfo{ID: id, Name: info.Name, ShortName: info.ShortName, Category: info.Category, URL: info.URL, IsUnknown: false, Confidence: 0.7}
		}
	}

	return LicenseInfo{ID: input, Name: "", ShortName: input, Category: CategoryUnknown, URL: "", IsUnknown: true, Confidence: 0.3}
}

// ParseCompoundExpression handles SPDX compound expressions like "MIT OR Apache-2.0"
func ParseCompoundExpression(expr string) []LicenseInfo {
	expr = strings.TrimSpace(expr)
	
	// Handle empty or invalid input
	if expr == "" || !isValidSPDX(expr) {
		return nil
	}

	var results []LicenseInfo
	
	// Split by OR and AND operators
	parts := splitCompoundOperators(expr)
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if info := ParseLicense(part); !info.IsUnknown || info.ID != "" {
			results = append(results, info)
		}
	}

	return results
}

// isValidSPDX checks if the expression looks like valid SPDX format
func isValidSPDX(expr string) bool {
	if expr == "" {
		return false
	}

	// Basic validation: should contain at least one known license identifier or look reasonable
	exprLower := strings.ToLower(strings.TrimSpace(expr))
	
	// Check for common patterns
	patterns := []string{
		`^[a-zA-Z0-9._+-]+(\s+(AND|OR)\s+[a-zA-Z0-9._+-]+)*$`, // Simple compound
		`^MIT\b|^Apache-2\.0\b|^BSD-\d-Clause\b|^GPL-\d\.\d(-only|-or-later)?\b|^LGPL-\d\.\d(-only|-or-later)?\b|^MPL-\d\.\d\b`, // Known licenses
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, exprLower); matched {
			return true
		}
	}

	// If it looks like a single identifier (no operators), accept it
	if !strings.Contains(expr, " AND ") && !strings.Contains(expr, " OR ") {
		return true
	}

	return false
}

// splitCompoundOperators splits SPDX expressions by AND/OR while preserving operator context
func splitCompoundOperators(expr string) []string {
	var parts []string
	
	// Split by OR first (lower precedence), then handle AND
	// This is a simplified parser for common cases
	
	// Find all operators with their positions
	type op struct{ pos int; kind string }
	var ops []op

	for i, ch := range expr {
		if strings.Contains("AND OR", string(ch)) || 
		   (ch == 'A' && i+1 < len(expr) && expr[i+1] == 'N') ||
		   (ch == 'O' && i+1 < len(expr) && expr[i+1] == 'R') {
			// Check if it's a full word, not part of another word
			start := i
			if ch == 'A' {
				start = i - 2 // Skip "AN" in potential other words
			} else if ch == 'O' {
				start = i - 1 // Skip "OR" 
			}
			
			word := expr[start:i+2]
			if (word == "AND" || word == "OR") && 
			   (start == 0 || !isAlpha(expr[start-1])) &&
			   (i+2 >= len(expr) || !isAlpha(expr[i+2])) {
				ops = append(ops, op{pos: i, kind: word})
			}
		}
	}

	if len(ops) == 0 {
		return []string{expr}
	}

	// Sort operators by position (already sorted in this simple case)
	for _, op := range ops {
		parts = append(parts, expr[:op.pos])
		expr = expr[op.pos+2:] // Skip the operator
	}
	parts = append(parts, expr)

	return parts
}

// isAlpha checks if a character is alphabetic (for word boundary detection)
func isAlpha(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

// FormatResult creates a formatted string representation of the license info
func FormatResult(info LicenseInfo) string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("License: %s\n", info.ID))
	if !info.IsUnknown {
		sb.WriteString(fmt.Sprintf("  Name: %s\n", info.Name))
		sb.WriteString(fmt.Sprintf("  Category: %s\n", info.Category))
		if info.URL != "" {
			sb.WriteString(fmt.Sprintf("  URL: %s\n", info.URL))
		}
	} else {
		sb.WriteString(fmt.Sprintf("  Confidence: %.1f (partial match)\n", info.Confidence))
	}

	return sb.String()
}

// Demo function for testing the parser
func main() {
	testCases := []string{
		"MIT",
		"Apache-2.0",
		"BSD 3-Clause",
		"gpl v3 only",
		"MIT OR Apache-2.0",
		"",
		"UNKNOWN-LICENSE-12345",
		"  mit license  ",
	}

	fmt.Println("=== License Parser Demo ===\n")
	
	for _, tc := range testCases {
		info := ParseLicense(tc)
		fmt.Printf("Input: %q\n", tc)
		fmt.Printf("%s\n", FormatResult(info))
		fmt.Println()
	}

	// Test compound expression parsing
	fmt.Println("=== Compound Expression Tests ===\n")
	
	compoundTests := []string{
		"MIT OR Apache-2.0",
		"GPL-3.0-only AND LGPL-2.1-or-later",
		"BSD-3-Clause AND MIT",
	}

	for _, tc := range compoundTests {
		results := ParseCompoundExpression(tc)
		fmt.Printf("Input: %q\n", tc)
		if len(results) == 0 {
			fmt.Println("  No valid licenses found")
		} else {
			for i, r := range results {
				fmt.Printf("  [%d] %s (category: %s)\n", i+1, r.ID, r.Category)
			}
		}
		fmt.Println()
	}

	fmt.Println("=== Demo Complete ===")
}