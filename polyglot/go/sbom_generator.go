package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SPDX 2.3 format structures
type SBOM struct {
	SPDXVersion string `json:"spdxVersion"`
	DocumentNamespace string `json:"documentNamespace"`
	Name string `json:"name"`
	DocumentID string `json:"documentID"`
	Package []Package `json:"packages"`
}

type Package struct {
	Name string `json:"name"`
	Version string `json:"version"`
	SourceAnchoredURL string `json:"sourceAnchoredURL,omitempty"`
	LicenseConcluded string `json:"licenseConcluded,omitempty"`
	LicenseDeclared string `json:"licenseDeclared,omitempty"`
	CopyrightText string `json:"copyrightText,omitempty"`
}

// PackageInfo holds parsed dependency info
type PackageInfo struct {
	Name    string
	Version string
	Licenses []string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: licenselens sbom [go.mod path]")
		fmt.Println("Default: current directory's go.mod")
		os.Exit(0)
	}

	modPath := os.Args[1]
	if modPath == "" {
		modPath = "."
	}

	sbom, err := GenerateSBOM(modPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	output, _ := json.MarshalIndent(sbom, "", "  ")
	fmt.Println(string(output))
}

// GenerateSBOM creates an SPDX SBOM from a go.mod file
func GenerateSBOM(modPath string) (*SBOM, error) {
	var sbom SBOM
	
	sbom.SPDXVersion = "SPDX-2.3"
	sbom.DocumentNamespace = fmt.Sprintf("licenselens:%s", modPath)
	sbom.Name = filepath.Base(modPath) + "-sbom"
	sbom.DocumentID = fmt.Sprintf("urn:uuid:%s", generateUUID())

	// Parse go.mod and go.sum
	modContent, err := os.ReadFile(filepath.Join(modPath, "go.mod"))
	if err != nil {
		return &sbom, fmt.Errorf("reading go.mod: %w", err)
	}

	sumContent, err := os.ReadFile(filepath.Join(modPath, "go.sum"))
	if err != nil {
		return &sbom, fmt.Errorf("reading go.sum: %w", err)
	}

	// Parse dependencies from both files
	directDeps, indirectDeps := parseGoModules(string(modContent), string(sumContent))

	// Combine and deduplicate
	allDeps := make(map[string]PackageInfo)
	for _, dep := range directDeps {
		key := normalizeKey(dep.Name, dep.Version)
		if existing, ok := allDeps[key]; ok {
			existing.Licenses = append(existing.Licenses, dep.Licenses...)
		} else {
			allDeps[key] = dep
		}
	}
	for _, dep := range indirectDeps {
		key := normalizeKey(dep.Name, dep.Version)
		if existing, ok := allDeps[key]; ok {
			existing.Licenses = append(existing.Licenses, dep.Licenses...)
		} else {
			allDeps[key] = dep
		}
	}

	// Convert to SPDX packages and sort for deterministic output
	packages := make([]Package, 0, len(allDeps))
	for _, info := range allDeps {
		pkg := Package{
			Name:            info.Name,
			Version:         info.Version,
			SourceAnchoredURL: fmt.Sprintf("https://pkg.go.dev/%s@%s", info.Name, info.Version),
		}

		// Extract license from module path (go.mod format)
		if strings.Contains(info.Licenses[0], "module ") {
			parts := strings.SplitN(info.Licenses[0], " ", 2)
			if len(parts) == 2 {
				pkg.LicenseConcluded = parts[1]
				pkg.LicenseDeclared = parts[1]
			}
		}

		// Default copyright for Go modules
		pkg.CopyrightText = "Copyright (c) The Go Authors. All rights reserved."

		if pkg.LicenseConcluded == "" {
			pkg.LicenseConcluded = "NOASSERTION"
			pkg.LicenseDeclared = "NOASSERTION"
		}

		packages = append(packages, pkg)
	}

	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Name < packages[j].Name
	})

	sbom.Package = packages

	return &sbom, nil
}

// parseGoModules extracts dependencies from go.mod and go.sum content
func parseGoModules(modContent, sumContent string) ([]PackageInfo, []PackageInfo) {
	var directDeps, indirectDeps []PackageInfo

	// Parse go.mod for direct dependencies
	directDeps = parseGoModDirect(modContent)

	// Parse go.sum for version and license info
	indirectDeps = parseGoSum(sumContent)

	return directDeps, indirectDeps
}

func parseGoModDirect(content string) []PackageInfo {
	var deps []PackageInfo
	
	lines := strings.Split(content, "\n")
	inRequireBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if inRequireBlock && (line == ")" || line == "") {
			inRequireBlock = false
			continue
		}

		if !inRequireBlock && strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}

		if inRequireBlock && len(line) > 0 {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) >= 2 {
				name := parts[0]
				version := parts[1]
				
				// Clean up version (remove v prefix if present for consistency)
				cleanVersion := strings.TrimPrefix(version, "v")

				info := PackageInfo{
					Name:    name,
					Version: cleanVersion,
				}

				// Extract license from module path
				if idx := strings.Index(name, "/"); idx != -1 {
					modulePath := name[:idx]
					info.Licenses = []string{modulePath}
				} else {
					info.Licenses = []string{name}
				}

				deps = append(deps, info)
			}
		}
	}

	return deps
}

func parseGoSum(content string) []PackageInfo {
	var deps []PackageInfo
	
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || !strings.Contains(line, " ") {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}

		name := parts[0]
		version := parts[1]

		info := PackageInfo{
			Name:    name,
			Version: version,
		}

		// Extract license from module path
		if idx := strings.Index(name, "/"); idx != -1 {
			modulePath := name[:idx]
			info.Licenses = []string{modulePath}
		} else {
			info.Licenses = []string{name}
		}

		deps = append(deps, info)
	}

	return deps
}

// normalizeKey creates a consistent key for deduplication
func normalizeKey(name, version string) string {
	cleanName := strings.TrimPrefix(name, "github.com/")
	cleanName = strings.ReplaceAll(cleanName, "/", "_")
	return fmt.Sprintf("%s@%s", cleanName, version)
}

// generateUUID creates a simple deterministic UUID for document ID
func generateUUID() string {
	seed := 0
	for _, c := range filepath.Base(os.Args[0]) + time.Now().String() {
		seed = seed*31 + int(c)
	}
	
	var uuid [8]byte
	for i := 0; i < 8; i++ {
		uuid[i] = byte((seed >> (i * 4)) & 0x0F)
	}

	return fmt.Sprintf("%02x%02x-%02x-%02x-%02x-%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5], uuid[6], uuid[7])
}

// time is imported for the UUID generation but needs to be added
import "time"