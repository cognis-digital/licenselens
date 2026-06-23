// Go port of the LICENSELENS license gate — single binary, zero deps.
//
// Mirrors the primary `licenselens scan` surface: parse a requirements.txt-style
// file (with inline `# license:` overrides), normalize each license to a
// canonical SPDX id, classify it against the default allow/warn/forbid policy,
// and gate the build via exit code (0 pass, 1 violation, 2 IO error).
//
//	go run . requirements.txt
//	go run . --format json requirements.txt
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var spdxAliases = map[string]string{
	"mit": "MIT", "mit license": "MIT", "the mit license": "MIT",
	"bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause",
	"bsd-2": "BSD-2-Clause", "bsd-2-clause": "BSD-2-Clause",
	"bsd-3": "BSD-3-Clause", "bsd-3-clause": "BSD-3-Clause",
	"apache": "Apache-2.0", "apache 2": "Apache-2.0", "apache 2.0": "Apache-2.0",
	"apache-2": "Apache-2.0", "apache-2.0": "Apache-2.0", "apache software license": "Apache-2.0",
	"isc": "ISC", "isc license": "ISC",
	"mpl": "MPL-2.0", "mpl-2.0": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
	"lgpl": "LGPL-3.0", "lgpl-2.1": "LGPL-2.1", "lgpl-3.0": "LGPL-3.0",
	"gpl": "GPL-3.0", "gpl-2.0": "GPL-2.0", "gplv2": "GPL-2.0",
	"gpl-3.0": "GPL-3.0", "gplv3": "GPL-3.0",
	"agpl": "AGPL-3.0", "agpl-3.0": "AGPL-3.0", "agplv3": "AGPL-3.0",
	"unlicense": "Unlicense", "public domain": "Unlicense",
	"proprietary": "Proprietary", "commercial": "Proprietary",
}

var policy = map[string][]string{
	"allow":  {"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "Unlicense", "PSF-2.0"},
	"warn":   {"MPL-2.0", "LGPL-2.1", "LGPL-3.0"},
	"forbid": {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "Proprietary"},
}

var reqRe = regexp.MustCompile(`^\s*([A-Za-z0-9._\-]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9._*\-]+)?`)
var licRe = regexp.MustCompile(`(?i)#\s*license:\s*([^#\n]+)`)
var spdxRe = regexp.MustCompile(`^[A-Za-z0-9.\-+]+$`)

// Normalize a free-form license string to a canonical SPDX id.
func normalize(raw string) string {
	c := strings.TrimSpace(raw)
	if c == "" {
		return "UNKNOWN"
	}
	if strings.Contains(c, "::") {
		parts := strings.Split(c, "::")
		c = strings.TrimSpace(parts[len(parts)-1])
	}
	key := strings.ToLower(c)
	if v, ok := spdxAliases[key]; ok {
		return v
	}
	keys := make([]string, 0, len(spdxAliases))
	for k := range spdxAliases {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		if strings.Contains(key, k) {
			return spdxAliases[k]
		}
	}
	if spdxRe.MatchString(c) {
		return c
	}
	return "UNKNOWN"
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Classify a normalized SPDX id into a risk bucket.
func classify(spdx string) string {
	if spdx == "UNKNOWN" {
		return "unknown"
	}
	if contains(policy["forbid"], spdx) {
		return "forbid"
	}
	if contains(policy["warn"], spdx) {
		return "warn"
	}
	if contains(policy["allow"], spdx) {
		return "allow"
	}
	return "unknown"
}

type Finding struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
	Risk    string `json:"risk"`
}

func scan(text string) []Finding {
	out := []Finding{}
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "-") {
			continue
		}
		override := ""
		if m := licRe.FindStringSubmatch(line); m != nil {
			override = strings.TrimSpace(m[1])
		}
		code := strings.SplitN(line, "#", 2)[0]
		m := reqRe.FindStringSubmatch(code)
		if m == nil || m[1] == "" {
			continue
		}
		ver := m[3]
		if ver == "" {
			ver = "*"
		}
		spdx := normalize(override)
		out = append(out, Finding{m[1], ver, spdx, classify(spdx)})
	}
	return out
}

func main() {
	args := os.Args[1:]
	format := "table"
	path := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) {
			format = args[i+1]
			i++
		} else {
			path = args[i]
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: licenselens-go [--format json] requirements.txt")
		os.Exit(2)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", path, err)
		os.Exit(2)
	}
	findings := scan(string(data))
	counts := map[string]int{"allow": 0, "warn": 0, "forbid": 0, "unknown": 0}
	for _, f := range findings {
		counts[f.Risk]++
	}
	passed := counts["forbid"] == 0 && counts["unknown"] == 0

	if format == "json" {
		out, _ := json.MarshalIndent(map[string]any{
			"tool": "licenselens", "findings": findings, "counts": counts, "passed": passed,
		}, "", "  ")
		fmt.Println(string(out))
	} else {
		for _, f := range findings {
			fmt.Printf("%-7s %-20s %-12s %s\n", strings.ToUpper(f.Risk), f.Name, f.Version, f.License)
		}
		gate := "FAIL"
		if passed {
			gate = "PASS"
		}
		fmt.Printf("gate: %s\n", gate)
	}
	if !passed {
		os.Exit(1)
	}
}
