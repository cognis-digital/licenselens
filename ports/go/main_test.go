package main

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"MIT License":             "MIT",
		"Apache Software License": "Apache-2.0",
		"GPLv3":                   "GPL-3.0",
		"BSD-3-Clause":            "BSD-3-Clause",
		"":                        "UNKNOWN",
		"License :: OSI Approved :: MIT License": "MIT",
	}
	for raw, want := range cases {
		if got := normalize(raw); got != want {
			t.Errorf("normalize(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"MIT": "allow", "MPL-2.0": "warn", "GPL-3.0": "forbid", "UNKNOWN": "unknown",
	}
	for spdx, want := range cases {
		if got := classify(spdx); got != want {
			t.Errorf("classify(%q) = %q, want %q", spdx, got, want)
		}
	}
}

func TestScanGate(t *testing.T) {
	fs := scan("good==1  # license: MIT\nbad==2  # license: GPL-3.0\nmystery==3\n")
	if len(fs) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(fs))
	}
	counts := map[string]int{}
	for _, f := range fs {
		counts[f.Risk]++
	}
	if counts["allow"] != 1 || counts["forbid"] != 1 || counts["unknown"] != 1 {
		t.Errorf("unexpected counts: %v", counts)
	}
}
