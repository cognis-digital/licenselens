#!/usr/bin/env node
// JavaScript / Node port of the LICENSELENS license gate — same surface, zero deps.
//
// Mirrors `licenselens scan`: parse a requirements.txt-style file (with inline
// `# license:` overrides), normalize each license to a canonical SPDX id,
// classify against the default allow/warn/forbid policy, gate via exit code
// (0 pass, 1 violation, 2 IO error).
//
//   node index.js requirements.txt
//   node index.js --format json requirements.txt
import { readFileSync } from "fs";

const ALIASES = {
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
};

const POLICY = {
  allow: ["MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "Unlicense", "PSF-2.0"],
  warn: ["MPL-2.0", "LGPL-2.1", "LGPL-3.0"],
  forbid: ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "Proprietary"],
};

export function normalize(raw) {
  let c = (raw || "").trim();
  if (!c) return "UNKNOWN";
  if (c.includes("::")) c = c.split("::").pop().trim();
  const key = c.toLowerCase();
  if (ALIASES[key]) return ALIASES[key];
  for (const k of Object.keys(ALIASES).sort((a, b) => b.length - a.length)) {
    if (key.includes(k)) return ALIASES[k];
  }
  if (/^[A-Za-z0-9.\-+]+$/.test(c)) return c;
  return "UNKNOWN";
}

export function classify(spdx) {
  if (spdx === "UNKNOWN") return "unknown";
  if (POLICY.forbid.includes(spdx)) return "forbid";
  if (POLICY.warn.includes(spdx)) return "warn";
  if (POLICY.allow.includes(spdx)) return "allow";
  return "unknown";
}

const REQ_RE = /^\s*([A-Za-z0-9._-]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9._*-]+)?/;
const LIC_RE = /#\s*license:\s*([^#\n]+)/i;

export function scan(text) {
  const findings = [];
  for (const line of text.split("\n")) {
    const s = line.trim();
    if (!s || s.startsWith("#") || s.startsWith("-")) continue;
    let override = null;
    const ml = LIC_RE.exec(line);
    if (ml) override = ml[1].trim();
    const code = line.split("#")[0];
    const m = REQ_RE.exec(code);
    if (!m || !m[1]) continue;
    const version = m[3] || "*";
    const spdx = normalize(override);
    findings.push({ name: m[1], version, license: spdx, risk: classify(spdx) });
  }
  return findings;
}

export function counts(findings) {
  const c = { allow: 0, warn: 0, forbid: 0, unknown: 0 };
  for (const f of findings) c[f.risk] = (c[f.risk] || 0) + 1;
  return c;
}

export function passed(findings) {
  const c = counts(findings);
  return c.forbid === 0 && c.unknown === 0;
}

function main(argv) {
  let format = "table";
  let path = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--format" && i + 1 < argv.length) { format = argv[++i]; }
    else { path = argv[i]; }
  }
  if (!path) {
    process.stderr.write("usage: licenselens-js [--format json] requirements.txt\n");
    process.exit(2);
  }
  let text;
  try { text = readFileSync(path, "utf8"); }
  catch (e) { process.stderr.write(`error: cannot read ${path}: ${e.message}\n`); process.exit(2); }
  const findings = scan(text);
  const ok = passed(findings);
  if (format === "json") {
    console.log(JSON.stringify({ tool: "licenselens", findings, counts: counts(findings), passed: ok }, null, 2));
  } else {
    for (const f of findings) {
      console.log(`${f.risk.toUpperCase().padEnd(7)} ${f.name.padEnd(20)} ${f.version.padEnd(12)} ${f.license}`);
    }
    console.log(`gate: ${ok ? "PASS" : "FAIL"}`);
  }
  process.exit(ok ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2));
}
