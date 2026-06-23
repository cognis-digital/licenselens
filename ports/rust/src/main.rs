// Rust port of the LICENSELENS license gate — fast, single binary, zero deps.
//
// Mirrors `licenselens scan`: parse a requirements.txt-style file (with inline
// `# license:` overrides), normalize each license to a canonical SPDX id,
// classify it against the default allow/warn/forbid policy, and gate via exit
// code (0 pass, 1 violation, 2 IO error).
//
//   cargo run -- requirements.txt
//   cargo run -- --format json requirements.txt
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::exit;

fn aliases() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    for (k, v) in [
        ("mit", "MIT"), ("mit license", "MIT"), ("the mit license", "MIT"),
        ("bsd", "BSD-3-Clause"), ("bsd license", "BSD-3-Clause"),
        ("bsd-2", "BSD-2-Clause"), ("bsd-2-clause", "BSD-2-Clause"),
        ("bsd-3", "BSD-3-Clause"), ("bsd-3-clause", "BSD-3-Clause"),
        ("apache", "Apache-2.0"), ("apache 2", "Apache-2.0"), ("apache 2.0", "Apache-2.0"),
        ("apache-2", "Apache-2.0"), ("apache-2.0", "Apache-2.0"),
        ("apache software license", "Apache-2.0"),
        ("isc", "ISC"), ("isc license", "ISC"),
        ("mpl", "MPL-2.0"), ("mpl-2.0", "MPL-2.0"), ("mozilla public license 2.0", "MPL-2.0"),
        ("lgpl", "LGPL-3.0"), ("lgpl-2.1", "LGPL-2.1"), ("lgpl-3.0", "LGPL-3.0"),
        ("gpl", "GPL-3.0"), ("gpl-2.0", "GPL-2.0"), ("gplv2", "GPL-2.0"),
        ("gpl-3.0", "GPL-3.0"), ("gplv3", "GPL-3.0"),
        ("agpl", "AGPL-3.0"), ("agpl-3.0", "AGPL-3.0"), ("agplv3", "AGPL-3.0"),
        ("unlicense", "Unlicense"), ("public domain", "Unlicense"),
        ("proprietary", "Proprietary"), ("commercial", "Proprietary"),
    ] {
        m.insert(k, v);
    }
    m
}

const ALLOW: &[&str] = &["MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "Unlicense", "PSF-2.0"];
const WARN: &[&str] = &["MPL-2.0", "LGPL-2.1", "LGPL-3.0"];
const FORBID: &[&str] = &["GPL-2.0", "GPL-3.0", "AGPL-3.0", "Proprietary"];

fn normalize(raw: &str) -> String {
    let mut c = raw.trim().to_string();
    if c.is_empty() {
        return "UNKNOWN".into();
    }
    if c.contains("::") {
        c = c.rsplit("::").next().unwrap().trim().to_string();
    }
    let key = c.to_lowercase();
    let a = aliases();
    if let Some(v) = a.get(key.as_str()) {
        return v.to_string();
    }
    let mut keys: Vec<&&str> = a.keys().collect();
    keys.sort_by(|x, y| y.len().cmp(&x.len()));
    for k in keys {
        if key.contains(*k) {
            return a[*k].to_string();
        }
    }
    if c.chars().all(|ch| ch.is_ascii_alphanumeric() || "-.+".contains(ch)) {
        return c;
    }
    "UNKNOWN".into()
}

fn classify(spdx: &str) -> &'static str {
    if spdx == "UNKNOWN" {
        return "unknown";
    }
    if FORBID.contains(&spdx) {
        return "forbid";
    }
    if WARN.contains(&spdx) {
        return "warn";
    }
    if ALLOW.contains(&spdx) {
        return "allow";
    }
    "unknown"
}

struct Finding {
    name: String,
    version: String,
    license: String,
    risk: String,
}

fn parse_override(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    for marker in ["# license:", "#license:"] {
        if let Some(idx) = lower.find(marker) {
            let rest = &line[idx + marker.len()..];
            let val = rest.split('#').next().unwrap_or("").trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn parse_name_version(line: &str) -> Option<(String, String)> {
    let code = line.split('#').next().unwrap_or("").trim();
    if code.is_empty() {
        return None;
    }
    let ops = ["==", ">=", "<=", "~=", "!=", ">", "<"];
    let mut name = code.to_string();
    let mut version = "*".to_string();
    for op in ops {
        if let Some(idx) = code.find(op) {
            name = code[..idx].trim().to_string();
            version = code[idx + op.len()..].trim().to_string();
            if version.is_empty() {
                version = "*".into();
            }
            break;
        }
    }
    if let Some(b) = name.find('[') {
        name = name[..b].to_string();
    }
    if name.is_empty() {
        return None;
    }
    Some((name, version))
}

fn scan(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for line in text.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') || s.starts_with('-') {
            continue;
        }
        let override_lic = parse_override(line);
        if let Some((name, version)) = parse_name_version(line) {
            let spdx = normalize(override_lic.as_deref().unwrap_or(""));
            let risk = classify(&spdx).to_string();
            out.push(Finding { name, version, license: spdx, risk });
        }
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut format = "table".to_string();
    let mut path = String::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--format" && i + 1 < args.len() {
            format = args[i + 1].clone();
            i += 2;
        } else {
            path = args[i].clone();
            i += 1;
        }
    }
    if path.is_empty() {
        eprintln!("usage: licenselens-rs [--format json] requirements.txt");
        exit(2);
    }
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path, e);
            exit(2);
        }
    };
    let findings = scan(&text);
    let mut counts: HashMap<&str, i32> = HashMap::new();
    for f in &findings {
        *counts.entry(f.risk.as_str()).or_insert(0) += 1;
    }
    let passed = *counts.get("forbid").unwrap_or(&0) == 0 && *counts.get("unknown").unwrap_or(&0) == 0;

    if format == "json" {
        let items: Vec<String> = findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"name\":\"{}\",\"version\":\"{}\",\"license\":\"{}\",\"risk\":\"{}\"}}",
                    f.name, f.version, f.license, f.risk
                )
            })
            .collect();
        println!(
            "{{\"tool\":\"licenselens\",\"findings\":[{}],\"passed\":{}}}",
            items.join(","),
            passed
        );
    } else {
        for f in &findings {
            println!("{:<7} {:<20} {:<12} {}", f.risk.to_uppercase(), f.name, f.version, f.license);
        }
        println!("gate: {}", if passed { "PASS" } else { "FAIL" });
    }
    if !passed {
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(normalize("MIT License"), "MIT");
        assert_eq!(normalize("Apache Software License"), "Apache-2.0");
        assert_eq!(normalize("GPLv3"), "GPL-3.0");
        assert_eq!(normalize("BSD-3-Clause"), "BSD-3-Clause");
        assert_eq!(normalize(""), "UNKNOWN");
        assert_eq!(normalize("License :: OSI Approved :: MIT License"), "MIT");
    }

    #[test]
    fn test_classify() {
        assert_eq!(classify("MIT"), "allow");
        assert_eq!(classify("MPL-2.0"), "warn");
        assert_eq!(classify("GPL-3.0"), "forbid");
        assert_eq!(classify("UNKNOWN"), "unknown");
    }

    #[test]
    fn test_scan_gate() {
        let fs = scan("good==1  # license: MIT\nbad==2  # license: GPL-3.0\nmystery==3\n");
        assert_eq!(fs.len(), 3);
        let forbid = fs.iter().filter(|f| f.risk == "forbid").count();
        let unknown = fs.iter().filter(|f| f.risk == "unknown").count();
        assert_eq!(forbid, 1);
        assert_eq!(unknown, 1);
    }
}
