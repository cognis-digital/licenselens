// polyglot/rust/license_parser.rs

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::PathBuf;

/// Represents a parsed license with metadata and source information.
#[derive(Debug, Clone)]
pub struct LicenseInfo {
    pub id: String,
    pub name: String,
    pub spdx_id: Option<String>,
    pub osi_approved: bool,
    pub url: Option<String>,
    pub text: Option<String>,
    pub confidence: f32,
}

/// Result of parsing a license source.
#[derive(Debug, Clone)]
pub struct ParseResult {
    pub info: LicenseInfo,
    pub source_type: SourceType,
    pub raw_input: String,
    pub warnings: Vec<String>,
}

/// Types of sources that can be parsed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SourceType {
    File(PathBuf),
    Stdin,
    SpdxIdentifier(String),
    RawString,
}

impl fmt::Display for SourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceType::File(p) => write!(f, "file({})", p.display()),
            SourceType::Stdin => write!(f, "stdin"),
            SourceType::SpdxIdentifier(s) => write!(f, "spdx_identifier(\"{}\")", s),
            SourceType::RawString => write!(f, "raw_string"),
        }
    }
}

/// Known licenses database.
#[derive(Debug)]
pub struct LicenseDatabase {
    /// Exact name matches (case-insensitive).
    exact: HashMap<String, String>, // name -> spdx_id
    /// Partial/fuzzy patterns.
    partial: Vec<(String, String)>, // pattern -> spdx_id
    /// OSI approved list.
    osi_approved: HashSet<String>,
}

impl Default for LicenseDatabase {
    fn default() -> Self {
        let mut exact = HashMap::new();
        let mut partial = Vec::new();
        
        // Exact matches (common ones)
        exact.insert("mit".to_ascii_lowercase(), "MIT".to_string());
        exact.insert("apache 2.0".to_ascii_lowercase(), "Apache-2.0".to_string());
        exact.insert("apache-2.0".to_ascii_lowercase(), "Apache-2.0".to_string());
        exact.insert("apache2".to_ascii_lowercase(), "Apache-2.0".to_string());
        exact.insert("bsd 3-clause".to_ascii_lowercase(), "BSD-3-Clause".to_string());
        exact.insert("bsd-3-clause".to_ascii_lowercase(), "BSD-3-Clause".to_string());
        exact.insert("isc".to_ascii_lowercase(), "ISC".to_string());
        exact.insert("zlib".to_ascii_lowercase(), "Zlib".to_string());
        exact.insert("unlicense".to_ascii_lowercase(), "Unlicense".to_string());
        exact.insert("wtfpl".to_ascii_lowercase(), "WTFPL".to_string());
        exact.insert("cc0-1.0".to_ascii_lowercase(), "CC0-1.0".to_string());
        
        // Partial matches with patterns
        partial.push(("gnu general public license v3".to_ascii_lowercase(), "GPL-3.0-only".to_string()));
        partial.push(("gplv3".to_ascii_lowercase(), "GPL-3.0-only".to_string()));
        partial.push(("affero general public license".to_ascii_lowercase(), "AGPL-3.0-only".to_string()));
        
        // OSI approved licenses (subset for demo)
        let mut osi = HashSet::new();
        osi.insert("MIT".to_string());
        osi.insert("Apache-2.0".to_string());
        osi.insert("BSD-3-Clause".to_string());
        osi.insert("ISC".to_string());
        osi.insert("Zlib".to_string());
        osi.insert("Unlicense".to_string());
        osi.insert("WTFPL".to_string());
        osi.insert("CC0-1.0".to_string());
        
        LicenseDatabase { exact, partial, osi_approved: osi }
    }
}

impl LicenseDatabase {
    pub fn new() -> Self {
        Default::default()
    }
    
    /// Check if a license name is OSI approved.
    pub fn is_osi_approved(&self, spdx_id: &str) -> bool {
        self.osi_approved.contains(spdx_id.to_ascii_uppercase().as_str())
    }

    /// Get the canonical SPDX ID for a license name.
    pub fn resolve_spdx_id(&self, input: &str) -> Option<String> {
        let normalized = input.trim().to_ascii_lowercase();
        
        // First try exact match
        if let Some(spdx) = self.exact.get(&normalized) {
            return Some(spdx.clone());
        }

        // Try partial pattern matching
        for (pattern, spdx) in &self.partial {
            if normalized.contains(pattern.as_str()) || pattern.contains(&normalized) {
                return Some(spdx.clone());
            }
        }

        None
    }
}

/// Parse a license from various sources.
pub fn parse_license(
    source: SourceType,
    raw_input: &str,
    db: &LicenseDatabase,
) -> Result<ParseResult, ParseError> {
    let info = match &source {
        SourceType::SpdxIdentifier(spdx_id) => {
            LicenseInfo {
                id: spdx_id.clone(),
                name: format!("SPDX ID: {}", spdx_id),
                spdx_id: Some(spdx_id.clone()),
                osi_approved: db.is_osi_approved(spdx_id),
                url: None,
                text: None,
                confidence: 1.0,
            }
        }
        
        SourceType::Stdin | SourceType::RawString => {
            parse_text(raw_input, db)
        }
        
        SourceType::File(path) => {
            let content = fs::read_to_string(path).map_err(|e| ParseError::Io(e))?;
            parse_text(&content, db)
        }
    };

    Ok(ParseResult {
        info,
        source_type: source,
        raw_input: raw_input.to_string(),
        warnings: Vec::new(),
    })
}

/// Parse license text content.
fn parse_text(content: &str, db: &LicenseDatabase) -> LicenseInfo {
    let normalized = content.trim().to_ascii_lowercase();
    
    // Check for SPDX identifier at start of file
    if let Some(spdx_id) = extract_spdx_header(&normalized) {
        return LicenseInfo {
            id: spdx_id.clone(),
            name: format!("SPDX Header: {}", spdx_id),
            spdx_id: Some(spdx_id),
            osi_approved: db.is_osi_approved(&spdx_id),
            url: None,
            text: Some(content.to_string()),
            confidence: 0.95,
        };
    }

    // Check for common license headers/patterns
    if let Some(spdx) = db.resolve_spdx_id(&normalized) {
        return LicenseInfo {
            id: spdx.clone(),
            name: format!("Detected: {}", spdx),
            spdx_id: Some(spdx),
            osi_approved: db.is_osi_approved(&spdx),
            url: None,
            text: Some(content.to_string()),
            confidence: 0.85,
        };
    }

    // Check for common license name patterns (case-insensitive)
    let detected = detect_license_name(&normalized);
    
    LicenseInfo {
        id: format!("detected-{}", detected),
        name: detected.clone(),
        spdx_id: None,
        osi_approved: false,
        url: None,
        text: Some(content.to_string()),
        confidence: 0.6,
    }
}

/// Extract SPDX identifier from file header.
fn extract_spdx_header(normalized: &str) -> Option<String> {
    // Look for "SPDX-License-Identifier:" pattern
    if let Some(pos) = normalized.find("spdx-license-identifier:") {
        let after = &normalized[pos + 24..];
        let id = after.split_whitespace().next()?.trim();
        
        // Validate it looks like an SPDX ID
        if id.starts_with('A') || id.starts_with('B') || 
           id.starts_with('C') || id.starts_with('E') ||
           id.starts_with('G') || id.starts_with('I') ||
           id.starts_with('L') || id.starts_with('M') ||
           id.starts_with('P') || id.starts_with("CC-") {
            return Some(id.to_string());
        }
    }

    // Look for "SPDX-FileCopyrightText:" followed by license reference
    if let Some(pos) = normalized.find("spdx-filecopyrighttext:") {
        let after = &normalized[pos + 25..];
        if let Some(eq_pos) = after.find('=') {
            let id = after[eq_pos + 1..].split_whitespace().next()?.trim();
            return Some(id.to_string());
        }
    }

    None
}

/// Detect license name from text content.
fn detect_license_name(normalized: &str) -> String {
    // Common license name patterns (partial matches)
    let patterns = [
        ("mit", "MIT License"),
        ("apache 2.0", "Apache License 2.0"),
        ("bsd 3-clause", "BSD 3-Clause License"),
        ("bsd 2-clause", "BSD 2-Clause License"),
        ("isc", "ISC License"),
        ("zlib", "Zlib License"),
        ("unlicense", "The Unlicense"),
        ("wtfpl", "WTFPL"),
        ("cc0-1.0", "CC0 Public Domain"),
        ("gnu gpl v3", "GNU GPL v3.0"),
        ("gplv3", "GNU GPL v3.0"),
        ("gnu lpl v2", "GNU LGPL v2.1"),
        ("gplv2", "GNU GPL v2.0"),
        ("gnu gpl v2", "GNU GPL v2.0"),
    ];

    for (pattern, name) in &patterns {
        if normalized.contains(*pattern) || pattern.contains(&normalized) {
            return name.to_string();
        }
    }

    // Fallback: look for license-like text patterns
    if normalized.contains("permission is hereby granted") {
        return "Permissive License".to_string();
    }

    if normalized.contains("redistribution and use in source and binary forms") {
        return "Standard Open Source License".to_string();
    }

    // Generic fallback
    let words: Vec<&str> = normalized.split_whitespace().collect();
    for word in &words[..10] {
        if !word.is_empty() && word.len() > 3 {
            return format!("Unknown (starts with '{}')", word);
        }
    }

    "Unknown".to_string()
}

/// Errors that can occur during parsing.
#[derive(Debug)]
pub enum ParseError {
    Io(std::io::Error),
    EmptyInput,
    InvalidSpdx(String),
    UnknownSource(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "IO error: {}", e),
            ParseError::EmptyInput => write!(f, "No input provided"),
            ParseError::InvalidSpdx(s) => write!(f, "Invalid SPDX identifier: {}", s),
            ParseError::UnknownSource(s) => write!(f, "Unknown source type: {}", s),
        }
    }
}

impl std::error::Error for ParseError {}

/// Builder for creating a license parser with custom database.
pub struct LicenseParserBuilder {
    db: LicenseDatabase,
}

impl Default for LicenseParserBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseParserBuilder {
    pub fn new() -> Self {
        Self {
            db: LicenseDatabase::default(),
        }
    }

    /// Build the parser with current database.
    pub fn build(self) -> LicenseParser {
        LicenseParser { db: self.db }
    }

    /// Add a custom license mapping.
    pub fn add_mapping(&mut self, name: &str, spdx_id: &str) {
        let normalized = name.to_ascii_lowercase();
        self.db.exact.insert(normalized, spdx_id.to_string());
    }

    /// Load additional license data from a file (e.g., JSON database).
    pub fn load_from_json(&mut self, path: impl AsRef<std::path::Path>) -> Result<(), ParseError> {
        let content = fs::read_to_string(path.as_ref())?;
        
        // Simple JSON parsing for demo purposes
        if content.contains("\"spdx_id\"") && content.contains("\"name\"") {
            // Extract SPDX IDs and names from the file
            let spdx_ids: Vec<&str> = content
                .split('"')
                .filter(|s| s.starts_with("SPDX-"))
                .collect();
            
            for id in &spdx_ids[..10] {
                if !id.is_empty() && id.len() > 5 {
                    let spdx = format!("{}-{}", id[4..].trim(), "demo");
                    self.db.exact.insert(id.to_ascii_lowercase(), spdx);
                }
            }
        }

        Ok(())
    }
}

/// The main license parser.
pub struct LicenseParser {
    db: LicenseDatabase,
}

impl Default for LicenseParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseParser {
    pub fn new() -> Self {
        Self {
            db: LicenseDatabase::default(),
        }
    }

    /// Parse a license from the given source.
    pub fn parse(&self, source: SourceType, raw_input: &str) -> Result<ParseResult, ParseError> {
        self.db.resolve_spdx_id(raw_input).map(|_| {
            let info = LicenseInfo {
                id: "demo".to_string(),
                name: format!("Demo Parser"),
                spdx_id: Some("MIT".to_string()),
                osi_approved: true,
                url: None,
                text: Some(raw_input.to_string()),
                confidence: 0.9,
            };

            ParseResult {
                info,
                source_type: source,
                raw_input: raw_input.to_string(),
                warnings: Vec::new(),
            }
        })
    }

    /// Check if a license is OSI approved.
    pub fn is_osi_approved(&self, spdx_id: &str) -> bool {
        self.db.is_osi_approved(spdx_id)
    }

    /// Get the canonical SPDX ID for input.
    pub fn resolve_spdx_id(&self, input: &str) -> Option<String> {
        self.db.resolve_spdx_id(input)
    }

    /// Parse multiple licenses from a directory (SBOM generation).
    pub fn parse_directory<P: AsRef<std::path::Path>>(
        &self,
        dir_path: P,
    ) -> Result<Vec<ParseResult>, ParseError> {
        let mut results = Vec::new();

        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let extension = path.extension().and_then(|e| e.to_str());
                
                // Only process text-based license files
                match extension {
                    Some("txt") | Some("md") | Some("rst") | Some("license") => {
                        let content = fs::read_to_string(&path)?;
                        
                        if !content.is_empty() {
                            let source = SourceType::File(path.clone());
                            
                            // Skip very small files (might be binary or metadata)
                            if content.len() > 100 {
                                match parse_license(source, &content, &self.db) {
                                    Ok(result) => results.push(result),
                                    Err(e) => {
                                        eprintln!("Error parsing {}: {}", path.display(), e);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(results)
    }

    /// Generate a simple SBOM from parsed licenses.
    pub fn generate_sbom(&self, results: &[ParseResult]) -> String {
        let mut sbom = String::from(r#"SPDX-JSON-Format-Version: 2.0
SPDXID: SPDXRef-DOCUMENT
DocumentNamespace