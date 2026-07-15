use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// SPDX SBOM structures (SPDX 2.3)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxDocument {
    pub spdx_version: String,
    pub spdx_id: String,
    pub name: String,
    pub document_namespace: String,
    pub document_date: String,
    pub creator: String,
    pub creators: Vec<String>,
    pub data_license: String,
    pub contributors: Vec<String>,
    pub authors: Vec<String>,
    pub package: Vec<SpdxPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxPackage {
    pub spdx_id: String,
    pub name: String,
    pub version_info: Option<String>,
    pub source_info: Option<String>,
    pub homepage: Option<String>,
    pub download_location: String,
    pub files_analyzed: bool,
    pub license_concluded: Option<String>,
    pub license_inferred: Option<String>,
    pub copyright_text: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub external_references: Vec<SpdxExternalRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxExternalRef {
    pub category: String,
    pub reference_type: String,
    pub reference: String,
}

// Cargo file structures

#[derive(Debug, Clone, Deserialize)]
struct CargoToml {
    package: Option<PackageMeta>,
    dependencies: HashMap<String, DependencySpec>,
    dev_dependencies: HashMap<String, DependencySpec>,
    build_dependencies: HashMap<String, DependencySpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct PackageMeta {
    name: String,
    version: String,
    authors: Vec<String>,
    license: Option<String>,
    description: Option<String>,
    homepage: Option<String>,
    readme: Option<String>,
    repository: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DependencySpec {
    version: Option<VersionReq>,
}

#[derive(Debug, Clone, Deserialize)]
struct VersionReq {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<String>,
}

impl Default for VersionReq {
    fn default() -> Self {
        Self {
            major: 0,
            minor: 0,
            patch: 0,
            pre: vec![],
        }
    }
}

#[derive(Debug, Clone)]
struct CargoLockEntry {
    name: String,
    version: String,
    dependencies: Vec<String>,
    checksum: Option<String>,
    source: Option<String>,
}

// SBOM Generator implementation

pub struct Sbo