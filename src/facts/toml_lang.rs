//! `.toml` extraction (§5.4) — primarily targeting `Cargo.toml`.
//!
//! Cargo dependency churn is the highest-signal use case: a version bump
//! to a security-relevant crate or a feature flag flip can change the
//! attack surface in ways the regular code review won't catch. We surface
//! the obvious risk classes so RT-D notices them.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use tree_sitter::{Language, Parser};

use super::types::{ExtractMethod, FactTable};

fn toml_language() -> Language {
    static LANG: OnceLock<Language> = OnceLock::new();
    LANG.get_or_init(|| tree_sitter_toml_ng::LANGUAGE.into())
        .clone()
}

pub fn extract_toml_facts(path: &Path, source: &str) -> Result<FactTable> {
    let mut parser = Parser::new();
    parser
        .set_language(&toml_language())
        .context("tree-sitter-toml grammar load")?;
    let _tree = parser.parse(source, None);

    let mut warnings = Vec::new();
    scan_textual(path, source, &mut warnings);
    warnings.sort();
    warnings.dedup();

    Ok(FactTable {
        file: path.to_path_buf(),
        language: super::types::Language::default(),
        functions: vec![],
        warnings,
        callers: vec![],
        extract_method: ExtractMethod::TreeSitter,
        fingerprints: vec![],
    })
}

fn scan_textual(path: &Path, source: &str, warnings: &mut Vec<String>) {
    let is_cargo = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_lowercase)
        .as_deref()
        == Some("cargo.toml");

    let mut in_dependencies = false;

    for (idx, raw_line) in source.lines().enumerate() {
        let line = raw_line.trim();
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);

        // Track which section we're in.
        if let Some(rest) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let section = rest.trim();
            in_dependencies = section.contains("dependencies")
                || section.contains("dev-dependencies")
                || section.contains("build-dependencies");
            continue;
        }

        // Wildcard / git / path dependencies in Cargo.toml deserve a flag —
        // they pin nothing or pin to a moving target.
        if is_cargo && in_dependencies {
            // `crate = "*"` — wildcard
            if line.contains("= \"*\"") {
                warnings.push(format!(
                    "Line {line_no}: wildcard dependency version '*' — pin to a SemVer range"
                ));
            }
            // `crate = { git = "..." }` without `rev = ` or `tag = `
            if line.contains("git =") && !line.contains("rev =") && !line.contains("tag =") {
                warnings.push(format!(
                    "Line {line_no}: git dependency without rev/tag pin — supply chain risk"
                ));
            }
            // `crate = { path = ... }` — fine for workspaces but worth surfacing
            // for review on standalone crates.
            if line.contains("path =") && !line.contains("workspace") {
                warnings.push(format!(
                    "Line {line_no}: path dependency — verify this is intentional outside a workspace"
                ));
            }
        }

        // `unsafe_code = "allow"` in [lints.rust]
        if line.contains("unsafe_code") && line.contains("allow") {
            warnings.push(format!(
                "Line {line_no}: unsafe_code lint set to allow — unsafe blocks won't be flagged by clippy"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn wildcard_version_is_flagged() {
        let src = "[dependencies]\nfoo = \"*\"\n";
        let table = extract_toml_facts(&PathBuf::from("Cargo.toml"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("wildcard")),
            "expected wildcard warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn git_dep_without_rev_is_flagged() {
        let src = "[dependencies]\nfoo = { git = \"https://github.com/x/y\" }\n";
        let table = extract_toml_facts(&PathBuf::from("Cargo.toml"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("git dependency")),
            "expected git-pin warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn git_dep_with_rev_is_not_flagged() {
        let src = "[dependencies]\nfoo = { git = \"https://github.com/x/y\", rev = \"abc123\" }\n";
        let table = extract_toml_facts(&PathBuf::from("Cargo.toml"), src).unwrap();
        assert!(
            !table.warnings.iter().any(|w| w.contains("git dependency")),
            "rev pin should silence the warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn unsafe_code_allow_is_flagged() {
        let src = "[lints.rust]\nunsafe_code = \"allow\"\n";
        let table = extract_toml_facts(&PathBuf::from("Cargo.toml"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("unsafe_code")),
            "expected unsafe lint warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn empty_input_is_safe() {
        let table = extract_toml_facts(&PathBuf::from("Cargo.toml"), "").unwrap();
        assert_eq!(table.extract_method, ExtractMethod::TreeSitter);
    }
}
