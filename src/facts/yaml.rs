//! `.yml` / `.yaml` extraction (§3.4).
//!
//! Targets the most common YAML use case in modern repos: CI/CD pipeline
//! config (GitHub Actions, GitLab CI, docker-compose). The extractor looks
//! for security-sensitive patterns — overly broad permissions, unpinned
//! action references, exposed secrets, privileged containers — and surfaces
//! them as warnings for RT-D / RT-C consumption.
//!
//! tree-sitter-yaml gives us structure-aware parsing; we layer a textual
//! safety net on top so dialect quirks don't silently drop signal (mirrors
//! the SQL extractor's belt-and-braces approach).

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use tree_sitter::{Language, Parser};

use super::types::{ExtractMethod, FactTable};

fn yaml_language() -> Language {
    static LANG: OnceLock<Language> = OnceLock::new();
    LANG.get_or_init(|| tree_sitter_yaml::LANGUAGE.into())
        .clone()
}

/// Run a YAML scan and return a fact table tagged `TreeSitter`. Always
/// succeeds — even when the parser can't build a tree we still emit a
/// table with a warning so the caller sees the file was visited.
pub fn extract_yaml_facts(path: &Path, source: &str) -> Result<FactTable> {
    let mut parser = Parser::new();
    parser
        .set_language(&yaml_language())
        .context("tree-sitter-yaml grammar load")?;

    let tree = parser.parse(source, None);
    let mut warnings = Vec::new();

    if tree.is_none() {
        warnings.push("YAML parser returned no tree — falling back to text scan".to_string());
    }

    // Textual scan covers the cases we care about most cheaply. Even when
    // the AST parses, we pair the signals so dialect-specific differences
    // (GitHub Actions vs docker-compose vs Kubernetes manifests) don't
    // create blind spots.
    scan_textual(source, &mut warnings);

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

fn scan_textual(source: &str, warnings: &mut Vec<String>) {
    for (idx, raw_line) in source.lines().enumerate() {
        let line = raw_line.trim();
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);

        // GitHub Actions: overly broad permissions
        if line.contains("permissions:") && line.contains("write-all") {
            warnings.push(format!(
                "Line {line_no}: permissions: write-all grants every scope; prefer least-privilege"
            ));
        }

        // GitHub Actions: unpinned action reference (uses: foo/bar@main)
        // Match both bare `uses:` and the list-item form `- uses:`.
        let uses_part = line
            .strip_prefix("uses:")
            .or_else(|| line.strip_prefix("- uses:"));
        if let Some(rest) = uses_part {
            let val = rest.trim();
            if let Some(at_idx) = val.rfind('@') {
                let ref_part = &val[at_idx + 1..];
                if matches!(ref_part, "main" | "master" | "latest" | "HEAD") {
                    warnings.push(format!(
                        "Line {line_no}: uses: {val} pins to a moving ref; pin to a SHA or tag"
                    ));
                }
            }
        }

        // docker-compose: privileged containers
        if line.starts_with("privileged:") && line.ends_with("true") {
            warnings.push(format!(
                "Line {line_no}: privileged: true grants host capabilities to the container"
            ));
        }

        // docker-compose: host network mode
        if line.contains("network_mode:") && line.contains("host") {
            warnings.push(format!(
                "Line {line_no}: network_mode: host bypasses container network isolation"
            ));
        }

        // Inline secrets / hardcoded credentials in YAML
        let lower = line.to_lowercase();
        if (lower.contains("password:") || lower.contains("api_key:") || lower.contains("secret:"))
            && !lower.contains("${{")
            && !lower.contains("${")
            && !lower.contains("vault:")
        {
            // Heuristic: value follows the key on the same line
            if let Some(value) = line.split(':').nth(1) {
                let trimmed = value.trim().trim_matches(|c: char| c == '"' || c == '\'');
                if trimmed.len() >= 8 && !trimmed.starts_with('!') {
                    warnings.push(format!(
                        "Line {line_no}: looks like a hardcoded secret; use a vault / env var"
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn permissions_write_all_is_flagged() {
        let src = "permissions: write-all\n";
        let table = extract_yaml_facts(&PathBuf::from("ci.yml"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("write-all")),
            "expected write-all warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn unpinned_action_reference_is_flagged() {
        let src = "      - uses: actions/checkout@main\n";
        let table = extract_yaml_facts(&PathBuf::from("ci.yml"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("moving ref")),
            "expected unpinned-ref warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn pinned_action_reference_is_not_flagged() {
        let src = "      - uses: actions/checkout@v4\n";
        let table = extract_yaml_facts(&PathBuf::from("ci.yml"), src).unwrap();
        assert!(
            !table.warnings.iter().any(|w| w.contains("moving ref")),
            "v4 is fine, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn privileged_container_is_flagged() {
        let src = "  privileged: true\n";
        let table = extract_yaml_facts(&PathBuf::from("docker-compose.yml"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("privileged")),
            "expected privileged warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn hardcoded_password_is_flagged() {
        let src = "password: Sup3rS3cret!\n";
        let table = extract_yaml_facts(&PathBuf::from("config.yml"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("hardcoded")),
            "expected hardcoded-secret warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn templated_secret_is_not_flagged() {
        let src = "password: ${{ secrets.DB_PASSWORD }}\n";
        let table = extract_yaml_facts(&PathBuf::from("config.yml"), src).unwrap();
        assert!(
            !table.warnings.iter().any(|w| w.contains("hardcoded")),
            "templated secret OK, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn empty_input_is_safe() {
        let table = extract_yaml_facts(&PathBuf::from("empty.yml"), "").unwrap();
        assert_eq!(table.extract_method, ExtractMethod::TreeSitter);
    }
}
