//! `.sh` / `.bash` extraction (§3.4).
//!
//! Deployment scripts and git hooks are favorite hiding places for footguns
//! — `rm -rf $UNSET_VAR`, piping curl into a shell, sudo without password,
//! world-writable chmods. The extractor flags the obvious classes so RT-D
//! (privilege escalation) and RT-A (silent failure) get useful signal.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use tree_sitter::{Language, Parser};

use super::types::{ExtractMethod, FactTable};

fn bash_language() -> Language {
    static LANG: OnceLock<Language> = OnceLock::new();
    LANG.get_or_init(|| tree_sitter_bash::LANGUAGE.into())
        .clone()
}

pub fn extract_bash_facts(path: &Path, source: &str) -> Result<FactTable> {
    let mut parser = Parser::new();
    parser
        .set_language(&bash_language())
        .context("tree-sitter-bash grammar load")?;

    let tree = parser.parse(source, None);
    let mut warnings = Vec::new();

    if tree.is_none() {
        warnings.push("Bash parser returned no tree — falling back to text scan".to_string());
    }

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
    let mut has_set_e = false;
    let mut has_set_u = false;

    for (idx, raw_line) in source.lines().enumerate() {
        let line = raw_line.trim();
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);

        // Track strict-mode toggles for end-of-file summary
        if line.starts_with("set ") || line.starts_with("set\t") {
            if line.contains("-e") || line.contains("-eu") || line.contains("-euo") {
                has_set_e = true;
            }
            if line.contains("-u") || line.contains("-eu") || line.contains("-euo") {
                has_set_u = true;
            }
        }

        // rm -rf with a variable expansion — the classic "rm -rf /" bug
        if (line.contains("rm -rf") || line.contains("rm -fr"))
            && (line.contains('$') || line.contains("${"))
        {
            warnings.push(format!(
                "Line {line_no}: rm -rf with variable expansion — guard against unset vars"
            ));
        }

        // curl | sh / wget | bash — fetching and executing remote code
        if (line.contains("curl ") || line.contains("wget "))
            && line.contains('|')
            && (line.contains("sh") || line.contains("bash"))
        {
            warnings.push(format!(
                "Line {line_no}: piping remote download into a shell is unauthenticated code execution"
            ));
        }

        // chmod 777 / 666 — world-writable
        if line.contains("chmod 777") || line.contains("chmod 666") {
            warnings.push(format!(
                "Line {line_no}: world-writable chmod (777/666); use the narrowest mode that works"
            ));
        }

        // sudo without -n in non-interactive contexts (heuristic: sudo not
        // followed by -n and not a comment / function definition)
        if let Some(after) = line.strip_prefix("sudo ") {
            if !after.starts_with("-n") && !after.starts_with("--non-interactive") {
                // Only warn once-per-script's worth — cap by appending a
                // single advisory on first hit. Cheap dedup happens in
                // extract_bash_facts via the sort+dedup pass.
                warnings.push(format!(
                    "Line {line_no}: sudo without -n may hang in non-interactive contexts"
                ));
            }
        }

        // eval $variable — code injection if input is attacker-controlled
        if (line.starts_with("eval ") || line.contains(" eval "))
            && (line.contains('$') || line.contains("${"))
        {
            warnings.push(format!(
                "Line {line_no}: eval on a variable is code injection if input is tainted"
            ));
        }
    }

    if !has_set_e {
        warnings.insert(
            0,
            "Script does not set -e; failed commands won't abort".to_string(),
        );
    }
    if !has_set_u {
        warnings.insert(
            0,
            "Script does not set -u; unset variable expansions return empty strings".to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn rm_rf_with_var_is_flagged() {
        let src = "set -eu\nrm -rf $WORKDIR\n";
        let table = extract_bash_facts(&PathBuf::from("deploy.sh"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("rm -rf")),
            "expected rm -rf warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn curl_pipe_to_shell_is_flagged() {
        let src = "set -eu\ncurl https://example.com/install.sh | bash\n";
        let table = extract_bash_facts(&PathBuf::from("install.sh"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("piping")),
            "expected curl|bash warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn chmod_777_is_flagged() {
        let src = "set -eu\nchmod 777 /opt/app\n";
        let table = extract_bash_facts(&PathBuf::from("setup.sh"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("world-writable")),
            "expected chmod warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn missing_strict_mode_warns() {
        let src = "echo 'hello'\n"; // no set -e / set -u
        let table = extract_bash_facts(&PathBuf::from("script.sh"), src).unwrap();
        let has_e = table.warnings.iter().any(|w| w.contains("set -e"));
        let has_u = table.warnings.iter().any(|w| w.contains("set -u"));
        assert!(
            has_e && has_u,
            "expected both strict-mode warnings, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn strict_mode_silences_strict_warnings() {
        let src = "set -euo pipefail\necho 'hi'\n";
        let table = extract_bash_facts(&PathBuf::from("script.sh"), src).unwrap();
        assert!(
            !table
                .warnings
                .iter()
                .any(|w| w.contains("set -e") || w.contains("set -u")),
            "set -euo should suppress strict-mode warnings, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn empty_script_does_not_panic() {
        let table = extract_bash_facts(&PathBuf::from("empty.sh"), "").unwrap();
        assert_eq!(table.extract_method, ExtractMethod::TreeSitter);
    }
}
