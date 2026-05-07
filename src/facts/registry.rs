//! Dispatch table for fact extraction across supported languages.
//!
//! Centralizes the file-extension → extractor mapping that previously lived
//! inline in `server::run_extraction`. New languages and extraction strategies
//! (textual fallback, blade preprocessing) plug in here.

use std::path::Path;

use crate::facts::types::{ExtractMethod, FactTable};

/// Successful extraction result. The `method` mirrors `facts.extract_method`
/// for callers that haven't deserialized the table yet.
#[derive(Debug)]
pub struct ExtractResult {
    pub facts: FactTable,
    pub method: ExtractMethod,
}

/// Reasons extraction can fail. The caller decides how to surface each kind
/// (logging to `format-issues.log`, error message to the user,
/// `skipped_files` reporting). `Unsupported` is currently unreachable —
/// `extract_for_path` falls back to the textual extractor (§2.5) for any
/// extension without a tree-sitter grammar — but the variant is kept for
/// callers that may want a future "strict, no-fallback" mode.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("unsupported language: .{ext}")]
    Unsupported { ext: String },

    #[error("no file extension")]
    NoExtension,

    #[error("parse error in .{ext} source: {source}")]
    Parse {
        ext: String,
        #[source]
        source: anyhow::Error,
    },
}

impl ExtractError {
    /// Suggest concrete next steps the agent can take when extraction
    /// failed. Returned in addition to the error message so the agent
    /// can autonomously try a recovery without bouncing back to the
    /// user (§6.4 parse error options).
    #[must_use]
    pub fn recovery_options(&self) -> Vec<&'static str> {
        match self {
            Self::Unsupported { .. } => vec![
                "skip this file with a warning",
                "fall back to textual heuristic scan (extract_method=Textual)",
                "add a tree-sitter grammar for this extension",
            ],
            Self::NoExtension => vec![
                "rename the file to include an extension",
                "skip this file with a warning",
            ],
            Self::Parse { .. } => vec![
                "fall back to textual heuristic scan (extract_method=Textual)",
                "split the file at language boundaries (e.g. PHP `__halt_compiler__`, Vue SFC blocks) and retry",
                "skip this file and continue with the remaining inputs",
                "report the parse error upstream so the grammar can be improved",
            ],
        }
    }
}

impl ExtractError {
    /// Best-effort extension name, used by callers when logging.
    /// Returns empty string for `NoExtension`.
    #[must_use]
    pub fn ext(&self) -> &str {
        match self {
            Self::Unsupported { ext } | Self::Parse { ext, .. } => ext,
            Self::NoExtension => "",
        }
    }

    /// Stable kind tag for `log_format_issue`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "unsupported",
            Self::NoExtension => "no_extension",
            Self::Parse { .. } => "parse_error",
        }
    }
}

/// Run the extractor matching this file's extension and wrap the resulting
/// `FactTable` in an `ExtractResult`. Returns a structured `ExtractError`
/// only for cases the caller has to act on (no extension, or a tree-sitter
/// parse failure). Unknown extensions get a heuristic textual scan so the
/// caller still sees *something*; the table's `extract_method` flags the
/// reduced precision.
pub fn extract_for_path(path: &Path, source: &str) -> Result<ExtractResult, ExtractError> {
    // `.blade.php` must beat the bare `.php` arm because `path.extension()`
    // strips only the trailing `.php`, hiding the Blade nature.
    if path
        .to_string_lossy()
        .ends_with(".blade.php")
    {
        return crate::facts::blade::extract_blade_facts(path, source)
            .map(|mut t| {
                t.fingerprints = crate::fingerprint::compute_for_table(&t, source);
                ExtractResult {
                    facts: t,
                    method: ExtractMethod::BladePreproc,
                }
            })
            .map_err(|source| ExtractError::Parse {
                ext: "blade.php".to_string(),
                source,
            });
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .ok_or(ExtractError::NoExtension)?;

    let (facts, method) = match ext {
        "php" => (
            crate::facts::php::extract_php_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        "rs" => (
            crate::facts::rust_lang::extract_rust_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        "ts" | "tsx" | "js" | "jsx" => (
            crate::facts::typescript::extract_ts_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        "py" => (
            crate::facts::python::extract_python_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        "md" => (
            crate::facts::markdown::extract_markdown_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        "sql" => (
            crate::facts::sql::extract_sql_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        "yml" | "yaml" => (
            crate::facts::yaml::extract_yaml_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        "sh" | "bash" => (
            crate::facts::bash::extract_bash_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        "toml" => (
            crate::facts::toml_lang::extract_toml_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        "json" => (
            crate::facts::json_lang::extract_json_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        "vue" => (
            crate::facts::vue::extract_vue_facts(path, source),
            ExtractMethod::TreeSitter,
        ),
        _ => (
            crate::facts::textual::extract_textual_facts(path, source),
            ExtractMethod::Textual,
        ),
    };

    facts
        .map(|mut t| {
            t.extract_method = method;
            t.fingerprints = crate::fingerprint::compute_for_table(&t, source);
            ExtractResult { facts: t, method }
        })
        .map_err(|source| ExtractError::Parse {
            ext: ext.to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn unsupported_extension_falls_back_to_textual() {
        let result = extract_for_path(&PathBuf::from("foo.lua"), "-- TODO: review\n")
            .expect("textual fallback must always succeed");
        assert_eq!(result.method, ExtractMethod::Textual);
        assert_eq!(result.facts.extract_method, ExtractMethod::Textual);
        assert!(
            result.facts.warnings.iter().any(|w| w.contains("TODO")),
            "textual fallback should surface TODO markers"
        );
    }

    #[test]
    fn no_extension_reports_empty_ext() {
        let err = extract_for_path(&PathBuf::from("Makefile"), "").unwrap_err();
        assert_eq!(err.ext(), "");
        assert_eq!(err.kind(), "no_extension");
    }

    #[test]
    fn supported_extension_returns_tree_sitter_method() {
        let result = extract_for_path(&PathBuf::from("test.md"), "# Heading\n");
        let r = result.expect("markdown extractor should accept simple input");
        assert_eq!(r.method, ExtractMethod::TreeSitter);
    }

    #[test]
    fn parse_error_recovery_options_are_actionable() {
        let err = ExtractError::Parse {
            ext: "php".to_string(),
            source: anyhow::anyhow!("syntax error at token X"),
        };
        let opts = err.recovery_options();
        assert!(!opts.is_empty(), "parse errors must have recovery options");
        assert!(
            opts.iter().any(|o| o.contains("textual")),
            "should suggest textual fallback"
        );
    }

    #[test]
    fn no_extension_recovery_options_include_skip_and_rename() {
        let opts = ExtractError::NoExtension.recovery_options();
        assert!(opts.iter().any(|o| o.contains("rename")));
        assert!(opts.iter().any(|o| o.contains("skip")));
    }
}
