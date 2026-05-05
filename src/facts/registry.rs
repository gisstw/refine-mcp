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
/// (logging to `format-issues.log`, error message to the user, `skipped_files`
/// reporting once §1.3 lands).
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
/// `FactTable` in an `ExtractResult`. Returns a structured `ExtractError` on
/// any failure so the caller can map it to logs and user-visible errors.
pub fn extract_for_path(path: &Path, source: &str) -> Result<ExtractResult, ExtractError> {
    // .blade.php must be detected before falling back to the PHP parser
    // (§2.3); this hook is reserved for that future commit.
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .ok_or(ExtractError::NoExtension)?;

    let facts = match ext {
        "php" => crate::facts::php::extract_php_facts(path, source),
        "rs" => crate::facts::rust_lang::extract_rust_facts(path, source),
        "ts" | "tsx" | "js" | "jsx" => crate::facts::typescript::extract_ts_facts(path, source),
        "py" => crate::facts::python::extract_python_facts(path, source),
        "md" => crate::facts::markdown::extract_markdown_facts(path, source),
        other => {
            return Err(ExtractError::Unsupported {
                ext: other.to_string(),
            });
        }
    };

    facts
        .map(|mut t| {
            t.extract_method = ExtractMethod::TreeSitter;
            ExtractResult {
                facts: t,
                method: ExtractMethod::TreeSitter,
            }
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
    fn unsupported_extension_reports_ext_and_kind() {
        let err = extract_for_path(&PathBuf::from("foo.lua"), "").unwrap_err();
        assert_eq!(err.ext(), "lua");
        assert_eq!(err.kind(), "unsupported");
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
}
