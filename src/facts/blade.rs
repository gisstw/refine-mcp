//! `.blade.php` preprocessing → PHP tree-sitter (§2.3).
//!
//! Laravel Blade templates mix PHP, HTML, and Blade-specific directives that
//! the PHP grammar does not understand. We preprocess the source — replacing
//! Blade tokens with PHP-equivalent or whitespace-padded substitutes —
//! before handing it to the existing PHP fact extractor.
//!
//! ## Critical invariant: byte-length per line is preserved
//!
//! Tier 2 review §0.5 / RT-B1 flagged that any byte-shift invalidates the
//! line:col mapping the PHP parser produces, so red team `file:line` reports
//! point at wrong code in the original `.blade.php`. Every replacement here
//! is length-preserving — when an exact PHP equivalent doesn't fit, we pad
//! the gap with spaces. The `blade_preprocess_preserves_byte_length_per_line`
//! test enforces this.

use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;
use regex::Regex;

use super::{php, types::FactTable};

/// `{{ expr }}` → `<?=expr;?>` (always equal-length: both wrappers are 7
/// characters, so 1-char inner stays 1-char inner).
static ECHO_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{\s*(.+?)\s*\}\}").unwrap());

/// `{!! expr !!}` → `<?= expr ;?>` (9-char wrappers on each side; pad inner
/// with two trailing spaces before `;` to keep length equal).
static RAW_ECHO_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{!!\s*(.+?)\s*!!\}").unwrap());

/// `@directive` and `@directive(args)`. Both become equal-length
/// runs of spaces so the line's byte length is preserved while the PHP
/// parser sees only whitespace where the directive was.
static DIRECTIVE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"@[A-Za-z_][A-Za-z0-9_]*(\s*\([^)]*\))?").unwrap());

/// Public entry point. Run the Blade preprocessor and feed the result to
/// the PHP fact extractor.
pub fn extract_blade_facts(path: &Path, source: &str) -> Result<FactTable> {
    let preprocessed = preprocess(source);
    let mut table = php::extract_php_facts(path, &preprocessed)?;
    table.extract_method = super::types::ExtractMethod::BladePreproc;
    Ok(table)
}

/// Apply all Blade-token replacements. Each replacement is padded so the
/// substitute occupies exactly the same number of bytes as the original
/// match. See module-level invariant.
#[must_use]
pub fn preprocess(src: &str) -> String {
    // Order matters: raw echo `{!! !!}` looks like `{{ }}` to the simple
    // regex if we ran the echo regex first.
    let mut out = src.to_string();
    out = replace_raw_echo(&out);
    out = replace_echo(&out);
    out = replace_directives(&out);
    out
}

fn replace_echo(src: &str) -> String {
    ECHO_RE
        .replace_all(src, |caps: &regex::Captures| {
            let inner = caps.get(1).map_or("", |m| m.as_str());
            let original_len = caps.get(0).unwrap().as_str().len();
            // Wrappers `<?=` (3) + `;?>` (3) = 6 bytes. Original wrappers
            // `{{` + ` ` + ` ` + `}}` = 6 bytes. So `inner` width is preserved.
            let candidate = format!("<?={inner};?>");
            pad_to_len(candidate, original_len)
        })
        .into_owned()
}

fn replace_raw_echo(src: &str) -> String {
    RAW_ECHO_RE
        .replace_all(src, |caps: &regex::Captures| {
            let inner = caps.get(1).map_or("", |m| m.as_str());
            let original_len = caps.get(0).unwrap().as_str().len();
            // Original wrappers `{!!` (3) + ` ` + ` ` + `!!}` (3) = 8 bytes.
            // PHP wrappers `<?=` (3) + ` ` + `;?>` (3) = 7 bytes — one byte
            // short, so we pad inner.
            let candidate = format!("<?= {inner} ;?>");
            pad_to_len(candidate, original_len)
        })
        .into_owned()
}

fn replace_directives(src: &str) -> String {
    DIRECTIVE_RE
        .replace_all(src, |caps: &regex::Captures| {
            let original = caps.get(0).unwrap().as_str();
            // Pure whitespace replacement preserves layout while letting the
            // PHP parser skip past the directive entirely.
            " ".repeat(original.len())
        })
        .into_owned()
}

/// Right-pad with spaces if shorter; truncate if accidentally longer (which
/// shouldn't happen for the patterns above, but guards against grammar
/// drift). When truncation happens we drop the trailing `;?>` last; this is
/// a degraded case the test suite will catch.
fn pad_to_len(mut s: String, target: usize) -> String {
    use std::cmp::Ordering;
    match s.len().cmp(&target) {
        Ordering::Less => {
            let pad = target - s.len();
            // Insert pad spaces before the trailing `;?>` so the PHP
            // statement terminator stays at the right place.
            if let Some(cut) = s.rfind(";?>") {
                let mut spaces = " ".repeat(pad);
                spaces.push_str(&s[cut..]);
                s.truncate(cut);
                s.push_str(&spaces);
            } else {
                for _ in 0..pad {
                    s.push(' ');
                }
            }
            s
        }
        Ordering::Equal => s,
        Ordering::Greater => {
            // Truncate from the middle, keep wrappers if possible.
            s.truncate(target);
            s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blade_preprocess_preserves_byte_length_per_line() {
        let blade = "\
@extends('layouts.app')
<h1>{{ $title }}</h1>
<p>{!! $raw_html !!}</p>
@if ($user)
  <span>Hello, {{ $user->name }}</span>
@endif
";
        let out = preprocess(blade);
        let orig: Vec<usize> = blade.lines().map(str::len).collect();
        let new: Vec<usize> = out.lines().map(str::len).collect();
        assert_eq!(
            orig, new,
            "every line must have identical byte length;\n  orig={orig:?}\n   new={new:?}"
        );
    }

    #[test]
    fn echo_becomes_php_echo() {
        let out = preprocess("<p>{{ $x }}</p>");
        assert!(
            out.contains("<?=$x;?>") || out.contains("<?= $x ;?>"),
            "expected PHP echo, got: {out}"
        );
    }

    #[test]
    fn raw_echo_becomes_php_echo() {
        let out = preprocess("{!! $html !!}");
        assert!(
            out.contains("<?=") && out.contains("$html"),
            "expected raw echo to become <?= $html ;?>, got: {out}"
        );
    }

    #[test]
    fn directive_becomes_whitespace() {
        let blade = "@if ($cond)\n  X\n@endif\n";
        let out = preprocess(blade);
        // Each Blade-only line should be all whitespace now.
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[0].trim().is_empty(),
            "@if line should be whitespace, got: {:?}",
            lines[0]
        );
        assert!(
            lines[2].trim().is_empty(),
            "@endif line should be whitespace, got: {:?}",
            lines[2]
        );
        assert_eq!(lines[1], "  X");
    }

    #[test]
    fn empty_input_is_safe() {
        assert_eq!(preprocess(""), "");
    }

    #[test]
    fn no_blade_tokens_means_no_change() {
        let src = "<?php echo 'hi'; ?>\n<p>plain</p>\n";
        assert_eq!(preprocess(src), src);
    }
}
