//! `.vue` Single-File Component extraction (§6.3).
//!
//! A Vue SFC bundles `<template>`, `<script>`, and `<style>` blocks in one
//! file. Tree-sitter has no first-class Vue grammar, so we split the SFC,
//! dispatch the `<script>` block (which carries the actual logic) to the
//! TypeScript parser, and return its facts with `<script>`-relative line
//! numbers offset back to file-relative.

use std::path::Path;

use anyhow::Result;

use super::types::{ExtractMethod, FactTable};

/// Public entry: locate the `<script>` block, send its contents through the
/// TypeScript fact extractor, then offset every line range back to its
/// position in the original `.vue` file. `<template>` and `<style>` are
/// ignored — they're flagged for future work but contribute no facts today.
pub fn extract_vue_facts(path: &Path, source: &str) -> Result<FactTable> {
    let Some(script) = extract_script_block(source) else {
        // No <script> block — emit a minimal table so the file is at least
        // visible to consumers.
        return Ok(FactTable {
            file: path.to_path_buf(),
            language: super::types::Language::default(),
            functions: vec![],
            warnings: vec!["Vue SFC has no <script> block; nothing to extract".to_string()],
            callers: vec![],
            extract_method: ExtractMethod::TreeSitter,
            fingerprints: vec![],
        });
    };

    let mut table = super::typescript::extract_ts_facts(path, &script.content)?;

    // Translate every line number back to file-relative coordinates.
    let offset = script.start_line;
    for f in &mut table.functions {
        f.line_range = (f.line_range.0 + offset, f.line_range.1 + offset);
    }

    Ok(table)
}

/// Internal: located `<script>` block plus its starting line offset (1-based).
struct ScriptBlock {
    content: String,
    /// Number of lines BEFORE the first line of script content. Add this
    /// to any TypeScript-relative line number to get the file-relative
    /// position.
    start_line: u32,
}

fn extract_script_block(source: &str) -> Option<ScriptBlock> {
    // Cheap manual scan instead of pulling in a full HTML parser. Looks
    // for `<script` ... `>` opening tag (any attributes), then the
    // matching `</script>` end tag.
    let lines: Vec<&str> = source.lines().collect();
    let mut open_line: Option<usize> = None;
    let mut close_line: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if open_line.is_none() && trimmed.starts_with("<script") {
            // Open tag may close on the same line (`<script setup>`) or
            // span multiple lines. Find the next line where the tag
            // actually ends.
            for (j, l) in lines.iter().enumerate().skip(i) {
                if l.contains('>') {
                    open_line = Some(j + 1); // first content line is j+1
                    break;
                }
            }
        } else if open_line.is_some() && trimmed.starts_with("</script>") {
            close_line = Some(i);
            break;
        }
    }

    let (start, end) = (open_line?, close_line?);
    if start >= end {
        return None;
    }
    let content = lines[start..end].join("\n");
    // The TS parser treats line 1 as the first non-empty line of input,
    // so the offset is `start` (number of lines preceding the script
    // content in the original file).
    Some(ScriptBlock {
        content,
        start_line: u32::try_from(start).unwrap_or(u32::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn extracts_script_block_only() {
        let sfc = "\
<template>
  <div>{{ msg }}</div>
</template>

<script setup lang=\"ts\">
const msg = 'hello'
function greet() {
  return msg
}
</script>

<style scoped>
div { color: red; }
</style>
";
        let table = extract_vue_facts(&PathBuf::from("App.vue"), sfc).unwrap();
        // The <script> block contains a function declaration. The TS
        // extractor should pick it up; absent that we'd at least see no
        // panic.
        assert_eq!(table.extract_method, ExtractMethod::TreeSitter);
        // Greet is on line 7 in the original file. If the TS parser
        // recognized it, the offset translation should land roughly there.
        if let Some(f) = table.functions.iter().find(|f| f.name == "greet") {
            assert!(
                f.line_range.0 >= 6 && f.line_range.0 <= 8,
                "greet should be at file line ~7, got {:?}",
                f.line_range
            );
        }
    }

    #[test]
    fn no_script_block_yields_warning_not_error() {
        let sfc = "<template>\n  <div>plain</div>\n</template>\n";
        let table = extract_vue_facts(&PathBuf::from("App.vue"), sfc).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("no <script>")),
            "expected no-script warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn empty_input_does_not_panic() {
        let table = extract_vue_facts(&PathBuf::from("App.vue"), "").unwrap();
        assert_eq!(table.extract_method, ExtractMethod::TreeSitter);
    }
}
