use std::path::Path;

use anyhow::Result;

use super::types::{
    CatchFact, ExternalCallFact, FactTable, FunctionFact, Language, LockFact, MutationFact,
    NullRiskFact, ParamFact, ReturnPathFact, SilentSkipFact,
};

/// Extract structure from a Markdown file.
///
/// Since Markdown has no code symbols, we represent each `##`-level section
/// as a synthetic `FunctionFact` (name = heading text, line_range covers the
/// section body). Section bodies are stored in `FactTable.warnings` so the
/// red-team prompt has access to the full plan text.
///
/// This allows `quick_review` to analyse plan files for logical gaps,
/// missing steps, and design blind spots.
pub fn extract_markdown_facts(path: &Path, source: &str) -> Result<FactTable> {
    let mut functions: Vec<FunctionFact> = Vec::new();
    let mut section_bodies: Vec<String> = Vec::new();

    let mut current_heading: Option<String> = None;
    let mut current_start: u32 = 0;
    let mut current_lines: Vec<&str> = Vec::new();

    let lines: Vec<&str> = source.lines().collect();
    let total = lines.len() as u32;

    let flush = |heading: String,
                 start: u32,
                 end: u32,
                 body_lines: &[&str],
                 fns: &mut Vec<FunctionFact>,
                 bodies: &mut Vec<String>| {
        let body = body_lines.join("\n");
        // Section heading and label in FactTable.functions for grep/filtering
        fns.push(FunctionFact {
            name: heading.clone(),
            line_range: (start, end),
            return_type: None,
            parameters: Vec::<ParamFact>::new(),
            transaction: None,
            locks: Vec::<LockFact>::new(),
            catch_blocks: Vec::<CatchFact>::new(),
            external_calls: Vec::<ExternalCallFact>::new(),
            state_mutations: Vec::<MutationFact>::new(),
            null_risks: Vec::<NullRiskFact>::new(),
            return_paths: Vec::<ReturnPathFact>::new(),
            silent_skips: Vec::<SilentSkipFact>::new(),
        });
        // Section body in FactTable.warnings so it appears in JSON for LLM analysis
        if !body.trim().is_empty() {
            bodies.push(format!("=== {heading} ===\n{body}"));
        }
    };

    for (i, line) in lines.iter().enumerate() {
        let lineno = i as u32 + 1;

        if line.starts_with("## ") {
            if let Some(heading) = current_heading.take() {
                let end = lineno.saturating_sub(1);
                flush(
                    heading,
                    current_start,
                    end,
                    &current_lines,
                    &mut functions,
                    &mut section_bodies,
                );
                current_lines.clear();
            }
            current_heading = Some(line.trim_start_matches('#').trim().to_string());
            current_start = lineno;
        } else if current_heading.is_some() {
            current_lines.push(line);
        }
    }

    // Flush final section
    if let Some(heading) = current_heading.take() {
        flush(
            heading,
            current_start,
            total,
            &current_lines,
            &mut functions,
            &mut section_bodies,
        );
    }

    Ok(FactTable {
        file: path.to_path_buf(),
        language: Language::Markdown,
        functions,
        warnings: section_bodies,
        callers: Vec::new(),
    })
}
