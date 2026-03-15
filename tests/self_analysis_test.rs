//! E2E self-analysis: run the Rust extractor on refine-mcp's own source code.
//! This validates that the tool can analyze itself without panics or errors.

use std::path::Path;

use refine_mcp::facts::rust_lang::extract_rust_facts;

const OWN_FILES: &[&str] = &[
    "src/server.rs",
    "src/types.rs",
    "src/lib.rs",
    "src/main.rs",
    "src/diff.rs",
    "src/health.rs",
    "src/facts/php.rs",
    "src/facts/rust_lang.rs",
    "src/facts/typescript.rs",
    "src/facts/python.rs",
    "src/facts/types.rs",
    "src/facts/blast_radius.rs",
    "src/facts/migration.rs",
];

#[test]
fn self_analysis_no_panics() {
    let mut total_fns = 0;
    let mut total_warnings = 0;
    let mut total_risks = 0;
    let mut total_mutations = 0;

    for &file in OWN_FILES {
        let path = Path::new(file);
        let source =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("Cannot read {file}: {e}"));

        let table = extract_rust_facts(path, &source)
            .unwrap_or_else(|e| panic!("Failed to extract facts from {file}: {e}"));

        total_fns += table.functions.len();
        total_warnings += table.warnings.len();
        for f in &table.functions {
            total_risks += f.null_risks.len();
            total_mutations += f.state_mutations.len();
        }
    }

    // Sanity checks — we know our own codebase has these
    assert!(total_fns > 30, "should find 30+ functions, got {total_fns}");
    assert!(
        total_risks > 0,
        "should detect some .unwrap()/.expect() risks"
    );

    eprintln!("\n=== Self-Analysis Summary ===");
    eprintln!("  Files analyzed: {}", OWN_FILES.len());
    eprintln!("  Functions found: {total_fns}");
    eprintln!("  Warnings: {total_warnings}");
    eprintln!("  Null/panic risks: {total_risks}");
    eprintln!("  State mutations: {total_mutations}");
}

#[test]
fn self_analysis_detail_report() {
    use std::fmt::Write;

    let mut report = String::new();

    for &file in OWN_FILES {
        let path = Path::new(file);
        let source = std::fs::read_to_string(path).unwrap();
        let table = extract_rust_facts(path, &source).unwrap();

        if !table.warnings.is_empty() || table.functions.iter().any(|f| !f.null_risks.is_empty()) {
            let _ = writeln!(report, "\n--- {file} ---");
            for w in &table.warnings {
                let _ = writeln!(report, "  ⚠ {w}");
            }
            for f in &table.functions {
                for r in &f.null_risks {
                    let _ = writeln!(report, "  L{}: {} — {}", r.line, r.reason, r.expression);
                }
            }
        }
    }

    eprintln!("\n=== Detailed Self-Analysis ===\n{report}");
    // This test always passes — it's for observing output
}
