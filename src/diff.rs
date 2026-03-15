use std::collections::HashMap;
use std::path::Path;

use crate::facts::types::FunctionFact;
use crate::types::{
    FunctionSignature, FunctionSummary, SignatureChange, StructuralDiff, StructuralDiffReport,
};

/// Compare before/after function lists for a single file.
/// Matches functions by name, then compares signatures.
#[must_use]
pub fn compute_structural_diff(
    file: &Path,
    before: &[FunctionFact],
    after: &[FunctionFact],
) -> StructuralDiff {
    let before_map: HashMap<&str, &FunctionFact> =
        before.iter().map(|f| (f.name.as_str(), f)).collect();
    let after_map: HashMap<&str, &FunctionFact> =
        after.iter().map(|f| (f.name.as_str(), f)).collect();

    let mut diff = StructuralDiff {
        file: file.to_path_buf(),
        ..Default::default()
    };

    // Find removed and changed
    for (name, before_fact) in &before_map {
        match after_map.get(name) {
            None => {
                diff.removed.push(FunctionSummary::from_fact(before_fact));
            }
            Some(after_fact) => {
                let before_sig = FunctionSignature::from_fact(before_fact);
                let after_sig = FunctionSignature::from_fact(after_fact);
                if before_sig == after_sig {
                    diff.unchanged_count += 1;
                } else {
                    let (breaking, reasons) = detect_breaking_change(&before_sig, &after_sig);
                    diff.changed.push(SignatureChange {
                        name: name.to_string(),
                        file: file.to_path_buf(),
                        before: before_sig,
                        after: after_sig,
                        breaking,
                        reasons,
                    });
                }
            }
        }
    }

    // Find added
    for (name, after_fact) in &after_map {
        if !before_map.contains_key(name) {
            diff.added.push(FunctionSummary::from_fact(after_fact));
        }
    }

    diff
}

/// Aggregate diffs from multiple files into a report.
#[must_use]
pub fn aggregate_diffs(diffs: Vec<StructuralDiff>) -> StructuralDiffReport {
    let mut report = StructuralDiffReport::default();
    for d in &diffs {
        report.total_added += d.added.len();
        report.total_removed += d.removed.len();
        report.total_changed += d.changed.len();
        report.breaking_changes += d.changed.iter().filter(|c| c.breaking).count();
    }
    report.files = diffs;
    report
}

/// Determine if a signature change is breaking and why.
fn detect_breaking_change(
    before: &FunctionSignature,
    after: &FunctionSignature,
) -> (bool, Vec<String>) {
    let mut reasons = Vec::new();
    let mut breaking = false;

    // Return type changed
    if before.return_type != after.return_type {
        reasons.push(format!(
            "return type changed: {:?} → {:?}",
            before.return_type, after.return_type
        ));
        breaking = true;
    }

    // Params removed
    let before_names: Vec<&str> = before.params.iter().map(|p| p.name.as_str()).collect();
    let after_names: Vec<&str> = after.params.iter().map(|p| p.name.as_str()).collect();

    for name in &before_names {
        if !after_names.contains(name) {
            reasons.push(format!("parameter removed: {name}"));
            breaking = true;
        }
    }

    // Params added (breaking — callers need to pass them)
    for name in &after_names {
        if !before_names.contains(name) {
            reasons.push(format!("parameter added: {name}"));
            breaking = true;
        }
    }

    // Param type changed
    for before_param in &before.params {
        if let Some(after_param) = after.params.iter().find(|p| p.name == before_param.name) {
            if before_param.type_hint != after_param.type_hint {
                reasons.push(format!(
                    "parameter {} type changed: {:?} → {:?}",
                    before_param.name, before_param.type_hint, after_param.type_hint
                ));
                breaking = true;
            }
            if before_param.nullable != after_param.nullable && before_param.nullable {
                // Nullable → non-nullable is breaking
                reasons.push(format!(
                    "parameter {} nullability changed: nullable → non-nullable",
                    before_param.name,
                ));
                breaking = true;
            }
        }
    }

    // Param order changed (even with same set)
    if before_names.len() == after_names.len()
        && before_names.iter().all(|n| after_names.contains(n))
        && before_names != after_names
    {
        reasons.push("parameter order changed".to_string());
        breaking = true;
    }

    (breaking, reasons)
}
