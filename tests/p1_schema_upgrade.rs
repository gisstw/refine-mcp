//! P1 end-to-end: simulate the v0 → v1 → v2 schema upgrade path that a
//! real plan goes through after agent-first evolution lands.
//!
//! Plan reference: `plans/agent-first-evolution-2026-05-05.md` §2.1
//! "Tier 2 補強 — 首次保護期".
//!
//! The scenarios here check the integration boundary between
//! `RefineState::merge_findings` and the `FingerprintMap` produced by
//! `facts::registry::extract_for_path` — the place where a regression
//! would leak silent auto-marks (RT-A2).

use std::collections::HashMap;
use std::path::PathBuf;

use refine_mcp::facts::types::FingerprintEntry;
use refine_mcp::state::{FingerprintMap, RefineState};
use refine_mcp::types::{Finding, FindingStatus, RedTeamId, Severity};

fn finding(id: &str, file: &str, line_range: (u32, u32), title: &str) -> Finding {
    Finding {
        id: id.to_string(),
        severity: Severity::High,
        title: title.to_string(),
        sources: vec![RedTeamId::RtA],
        file_path: PathBuf::from(file),
        line_range: Some(line_range),
        problem: String::new(),
        attack_scenario: String::new(),
        suggested_fix: None,
        affected_plan_steps: vec![],
        status: FindingStatus::New,
        impact_score: 0,
        fingerprint: None,
        symbol_path: None,
        auto_marked: None,
    }
}

fn map_with(file: &str, entries: Vec<((u32, u32), &str, &str)>) -> FingerprintMap {
    let mut m = HashMap::new();
    m.insert(
        PathBuf::from(file),
        entries
            .into_iter()
            .map(|(range, sym, hash)| FingerprintEntry {
                line_range: range,
                symbol_path: sym.to_string(),
                content_hash: hash.to_string(),
            })
            .collect(),
    );
    m
}

/// Run 1 (v0 → v1): legacy state, no fingerprints anywhere — must not
/// auto-mark, must backfill incoming finding's fingerprint.
/// Run 2 (v1 → v2): fingerprint still present in map → no change.
/// Run 3 (v2 stable): fingerprint disappears from map → auto-mark Fixed.
#[test]
fn full_v0_to_v2_upgrade_chain() {
    let mut state = RefineState::default();
    assert_eq!(state.schema_version, 0);

    // Run 1 — first time we have a fingerprint map. v0 → v1.
    let map = map_with(
        "src/cart.php",
        vec![((10, 30), "CartService::charge", "abcdef0123456789")],
    );
    state.merge_findings(
        vec![finding("F1", "src/cart.php", (15, 20), "missing transaction")],
        &map,
    );
    assert_eq!(state.schema_version, 1, "first run: v0 → v1");
    assert_eq!(state.findings[0].status, FindingStatus::New);
    assert_eq!(
        state.findings[0].fingerprint.as_deref(),
        Some("abcdef0123456789"),
        "fingerprint must be backfilled from enclosing function entry"
    );

    // Run 2 — same fingerprint still present. v1 → v2, no auto-mark
    // because grace period prevents it on this transition too.
    state.merge_findings(vec![], &map);
    assert_eq!(state.schema_version, 2);
    assert_eq!(state.findings[0].status, FindingStatus::New);

    // Run 3 — fingerprint gone (function rewritten). Schema is at 2,
    // auto-mark engages.
    let new_map = map_with(
        "src/cart.php",
        vec![((10, 30), "CartService::charge", "9999999999999999")],
    );
    state.merge_findings(vec![], &new_map);
    assert_eq!(
        state.findings[0].status,
        FindingStatus::Fixed,
        "v2 + missing fingerprint must auto-mark Fixed"
    );
    assert!(state.findings[0].auto_marked.is_some());
}

/// Empty fingerprint map at v2 must NOT auto-mark — `extract_facts` may
/// have failed for unrelated reasons.
#[test]
fn empty_map_at_v2_preserves_findings() {
    let mut state = RefineState {
        schema_version: 2,
        ..RefineState::default()
    };
    let mut f = finding("F1", "src/cart.php", (15, 20), "issue");
    f.fingerprint = Some("abcdef".to_string());
    state.findings.push(f);

    state.merge_findings(vec![], &FingerprintMap::new());
    assert_eq!(state.findings[0].status, FindingStatus::New);
}

/// User-set statuses (`Fixed` / `FalsePositive`) must survive a v2 run
/// that would otherwise touch them. `mark_finding`'s persistence guarantee.
#[test]
fn user_set_status_is_not_overwritten_at_v2() {
    let mut state = RefineState {
        schema_version: 2,
        ..RefineState::default()
    };
    let mut f1 = finding("F1", "src/a.php", (1, 5), "issue 1");
    f1.fingerprint = Some("a".to_string());
    f1.status = FindingStatus::FalsePositive;
    state.findings.push(f1);

    let mut f2 = finding("F2", "src/a.php", (10, 15), "issue 2");
    f2.fingerprint = Some("b".to_string());
    f2.status = FindingStatus::Fixed;
    state.findings.push(f2);

    // Map has neither fingerprint — auto-mark would fire on a New finding,
    // but these aren't New.
    let map = map_with("src/a.php", vec![((1, 100), "x", "different")]);
    state.merge_findings(vec![], &map);

    assert_eq!(state.findings[0].status, FindingStatus::FalsePositive);
    assert_eq!(state.findings[1].status, FindingStatus::Fixed);
}
