use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::facts::types::FingerprintEntry;
use crate::types::{Finding, FindingStatus};

/// Persistent state across refine runs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct RefineState {
    pub findings: Vec<Finding>,
    pub run_count: u32,
    pub last_run: Option<String>,
    /// Tracks how many times this state has been processed by a
    /// fingerprint-aware merge. Auto-mark-as-fixed only kicks in once
    /// `schema_version >= 2`, giving a one-run grace period after
    /// upgrade so legacy findings get backfilled with fingerprints
    /// before being eligible for automatic resolution. See plan §2.1
    /// "Tier 2 補強 — 首次保護期".
    #[serde(default)]
    pub schema_version: u8,
    /// Findings the user has confirmed are false positives. Carried as a
    /// separate, append-only history (instead of just keeping the
    /// `Finding` with status `FalsePositive`) so we can prune resolved
    /// findings without losing the "don't report this again" signal.
    /// Plan §6.1.
    #[serde(default)]
    pub false_positive_history: Vec<FalsePositiveEntry>,
}

/// Compact record of a finding that was marked false positive at some
/// point, used to keep `prepare_attack` from producing the same noise on
/// subsequent runs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FalsePositiveEntry {
    pub fingerprint: Option<String>,
    pub title: String,
    pub category: Option<String>,
    pub note: Option<String>,
}

/// Map a finding's source file to all known fingerprint entries in that file.
/// This is the shape `merge_findings` consumes; build it from the run's
/// `FactTable` outputs.
pub type FingerprintMap = HashMap<PathBuf, Vec<FingerprintEntry>>;

impl RefineState {
    /// Load state from the default location relative to a plan path.
    ///
    /// Returns default (empty) state if file doesn't exist yet.
    /// Returns error if file exists but is corrupted or unreadable.
    pub fn load(plan_path: &Path) -> anyhow::Result<Self> {
        let state_path = state_path_from_plan(plan_path);
        Self::load_from(&state_path)
    }

    /// Load state from a specific path.
    ///
    /// - File not found → Ok(default) (first run)
    /// - File corrupted → Err (caller decides recovery)
    /// - Permission denied → Err
    pub fn load_from(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                serde_json::from_str(&content).context("State file corrupted — JSON parse failed")
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).context("Failed to read state file"),
        }
    }

    /// Save state to the default location relative to a plan path.
    pub fn save(&self, plan_path: &Path) -> anyhow::Result<()> {
        let state_path = state_path_from_plan(plan_path);
        self.save_to(&state_path)
    }

    /// Save state atomically: write to temp file then rename.
    ///
    /// Prevents corruption from mid-write crashes or concurrent reads.
    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json).context("Failed to write temp state file")?;
        std::fs::rename(&tmp, path).context("Failed to atomic-rename state file")?;
        Ok(())
    }

    /// Merge new findings from a refine run with existing state.
    ///
    /// - New findings are added (with fingerprint backfilled from
    ///   `current_fingerprints` when an enclosing entry exists).
    /// - Existing findings with matching `(file_path, line_range, title)` are
    ///   updated.
    /// - Findings marked `Fixed` or `FalsePositive` are preserved.
    /// - Auto-mark-as-fixed: existing `New` findings whose stored
    ///   `fingerprint` no longer appears in `current_fingerprints` get
    ///   flipped to `Fixed`, but only once `schema_version >= 2` and the map
    ///   is non-empty — see "Tier 2 補強 — 首次保護期" in plan §2.1.
    pub fn merge_findings(
        &mut self,
        new_findings: Vec<Finding>,
        current_fingerprints: &FingerprintMap,
    ) {
        let auto_mark_enabled =
            self.schema_version >= 2 && !current_fingerprints.is_empty();

        if auto_mark_enabled {
            for existing in &mut self.findings {
                if existing.status != FindingStatus::New {
                    continue;
                }
                let Some(fp) = existing.fingerprint.as_deref() else {
                    continue;
                };
                let still_present = current_fingerprints
                    .get(&existing.file_path)
                    .is_some_and(|entries| entries.iter().any(|e| e.content_hash == fp));
                if !still_present {
                    existing.status = FindingStatus::Fixed;
                    existing.auto_marked =
                        Some("fingerprint not found in latest run".to_string());
                }
            }
        }

        for new in new_findings {
            let existing_idx = self.findings.iter().position(|f| {
                f.file_path == new.file_path
                    && f.line_range == new.line_range
                    && f.title == new.title
            });

            if let Some(idx) = existing_idx {
                let existing = &mut self.findings[idx];
                if existing.status == FindingStatus::New {
                    existing.severity = new.severity;
                    existing.problem.clone_from(&new.problem);
                    existing.attack_scenario.clone_from(&new.attack_scenario);
                    existing.suggested_fix.clone_from(&new.suggested_fix);
                    existing.impact_score = new.impact_score;

                    // Backfill fingerprint/symbol on legacy findings (v0)
                    // the first time we have data to do so.
                    if existing.fingerprint.is_none() {
                        if let Some(entry) = enclosing_entry(
                            current_fingerprints,
                            &existing.file_path,
                            existing.line_range,
                        ) {
                            existing.fingerprint = Some(entry.content_hash.clone());
                            existing.symbol_path = Some(entry.symbol_path.clone());
                        }
                    }

                    for src in &new.sources {
                        if !existing.sources.contains(src) {
                            existing.sources.push(*src);
                        }
                    }
                }
            } else {
                let mut to_insert = new;
                if let Some(entry) = enclosing_entry(
                    current_fingerprints,
                    &to_insert.file_path,
                    to_insert.line_range,
                ) {
                    to_insert.fingerprint = Some(entry.content_hash.clone());
                    to_insert.symbol_path = Some(entry.symbol_path.clone());
                }
                self.findings.push(to_insert);
            }
        }

        self.run_count += 1;
        self.schema_version = self.schema_version.saturating_add(1).min(2);
    }

    /// Record a finding as a false positive in the long-lived history,
    /// even if the original `Finding` is later pruned. Idempotent — a
    /// duplicate (matching `fingerprint` + `title`) is dropped.
    pub fn record_false_positive(&mut self, finding: &Finding, note: Option<String>) {
        let entry = FalsePositiveEntry {
            fingerprint: finding.fingerprint.clone(),
            title: finding.title.clone(),
            category: finding
                .symbol_path
                .as_ref()
                .and_then(|s| s.strip_prefix("category:").map(str::to_owned)),
            note,
        };
        if !self.false_positive_history.iter().any(|e| {
            e.fingerprint == entry.fingerprint && e.title == entry.title
        }) {
            self.false_positive_history.push(entry);
        }
    }

    /// Render the FP history as a prompt fragment red teams can read.
    /// Empty when there's no history. Limited to the most recent
    /// `max` entries to keep prompts compact.
    #[must_use]
    pub fn render_false_positive_hints(&self, max: usize) -> String {
        use std::fmt::Write;
        if self.false_positive_history.is_empty() {
            return String::new();
        }
        let mut out = String::from(
            "\n## Known false positives (do NOT re-report)\n\nThese findings were marked false positive in past runs and should not be reported again unless the underlying code has materially changed:\n\n",
        );
        let n = self.false_positive_history.len().min(max);
        for entry in self.false_positive_history.iter().rev().take(n) {
            let cat = entry.category.as_deref().unwrap_or("uncategorized");
            let note = entry
                .note
                .as_deref()
                .map_or(String::new(), |n| format!(" — {n}"));
            let _ = writeln!(out, "- \"{}\" ({cat}){note}", entry.title);
        }
        out
    }

    /// True when there's nothing worth persisting: no findings, no FP
    /// history, and we're at the default schema version. Used by
    /// `finalize_refinement` to avoid spamming `plans/` with empty
    /// `refine-state-*.json` files (§6.2).
    #[must_use]
    pub fn is_effectively_empty(&self) -> bool {
        self.findings.is_empty()
            && self.false_positive_history.is_empty()
            && self.schema_version == 0
    }

    /// Get active findings (excluding Fixed and `FalsePositive`).
    #[must_use]
    pub fn active_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| {
                !matches!(
                    f.status,
                    FindingStatus::Fixed | FindingStatus::FalsePositive
                )
            })
            .collect()
    }
}

/// Find the fingerprint entry whose `line_range` encloses the finding's
/// reported range. Findings often span just a few lines inside a function,
/// so we don't require strict equality — just containment.
fn enclosing_entry<'a>(
    map: &'a FingerprintMap,
    file: &Path,
    finding_range: Option<(u32, u32)>,
) -> Option<&'a FingerprintEntry> {
    let (find_start, find_end) = finding_range?;
    let entries = map.get(file)?;
    entries.iter().find(|e| {
        let (es, ee) = e.line_range;
        es <= find_start && find_end <= ee
    })
}

/// Derive state file path from plan path.
///
/// Each plan gets its own state file to prevent cross-contamination.
/// Given `.claude/plans/my-plan.md`, state goes to `.claude/refine-state/my-plan.json`.
fn state_path_from_plan(plan_path: &Path) -> PathBuf {
    let dir = plan_path.parent().unwrap_or(Path::new("."));
    let stem = plan_path
        .file_stem()
        .unwrap_or(std::ffi::OsStr::new("default"));

    // Check specifically for `.claude/plans/` — both components must match
    if dir.ends_with("plans") {
        if let Some(parent) = dir.parent() {
            if parent.ends_with(".claude") {
                return parent
                    .join("refine-state")
                    .join(stem)
                    .with_extension("json");
            }
        }
    }

    // If we're directly in .claude/, use it
    if dir.ends_with(".claude") {
        return dir.join("refine-state").join(stem).with_extension("json");
    }

    // Anchor to plan file's parent directory
    dir.join(format!("refine-state-{}.json", stem.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RedTeamId, Severity};

    fn make_finding(id: &str, file: &str, title: &str) -> Finding {
        Finding {
            id: id.to_string(),
            severity: Severity::Fatal,
            title: title.to_string(),
            sources: vec![RedTeamId::RtA],
            file_path: PathBuf::from(file),
            line_range: Some((10, 20)),
            problem: "problem".to_string(),
            attack_scenario: "attack".to_string(),
            suggested_fix: None,
            affected_plan_steps: Vec::new(),
            status: FindingStatus::New,
            impact_score: 100,
            fingerprint: None,
            symbol_path: None,
            auto_marked: None,
        }
    }

    #[test]
    fn merge_adds_new_findings() {
        let mut state = RefineState::default();
        let findings = vec![make_finding("F1", "a.php", "issue A")];
        state.merge_findings(findings, &FingerprintMap::new());
        assert_eq!(state.findings.len(), 1);
        assert_eq!(state.run_count, 1);
    }

    #[test]
    fn merge_updates_existing_new_findings() {
        let mut state = RefineState::default();
        state.merge_findings(vec![make_finding("F1", "a.php", "issue A")], &FingerprintMap::new());

        // Second run with same finding but updated
        let mut updated = make_finding("F1-new", "a.php", "issue A");
        updated.severity = Severity::High;
        updated.sources = vec![RedTeamId::RtB];
        state.merge_findings(vec![updated], &FingerprintMap::new());

        assert_eq!(state.findings.len(), 1);
        assert_eq!(state.findings[0].severity, Severity::High);
        assert_eq!(state.findings[0].sources.len(), 2); // merged
        assert_eq!(state.run_count, 2);
    }

    #[test]
    fn merge_preserves_fixed_status() {
        let mut state = RefineState::default();
        state.merge_findings(vec![make_finding("F1", "a.php", "issue A")], &FingerprintMap::new());

        // Mark as fixed
        state.findings[0].status = FindingStatus::Fixed;

        // New run with same finding
        let updated = make_finding("F1-new", "a.php", "issue A");
        state.merge_findings(vec![updated], &FingerprintMap::new());

        // Should NOT overwrite fixed status
        assert_eq!(state.findings[0].status, FindingStatus::Fixed);
        assert_eq!(state.findings.len(), 1);
    }

    #[test]
    fn active_findings_excludes_fixed() {
        let mut state = RefineState::default();
        state.merge_findings(vec![
            make_finding("F1", "a.php", "issue A"),
            make_finding("F2", "b.php", "issue B"),
        ], &FingerprintMap::new());

        state.findings[0].status = FindingStatus::Fixed;

        let active = state.active_findings();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].title, "issue B");
    }

    #[test]
    fn roundtrip_json() {
        let mut state = RefineState::default();
        state.merge_findings(vec![make_finding("F1", "a.php", "issue A")], &FingerprintMap::new());
        state.last_run = Some("2026-02-27".to_string());

        let json = serde_json::to_string(&state).unwrap();
        let loaded: RefineState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.run_count, 1);
        assert_eq!(loaded.last_run.as_deref(), Some("2026-02-27"));
    }

    #[test]
    fn load_from_nonexistent_returns_default() {
        let state =
            RefineState::load_from(Path::new("/tmp/refine_nonexistent_12345.json")).unwrap();
        assert_eq!(state.findings.len(), 0);
        assert_eq!(state.run_count, 0);
    }

    #[test]
    fn load_from_corrupted_returns_error() {
        let tmp = std::env::temp_dir().join("refine_test_corrupt.json");
        std::fs::write(&tmp, "NOT VALID JSON {{{").unwrap();
        let result = RefineState::load_from(&tmp);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("corrupted"));
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn save_to_atomic_roundtrip() {
        let tmp = std::env::temp_dir().join("refine_test_atomic.json");
        let mut state = RefineState::default();
        state.merge_findings(vec![make_finding("F1", "a.php", "issue A")], &FingerprintMap::new());
        state.save_to(&tmp).unwrap();

        let loaded = RefineState::load_from(&tmp).unwrap();
        assert_eq!(loaded.findings.len(), 1);
        // Verify no .tmp file remains
        assert!(!tmp.with_extension("json.tmp").exists());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn state_path_from_plan_in_claude_plans() {
        let path = state_path_from_plan(Path::new(".claude/plans/my-plan.md"));
        assert_eq!(path, PathBuf::from(".claude/refine-state/my-plan.json"));
    }

    #[test]
    fn state_path_from_plan_different_plans_get_different_state() {
        let path_a = state_path_from_plan(Path::new(".claude/plans/plan-a.md"));
        let path_b = state_path_from_plan(Path::new(".claude/plans/plan-b.md"));
        assert_ne!(path_a, path_b);
        assert_eq!(path_a, PathBuf::from(".claude/refine-state/plan-a.json"));
        assert_eq!(path_b, PathBuf::from(".claude/refine-state/plan-b.json"));
    }

    #[test]
    fn state_path_from_plan_in_arbitrary_dir() {
        let path = state_path_from_plan(Path::new("/tmp/my-project/plan.md"));
        assert_eq!(
            path,
            PathBuf::from("/tmp/my-project/refine-state-plan.json")
        );
    }

    fn fp_map(file: &str, entries: Vec<(&str, (u32, u32), &str)>) -> FingerprintMap {
        let mut m = FingerprintMap::new();
        m.insert(
            PathBuf::from(file),
            entries
                .into_iter()
                .map(|(sym, range, hash)| FingerprintEntry {
                    line_range: range,
                    symbol_path: sym.to_string(),
                    content_hash: hash.to_string(),
                })
                .collect(),
        );
        m
    }

    #[test]
    fn schema_version_starts_at_zero_and_bumps_to_two() {
        let mut state = RefineState::default();
        assert_eq!(state.schema_version, 0);
        state.merge_findings(vec![], &FingerprintMap::new());
        assert_eq!(state.schema_version, 1, "first run goes from 0 to 1");
        state.merge_findings(vec![], &FingerprintMap::new());
        assert_eq!(state.schema_version, 2, "second run reaches 2");
        state.merge_findings(vec![], &FingerprintMap::new());
        assert_eq!(state.schema_version, 2, "saturates at 2");
    }

    #[test]
    fn first_run_does_not_auto_mark_legacy_findings() {
        // Tier 2 §0.5 / RT-A2: legacy v0 state has no fingerprints; first
        // post-upgrade run must not interpret missing fingerprints as
        // "fixed". We simulate by injecting a finding with a fingerprint
        // that won't be in the map, but on a fresh state (schema_version=0).
        let mut state = RefineState::default();
        let mut f = make_finding("F1", "a.php", "issue A");
        f.fingerprint = Some("abc".to_string());
        state.findings.push(f);

        // First merge, current run computed nothing yet (empty map):
        state.merge_findings(vec![], &FingerprintMap::new());
        assert_eq!(
            state.findings[0].status,
            FindingStatus::New,
            "schema v0 → v1 must not auto-mark"
        );

        // Second merge with a non-empty map that does NOT contain the
        // finding's fingerprint — still must not auto-mark, schema is at 1
        // (one-run grace period). Use a different file so even the
        // is_empty() guard would let us through.
        let map = fp_map("a.php", vec![("foo", (10, 20), "different-hash")]);
        state.merge_findings(vec![], &map);
        assert_eq!(
            state.findings[0].status,
            FindingStatus::New,
            "schema v1 → v2 still in grace period"
        );

        // Third merge, schema_version is now 2 → auto-mark engages.
        state.merge_findings(vec![], &map);
        assert_eq!(
            state.findings[0].status,
            FindingStatus::Fixed,
            "schema v2 with non-empty map auto-marks"
        );
        assert!(state.findings[0].auto_marked.is_some());
    }

    #[test]
    fn empty_fingerprint_map_never_auto_marks_even_at_v2() {
        // Even if schema_version is at 2, an empty map must not trigger
        // auto-mark — extract_facts may have failed and we don't want to
        // resolve everything by mistake.
        let mut state = RefineState {
            schema_version: 2,
            ..RefineState::default()
        };
        let mut f = make_finding("F1", "a.php", "issue A");
        f.fingerprint = Some("abc".to_string());
        state.findings.push(f);

        state.merge_findings(vec![], &FingerprintMap::new());
        assert_eq!(state.findings[0].status, FindingStatus::New);
    }

    #[test]
    fn fingerprint_still_present_keeps_finding_new() {
        let mut state = RefineState {
            schema_version: 2,
            ..RefineState::default()
        };
        let mut f = make_finding("F1", "a.php", "issue A");
        f.fingerprint = Some("abc".to_string());
        state.findings.push(f);

        let map = fp_map("a.php", vec![("foo", (5, 25), "abc")]);
        state.merge_findings(vec![], &map);
        assert_eq!(state.findings[0].status, FindingStatus::New);
    }

    #[test]
    fn manual_status_update_persists_through_save_load() {
        // Simulates what the mark_finding MCP tool does: load → mutate
        // by id → save → reload, status survives the round trip.
        let tmp = std::env::temp_dir().join("refine_test_mark_finding.json");
        let _ = std::fs::remove_file(&tmp);

        let mut state = RefineState::default();
        state.merge_findings(
            vec![make_finding("F1", "a.php", "issue A")],
            &FingerprintMap::new(),
        );
        state.save_to(&tmp).unwrap();

        let mut loaded = RefineState::load_from(&tmp).unwrap();
        let target = loaded
            .findings
            .iter_mut()
            .find(|f| f.id == "F1")
            .expect("finding present");
        target.status = FindingStatus::FalsePositive;
        target.auto_marked = Some("not exploitable in this context".to_string());
        loaded.save_to(&tmp).unwrap();

        let reloaded = RefineState::load_from(&tmp).unwrap();
        assert_eq!(reloaded.findings[0].status, FindingStatus::FalsePositive);
        assert_eq!(
            reloaded.findings[0].auto_marked.as_deref(),
            Some("not exploitable in this context")
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn record_false_positive_is_idempotent() {
        let mut state = RefineState::default();
        let mut f = make_finding("F1", "a.php", "issue A");
        f.fingerprint = Some("hash".to_string());
        state.findings.push(f.clone());

        state.record_false_positive(&f, Some("not exploitable".into()));
        state.record_false_positive(&f, Some("not exploitable".into()));
        state.record_false_positive(&f, Some("different note".into()));
        // Same fingerprint+title is dedup'd regardless of note.
        assert_eq!(state.false_positive_history.len(), 1);
    }

    #[test]
    fn render_false_positive_hints_includes_recent_titles() {
        let mut state = RefineState::default();
        for i in 0..5 {
            let mut f = make_finding(
                &format!("F{i}"),
                "a.php",
                &format!("title {i}"),
            );
            f.fingerprint = Some(format!("hash-{i}"));
            state.record_false_positive(&f, None);
        }
        let hints = state.render_false_positive_hints(3);
        assert!(hints.contains("title 4"));
        assert!(hints.contains("title 3"));
        assert!(hints.contains("title 2"));
        assert!(!hints.contains("title 1"), "max=3 should skip older entries");
    }

    #[test]
    fn is_effectively_empty_recognises_fresh_state() {
        let state = RefineState::default();
        assert!(state.is_effectively_empty());
    }

    #[test]
    fn is_effectively_empty_false_when_history_present() {
        let mut state = RefineState::default();
        let mut f = make_finding("F1", "a.php", "issue A");
        f.fingerprint = Some("h".to_string());
        state.record_false_positive(&f, None);
        assert!(!state.is_effectively_empty());
    }

    #[test]
    fn new_findings_get_fingerprint_backfilled() {
        // Inserting a new finding inside a tracked function should pick up
        // the enclosing entry's fingerprint and symbol_path.
        let mut state = RefineState::default();
        let map = fp_map("a.php", vec![("doWork", (5, 30), "deadbeef")]);

        state.merge_findings(
            vec![make_finding("F1", "a.php", "issue A")], // line_range = (10,20) ⊂ (5,30)
            &map,
        );

        assert_eq!(state.findings[0].fingerprint.as_deref(), Some("deadbeef"));
        assert_eq!(state.findings[0].symbol_path.as_deref(), Some("doWork"));
    }
}
