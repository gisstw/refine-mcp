use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::types::{Finding, FindingStatus};

/// Persistent state across refine runs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct RefineState {
    pub findings: Vec<Finding>,
    pub run_count: u32,
    pub last_run: Option<String>,
}

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
    /// - New findings are added
    /// - Existing findings with matching `(file_path, line_range)` are updated
    /// - Findings marked `Fixed` or `FalsePositive` are preserved but excluded from active set
    pub fn merge_findings(&mut self, new_findings: Vec<Finding>) {
        for new in new_findings {
            let existing = self.findings.iter_mut().find(|f| {
                f.file_path == new.file_path
                    && f.line_range == new.line_range
                    && f.title == new.title
            });

            if let Some(existing) = existing {
                // Don't overwrite user-set statuses
                if existing.status == FindingStatus::New {
                    existing.severity = new.severity;
                    existing.problem.clone_from(&new.problem);
                    existing.attack_scenario.clone_from(&new.attack_scenario);
                    existing.suggested_fix.clone_from(&new.suggested_fix);
                    existing.impact_score = new.impact_score;

                    // Merge sources
                    for src in &new.sources {
                        if !existing.sources.contains(src) {
                            existing.sources.push(*src);
                        }
                    }
                }
            } else {
                self.findings.push(new);
            }
        }
        self.run_count += 1;
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
        }
    }

    #[test]
    fn merge_adds_new_findings() {
        let mut state = RefineState::default();
        let findings = vec![make_finding("F1", "a.php", "issue A")];
        state.merge_findings(findings);
        assert_eq!(state.findings.len(), 1);
        assert_eq!(state.run_count, 1);
    }

    #[test]
    fn merge_updates_existing_new_findings() {
        let mut state = RefineState::default();
        state.merge_findings(vec![make_finding("F1", "a.php", "issue A")]);

        // Second run with same finding but updated
        let mut updated = make_finding("F1-new", "a.php", "issue A");
        updated.severity = Severity::High;
        updated.sources = vec![RedTeamId::RtB];
        state.merge_findings(vec![updated]);

        assert_eq!(state.findings.len(), 1);
        assert_eq!(state.findings[0].severity, Severity::High);
        assert_eq!(state.findings[0].sources.len(), 2); // merged
        assert_eq!(state.run_count, 2);
    }

    #[test]
    fn merge_preserves_fixed_status() {
        let mut state = RefineState::default();
        state.merge_findings(vec![make_finding("F1", "a.php", "issue A")]);

        // Mark as fixed
        state.findings[0].status = FindingStatus::Fixed;

        // New run with same finding
        let updated = make_finding("F1-new", "a.php", "issue A");
        state.merge_findings(vec![updated]);

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
        ]);

        state.findings[0].status = FindingStatus::Fixed;

        let active = state.active_findings();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].title, "issue B");
    }

    #[test]
    fn roundtrip_json() {
        let mut state = RefineState::default();
        state.merge_findings(vec![make_finding("F1", "a.php", "issue A")]);
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
        state.merge_findings(vec![make_finding("F1", "a.php", "issue A")]);
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
}
