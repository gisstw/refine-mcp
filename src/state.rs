use std::path::{Path, PathBuf};

use crate::types::{Finding, FindingStatus};

/// Default state file path relative to project root.
const DEFAULT_STATE_FILE: &str = ".claude/refine-state.json";

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
    /// Returns default (empty) state if file doesn't exist.
    #[must_use]
    pub fn load(plan_path: &Path) -> Self {
        let state_path = state_path_from_plan(plan_path);
        Self::load_from(&state_path)
    }

    /// Load state from a specific path.
    #[must_use]
    pub fn load_from(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save state to the default location relative to a plan path.
    pub fn save(&self, plan_path: &Path) -> anyhow::Result<()> {
        let state_path = state_path_from_plan(plan_path);
        self.save_to(&state_path)
    }

    /// Save state to a specific path.
    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
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
            .filter(|f| !matches!(f.status, FindingStatus::Fixed | FindingStatus::FalsePositive))
            .collect()
    }
}

/// Derive state file path from plan path.
///
/// Given `.claude/plans/my-plan.md`, state goes to `.claude/refine-state.json`.
fn state_path_from_plan(plan_path: &Path) -> PathBuf {
    // Walk up to find .claude/ directory
    let mut dir = plan_path.parent().unwrap_or(Path::new("."));

    // If we're in .claude/plans/, go up to .claude/
    if dir.ends_with("plans") {
        dir = dir.parent().unwrap_or(Path::new("."));
    }

    // If we're in .claude/, use it directly
    if dir.ends_with(".claude") {
        return dir.join("refine-state.json");
    }

    // Otherwise use default path from current directory
    PathBuf::from(DEFAULT_STATE_FILE)
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
    fn state_path_from_plan_in_claude_plans() {
        let path = state_path_from_plan(Path::new(".claude/plans/my-plan.md"));
        assert_eq!(path, PathBuf::from(".claude/refine-state.json"));
    }
}
