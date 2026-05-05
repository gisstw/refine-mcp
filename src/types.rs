use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ─── Red Team Identity ───────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RedTeamId {
    /// Single-op: silent failure + type safety + idempotency
    RtA,
    /// Multi-op: concurrency + TOCTOU + behavioral changes
    RtB,
    /// Data integrity: schema drift + data loss + constraint violations
    RtC,
    /// Auth boundary: privilege escalation + access control + session hijack
    RtD,
    /// Blue team: cross-analysis and synthesis (not a red team role)
    BlueTeam,
}

// ─── Finding ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Fatal,
    High,
}

impl Severity {
    /// Numeric rank: higher = more severe (Fatal=2, High=1).
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Fatal => 2,
            Self::High => 1,
        }
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    #[default]
    New,
    Confirmed,
    Fixed,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub sources: Vec<RedTeamId>,
    pub file_path: PathBuf,
    pub line_range: Option<(u32, u32)>,
    pub problem: String,
    pub attack_scenario: String,
    pub suggested_fix: Option<String>,
    pub affected_plan_steps: Vec<String>,
    #[serde(default)]
    pub status: FindingStatus,
    /// Set by `dedup::dedup_findings()` — do not set manually at construction.
    #[serde(default)]
    pub impact_score: u32,
    /// AST `content_hash` covering the function this finding lives in. Set by
    /// `RefineState::merge_findings` from the run's current fingerprint map.
    /// Drives auto-mark-as-fixed across runs (§2.1).
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Symbol path for the same enclosing function, mirrored from the
    /// fingerprint entry for human-readable diagnostics.
    #[serde(default)]
    pub symbol_path: Option<String>,
    /// Why a finding's status was changed automatically (e.g. "fingerprint
    /// not found in latest run"). Empty when the user set the status
    /// manually.
    #[serde(default)]
    pub auto_marked: Option<String>,
}

impl Finding {
    /// Create a new finding with safe defaults (`status` = New, `impact_score` = 0).
    #[must_use]
    pub fn new(severity: Severity, title: String, source: RedTeamId, file_path: PathBuf) -> Self {
        Self {
            id: "RT-000".to_string(), // Placeholder — parser/dedup assigns final IDs
            severity,
            title,
            sources: vec![source],
            file_path,
            line_range: None,
            problem: String::new(),
            attack_scenario: String::new(),
            suggested_fix: None,
            affected_plan_steps: Vec::new(),
            status: FindingStatus::New,
            impact_score: 0,
            fingerprint: None,
            symbol_path: None,
            auto_marked: None,
        }
    }
}

// ─── Refine Mode ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RefineMode {
    /// 2 Opus red + 1 Opus blue
    #[default]
    Default,
    /// 2 Sonnet red + 1 Sonnet blue
    Lite,
    /// 2 Haiku red + 1 Sonnet blue
    Auto,
}

impl RefineMode {
    #[must_use]
    pub fn red_model(&self) -> &'static str {
        match self {
            Self::Default => "opus",
            Self::Lite => "sonnet",
            Self::Auto => "haiku",
        }
    }

    #[must_use]
    pub fn blue_model(&self) -> &'static str {
        match self {
            Self::Default => "opus",
            Self::Lite | Self::Auto => "sonnet",
        }
    }

    /// Default number of red teams for this mode.
    ///
    /// Can be overridden via `PrepareAttackParams::red_count`.
    #[must_use]
    pub fn red_count(&self) -> usize {
        match self {
            Self::Default | Self::Lite | Self::Auto => 2,
        }
    }
}

// ─── Prompt Output ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedTeamPrompt {
    pub id: RedTeamId,
    pub prompt: String,
    pub recommended_model: String,
}

// ─── Synthesis Output ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesisResult {
    pub findings: Vec<Finding>,
    pub blue_prompt: String,
    pub stats: SynthesisStats,
    pub refinement_draft: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesisStats {
    pub raw_count: usize,
    pub after_dedup: usize,
    pub after_validation: usize,
    pub fatal_count: usize,
    pub high_count: usize,
}
