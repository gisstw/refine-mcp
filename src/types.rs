use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ─── Red Team Identity ───────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RedTeamId {
    /// Single-op: silent failure + type safety + idempotency
    RtA,
    /// Multi-op: concurrency + TOCTOU + behavioral changes
    RtB,
}

// ─── Finding ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Fatal,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
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
    pub status: FindingStatus,
    pub impact_score: u32,
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

    #[must_use]
    pub fn red_count(&self) -> usize {
        2
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
