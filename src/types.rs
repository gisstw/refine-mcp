use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::facts::types::FunctionFact;

// ─── Structural Diff ────────────────────────────────────────

/// A function signature (name + params + return type) for comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionSignature {
    pub name: String,
    pub params: Vec<ParamSignature>,
    pub return_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParamSignature {
    pub name: String,
    pub type_hint: Option<String>,
    pub nullable: bool,
}

/// A change in a function's signature between two versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureChange {
    pub name: String,
    pub file: PathBuf,
    pub before: FunctionSignature,
    pub after: FunctionSignature,
    pub breaking: bool,
    pub reasons: Vec<String>,
}

/// Result of comparing two sets of `FunctionFact`s (before vs after).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StructuralDiff {
    pub file: PathBuf,
    pub added: Vec<FunctionSummary>,
    pub removed: Vec<FunctionSummary>,
    pub changed: Vec<SignatureChange>,
    pub unchanged_count: usize,
}

/// Lightweight summary of a function (for added/removed lists).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub name: String,
    pub line_range: (u32, u32),
    pub params: Vec<ParamSignature>,
    pub return_type: Option<String>,
}

/// Aggregated diff across multiple files.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StructuralDiffReport {
    pub files: Vec<StructuralDiff>,
    pub total_added: usize,
    pub total_removed: usize,
    pub total_changed: usize,
    pub breaking_changes: usize,
}

// ─── Health Snapshot ────────────────────────────────────────

/// Per-function health metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionHealth {
    pub name: String,
    pub file: PathBuf,
    pub line_range: (u32, u32),
    pub lines: u32,
    pub param_count: usize,
    pub max_nesting_depth: u32,
    pub branch_count: u32,
}

/// Health report for a set of files.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HealthReport {
    pub functions: Vec<FunctionHealth>,
    pub warnings: Vec<String>,
}

// ─── Conversion helpers ─────────────────────────────────────

impl FunctionSignature {
    /// Extract signature from a `FunctionFact`.
    #[must_use]
    pub fn from_fact(fact: &FunctionFact) -> Self {
        Self {
            name: fact.name.clone(),
            params: fact
                .parameters
                .iter()
                .map(|p| ParamSignature {
                    name: p.name.clone(),
                    type_hint: p.type_hint.clone(),
                    nullable: p.nullable,
                })
                .collect(),
            return_type: fact.return_type.clone(),
        }
    }
}

impl FunctionSummary {
    /// Extract summary from a `FunctionFact`.
    #[must_use]
    pub fn from_fact(fact: &FunctionFact) -> Self {
        Self {
            name: fact.name.clone(),
            line_range: fact.line_range,
            params: fact
                .parameters
                .iter()
                .map(|p| ParamSignature {
                    name: p.name.clone(),
                    type_hint: p.type_hint.clone(),
                    nullable: p.nullable,
                })
                .collect(),
            return_type: fact.return_type.clone(),
        }
    }
}
