use std::path::{Path, PathBuf};

use rmcp::{
    ServerHandler,
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use refine_mcp::dedup::dedup_findings;
use refine_mcp::facts::types::FactTable;
use refine_mcp::parser::parse_red_team_output;
use refine_mcp::prompts::build_blue_team_prompt;
use refine_mcp::state::RefineState;
use refine_mcp::types::RefineMode;

// ─── Tool Parameter Structs ────────────────────────────────────

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct DiscoverPlanParams {
    /// Directory to search (default: .claude/plans/)
    pub plan_dir: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ExtractFactsParams {
    /// List of file paths to analyze
    pub file_paths: Vec<String>,
    /// If true, filter `file_paths` to only those changed in `git diff HEAD`
    pub diff_only: Option<bool>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PrepareAttackParams {
    /// Path to the plan file
    pub plan_path: String,
    /// JSON-encoded fact tables from `extract_facts`
    pub facts_json: String,
    /// Refine mode: default, lite, or auto
    pub mode: Option<String>,
    /// Number of red teams (2-4), or omit for auto-selection based on fact signals.
    /// Auto mode analyzes the fact tables and picks relevant red team roles.
    pub red_count: Option<u8>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SynthesizeFindingsParams {
    /// Raw markdown reports from red team agents
    pub raw_reports: Vec<String>,
    /// Path to plan file (for loading persistent state)
    pub plan_path: Option<String>,
    /// Brief plan summary for blue team context
    pub plan_summary: Option<String>,
    /// Refine mode for blue team model selection
    pub mode: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct FinalizeRefinementParams {
    /// Path to the plan file
    pub plan_path: String,
    /// Blue team cross-analysis result (markdown)
    pub blue_result: String,
    /// JSON-encoded findings from `synthesize_findings`
    pub findings_json: String,
    /// Refine mode used
    pub mode: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct DiscoverAndExtractParams {
    /// Directory to search for plan files (default: .claude/plans/)
    pub plan_dir: Option<String>,
    /// If true, only extract from files changed in `git diff HEAD` (incremental mode)
    pub diff_only: Option<bool>,
}

// ─── MCP Server ────────────────────────────────────────────────

/// MCP server for grounded red-blue adversarial plan refinement.
#[derive(Clone)]
pub struct RefineServer {
    tool_router: ToolRouter<Self>,
}

impl RefineServer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl RefineServer {
    // ── Tool 1: discover_plan ──────────────────────────────────

    /// Find the most recently modified plan file in the given directory.
    #[tool(
        description = "Discover the most recently modified plan file in .claude/plans/ and extract referenced source file paths"
    )]
    async fn discover_plan(
        &self,
        params: Parameters<DiscoverPlanParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let dir = params
            .0
            .plan_dir
            .unwrap_or_else(|| ".claude/plans".to_string());
        let dir_path = PathBuf::from(&dir);

        if !dir_path.is_dir() {
            return Err(rmcp::ErrorData::invalid_params(
                format!("Directory not found: {dir}"),
                None,
            ));
        }

        // Find the most recently modified .md file
        let mut latest: Option<(PathBuf, std::time::SystemTime)> = None;
        let entries = std::fs::read_dir(&dir_path).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("Failed to read directory: {e}"), None)
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "md") {
                if let Ok(meta) = path.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if latest.as_ref().is_none_or(|(_, t)| modified > *t) {
                            latest = Some((path, modified));
                        }
                    }
                }
            }
        }

        let Some((plan_path, _)) = latest else {
            return Err(rmcp::ErrorData::invalid_params(
                format!("No .md files found in {dir}"),
                None,
            ));
        };

        // Read plan and extract referenced file paths
        let plan_content = std::fs::read_to_string(&plan_path).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("Failed to read plan: {e}"), None)
        })?;
        let file_refs = extract_file_references(&plan_content);

        let result = serde_json::json!({
            "plan_path": plan_path.to_string_lossy(),
            "file_count": file_refs.len(),
            "files": file_refs,
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap_or_default(),
        )]))
    }

    // ── Tool 1b: discover_and_extract ──────────────────────────

    /// Discover plan + extract facts in a single step (saves 1 MCP round-trip).
    #[tool(
        description = "Discover the latest plan file, extract referenced source paths, and run tree-sitter fact extraction — all in one call"
    )]
    async fn discover_and_extract(
        &self,
        params: Parameters<DiscoverAndExtractParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let dir = params
            .0
            .plan_dir
            .unwrap_or_else(|| ".claude/plans".to_string());
        let diff_only = params.0.diff_only.unwrap_or(false);
        let dir_path = PathBuf::from(&dir);

        if !dir_path.is_dir() {
            return Err(rmcp::ErrorData::invalid_params(
                format!("Directory not found: {dir}"),
                None,
            ));
        }

        // ── Step 1: discover plan (same logic as discover_plan) ──
        let mut latest: Option<(PathBuf, std::time::SystemTime)> = None;
        let entries = std::fs::read_dir(&dir_path).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("Failed to read directory: {e}"), None)
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "md") {
                if let Ok(meta) = path.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if latest.as_ref().is_none_or(|(_, t)| modified > *t) {
                            latest = Some((path, modified));
                        }
                    }
                }
            }
        }

        let Some((plan_path, _)) = latest else {
            return Err(rmcp::ErrorData::invalid_params(
                format!("No .md files found in {dir}"),
                None,
            ));
        };

        let plan_content = std::fs::read_to_string(&plan_path).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("Failed to read plan: {e}"), None)
        })?;
        let mut file_refs = extract_file_references(&plan_content);

        // ── Step 1b: if diff_only, intersect with git changed files ──
        if diff_only {
            let changed = git_changed_files();
            if !changed.is_empty() {
                file_refs.retain(|f| changed.iter().any(|c| f.ends_with(c) || c.ends_with(f)));
            }
        }

        // ── Step 2: extract facts from referenced files ──
        let mut tables = Vec::new();
        let mut errors = Vec::new();

        for file_path_str in &file_refs {
            let path = PathBuf::from(file_path_str);
            if !path.exists() {
                errors.push(format!("File not found: {file_path_str}"));
                continue;
            }
            let source = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    errors.push(format!("Failed to read {file_path_str}: {e}"));
                    continue;
                }
            };
            let result = match path.extension().and_then(|e| e.to_str()) {
                Some("php") => refine_mcp::facts::php::extract_php_facts(&path, &source),
                Some("rs") => refine_mcp::facts::rust_lang::extract_rust_facts(&path, &source),
                Some("ts" | "tsx" | "js" | "jsx") => {
                    refine_mcp::facts::typescript::extract_ts_facts(&path, &source)
                }
                Some("py") => refine_mcp::facts::python::extract_python_facts(&path, &source),
                Some(ext) => {
                    errors.push(format!("Unsupported language: .{ext} ({file_path_str})"));
                    continue;
                }
                None => {
                    errors.push(format!("No file extension: {file_path_str}"));
                    continue;
                }
            };
            match result {
                Ok(table) => tables.push(table),
                Err(e) => errors.push(format!("Parse error for {file_path_str}: {e}")),
            }
        }

        if tables.is_empty() && !errors.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "All {} referenced files failed extraction: {}",
                    errors.len(),
                    errors.join("; ")
                ),
                None,
            ));
        }

        let output = serde_json::json!({
            "plan_path": plan_path.to_string_lossy(),
            "plan_content": plan_content,
            "referenced_files": file_refs,
            "fact_tables": tables,
            "errors": errors,
            "file_count": tables.len(),
            "total_functions": tables.iter().map(|t| t.functions.len()).sum::<usize>(),
            "total_warnings": tables.iter().map(|t| t.warnings.len()).sum::<usize>(),
            "diff_only": diff_only,
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }

    // ── Tool 2: extract_facts ──────────────────────────────────

    /// Extract structured facts from source files using tree-sitter.
    #[tool(
        description = "Extract structured facts from source files using tree-sitter analysis. Returns JSON fact tables."
    )]
    async fn extract_facts(
        &self,
        params: Parameters<ExtractFactsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let diff_only = params.0.diff_only.unwrap_or(false);
        let mut file_paths = params.0.file_paths;

        // Filter to git-changed files if requested
        if diff_only {
            let changed = git_changed_files();
            if !changed.is_empty() {
                file_paths.retain(|f| changed.iter().any(|c| f.ends_with(c) || c.ends_with(f)));
            }
        }

        let mut tables = Vec::new();
        let mut errors = Vec::new();

        for file_path_str in &file_paths {
            let path = PathBuf::from(file_path_str);

            if !path.exists() {
                errors.push(format!("File not found: {file_path_str}"));
                continue;
            }

            let source = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    errors.push(format!("Failed to read {file_path_str}: {e}"));
                    continue;
                }
            };

            let result = match path.extension().and_then(|e| e.to_str()) {
                Some("php") => refine_mcp::facts::php::extract_php_facts(&path, &source),
                Some("rs") => refine_mcp::facts::rust_lang::extract_rust_facts(&path, &source),
                Some("ts" | "tsx" | "js" | "jsx") => {
                    refine_mcp::facts::typescript::extract_ts_facts(&path, &source)
                }
                Some("py") => refine_mcp::facts::python::extract_python_facts(&path, &source),
                Some(ext) => {
                    errors.push(format!("Unsupported language: .{ext} ({file_path_str})"));
                    continue;
                }
                None => {
                    errors.push(format!("No file extension: {file_path_str}"));
                    continue;
                }
            };

            match result {
                Ok(table) => tables.push(table),
                Err(e) => errors.push(format!("Parse error for {file_path_str}: {e}")),
            }
        }

        // Step 2.3: Return error if ALL files failed extraction
        if tables.is_empty() && !errors.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "All {} files failed extraction: {}",
                    errors.len(),
                    errors.join("; ")
                ),
                None,
            ));
        }

        let output = serde_json::json!({
            "fact_tables": tables,
            "errors": errors,
            "file_count": tables.len(),
            "total_functions": tables.iter().map(|t| t.functions.len()).sum::<usize>(),
            "total_warnings": tables.iter().map(|t| t.warnings.len()).sum::<usize>(),
            "diff_only": diff_only,
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }

    // ── Tool 3: prepare_attack ─────────────────────────────────

    /// Assemble red team prompts from plan content and fact tables.
    #[tool(
        description = "Prepare red team attack prompts from plan and extracted facts. Returns prompts with model recommendations."
    )]
    async fn prepare_attack(
        &self,
        params: Parameters<PrepareAttackParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mode = parse_mode(params.0.mode.as_deref())?;

        // Read plan content
        let plan_content = std::fs::read_to_string(&params.0.plan_path).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("Failed to read plan: {e}"), None)
        })?;

        // Parse fact tables
        let fact_tables: Vec<FactTable> =
            serde_json::from_str(&params.0.facts_json).map_err(|e| {
                rmcp::ErrorData::invalid_params(format!("Invalid facts_json: {e}"), None)
            })?;

        let prompts = if let Some(n) = params.0.red_count {
            // Explicit count: use fixed N teams (RT-A..RT-D in order)
            refine_mcp::prompts::build_red_team_prompts_n(
                mode,
                &plan_content,
                &fact_tables,
                n as usize,
            )
        } else {
            // Auto-select: pick relevant teams based on fact signals
            let teams = refine_mcp::prompts::auto_select_red_teams(&fact_tables);
            refine_mcp::prompts::build_red_team_prompts_selected(
                mode,
                &plan_content,
                &fact_tables,
                &teams,
            )
        };

        let team_ids: Vec<String> = prompts.iter().map(|p| format!("{:?}", p.id)).collect();
        let output = serde_json::json!({
            "prompts": prompts,
            "mode": format!("{mode:?}"),
            "red_count": prompts.len(),
            "teams": team_ids,
            "auto_selected": params.0.red_count.is_none(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }

    // ── Tool 4: synthesize_findings ────────────────────────────

    /// Parse, validate, dedup, and rank red team findings.
    #[tool(
        description = "Synthesize red team reports: parse markdown, dedup, validate, rank, merge with persistent state, generate blue team prompt"
    )]
    async fn synthesize_findings(
        &self,
        params: Parameters<SynthesizeFindingsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mode = parse_mode(params.0.mode.as_deref())?;
        let plan_summary = params.0.plan_summary.unwrap_or_default();

        // Parse all raw reports
        let mut all_findings = Vec::new();
        let mut parse_errors = Vec::new();
        let raw_count_total: usize = params.0.raw_reports.len();

        for (i, report) in params.0.raw_reports.iter().enumerate() {
            match parse_red_team_output(report) {
                Ok(findings) => all_findings.extend(findings),
                Err(e) => parse_errors.push(format!("Report {}: {e}", i + 1)),
            }
        }

        let raw_finding_count = all_findings.len();

        // Dedup and score
        let deduped = dedup_findings(all_findings);

        // Load persistent state and merge if plan_path provided
        let plan_path = params.0.plan_path.as_deref().map(Path::new);
        let mut state = match plan_path {
            Some(pp) => RefineState::load(pp).unwrap_or_else(|e| {
                parse_errors.push(format!("State load warning: {e}"));
                RefineState::default()
            }),
            None => RefineState::default(),
        };
        state.merge_findings(deduped.clone());
        state.last_run = Some(date_today());

        // Use active findings (excludes Fixed/FalsePositive) for blue prompt
        let active: Vec<refine_mcp::types::Finding> =
            state.active_findings().into_iter().cloned().collect();

        // Generate blue team prompt from active findings only
        let blue_prompt = build_blue_team_prompt(mode, &active, &plan_summary);

        // Stats
        let fatal_count = active
            .iter()
            .filter(|f| f.severity == refine_mcp::types::Severity::Fatal)
            .count();
        let high_count = active.len() - fatal_count;

        // Save state (best-effort, don't fail the tool)
        if let Some(pp) = plan_path {
            if let Err(e) = state.save(pp) {
                parse_errors.push(format!("State save warning: {e}"));
            }
        }

        let output = serde_json::json!({
            "findings": active,
            "blue_prompt": blue_prompt.prompt,
            "blue_model": blue_prompt.recommended_model,
            "stats": {
                "raw_reports": raw_count_total,
                "raw_findings": raw_finding_count,
                "after_dedup": deduped.len(),
                "active_findings": active.len(),
                "total_state_findings": state.findings.len(),
                "run_count": state.run_count,
                "fatal_count": fatal_count,
                "high_count": high_count,
            },
            "parse_errors": parse_errors,
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }

    // ── Tool 5: finalize_refinement ────────────────────────────

    /// Write refinement section to plan file.
    #[tool(
        description = "Backup plan and append refinement section with findings and blue team analysis"
    )]
    async fn finalize_refinement(
        &self,
        params: Parameters<FinalizeRefinementParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let plan_path = PathBuf::from(&params.0.plan_path);
        let mode = parse_mode(params.0.mode.as_deref())?;

        // Parse findings
        let findings: Vec<refine_mcp::types::Finding> =
            serde_json::from_str(&params.0.findings_json).map_err(|e| {
                rmcp::ErrorData::invalid_params(format!("Invalid findings_json: {e}"), None)
            })?;

        // Read original plan for backup
        let original = std::fs::read_to_string(&plan_path).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("Failed to read plan: {e}"), None)
        })?;

        // Create backup (snapshot before our append)
        let backup_path = plan_path.with_extension("draft.md");
        std::fs::write(&backup_path, &original).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("Failed to create backup: {e}"), None)
        })?;

        // Generate refinement section
        let refinement = generate_refinement_section(&findings, &params.0.blue_result, mode);

        // Append to plan (O_APPEND is atomic on POSIX — no TOCTOU)
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&plan_path)
                .map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("Failed to open plan for append: {e}"),
                        None,
                    )
                })?;
            write!(file, "\n\n{refinement}").map_err(|e| {
                rmcp::ErrorData::internal_error(format!("Failed to append to plan: {e}"), None)
            })?;
        }

        // Update state metadata (NO merge — synthesize_findings already merged)
        let mut state = RefineState::load(&plan_path).unwrap_or_else(|e| {
            tracing::warn!("Failed to load state in finalize: {e}");
            RefineState::default()
        });
        state.last_run = Some(date_today());
        let state_warning = state.save(&plan_path).err().map(|e| e.to_string());

        let fatal_count = findings
            .iter()
            .filter(|f| f.severity == refine_mcp::types::Severity::Fatal)
            .count();

        let mut output = serde_json::json!({
            "plan_path": plan_path.to_string_lossy(),
            "backup_path": backup_path.to_string_lossy(),
            "findings_count": findings.len(),
            "fatal_count": fatal_count,
            "high_count": findings.len() - fatal_count,
            "mode": format!("{mode:?}"),
            "state_run_count": state.run_count,
        });
        if let Some(warn) = state_warning {
            output["state_warning"] = serde_json::Value::String(warn);
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for RefineServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Grounded red-blue adversarial plan refinement. \
                 Uses tree-sitter to extract structured facts from source code, \
                 then provides focused prompts for LLM red team analysis."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ─── Helper Functions ──────────────────────────────────────────

fn parse_mode(mode_str: Option<&str>) -> Result<RefineMode, rmcp::ErrorData> {
    match mode_str {
        None | Some("default") => Ok(RefineMode::Default),
        Some("lite") => Ok(RefineMode::Lite),
        Some("auto") => Ok(RefineMode::Auto),
        Some(other) => Err(rmcp::ErrorData::invalid_params(
            format!("Invalid mode: {other}. Use: default, lite, or auto"),
            None,
        )),
    }
}

/// Extract file paths referenced in a plan markdown document.
fn extract_file_references(content: &str) -> Vec<String> {
    use regex::Regex;
    use std::sync::LazyLock;

    static RE_FILE_REF: LazyLock<Regex> = LazyLock::new(|| {
        // Match relative paths (app/..., src/...) and absolute paths (/home/..., /var/...)
        Regex::new(r"(?:^|\s|`)((?:(?:app|src|resources|routes|config|database|tests|public)/|/[\w.]+/)[^\s`\)]+\.\w+)")
            .expect("valid regex")
    });

    let mut files: Vec<String> = RE_FILE_REF
        .captures_iter(content)
        .map(|cap| cap[1].to_string())
        .collect();

    files.sort();
    files.dedup();
    files
}

/// Generate the refinement section markdown.
fn generate_refinement_section(
    findings: &[refine_mcp::types::Finding],
    blue_result: &str,
    mode: RefineMode,
) -> String {
    use std::fmt::Write;

    let now = date_today();

    let fatal_count = findings
        .iter()
        .filter(|f| f.severity == refine_mcp::types::Severity::Fatal)
        .count();
    let high_count = findings.len() - fatal_count;

    let mut out = String::with_capacity(2048);
    writeln!(out, "---").ok();
    writeln!(out, "## 🔴 Refinement（紅藍對抗精鍊）").ok();
    writeln!(out, "> Refined: {now} | Mode: {mode:?} | Agents: 2R+1B").ok();
    writeln!(out).ok();
    writeln!(out, "### 發現摘要").ok();
    writeln!(out, "- FATAL: {fatal_count} 個").ok();
    writeln!(out, "- HIGH: {high_count} 個").ok();
    writeln!(out).ok();

    // FATAL findings
    if fatal_count > 0 {
        writeln!(out, "### FATAL 問題").ok();
        let mut idx = 1;
        for f in findings {
            if f.severity != refine_mcp::types::Severity::Fatal {
                continue;
            }
            write_finding(&mut out, f, idx);
            idx += 1;
        }
        writeln!(out).ok();
    }

    // HIGH findings
    if high_count > 0 {
        writeln!(out, "### HIGH 問題").ok();
        let mut idx = 1;
        for f in findings {
            if f.severity != refine_mcp::types::Severity::High {
                continue;
            }
            write_finding(&mut out, f, idx);
            idx += 1;
        }
        writeln!(out).ok();
    }

    // Blue team analysis
    if !blue_result.trim().is_empty() {
        writeln!(out, "### 交叉分析（藍隊）").ok();
        writeln!(out).ok();
        writeln!(out, "{blue_result}").ok();
        writeln!(out).ok();
    }

    out
}

fn write_finding(out: &mut String, f: &refine_mcp::types::Finding, idx: usize) {
    use std::fmt::Write;

    let location = match f.line_range {
        Some((start, end)) if start == end => {
            format!("{}:{start}", f.file_path.display())
        }
        Some((start, end)) => format!("{}:{start}-{end}", f.file_path.display()),
        None => f.file_path.display().to_string(),
    };

    let sources: Vec<&str> = f
        .sources
        .iter()
        .map(|s| match s {
            refine_mcp::types::RedTeamId::RtA => "RT-A",
            refine_mcp::types::RedTeamId::RtB => "RT-B",
            refine_mcp::types::RedTeamId::RtC => "RT-C",
            refine_mcp::types::RedTeamId::RtD => "RT-D",
        })
        .collect();

    writeln!(out, "{idx}. **{}** ({location})", f.title).ok();
    writeln!(out, "   - 來源：{}", sources.join(", ")).ok();
    writeln!(out, "   - 問題：{}", f.problem).ok();
    writeln!(out, "   - 攻擊場景：{}", f.attack_scenario).ok();
    if let Some(fix) = &f.suggested_fix {
        writeln!(out, "   - 建議修復：{fix}").ok();
    }
}

/// Get files changed relative to HEAD via `git diff`.
///
/// Returns an empty vec on any failure (no git, not a repo, etc.).
fn git_changed_files() -> Vec<String> {
    std::process::Command::new("git")
        .args(["diff", "--name-only", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Get current date as YYYY-MM-DD string.
fn date_today() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        now.month() as u8,
        now.day()
    )
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use refine_mcp::types::{Finding, FindingStatus, RedTeamId, Severity};

    // ── parse_mode ──

    #[test]
    fn parse_mode_default_variants() {
        assert_eq!(parse_mode(None).unwrap(), RefineMode::Default);
        assert_eq!(parse_mode(Some("default")).unwrap(), RefineMode::Default);
        assert_eq!(parse_mode(Some("lite")).unwrap(), RefineMode::Lite);
        assert_eq!(parse_mode(Some("auto")).unwrap(), RefineMode::Auto);
    }

    #[test]
    fn parse_mode_invalid_returns_error() {
        let err = parse_mode(Some("turbo")).unwrap_err();
        assert!(err.message.contains("turbo"));
    }

    // ── extract_file_references ──

    #[test]
    fn extracts_relative_paths() {
        let content = "Modify `app/Services/BillingService.php` and `src/main.rs` here.";
        let refs = extract_file_references(content);
        assert_eq!(
            refs,
            vec!["app/Services/BillingService.php", "src/main.rs",]
        );
    }

    #[test]
    fn extracts_absolute_paths() {
        let content = "Source: `/home/www/project/src/main.rs` is the entry.";
        let refs = extract_file_references(content);
        assert!(
            refs.iter()
                .any(|r| r.contains("home/www/project/src/main.rs"))
        );
    }

    #[test]
    fn deduplicates_and_sorts() {
        let content = "app/A.php and app/B.php and app/A.php again";
        let refs = extract_file_references(content);
        assert_eq!(refs, vec!["app/A.php", "app/B.php"]);
    }

    #[test]
    fn ignores_non_file_paths() {
        let content = "This is plain text with no file references at all.";
        let refs = extract_file_references(content);
        assert!(refs.is_empty());
    }

    // ── date_today ──

    #[test]
    fn date_today_format() {
        let d = date_today();
        // Should match YYYY-MM-DD
        assert_eq!(d.len(), 10);
        assert_eq!(&d[4..5], "-");
        assert_eq!(&d[7..8], "-");
        let year: u32 = d[..4].parse().unwrap();
        assert!(year >= 2026);
    }

    // ── generate_refinement_section ──

    fn make_finding(severity: Severity, title: &str) -> Finding {
        Finding {
            id: "T-001".to_string(),
            severity,
            title: title.to_string(),
            sources: vec![RedTeamId::RtA],
            file_path: PathBuf::from("app/Services/Svc.php"),
            line_range: Some((10, 20)),
            problem: "test problem".to_string(),
            attack_scenario: "test attack".to_string(),
            suggested_fix: None,
            affected_plan_steps: Vec::new(),
            status: FindingStatus::New,
            impact_score: 100,
        }
    }

    #[test]
    fn refinement_section_contains_header() {
        let findings = vec![make_finding(Severity::Fatal, "bug A")];
        let section = generate_refinement_section(&findings, "", RefineMode::Default);
        assert!(section.contains("## 🔴 Refinement"));
        assert!(section.contains("Mode: Default"));
        assert!(section.contains("FATAL: 1"));
        assert!(section.contains("HIGH: 0"));
    }

    #[test]
    fn refinement_section_lists_findings() {
        let findings = vec![
            make_finding(Severity::Fatal, "fatal bug"),
            make_finding(Severity::High, "high issue"),
        ];
        let section = generate_refinement_section(&findings, "", RefineMode::Lite);
        assert!(section.contains("**fatal bug**"));
        assert!(section.contains("**high issue**"));
        assert!(section.contains("### FATAL 問題"));
        assert!(section.contains("### HIGH 問題"));
    }

    #[test]
    fn refinement_section_includes_blue_result() {
        let section =
            generate_refinement_section(&[], "Blue team found combo attack", RefineMode::Auto);
        assert!(section.contains("### 交叉分析（藍隊）"));
        assert!(section.contains("Blue team found combo attack"));
    }

    #[test]
    fn refinement_section_empty_blue_skipped() {
        let section = generate_refinement_section(&[], "", RefineMode::Auto);
        assert!(!section.contains("交叉分析"));
    }

    // ── write_finding ──

    #[test]
    fn write_finding_format() {
        let mut f = make_finding(Severity::Fatal, "test title");
        f.suggested_fix = Some("fix it".to_string());
        f.sources = vec![RedTeamId::RtA, RedTeamId::RtB];

        let mut out = String::new();
        write_finding(&mut out, &f, 1);

        assert!(out.contains("1. **test title**"));
        assert!(out.contains("app/Services/Svc.php:10-20"));
        assert!(out.contains("RT-A, RT-B"));
        assert!(out.contains("建議修復：fix it"));
    }

    #[test]
    fn write_finding_no_line_range() {
        let mut f = make_finding(Severity::High, "no lines");
        f.line_range = None;

        let mut out = String::new();
        write_finding(&mut out, &f, 3);

        assert!(out.contains("3. **no lines** (app/Services/Svc.php)"));
    }

    #[test]
    fn write_finding_same_start_end_line() {
        let mut f = make_finding(Severity::High, "single line");
        f.line_range = Some((42, 42));

        let mut out = String::new();
        write_finding(&mut out, &f, 1);

        assert!(out.contains("app/Services/Svc.php:42)"));
        assert!(!out.contains("42-42"));
    }
}
