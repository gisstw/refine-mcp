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
use refine_mcp::prompts::{build_blue_team_prompt, build_red_team_prompts};
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
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PrepareAttackParams {
    /// Path to the plan file
    pub plan_path: String,
    /// JSON-encoded fact tables from `extract_facts`
    pub facts_json: String,
    /// Refine mode: default, lite, or auto
    pub mode: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SynthesizeFindingsParams {
    /// Raw markdown reports from red team agents
    pub raw_reports: Vec<String>,
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
    #[tool(description = "Discover the most recently modified plan file in .claude/plans/ and extract referenced source file paths")]
    async fn discover_plan(
        &self,
        params: Parameters<DiscoverPlanParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let dir = params.0.plan_dir.unwrap_or_else(|| ".claude/plans".to_string());
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

    // ── Tool 2: extract_facts ──────────────────────────────────

    /// Extract structured facts from source files using tree-sitter.
    #[tool(description = "Extract structured facts from source files using tree-sitter analysis. Returns JSON fact tables.")]
    async fn extract_facts(
        &self,
        params: Parameters<ExtractFactsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut tables = Vec::new();
        let mut errors = Vec::new();

        for file_path_str in &params.0.file_paths {
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

        let output = serde_json::json!({
            "fact_tables": tables,
            "errors": errors,
            "file_count": tables.len(),
            "total_functions": tables.iter().map(|t| t.functions.len()).sum::<usize>(),
            "total_warnings": tables.iter().map(|t| t.warnings.len()).sum::<usize>(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }

    // ── Tool 3: prepare_attack ─────────────────────────────────

    /// Assemble red team prompts from plan content and fact tables.
    #[tool(description = "Prepare red team attack prompts from plan and extracted facts. Returns prompts with model recommendations.")]
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

        let prompts = build_red_team_prompts(mode, &plan_content, &fact_tables);

        let output = serde_json::json!({
            "prompts": prompts,
            "mode": format!("{mode:?}"),
            "red_count": prompts.len(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }

    // ── Tool 4: synthesize_findings ────────────────────────────

    /// Parse, validate, dedup, and rank red team findings.
    #[tool(description = "Synthesize red team reports: parse markdown, dedup, validate, rank, generate blue team prompt")]
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

        // Generate blue team prompt
        let blue_prompt = build_blue_team_prompt(mode, &deduped, &plan_summary);

        // Stats
        let fatal_count = deduped
            .iter()
            .filter(|f| f.severity == refine_mcp::types::Severity::Fatal)
            .count();
        let high_count = deduped.len() - fatal_count;

        let output = serde_json::json!({
            "findings": deduped,
            "blue_prompt": blue_prompt.prompt,
            "blue_model": blue_prompt.recommended_model,
            "stats": {
                "raw_reports": raw_count_total,
                "raw_findings": raw_finding_count,
                "after_dedup": deduped.len(),
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
    #[tool(description = "Backup plan and append refinement section with findings and blue team analysis")]
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

        // Read original plan
        let original = std::fs::read_to_string(&plan_path).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("Failed to read plan: {e}"), None)
        })?;

        // Create backup
        let backup_path = plan_path.with_extension("draft.md");
        std::fs::write(&backup_path, &original).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("Failed to create backup: {e}"), None)
        })?;

        // Generate refinement section
        let refinement = generate_refinement_section(&findings, &params.0.blue_result, mode);

        // Append to plan
        let mut updated = original;
        updated.push_str("\n\n");
        updated.push_str(&refinement);

        std::fs::write(&plan_path, &updated).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("Failed to write plan: {e}"), None)
        })?;

        let fatal_count = findings
            .iter()
            .filter(|f| f.severity == refine_mcp::types::Severity::Fatal)
            .count();

        let output = serde_json::json!({
            "plan_path": plan_path.to_string_lossy(),
            "backup_path": backup_path.to_string_lossy(),
            "findings_count": findings.len(),
            "fatal_count": fatal_count,
            "high_count": findings.len() - fatal_count,
            "mode": format!("{mode:?}"),
        });

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
    use std::sync::LazyLock;
    use regex::Regex;

    static RE_FILE_REF: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?:^|\s|`)((?:app|src|resources|routes|config|database|tests|public)/[^\s`\)]+\.\w+)")
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

    let now = chrono_date_now();

    let fatal_count = findings
        .iter()
        .filter(|f| f.severity == refine_mcp::types::Severity::Fatal)
        .count();
    let high_count = findings.len() - fatal_count;

    let mut out = String::with_capacity(2048);
    writeln!(out, "---").ok();
    writeln!(out, "## 🔴 Refinement（紅藍對抗精鍊）").ok();
    writeln!(
        out,
        "> Refined: {now} | Mode: {mode:?} | Agents: 2R+1B"
    )
    .ok();
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

/// Get current date as YYYY-MM-DD string (avoids chrono dependency).
fn chrono_date_now() -> String {
    // Use simple approach to avoid adding chrono just for a date
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Rough date calculation (good enough for display)
    let days = secs / 86400;
    let years = (days * 400) / 146_097; // Approximate
    let year = 1970 + years;
    let day_of_year = days - (years * 365 + years / 4 - years / 100 + years / 400);
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    let mut remaining = day_of_year;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        month += 1;
    }
    let day = remaining + 1;
    format!("{year:04}-{month:02}-{day:02}")
}

/// Validate that a path reference actually exists on disk.
#[allow(dead_code)]
fn validate_file_exists(file_path: &Path) -> bool {
    file_path.exists()
}
