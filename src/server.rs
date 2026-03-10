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
    /// JSON-encoded fact tables from `extract_facts`.
    /// Either provide this OR `facts_file` (path to a JSON file containing the fact tables).
    pub facts_json: Option<String>,
    /// Path to a JSON file containing fact tables (alternative to `facts_json`).
    /// Useful when output exceeds inline size limits.
    pub facts_file: Option<String>,
    /// Refine mode: default, lite, or auto
    pub mode: Option<String>,
    /// Number of red teams (2-4), or omit for auto-selection based on fact signals.
    /// Auto mode analyzes the fact tables and picks relevant red team roles.
    pub red_count: Option<u8>,
    /// JSON-encoded `SchemaSnapshot` from `extract_migration_facts` (optional)
    pub schema_json: Option<String>,
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
    /// JSON array of Finding objects (from `synthesize_findings` output, or manually constructed).
    /// See tool description for required fields and example.
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

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ExpandBlastRadiusParams {
    /// Function/method names to search for callers.
    /// If empty or omitted, auto-detects from git diff of plan files.
    pub symbols: Option<Vec<String>>,
    /// Directories to search (default: `["app/", "routes/"]`)
    pub search_paths: Option<Vec<String>>,
    /// Files to exclude from results (typically the source files being modified)
    pub exclude_files: Option<Vec<String>>,
    /// Plan file paths (used for auto-detecting changed symbols via git diff)
    pub plan_files: Option<Vec<String>>,
    /// Max grep results per symbol (default: 20)
    pub max_per_symbol: Option<usize>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ExtractMigrationFactsParams {
    /// Path to migration directory (default: database/migrations)
    pub migration_dir: Option<String>,
    /// Only include tables matching these names (default: all)
    pub table_filter: Option<Vec<String>>,
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
        let dir_path = validate_dir(&dir)?;

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
        let dir_path = validate_dir(&dir)?;

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
                file_refs.retain(|f| {
                    let fp = Path::new(f);
                    changed
                        .iter()
                        .any(|c| fp.ends_with(c) || Path::new(c).ends_with(f))
                });
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
        let mut file_paths = Vec::with_capacity(params.0.file_paths.len());
        for fp in &params.0.file_paths {
            validate_path(fp)?;
            file_paths.push(fp.clone());
        }

        // Filter to git-changed files if requested
        if diff_only {
            let changed = git_changed_files();
            if !changed.is_empty() {
                file_paths.retain(|f| {
                    let fp = Path::new(f);
                    changed
                        .iter()
                        .any(|c| fp.ends_with(c) || Path::new(c).ends_with(f))
                });
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
        let plan_path = validate_path(&params.0.plan_path)?;

        // Read plan content
        let plan_content = std::fs::read_to_string(&plan_path).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("Failed to read plan: {e}"), None)
        })?;

        // Parse fact tables from JSON string or file
        let facts_str = match (&params.0.facts_json, &params.0.facts_file) {
            (Some(json), _) => json.clone(),
            (None, Some(file_path)) => {
                // Read from file — handles Claude Code's oversized output files
                std::fs::read_to_string(file_path).map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        format!("Failed to read facts_file '{file_path}': {e}"),
                        None,
                    )
                })?
            }
            (None, None) => {
                return Err(rmcp::ErrorData::invalid_params(
                    "Either facts_json or facts_file must be provided".to_string(),
                    None,
                ));
            }
        };

        // If facts_file was a Claude Code tool-results JSON wrapper, unwrap it
        let facts_json_str = if facts_str.trim_start().starts_with('[') {
            // Could be either raw fact tables array or Claude Code wrapper [{type, text}]
            if let Ok(wrapper) = serde_json::from_str::<Vec<serde_json::Value>>(&facts_str) {
                if let Some(first) = wrapper.first() {
                    if first.get("type").and_then(|t| t.as_str()) == Some("text") {
                        // Claude Code wrapper format — extract the text field
                        first
                            .get("text")
                            .and_then(|t| t.as_str())
                            .unwrap_or(&facts_str)
                            .to_string()
                    } else {
                        facts_str
                    }
                } else {
                    facts_str
                }
            } else {
                facts_str
            }
        } else {
            facts_str
        };

        // Parse the inner JSON to extract fact_tables array
        let fact_tables: Vec<FactTable> =
            if let Ok(outer) = serde_json::from_str::<serde_json::Value>(&facts_json_str) {
                if let Some(ft) = outer.get("fact_tables") {
                    // discover_and_extract output format: {fact_tables: [...], plan_path: ...}
                    serde_json::from_value(ft.clone()).map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("Invalid fact_tables in response: {e}"),
                            None,
                        )
                    })?
                } else {
                    // Direct array of FactTable
                    serde_json::from_value(outer).map_err(|e| {
                        rmcp::ErrorData::invalid_params(format!("Invalid facts_json: {e}"), None)
                    })?
                }
            } else {
                return Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "Invalid JSON in facts: {}",
                        &facts_json_str[..facts_json_str.len().min(200)]
                    ),
                    None,
                ));
            };

        // ── Function-level filtering (v5.1) ──────────────────────
        // Only keep functions relevant to the plan to reduce prompt noise.
        let plan_mentioned = extract_plan_functions(&plan_content);
        let original_fn_count: usize = fact_tables.iter().map(|t| t.functions.len()).sum();

        let (fact_tables, filter_stats) = if plan_mentioned.is_empty() || original_fn_count == 0 {
            // No function names extracted or no functions — skip filtering
            (fact_tables, None)
        } else {
            // Collect callees of plan-mentioned functions (from external_calls.target)
            let plan_callees: std::collections::HashSet<String> = fact_tables
                .iter()
                .flat_map(|t| t.functions.iter())
                .filter(|f| plan_mentioned.contains(&f.name))
                .flat_map(|f| f.external_calls.iter())
                .filter_map(|ec| {
                    // target looks like "$this->fooService->barMethod" or "SomeClass::method"
                    let name = ec
                        .target
                        .rsplit("::")
                        .next()
                        .or_else(|| ec.target.rsplit("->").next())
                        .unwrap_or(&ec.target);
                    let clean = name.trim_end_matches('(').trim();
                    if clean.len() >= 3 {
                        Some(clean.to_string())
                    } else {
                        None
                    }
                })
                .collect();

            // Mutation targets from plan-mentioned + callee functions
            let relevant_fns: std::collections::HashSet<&str> = plan_mentioned
                .iter()
                .chain(plan_callees.iter())
                .map(|s| s.as_str())
                .collect();

            let plan_mutation_targets: std::collections::HashSet<String> = fact_tables
                .iter()
                .flat_map(|t| t.functions.iter())
                .filter(|f| relevant_fns.contains(f.name.as_str()))
                .flat_map(|f| f.state_mutations.iter())
                .map(|m| m.target.to_lowercase())
                .collect();

            // Filter
            let filtered: Vec<FactTable> = fact_tables
                .into_iter()
                .map(|mut t| {
                    t.functions.retain(|f| {
                        plan_mentioned.contains(&f.name)
                            || plan_callees.contains(&f.name)
                            || t.callers.iter().any(|c| c.symbol == f.name)
                            || f.state_mutations.iter().any(|m| {
                                plan_mutation_targets.contains(&m.target.to_lowercase())
                            })
                    });
                    t
                })
                .collect();

            let filtered_fn_count: usize = filtered.iter().map(|t| t.functions.len()).sum();

            let stats = serde_json::json!({
                "original_function_count": original_fn_count,
                "filtered_function_count": filtered_fn_count,
                "plan_mentioned": plan_mentioned.iter().take(20).collect::<Vec<_>>(),
                "plan_callees_found": plan_callees.len(),
                "shared_mutation_targets": plan_mutation_targets.iter().take(10).collect::<Vec<_>>(),
                "reduction_percent": if original_fn_count > 0 {
                    100 - (filtered_fn_count * 100 / original_fn_count)
                } else { 0 },
                "aggressive_warning": original_fn_count > 0 && filtered_fn_count * 5 < original_fn_count,
            });

            (filtered, Some(stats))
        };

        // Build schema section for prompt injection
        let schema_section = if let Some(ref schema_str) = params.0.schema_json {
            match serde_json::from_str::<refine_mcp::facts::types::SchemaSnapshot>(schema_str) {
                Ok(schema) => {
                    // Only include tables referenced by state_mutations
                    let mutation_targets: std::collections::HashSet<String> = fact_tables
                        .iter()
                        .flat_map(|t| t.functions.iter())
                        .flat_map(|f| f.state_mutations.iter())
                        .map(|m| m.target.to_lowercase())
                        .collect();

                    let relevant_tables: Vec<_> = schema
                        .tables
                        .iter()
                        .filter(|t| {
                            mutation_targets
                                .iter()
                                .any(|mt| mt.contains(&t.table_name.to_lowercase()))
                        })
                        .collect();

                    if relevant_tables.is_empty() && schema.type_warnings.is_empty() {
                        String::new()
                    } else {
                        let filtered = serde_json::json!({
                            "relevant_tables": relevant_tables,
                            "type_warnings": schema.type_warnings,
                        });
                        format!(
                            "\n```json\n{}\n```\n",
                            serde_json::to_string_pretty(&filtered).unwrap_or_default()
                        )
                    }
                }
                Err(_) => String::new(),
            }
        } else {
            String::new()
        };

        let (prompts, auto_dispatch) = if let Some(n) = params.0.red_count {
            // Explicit count: use fixed N teams (RT-A..RT-D in order)
            let count = (n as usize).clamp(2, 4);
            let ids: Vec<refine_mcp::types::RedTeamId> = [
                refine_mcp::types::RedTeamId::RtA,
                refine_mcp::types::RedTeamId::RtB,
                refine_mcp::types::RedTeamId::RtC,
                refine_mcp::types::RedTeamId::RtD,
            ][..count]
                .to_vec();
            let prompts = refine_mcp::prompts::build_red_team_prompts_with_schema(
                mode,
                &plan_content,
                &fact_tables,
                &ids,
                &schema_section,
            );
            (prompts, None)
        } else {
            // Auto-select: pick relevant teams based on fact signals
            let dispatch = refine_mcp::prompts::auto_select_red_teams(&fact_tables);
            let prompts = refine_mcp::prompts::build_red_team_prompts_with_schema(
                mode,
                &plan_content,
                &fact_tables,
                &dispatch.teams,
                &schema_section,
            );
            (prompts, Some(dispatch))
        };

        let team_ids: Vec<String> = prompts.iter().map(|p| format!("{:?}", p.id)).collect();

        // Include dispatch reasoning when auto-selected
        let dispatch_info = if let Some(dispatch) = auto_dispatch {
            serde_json::json!({
                "activated": team_ids,
                "reasoning": dispatch.reasoning,
            })
        } else {
            serde_json::json!(null)
        };

        let mut output = serde_json::json!({
            "prompts": prompts,
            "mode": format!("{mode:?}"),
            "red_count": prompts.len(),
            "teams": team_ids,
            "auto_selected": params.0.red_count.is_none(),
            "dispatch": dispatch_info,
        });
        if let Some(stats) = filter_stats {
            output["filtering"] = stats;
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }

    // ── Tool 3b: expand_blast_radius ─────────────────────────

    #[tool(
        description = "Find all callers of specified functions using grep. Auto-detects changed function signatures from git diff if symbols not provided. Returns call graph and expanded file list for feeding into extract_facts."
    )]
    async fn expand_blast_radius(
        &self,
        params: Parameters<ExpandBlastRadiusParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let search_paths: Vec<PathBuf> = params
            .0
            .search_paths
            .unwrap_or_else(|| vec!["app/".to_string(), "routes/".to_string()])
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let exclude_files: Vec<PathBuf> = params
            .0
            .exclude_files
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let max_per_symbol = params.0.max_per_symbol.unwrap_or(20);

        let symbols = match params.0.symbols {
            Some(syms) if !syms.is_empty() => syms,
            _ => {
                let plan_files: Vec<PathBuf> = params
                    .0
                    .plan_files
                    .unwrap_or_default()
                    .into_iter()
                    .map(PathBuf::from)
                    .collect();
                refine_mcp::facts::blast_radius::extract_changed_symbols(&plan_files)
            }
        };

        if symbols.is_empty() {
            let output = serde_json::json!({
                "call_graph": {},
                "expanded_files": [],
                "total_callers": 0,
                "symbols_searched": [],
                "note": "No symbols to search. Provide symbols or ensure plan files have git changes."
            });
            return Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&output).unwrap_or_default(),
            )]));
        }

        let result = refine_mcp::facts::blast_radius::expand_blast_radius(
            &symbols,
            &search_paths,
            &exclude_files,
            max_per_symbol,
        );

        let output = serde_json::json!({
            "call_graph": result.call_graph,
            "expanded_files": result.expanded_files,
            "total_callers": result.total_callers,
            "symbols_searched": symbols,
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }

    // ── Tool 3c: extract_migration_facts ───────────────────────

    #[tool(
        description = "Parse Laravel migration files to extract database schema: column types, nullable, defaults, foreign keys, indexes. Generates warnings for risky patterns (VARCHAR price columns, ENUM pitfalls). Feed the output into prepare_attack as schema_json."
    )]
    async fn extract_migration_facts(
        &self,
        params: Parameters<ExtractMigrationFactsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let migration_dir = params
            .0
            .migration_dir
            .unwrap_or_else(|| "database/migrations".to_string());

        let dir_path = validate_dir(&migration_dir)?;

        let snapshot =
            refine_mcp::facts::migration::extract_migration_facts(&dir_path).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("Migration parse failed: {e}"), None)
            })?;

        let filtered = if let Some(filter) = params.0.table_filter {
            refine_mcp::facts::types::SchemaSnapshot {
                tables: snapshot
                    .tables
                    .into_iter()
                    .filter(|t| filter.iter().any(|f| t.table_name.contains(f)))
                    .collect(),
                type_warnings: snapshot
                    .type_warnings
                    .into_iter()
                    .filter(|w| filter.iter().any(|f| w.contains(f)))
                    .collect(),
            }
        } else {
            snapshot
        };

        let table_count = filtered.tables.len();
        let column_count: usize = filtered.tables.iter().map(|t| t.columns.len()).sum();
        let warning_count = filtered.type_warnings.len();

        let output = serde_json::json!({
            "schema": filtered,
            "table_count": table_count,
            "column_count": column_count,
            "warning_count": warning_count,
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
        description = "Backup plan and append refinement section with findings and blue team analysis.\n\n\
        The `findings_json` parameter must be a JSON array of Finding objects. \
        Each Finding requires these fields:\n\
        - id: string (e.g. \"RT-A\")\n\
        - severity: \"fatal\" or \"high\" (lowercase only)\n\
        - title: string\n\
        - problem: string describing the issue\n\
        - attack_scenario: string describing how it can fail (or \"N/A\" if none)\n\
        - sources: array of RedTeamId values: \"RtA\", \"RtB\", \"RtC\", \"RtD\", or \"BlueTeam\"\n\
        - file_path: string (relative path to the affected file)\n\
        - affected_plan_steps: array of strings (e.g. [\"Step 1\", \"Step 2\"])\n\n\
        Optional fields: line_range ([start, end] as [u32, u32]), suggested_fix (string), \
        status (\"new\"|\"confirmed\"|\"fixed\"|\"false_positive\", default: \"new\")\n\n\
        Example: [{\"id\":\"RT-A\",\"severity\":\"high\",\"title\":\"Missing null check\",\
        \"problem\":\"Config value used without fallback\",\
        \"attack_scenario\":\"App crashes when config key is unset\",\
        \"sources\":[\"RtA\"],\"file_path\":\"src/config.rs\",\
        \"affected_plan_steps\":[\"Step 2\"],\"suggested_fix\":\"Add default value\"}]\n\n\
        Tip: If you used `synthesize_findings` first, pass its `findings` array directly as a JSON string."
    )]
    async fn finalize_refinement(
        &self,
        params: Parameters<FinalizeRefinementParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let plan_path = validate_path(&params.0.plan_path)?;
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

        // Atomic write: write full content (original + refinement) to .tmp, then rename
        let new_content = format!("{original}\n\n{refinement}");
        let tmp_path = plan_path.with_extension("md.tmp");
        std::fs::write(&tmp_path, &new_content).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("Failed to write temp file: {e}"), None)
        })?;
        std::fs::rename(&tmp_path, &plan_path).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("Failed to atomic-rename plan file: {e}"), None)
        })?;

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

// ─── Path Validation ──────────────────────────────────────────

/// Validate a path is safe to access.
///
/// Rejects paths with `..` components (traversal) and absolute paths
/// outside the current working directory.
fn validate_path(p: &str) -> Result<PathBuf, rmcp::ErrorData> {
    let path = PathBuf::from(p);

    // Reject path traversal
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(rmcp::ErrorData::invalid_params(
            format!("Path traversal rejected: {p}"),
            None,
        ));
    }

    // For absolute paths, verify they're under CWD
    if path.is_absolute() {
        if let Ok(cwd) = std::env::current_dir() {
            if !path.starts_with(&cwd) {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("Absolute path outside working directory: {p}"),
                    None,
                ));
            }
        }
    }

    Ok(path)
}

/// Validate a directory path (same rules as [`validate_path`], must also be a directory).
fn validate_dir(p: &str) -> Result<PathBuf, rmcp::ErrorData> {
    let path = validate_path(p)?;
    if !path.is_dir() {
        return Err(rmcp::ErrorData::invalid_params(
            format!("Directory not found: {p}"),
            None,
        ));
    }
    Ok(path)
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

/// Extract function/method names mentioned in plan content.
///
/// Uses multiple regex patterns to catch different reference styles:
/// backtick-wrapped, method calls (->method, ::method), and bare function().
/// Skips language keywords but NOT method names like create/update/save.
fn extract_plan_functions(plan_content: &str) -> std::collections::HashSet<String> {
    use regex::Regex;
    use std::sync::LazyLock;

    // Pattern 1: backtick-wrapped identifiers: `processBooking`
    static RE_BACKTICK: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"`(\w{3,})`").expect("valid regex"));

    // Pattern 2: method calls: ->processBooking( or ::processBooking(
    static RE_METHOD: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?:->|::)(\w{3,})\s*\(").expect("valid regex"));

    // Pattern 3: function references with parens: processBooking(
    static RE_FUNC_CALL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b([a-zA-Z_]\w{2,})\s*\(").expect("valid regex"));

    let blocklist: std::collections::HashSet<&str> = [
        // English prose words
        "the", "and", "for", "with", "from", "this", "that", "will", "are", "not",
        "use", "has", "can", "may", "let", "but", "all", "also", "each", "when",
        "then", "than", "into", "only", "some", "such", "like", "need", "must",
        "should", "would", "could", "been", "have", "does", "make", "take",
        // Language keywords
        "pub", "mod", "mut", "ref", "self", "super", "const",
        "step", "plan", "file", "code", "line", "note", "todo", "see",
        "true", "false", "null", "none", "void",
        "return", "class", "function", "method", "trait", "struct", "impl", "enum",
        "public", "private", "protected", "static", "async", "await", "abstract",
        "interface", "extends", "implements", "namespace", "require", "include",
        // Type names (not method names)
        "string", "array", "bool", "int", "float", "mixed", "object",
        "varchar", "integer", "boolean", "nullable", "default", "index",
        "Table", "Model", "Service", "Controller", "Migration", "Seeder",
        // Plan structure words
        "Problem", "Goal", "Risk", "Impact", "Before", "After", "Expected",
        "Metric", "Testing", "Files", "Modify",
    ]
    .into_iter()
    .collect();

    let mut names = std::collections::HashSet::new();
    for re in [&*RE_BACKTICK, &*RE_METHOD, &*RE_FUNC_CALL] {
        for cap in re.captures_iter(plan_content) {
            let name = &cap[1];
            if !blocklist.contains(name) {
                names.insert(name.to_string());
            }
        }
    }
    names
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
            refine_mcp::types::RedTeamId::BlueTeam => "Blue",
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

    // ── extract_plan_functions ──

    #[test]
    fn extract_plan_functions_backtick() {
        let plan = "Modify `processBooking` to handle cancellations. Also update `applyBookingMetadata`.";
        let fns = extract_plan_functions(plan);
        assert!(fns.contains("processBooking"));
        assert!(fns.contains("applyBookingMetadata"));
    }

    #[test]
    fn extract_plan_functions_method_call() {
        let plan = "Call $this->reservationService->createWalkinReservation() and Beds24Service::syncAvailability()";
        let fns = extract_plan_functions(plan);
        assert!(fns.contains("createWalkinReservation"));
        assert!(fns.contains("syncAvailability"));
    }

    #[test]
    fn extract_plan_functions_skips_keywords() {
        let plan = "Use the `function` keyword to `return` a `string` value. Call `processBooking()`.";
        let fns = extract_plan_functions(plan);
        assert!(!fns.contains("function"));
        assert!(!fns.contains("return"));
        assert!(!fns.contains("string"));
        assert!(fns.contains("processBooking"));
    }

    #[test]
    fn extract_plan_functions_keeps_crud_methods() {
        let plan = "Call create() and update() and delete() and save() and find()";
        let fns = extract_plan_functions(plan);
        // These are valid method names in Laravel, should NOT be blocked
        assert!(fns.contains("create"));
        assert!(fns.contains("update"));
        assert!(fns.contains("delete"));
        assert!(fns.contains("save"));
        assert!(fns.contains("find"));
    }

    #[test]
    fn extract_plan_functions_empty_plan() {
        let plan = "This plan has no function references at all.";
        let fns = extract_plan_functions(plan);
        // "plan" and "function" are blocklisted, "This" and "has" are < 3 chars or blocklisted
        assert!(fns.is_empty() || fns.iter().all(|f| f.len() >= 3));
    }
}
