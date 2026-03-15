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

use refine_mcp::diff::{aggregate_diffs, compute_structural_diff};
use refine_mcp::facts::blast_radius;
use refine_mcp::facts::types::FactTable;
use refine_mcp::health::compute_health;

// ─── Tool Parameter Structs ────────────────────────────────────

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct StructuralDiffParams {
    /// File paths to analyze.
    pub file_paths: Vec<String>,
    /// Git ref for "before" version (default: "HEAD")
    pub base_ref: Option<String>,
    /// Git ref for "after" version. If omitted, uses working tree.
    pub compare_ref: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ImpactAnalysisParams {
    /// Function/method names to search for callers.
    /// If empty, auto-detects changed symbols from git diff.
    pub symbols: Option<Vec<String>>,
    /// Directories to search (default: ["app/", "routes/", "src/"])
    pub search_paths: Option<Vec<String>>,
    /// Files to exclude from results
    pub exclude_files: Option<Vec<String>>,
    /// Source files for auto-detecting changed symbols via git diff
    pub source_files: Option<Vec<String>>,
    /// Max results per symbol (default: 20)
    pub max_per_symbol: Option<usize>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ExtractFactsParams {
    /// List of file paths to analyze
    pub file_paths: Vec<String>,
    /// If true, filter to only files changed in git diff HEAD
    pub diff_only: Option<bool>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ExtractSchemaParams {
    /// Path to migration directory (default: database/migrations)
    pub migration_dir: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct HealthSnapshotParams {
    /// File paths to analyze
    pub file_paths: Vec<String>,
}

// ─── Server ────────────────────────────────────────────────────

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
    /// Compare function signatures between two git refs (or git ref vs working tree).
    #[tool(
        description = "Compare function signatures between two git refs (or git ref vs working tree). Returns added, removed, and changed functions with breaking change detection."
    )]
    async fn structural_diff(
        &self,
        params: Parameters<StructuralDiffParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let params = params.0;
        let base_ref = params.base_ref.as_deref().unwrap_or("HEAD");
        let mut all_diffs = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        for file_path in &params.file_paths {
            let resolved = resolve_path(file_path);

            let before_source = get_git_file_content(file_path, base_ref);
            let after_source = if let Some(ref compare) = params.compare_ref {
                get_git_file_content(file_path, compare)
            } else {
                match std::fs::read_to_string(&resolved) {
                    Ok(s) => s,
                    Err(e) => {
                        errors.push(format!("{}: {e}", resolved.display()));
                        continue;
                    }
                }
            };

            if before_source.is_empty() && after_source.is_empty() {
                errors.push(format!("{file_path}: file not found in git or working tree"));
                continue;
            }

            let lang = detect_language(file_path);
            let before_facts = extract_functions(&before_source, lang);
            let after_facts = extract_functions(&after_source, lang);

            let diff = compute_structural_diff(&resolved, &before_facts, &after_facts);
            if !diff.added.is_empty() || !diff.removed.is_empty() || !diff.changed.is_empty() {
                all_diffs.push(diff);
            }
        }

        let report = aggregate_diffs(all_diffs);
        let mut result = serde_json::to_value(&report).unwrap_or_default();
        if !errors.is_empty() {
            result["errors"] = serde_json::json!(errors);
        }
        let json = serde_json::to_string_pretty(&result).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Find callers of specified functions across the codebase.
    #[tool(
        description = "Find callers of specified functions across the codebase. Auto-detects changed function names from git diff if symbols not provided."
    )]
    async fn impact_analysis(
        &self,
        params: Parameters<ImpactAnalysisParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let params = params.0;
        let default_paths = vec![
            "app/".to_string(),
            "routes/".to_string(),
            "src/".to_string(),
        ];

        let symbols = match params.symbols {
            Some(ref syms) if !syms.is_empty() => syms.clone(),
            _ => auto_detect_symbols(&params.source_files),
        };

        if symbols.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                r#"{"error": "No symbols to analyze. Provide symbols or source_files with git changes."}"#,
            )]));
        }

        let search_paths: Vec<PathBuf> = params
            .search_paths
            .as_deref()
            .unwrap_or(&default_paths)
            .iter()
            .map(PathBuf::from)
            .collect();

        let exclude: Vec<PathBuf> = params
            .exclude_files
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(PathBuf::from)
            .collect();

        let max = params.max_per_symbol.unwrap_or(20);

        let result = blast_radius::expand_blast_radius(&symbols, &search_paths, &exclude, max);
        let json = serde_json::to_string_pretty(&result).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Extract structured facts from source files using tree-sitter.
    #[tool(
        description = "Extract structured facts from source files using tree-sitter. Returns function signatures, parameters, transactions, locks, catch blocks, etc."
    )]
    async fn extract_facts(
        &self,
        params: Parameters<ExtractFactsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let params = params.0;
        let mut file_paths = params.file_paths;

        if params.diff_only.unwrap_or(false) {
            file_paths = filter_to_changed_files(&file_paths);
        }

        let mut tables: Vec<FactTable> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        for path_str in &file_paths {
            match read_source(path_str) {
                Ok((resolved, source)) => {
                    let lang = detect_language(path_str);
                    if let Some(table) = extract_fact_table(&resolved, &source, lang) {
                        tables.push(table);
                    }
                }
                Err(e) => errors.push(e),
            }
        }

        let mut result = serde_json::json!({ "facts": tables });
        if !errors.is_empty() {
            result["errors"] = serde_json::json!(errors);
        }
        let json = serde_json::to_string_pretty(&result).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Parse Laravel migration files to extract database schema.
    #[tool(
        description = "Parse Laravel migration files to extract database schema. Returns column types, nullable, defaults, foreign keys, indexes."
    )]
    async fn extract_schema(
        &self,
        params: Parameters<ExtractSchemaParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let params = params.0;
        let migration_dir = params
            .migration_dir
            .as_deref()
            .unwrap_or("database/migrations");

        match refine_mcp::facts::migration::extract_migration_facts(Path::new(migration_dir)) {
            Ok(snapshot) => {
                let json = serde_json::to_string_pretty(&snapshot).unwrap_or_default();
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to extract schema: {e}"
            ))])),
        }
    }

    /// Compute per-function health metrics.
    #[tool(
        description = "Compute per-function health metrics: line count, parameter count, nesting depth, and branch count. Generates warnings for functions exceeding thresholds."
    )]
    async fn health_snapshot(
        &self,
        params: Parameters<HealthSnapshotParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let params = params.0;
        let mut all_functions = Vec::new();
        let mut all_warnings = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        for path_str in &params.file_paths {
            match read_source(path_str) {
                Ok((resolved, source)) => {
                    let lang_str = detect_language(path_str);
                    let report = compute_health(&source, &resolved, lang_str);
                    all_functions.extend(report.functions);
                    all_warnings.extend(report.warnings);
                }
                Err(e) => errors.push(e),
            }
        }

        let mut result = serde_json::json!({
            "functions": all_functions,
            "warnings": all_warnings,
        });
        if !errors.is_empty() {
            result["errors"] = serde_json::json!(errors);
        }
        let json = serde_json::to_string_pretty(&result).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

#[tool_handler]
impl ServerHandler for RefineServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Structural change impact analyzer. Use structural_diff to detect \
                 breaking changes, impact_analysis to find affected callers, \
                 health_snapshot for code complexity metrics, extract_facts for \
                 tree-sitter analysis, and extract_schema for Laravel migrations."
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ─── Path Resolution ───────────────────────────────────────────

/// Resolve a file path: if relative and not found in CWD, try common project roots.
/// Returns the resolved absolute path or the original if nothing found.
fn resolve_path(path_str: &str) -> PathBuf {
    let path = PathBuf::from(path_str);

    // Already absolute and exists — use as-is
    if path.is_absolute() {
        return path;
    }

    // Relative — try CWD first
    if path.exists() {
        return path;
    }

    // Try git repo root (most reliable for project-relative paths)
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
    {
        if output.status.success() {
            let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let candidate = PathBuf::from(&root).join(&path);
            if candidate.exists() {
                return candidate;
            }
        }
    }

    // Fallback: return original (will fail at read, but error gets reported)
    path
}

/// Read a file with path resolution. Returns (resolved_path, source) or error message.
fn read_source(path_str: &str) -> Result<(PathBuf, String), String> {
    let resolved = resolve_path(path_str);
    match std::fs::read_to_string(&resolved) {
        Ok(source) => Ok((resolved, source)),
        Err(e) => Err(format!("{}: {e}", resolved.display())),
    }
}

// ─── Helpers ───────────────────────────────────────────────────

fn detect_language(path: &str) -> &str {
    if path.ends_with(".php") {
        "php"
    } else if path.ends_with(".rs") {
        "rust"
    } else if path.ends_with(".ts") || path.ends_with(".tsx") {
        "typescript"
    } else if path.ends_with(".py") {
        "python"
    } else {
        "unknown"
    }
}

fn get_git_file_content(path: &str, git_ref: &str) -> String {
    let output = std::process::Command::new("git")
        .args(["show", &format!("{git_ref}:{path}")])
        .output();

    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => String::new(),
    }
}

fn extract_functions(source: &str, lang: &str) -> Vec<refine_mcp::facts::types::FunctionFact> {
    if source.is_empty() {
        return Vec::new();
    }
    let path = Path::new("temp");
    extract_fact_table(path, source, lang)
        .map(|t| t.functions)
        .unwrap_or_default()
}

fn extract_fact_table(path: &Path, source: &str, lang: &str) -> Option<FactTable> {
    match lang {
        "php" => refine_mcp::facts::php::extract_php_facts(path, source).ok(),
        "rust" => refine_mcp::facts::rust_lang::extract_rust_facts(path, source).ok(),
        "typescript" => refine_mcp::facts::typescript::extract_ts_facts(path, source).ok(),
        "python" => refine_mcp::facts::python::extract_python_facts(path, source).ok(),
        _ => None,
    }
}

fn filter_to_changed_files(paths: &[String]) -> Vec<String> {
    let output = std::process::Command::new("git")
        .args(["diff", "HEAD", "--name-only"])
        .output();

    let changed: Vec<String> = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(String::from)
            .collect(),
        _ => return paths.to_vec(),
    };

    paths
        .iter()
        .filter(|p| changed.iter().any(|c| p.ends_with(c) || c.ends_with(p.as_str())))
        .cloned()
        .collect()
}

fn auto_detect_symbols(source_files: &Option<Vec<String>>) -> Vec<String> {
    let files: Vec<PathBuf> = source_files
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(PathBuf::from)
        .collect();

    blast_radius::extract_changed_symbols(&files)
}
