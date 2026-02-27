use rmcp::{
    ServerHandler,
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct FinalizeRefinementParams {
    /// Path to the plan file
    pub plan_path: String,
    /// Blue team cross-analysis result
    pub blue_result: String,
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
    /// Find the most recently modified plan file in the given directory.
    #[tool(description = "Discover the most recently modified plan file in .claude/plans/")]
    async fn discover_plan(
        &self,
        params: Parameters<DiscoverPlanParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let dir = params.0.plan_dir.unwrap_or_else(|| ".claude/plans".to_string());
        Ok(CallToolResult::success(vec![Content::text(format!(
            "TODO: discover latest plan in {dir}"
        ))]))
    }

    /// Extract structured facts from source files using tree-sitter.
    #[tool(description = "Extract structured facts from source files using tree-sitter analysis")]
    async fn extract_facts(
        &self,
        params: Parameters<ExtractFactsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "TODO: extract facts from {} files",
            params.0.file_paths.len()
        ))]))
    }

    /// Assemble red team prompts from plan content and fact tables.
    #[tool(description = "Prepare red team attack prompts from plan and extracted facts")]
    async fn prepare_attack(
        &self,
        params: Parameters<PrepareAttackParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let _mode: RefineMode = params
            .0
            .mode
            .as_deref()
            .map(|m| serde_json::from_str(&format!("\"{m}\"")))
            .transpose()
            .map_err(|e| rmcp::ErrorData::invalid_params(format!("Invalid mode: {e}"), None))?
            .unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "TODO: prepare attack prompts for {}",
            params.0.plan_path
        ))]))
    }

    /// Parse, validate, dedup, and rank red team findings.
    #[tool(
        description = "Synthesize red team reports: parse markdown, dedup, validate, rank, generate blue team prompt"
    )]
    async fn synthesize_findings(
        &self,
        params: Parameters<SynthesizeFindingsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "TODO: synthesize {} reports",
            params.0.raw_reports.len()
        ))]))
    }

    /// Write refinement section to plan file.
    #[tool(description = "Backup plan and append refinement section with findings")]
    async fn finalize_refinement(
        &self,
        params: Parameters<FinalizeRefinementParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "TODO: finalize refinement for {}",
            params.0.plan_path
        ))]))
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
