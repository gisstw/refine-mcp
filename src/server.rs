use rmcp::{
    ServerHandler,
    handler::server::tool::ToolRouter,
    model::{ServerCapabilities, ServerInfo},
    tool_router,
};

// Stub server — will be replaced in Chunk 5
pub struct RefineServer;

impl RefineServer {
    pub fn new() -> Self {
        Self
    }
}

#[tool_router]
impl RefineServer {}

impl ServerHandler for RefineServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("Structural change impact analyzer (stub)".to_string()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}
