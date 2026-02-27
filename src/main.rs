use rmcp::{ServiceExt, transport::stdio};

mod server;

use server::RefineServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Log to stderr (stdout is reserved for MCP JSON-RPC)
    tracing_subscriber::fmt()
        .with_env_filter("refine_mcp=debug")
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting refine-mcp server");

    let server = RefineServer::new();
    let service = server.serve(stdio()).await?;
    service.waiting().await?;

    Ok(())
}
