//! The MCP server handler. The protocol (framing, initialisation, request
//! routing, cancellation) is rmcp's; this file only says what the server is
//! called, which tools it has and what a call does.

use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorData,
    Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::RoleServer;

use super::client::FerroClient;
use super::tools::{self, TOOL_HTTP_REQUEST, TOOL_LIST_CREDENTIALS};

const INSTRUCTIONS: &str = "\
Ferrowarden makes API calls with named vault credentials without showing you the values. \
Call list_credentials to see the placeholders you may use, then call http_request with those \
placeholders where a credential belongs. If a call is refused with 403, do not retry it with \
other credentials, hosts or methods; tell the user.";

#[derive(Clone)]
pub struct FerrowardenMcp {
    client: Arc<FerroClient>,
}

impl FerrowardenMcp {
    pub fn new(client: Arc<FerroClient>) -> Self {
        Self { client }
    }
}

impl ServerHandler for FerrowardenMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "ferrowarden-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(tools::definitions()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let result = match request.name.as_ref() {
            TOOL_LIST_CREDENTIALS => {
                // The tool takes no arguments; the schema forbids extra ones.
                if request.arguments.as_ref().is_some_and(|a| !a.is_empty()) {
                    CallToolResult::error(vec![ContentBlock::text(
                        "list_credentials takes no arguments.",
                    )])
                } else {
                    tools::list_credentials(&self.client).await
                }
            }
            TOOL_HTTP_REQUEST => tools::http_request(&self.client, request.arguments).await,
            // The name is the caller's, not a secret, but it is not echoed.
            _ => {
                return Err(ErrorData::invalid_params(
                    "unknown tool; this server has list_credentials and http_request",
                    None,
                ))
            }
        };
        Ok(result.into())
    }
}
