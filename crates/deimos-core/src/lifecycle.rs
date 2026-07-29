use serde::{Deserialize, Serialize};

pub const CAPABILITY_AGENT_LIFECYCLE: &str = "agent.lifecycle.v1";
pub const OP_AGENT_HEALTH: &str = "agent.health";
pub const OP_AGENT_SHUTDOWN: &str = "agent.shutdown";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentIdentity {
    /// Opaque identity generated once for this agent process.
    pub instance_id: String,
    /// Agent application version, independent of the RPC protocol version.
    pub version: String,
    pub process_id: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    Ready,
    ShuttingDown,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionDiagnostics {
    pub open: usize,
    pub closed: usize,
    pub exited: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentHealth {
    pub identity: AgentIdentity,
    pub state: AgentState,
    pub sessions: SessionDiagnostics,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentHealthRequest {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentShutdownRequest {
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentShutdownResponse {
    pub identity: AgentIdentity,
    pub state: AgentState,
    pub reason: String,
}
