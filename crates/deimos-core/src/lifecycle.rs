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
    /// Immutable artifact identity. Production builds should set
    /// `DEIMOS_BUILD_ID` to the artifact digest or source revision.
    #[serde(default = "unknown_build_id")]
    pub build_id: String,
    pub process_id: u32,
}

fn unknown_build_id() -> String {
    "unknown-legacy-build".to_string()
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

#[cfg(test)]
mod tests {
    use super::AgentIdentity;

    #[test]
    fn legacy_identity_without_build_id_is_safely_marked_unknown() {
        let identity: AgentIdentity =
            serde_json::from_str(r#"{"instance_id":"legacy","version":"0.1.0","process_id":7}"#)
                .expect("legacy identity should remain decodable");
        assert_eq!(identity.build_id, "unknown-legacy-build");
    }

    #[test]
    fn current_build_identity_is_embedded_and_nonempty() {
        assert!(!crate::BUILD_ID.is_empty());
        assert!(crate::BUILD_ID.len() <= 128);
    }
}
