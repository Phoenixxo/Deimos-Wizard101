use serde::{Deserialize, Serialize};

use crate::client::{ClientDescriptor, ClientId};
use crate::secret::SealedCredential;

pub const CAPABILITY_GAME_PROCESS: &str = "game.process.v1";
pub const CAPABILITY_GAME_LOGIN: &str = "game.login.v1";
pub const OP_GAME_LAUNCH: &str = "game.launch";
pub const OP_GAME_LOGIN: &str = "game.login";
pub const OP_GAME_TERMINATE: &str = "game.terminate";

pub const DEFAULT_GAME_OPERATION_TIMEOUT_MS: u32 = 30_000;
pub const MAX_GAME_OPERATION_TIMEOUT_MS: u32 = 120_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameLaunchRequest {
    /// Windows installation directory containing the game's `Bin` directory.
    pub game_path: String,
    /// Login endpoint in `host:port` form. Authentication data is deliberately
    /// not part of this process-launch contract.
    pub login_server: String,
    pub timeout_ms: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameLaunchResponse {
    /// PID returned by the Windows process creation API. The confirmed client
    /// is required to match this process's full identity and own a game window.
    pub launched_process_id: u32,
    pub client: ClientDescriptor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameTerminateRequest {
    pub client_id: ClientId,
    pub timeout_ms: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameTerminateResponse {
    pub client_id: ClientId,
    pub process_id: u32,
    pub terminated: bool,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameLoginRequest {
    pub client_id: ClientId,
    pub agent_instance_id: String,
    pub transfer_id: String,
    pub credential: SealedCredential,
    pub timeout_ms: u32,
}

impl std::fmt::Debug for GameLoginRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GameLoginRequest")
            .field("client_id", &self.client_id)
            .field("agent_instance_id", &self.agent_instance_id)
            .field("transfer_id", &self.transfer_id)
            .field("credential", &"[REDACTED]")
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameLoginResponse {
    pub client_id: ClientId,
    pub authenticated: bool,
    pub cleanup_complete: bool,
}

pub fn login_associated_data(
    agent_instance_id: &str,
    client_id: &ClientId,
    transfer_id: &str,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(
        OP_GAME_LOGIN.len() + agent_instance_id.len() + client_id.0.len() + transfer_id.len() + 3,
    );
    context.extend_from_slice(OP_GAME_LOGIN.as_bytes());
    context.push(0);
    context.extend_from_slice(agent_instance_id.as_bytes());
    context.push(0);
    context.extend_from_slice(client_id.0.as_bytes());
    context.push(0);
    context.extend_from_slice(transfer_id.as_bytes());
    context
}
