use serde::{Deserialize, Serialize};

use crate::client::{ClientDescriptor, ClientId};

pub const CAPABILITY_GAME_PROCESS: &str = "game.process.v1";
pub const OP_GAME_LAUNCH: &str = "game.launch";
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
