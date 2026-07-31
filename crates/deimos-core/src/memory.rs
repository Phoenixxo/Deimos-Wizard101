use serde::{Deserialize, Serialize};

use crate::process::ProcessSessionId;

pub const CAPABILITY_MEMORY_READ_ONLY: &str = "memory.read_only.v1";
pub const CAPABILITY_MEMORY_MUTATION: &str = "memory.mutation.v1";
/// Enables agent-owned transactional detours.  This capability is deliberately
/// separate from generic mutation so existing mutation clients cannot install
/// code hooks merely by negotiating `memory.mutation.v1`.
pub const CAPABILITY_MEMORY_HOOK: &str = "memory.hook.v1";
pub const CAPABILITY_REMOTE_THREAD: &str = "thread.remote.v1";
pub const OP_MEMORY_REGIONS: &str = "memory.regions";
pub const OP_MEMORY_READ: &str = "memory.read";
pub const OP_MEMORY_READ_BATCH: &str = "memory.read_batch";
pub const OP_MEMORY_READ_TYPED: &str = "memory.read_typed";
pub const OP_MEMORY_POINTER_CHAIN: &str = "memory.pointer_chain";
pub const OP_MEMORY_SCAN: &str = "memory.scan";
pub const OP_MEMORY_WRITE: &str = "memory.write";
pub const OP_MEMORY_ALLOCATE: &str = "memory.allocate";
pub const OP_MEMORY_FREE: &str = "memory.free";
pub const OP_MEMORY_PROTECT: &str = "memory.protect";
pub const OP_THREAD_START: &str = "thread.start";
pub const OP_HOOK_ACTIVATE: &str = "hook.activate";
pub const OP_HOOK_DEACTIVATE: &str = "hook.deactivate";
pub const OP_HOOK_HEARTBEAT: &str = "hook.heartbeat";

pub const DEFAULT_SCAN_MAX_MATCHES: usize = 256;
// These limits keep Vec<u8>-encoded JSON results comfortably below the 1 MiB
// RPC frame limit, including object and array overhead.
pub const MAX_MEMORY_READ_BYTES: usize = 64 * 1024;
pub const MAX_BATCH_ITEMS: usize = 128;
pub const MAX_BATCH_BYTES: usize = 64 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 4096;
pub const MAX_POINTER_OFFSETS: usize = 64;
pub const MAX_SCAN_MATCHES: usize = 4096;
pub const MAX_SCAN_REGIONS: usize = 4096;
pub const MAX_SCAN_ERRORS: usize = 256;
pub const MAX_MEMORY_WRITE_BYTES: usize = 64 * 1024;
pub const MAX_ALLOCATION_BYTES: usize = 16 * 1024 * 1024;
// Keep one second of headroom under the default five-second RPC I/O timeout
// for validation, serialization, and transport.
pub const MAX_REMOTE_THREAD_WAIT_MS: u32 = 4_000;
pub const MIN_HOOK_SIGNATURE_BYTES: usize = 14;
pub const MAX_HOOK_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryProtection {
    ReadOnly,
    ReadWrite,
    ExecuteRead,
    ExecuteReadWrite,
    CopyOnWrite,
    ExecuteCopyOnWrite,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryRegionDescriptor {
    pub base_address: String,
    pub size: usize,
    pub protection: MemoryProtection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryRegionsResponse {
    pub session_id: ProcessSessionId,
    pub regions: Vec<MemoryRegionDescriptor>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryValueType {
    U8,
    I32,
    U32,
    U64,
    F32,
    F64,
}

impl MemoryValueType {
    pub const fn size(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::I32 | Self::U32 | Self::F32 => 4,
            Self::U64 | Self::F64 => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    #[default]
    LittleEndian,
    BigEndian,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemorySessionRequest {
    pub session_id: ProcessSessionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryReadRequest {
    pub session_id: ProcessSessionId,
    /// Hexadecimal address text avoids precision loss in Python/JavaScript.
    pub address: String,
    pub size: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryReadResponse {
    pub session_id: ProcessSessionId,
    pub address: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryWriteRequest {
    pub session_id: ProcessSessionId,
    pub address: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryWriteResponse {
    pub session_id: ProcessSessionId,
    pub address: String,
    pub bytes_written: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryAllocateRequest {
    pub session_id: ProcessSessionId,
    pub size: usize,
    pub protection: MemoryProtection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryAllocationResponse {
    pub session_id: ProcessSessionId,
    pub allocation_id: String,
    pub address: String,
    pub size: usize,
    pub protection: MemoryProtection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryFreeRequest {
    pub session_id: ProcessSessionId,
    pub allocation_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryFreeResponse {
    pub session_id: ProcessSessionId,
    pub allocation_id: String,
    pub address: String,
    pub size: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryProtectRequest {
    pub session_id: ProcessSessionId,
    pub address: String,
    pub size: usize,
    pub protection: MemoryProtection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryProtectResponse {
    pub session_id: ProcessSessionId,
    pub address: String,
    pub size: usize,
    pub previous_protection: MemoryProtection,
    pub protection: MemoryProtection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoteThreadStartRequest {
    pub session_id: ProcessSessionId,
    pub start_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    #[serde(default)]
    pub wait_timeout_ms: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoteThreadStartResponse {
    pub session_id: ProcessSessionId,
    pub thread_id: u32,
    pub completed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<u32>,
}

/// A hook is identified within a mutation session by `hook_key`.  The
/// signature is always scanned uniquely before the target is modified.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HookActivateRequest {
    pub session_id: ProcessSessionId,
    pub hook_key: String,
    pub signature: String,
    pub scope: MemoryScanScope,
    /// Bytes placed before the saved instructions in the remote trampoline.
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HookActivateResponse {
    pub session_id: ProcessSessionId,
    pub hook_key: String,
    pub target_address: String,
    pub allocation_id: String,
    pub allocation_address: String,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HookDeactivateRequest {
    pub session_id: ProcessSessionId,
    pub hook_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HookDeactivateResponse {
    pub session_id: ProcessSessionId,
    pub hook_key: String,
    /// Deactivation is idempotent: false means the hook was already absent.
    pub deactivated: bool,
    pub allocation_released: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HookHeartbeatRequest {
    pub session_id: ProcessSessionId,
    pub hook_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HookHeartbeatResponse {
    pub session_id: ProcessSessionId,
    pub hook_key: String,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryBatchReadRequest {
    pub session_id: ProcessSessionId,
    pub reads: Vec<MemoryReadItem>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryReadItem {
    pub address: String,
    pub size: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryBatchReadResponse {
    pub session_id: ProcessSessionId,
    /// Per-item results are atomic: a failed item never contains partial bytes,
    /// while other items remain independently usable.
    pub results: Vec<MemoryReadItemResult>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryReadItemResult {
    pub address: String,
    pub requested_size: usize,
    pub bytes: Option<Vec<u8>>,
    pub error: Option<MemoryItemError>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryItemError {
    pub code: MemoryItemErrorCode,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryItemErrorCode {
    InvalidAddress,
    InvalidSize,
    ReadFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TypedMemoryReadRequest {
    pub session_id: ProcessSessionId,
    pub address: String,
    pub value_type: MemoryValueType,
    #[serde(default)]
    pub byte_order: ByteOrder,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TypedMemoryReadResponse {
    pub session_id: ProcessSessionId,
    pub address: String,
    pub value_type: MemoryValueType,
    pub byte_order: ByteOrder,
    pub raw_bytes: Vec<u8>,
    pub value: TypedMemoryValue,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TypedMemoryValue {
    U8 { value: u8 },
    I32 { value: i32 },
    U32 { value: u32 },
    U64 { value: u64 },
    F32 { value: f32 },
    F64 { value: f64 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryScanScope {
    Process,
    Module { name: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryScanRequest {
    pub session_id: ProcessSessionId,
    /// Bytes are separated by whitespace; `??` is a single-byte wildcard.
    pub signature: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub unique: bool,
    #[serde(default = "default_scan_max_matches")]
    pub max_matches: usize,
    pub scope: MemoryScanScope,
}

fn default_scan_max_matches() -> usize {
    DEFAULT_SCAN_MAX_MATCHES
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryScanResponse {
    pub session_id: ProcessSessionId,
    pub matches: Vec<String>,
    pub scanned_regions: usize,
    pub skipped_regions: usize,
    pub errors: Vec<MemoryScanRegionError>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryScanRegionError {
    pub base_address: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryPointerChainRequest {
    pub session_id: ProcessSessionId,
    pub signature: String,
    pub offsets: Vec<u64>,
    pub dereference_count: usize,
    pub pointer_width: u8,
    #[serde(default)]
    pub byte_order: ByteOrder,
    pub value_type: MemoryValueType,
    pub scope: MemoryScanScope,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MemoryPointerChainResponse {
    pub session_id: ProcessSessionId,
    pub root_match: String,
    pub target_address: String,
    pub value_type: MemoryValueType,
    pub byte_order: ByteOrder,
    pub raw_bytes: Vec<u8>,
    pub value: TypedMemoryValue,
}
