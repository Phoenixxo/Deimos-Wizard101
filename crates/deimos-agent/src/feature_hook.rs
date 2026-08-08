//! Agent-owned hooks used by movement, chat, and Deimos automation.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::thread;
use std::time::{Duration, Instant};

use deimos_core::memory::{
    CoreHook, CoreHookRequest, FeatureActionResponse, FeatureBuddyAddRequest,
    FeatureChatSendRequest, FeatureHook, FeatureHookDeactivateResponse, FeatureHookExport,
    FeatureHookExportRequest, FeatureHookExportResponse, FeatureHookRequest, FeatureHookResponse,
    FeatureHookSessionRequest, FeatureHooksResponse, FeatureMousePositionRequest,
    FeatureTeleportRequest, HookActivateRequest, HookDeactivateRequest, HookHeartbeatRequest,
    MemoryReadRequest, MemoryScanRequest, MemoryScanScope, MemoryWriteRequest,
};
use deimos_core::process::{ModuleDescriptor, ProcessKind, ProcessSessionId};
use deimos_core::rpc::{RpcError, RpcErrorCode};
use serde_json::json;

use crate::core_hook;
use crate::diagnostics::HookTimingSpan;
use crate::hook::{self, HookApiError, HookMetadata, HookPatch, HookState};
use crate::memory::{self, MemoryApiError};
use crate::mutation::{self, MutationApiError, MutationState};
use crate::process::{MutationBackend, ProcessApiError, ProcessSessionRegistry};

const MODULE: &str = "WizardGraphicalClient.exe";
const MAX_CHAT_WCHARS: usize = 79;
const CHAT_TYPE_MARKER: &[u8] = &[0xc7, 0x45, 0xf0, 0x09, 0, 0, 0];
const CHAT_HOOK_SITE: &[u8] = &[0x48, 0x8d, 0x4d, 0xf8, 0x48, 0x3b, 0xc8];
const SEND_FUNCTION_MARKER: &[u8] = &[0x48, 0x83, 0xc2, 0x20];
const ACTION_POLL: Duration = Duration::from_millis(20);
const MAX_EXPORT_FORWARD_DEPTH: usize = 4;
const MAX_EXPORT_NAME_BYTES: usize = 4096;
const MAX_EXPORT_TABLE_ENTRIES: usize = 1_000_000;

#[derive(Clone)]
struct Template {
    signature: String,
    scope: MemoryScanScope,
    target_offset: usize,
    overwrite_size: usize,
    payload: Vec<u8>,
    exports: BTreeMap<FeatureHookExport, (usize, usize)>,
    resolved_target: Option<usize>,
    auxiliary_patches: Vec<HookPatch>,
    movement_action_patches: Option<(usize, usize)>,
    payload_kind: PayloadKind,
    replay_original: bool,
    quiescence_offset: usize,
}

#[derive(Clone, Copy)]
enum PayloadKind {
    Movement {
        first_je: usize,
        second_je: usize,
        first_original: [u8; 8],
        second_original: [u8; 8],
    },
    Mouse,
    Chat,
    ChatSend {
        send: usize,
        buddy: usize,
        operator_new: usize,
    },
    Dance,
}

#[derive(Debug)]
pub enum FeatureHookApiError {
    Hook(HookApiError),
    Memory(MemoryApiError),
    Mutation(MutationApiError),
    Process(ProcessApiError),
    Request { code: RpcErrorCode, message: String },
}

impl From<HookApiError> for FeatureHookApiError {
    fn from(error: HookApiError) -> Self {
        Self::Hook(error)
    }
}

impl From<MemoryApiError> for FeatureHookApiError {
    fn from(error: MemoryApiError) -> Self {
        Self::Memory(error)
    }
}

impl From<MutationApiError> for FeatureHookApiError {
    fn from(error: MutationApiError) -> Self {
        Self::Mutation(error)
    }
}

impl From<ProcessApiError> for FeatureHookApiError {
    fn from(error: ProcessApiError) -> Self {
        Self::Process(error)
    }
}

impl FeatureHookApiError {
    fn request(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self::Request {
            code,
            message: message.into(),
        }
    }

    pub fn into_rpc_error(self, request_id: u64, operation: &str) -> RpcError {
        match self {
            Self::Hook(error) => error.into_rpc_error(request_id, operation),
            Self::Memory(error) => error.into_rpc_error(request_id, operation),
            Self::Mutation(error) => error.into_rpc_error(request_id, operation),
            Self::Process(error) => error.into_rpc_error(request_id, operation),
            Self::Request { code, message } => {
                RpcError::new(code, message, request_id, operation, None)
            }
        }
    }
}

pub fn activate<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    request: &FeatureHookRequest,
    now: Instant,
) -> Result<FeatureHookResponse, FeatureHookApiError> {
    let key = hook_key(request.hook);
    if hooks
        .allocation_address(&request.session_id, &key)
        .is_some()
    {
        hook::heartbeat(
            hooks,
            &HookHeartbeatRequest {
                session_id: request.session_id.clone(),
                hook_key: key,
            },
            now,
        )?;
        return Ok(FeatureHookResponse {
            session_id: request.session_id.clone(),
            hook: request.hook,
            active: true,
        });
    }
    if hooks
        .allocation_address(&request.session_id, &key)
        .is_some()
    {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::InvalidRequest,
            "a prior feature-hook activation failed and retained recovery ownership; deactivate it before retrying",
        ));
    }
    let fixture = sessions.process_kind(&request.session_id) == Some(ProcessKind::MemoryFixture);
    let operation = format!("feature_hook.activate.{}", hook_key(request.hook));
    let timing = HookTimingSpan::new(&operation, "total");
    let template_timing = HookTimingSpan::new(&operation, "build_template");
    let template = template_for_target(
        sessions,
        backend,
        &request.session_id,
        request.hook,
        fixture,
    )?;
    template_timing.finish(
        "ok",
        json!({
            "fixture": fixture,
            "auxiliary_patch_count": template.auxiliary_patches.len(),
        }),
    );
    let mut metadata = HookMetadata::default();
    for (export, (offset, size)) in &template.exports {
        metadata
            .exports
            .insert(export_name(*export).to_string(), (*offset, *size));
    }
    if request.hook == FeatureHook::ChatSend {
        let private_offset = template
            .exports
            .values()
            .map(|(offset, size)| offset + size)
            .max()
            .expect("chat-send hook has public exports");
        metadata.exports.insert(
            "chat_message_buffer".to_string(),
            (private_offset, (MAX_CHAT_WCHARS + 1) * 2),
        );
    }
    if let Some((first, second)) = template.movement_action_patches {
        metadata
            .patch_indices
            .insert("movement_forward".to_string(), first);
        metadata
            .patch_indices
            .insert("movement_backward".to_string(), second);
    }
    metadata.quiescence = Some((template.quiescence_offset, size_of::<u64>()));
    let payload_kind = template.payload_kind;
    let replay_original = template.replay_original;
    let payload_builder = |allocation| build_payload(payload_kind, allocation).0;
    hook::activate_feature_template(
        sessions,
        backend,
        mutations,
        hooks,
        &HookActivateRequest {
            session_id: request.session_id.clone(),
            hook_key: hook_key(request.hook),
            signature: template.signature,
            scope: template.scope,
            payload: template.payload,
        },
        template.target_offset,
        template.overwrite_size,
        template.resolved_target,
        template.auxiliary_patches,
        metadata,
        replay_original,
        &|allocation| Ok(payload_builder(allocation)),
        now,
    )?;
    timing.finish(
        "ok",
        json!({
            "fixture": fixture,
            "hook": hook_key(request.hook),
        }),
    );
    Ok(FeatureHookResponse {
        session_id: request.session_id.clone(),
        hook: request.hook,
        active: true,
    })
}

pub fn deactivate<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    request: &FeatureHookRequest,
) -> Result<FeatureHookDeactivateResponse, FeatureHookApiError> {
    let key = hook_key(request.hook);
    if hooks
        .allocation_address(&request.session_id, &key)
        .is_some()
    {
        match request.hook {
            FeatureHook::MovementTeleport => {
                let (helper, _) = hooks
                    .export_address(&request.session_id, &key, "teleport_helper")
                    .ok_or_else(|| {
                        FeatureHookApiError::request(
                            RpcErrorCode::InvalidRequest,
                            "movement hook exports are unavailable during deactivation",
                        )
                    })?;
                ensure_action_idle(
                    sessions,
                    backend,
                    &request.session_id,
                    helper + 12,
                    "teleport",
                )?;
            }
            FeatureHook::ChatSend => {
                for (export, action) in [
                    ("send_trigger", "chat send"),
                    ("buddy_trigger", "buddy add"),
                ] {
                    let (trigger, _) = hooks
                        .export_address(&request.session_id, &key, export)
                        .ok_or_else(|| {
                            FeatureHookApiError::request(
                                RpcErrorCode::InvalidRequest,
                                "chat-send hook exports are unavailable during deactivation",
                            )
                        })?;
                    ensure_action_idle(sessions, backend, &request.session_id, trigger, action)?;
                }
            }
            _ => {}
        }
    }
    let response = hook::deactivate(
        sessions,
        backend,
        mutations,
        hooks,
        &HookDeactivateRequest {
            session_id: request.session_id.clone(),
            hook_key: key,
        },
    )?;
    Ok(FeatureHookDeactivateResponse {
        session_id: request.session_id.clone(),
        hook: request.hook,
        deactivated: response.deactivated,
    })
}

pub fn heartbeat_all(
    hooks: &mut HookState,
    request: &FeatureHookSessionRequest,
    now: Instant,
) -> Result<FeatureHooksResponse, FeatureHookApiError> {
    let mut responses = Vec::new();
    for selected in FeatureHook::ALL {
        let key = hook_key(selected);
        if hooks
            .allocation_address(&request.session_id, &key)
            .is_none()
        {
            continue;
        }
        hook::heartbeat(
            hooks,
            &HookHeartbeatRequest {
                session_id: request.session_id.clone(),
                hook_key: key,
            },
            now,
        )?;
        responses.push(FeatureHookResponse {
            session_id: request.session_id.clone(),
            hook: selected,
            active: true,
        });
    }
    Ok(FeatureHooksResponse {
        session_id: request.session_id.clone(),
        hooks: responses,
    })
}

pub fn read_export<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    hooks: &HookState,
    request: &FeatureHookExportRequest,
) -> Result<FeatureHookExportResponse, FeatureHookApiError> {
    sessions.status(backend, &request.session_id)?;
    let selected = export_hook(request.export);
    let (address, _) = hooks
        .export_address(
            &request.session_id,
            &hook_key(selected),
            export_name(request.export),
        )
        .ok_or_else(|| {
            FeatureHookApiError::request(
                RpcErrorCode::InvalidRequest,
                format!("feature hook {selected:?} is not active"),
            )
        })?;
    Ok(FeatureHookExportResponse {
        session_id: request.session_id.clone(),
        export: request.export,
        address: format_address(address),
    })
}

pub fn set_mouse_position<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    hooks: &HookState,
    request: &FeatureMousePositionRequest,
) -> Result<FeatureActionResponse, FeatureHookApiError> {
    let address = export_address(
        sessions,
        backend,
        hooks,
        &request.session_id,
        FeatureHookExport::MousePosition,
    )?;
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&request.x.to_le_bytes());
    bytes.extend_from_slice(&request.y.to_le_bytes());
    write_at(sessions, backend, &request.session_id, address, bytes)?;
    Ok(action_response(&request.session_id, true))
}

pub fn teleport<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    hooks: &mut HookState,
    request: &FeatureTeleportRequest,
) -> Result<FeatureActionResponse, FeatureHookApiError> {
    let helper = export_address(
        sessions,
        backend,
        hooks,
        &request.session_id,
        FeatureHookExport::TeleportHelper,
    )?;
    let fixture = sessions.process_kind(&request.session_id) == Some(ProcessKind::MemoryFixture);
    if read_at(sessions, backend, &request.session_id, helper + 12, 1)?[0] != 0 {
        if !request.wait_on_inuse {
            return Err(FeatureHookApiError::request(
                RpcErrorCode::InvalidRequest,
                "a teleport is already pending",
            ));
        }
        wait_for_zero(
            sessions,
            backend,
            &request.session_id,
            helper + 12,
            request.wait_timeout_ms,
        )?;
    }
    let object_address = parse_address(&request.object_address)?;
    if request
        .position
        .iter()
        .any(|coordinate| !coordinate.is_finite())
    {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::InvalidRequest,
            "teleport coordinates must be finite numbers",
        ));
    }
    let current_client = core_hook::read_base(
        sessions,
        backend,
        hooks,
        &CoreHookRequest {
            session_id: request.session_id.clone(),
            hook: CoreHook::Client,
        },
    )?;
    let current_client_address = parse_address(&current_client.base_address)?;
    if current_client_address == 0 {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::InvalidRequest,
            "teleport is unavailable while the current client object is loading",
        ));
    }
    if current_client_address != object_address {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::InvalidRequest,
            "the client object changed before teleporting; wait for the zone to finish loading and try again",
        ));
    }
    let movement_key = hook_key(FeatureHook::MovementTeleport);
    let first_patch = hooks
        .patch_index(&request.session_id, &movement_key, "movement_forward")
        .ok_or_else(|| {
            FeatureHookApiError::request(
                RpcErrorCode::InvalidRequest,
                "movement hook action patches are unavailable",
            )
        })?;
    let second_patch = hooks
        .patch_index(&request.session_id, &movement_key, "movement_backward")
        .ok_or_else(|| {
            FeatureHookApiError::request(
                RpcErrorCode::InvalidRequest,
                "movement hook action patches are unavailable",
            )
        })?;
    if let Err(error) = hook::apply_owned_patch(
        sessions,
        backend,
        hooks,
        &request.session_id,
        &movement_key,
        first_patch,
    ) {
        let _ = hook::restore_owned_patch(
            sessions,
            backend,
            hooks,
            &request.session_id,
            &movement_key,
            first_patch,
        );
        return Err(error.into());
    }
    if let Err(error) = hook::apply_owned_patch(
        sessions,
        backend,
        hooks,
        &request.session_id,
        &movement_key,
        second_patch,
    ) {
        let cleanup = restore_movement_action_patches(
            sessions,
            backend,
            hooks,
            &request.session_id,
            first_patch,
            second_patch,
        );
        return match cleanup {
            Ok(()) => Err(error.into()),
            Err(cleanup_error) => Err(cleanup_error),
        };
    }
    let mut bytes = Vec::with_capacity(21);
    for coordinate in request.position {
        bytes.extend_from_slice(&coordinate.to_le_bytes());
    }
    bytes.push(1);
    bytes.extend_from_slice(&(object_address as u64).to_le_bytes());
    let action_result = (|| {
        write_at(sessions, backend, &request.session_id, helper, bytes)?;
        if fixture {
            write_at(sessions, backend, &request.session_id, helper + 12, vec![0])?;
            return Ok(action_response(&request.session_id, true));
        }
        if !request.purge_after_timeout {
            return Ok(action_response(&request.session_id, true));
        }
        match wait_for_zero(
            sessions,
            backend,
            &request.session_id,
            helper + 12,
            request.purge_timeout_ms,
        ) {
            Ok(()) => Ok(action_response(&request.session_id, true)),
            Err(FeatureHookApiError::Request {
                code: RpcErrorCode::Timeout,
                ..
            }) => {
                write_at(sessions, backend, &request.session_id, helper + 12, vec![0])?;
                Ok(action_response(&request.session_id, false))
            }
            Err(error) => Err(error),
        }
    })();
    if !fixture && !request.purge_after_timeout && action_result.is_ok() {
        return action_result;
    }
    let cleanup = restore_movement_action_patches(
        sessions,
        backend,
        hooks,
        &request.session_id,
        first_patch,
        second_patch,
    );
    match cleanup {
        Ok(()) => action_result,
        Err(error) => Err(error),
    }
}

fn restore_movement_action_patches<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    hooks: &HookState,
    session_id: &ProcessSessionId,
    first: usize,
    second: usize,
) -> Result<(), FeatureHookApiError> {
    let second_result = hook::restore_owned_patch(
        sessions,
        backend,
        hooks,
        session_id,
        &hook_key(FeatureHook::MovementTeleport),
        second,
    );
    let first_result = hook::restore_owned_patch(
        sessions,
        backend,
        hooks,
        session_id,
        &hook_key(FeatureHook::MovementTeleport),
        first,
    );
    second_result?;
    first_result?;
    Ok(())
}

pub fn send_chat<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    hooks: &HookState,
    request: &FeatureChatSendRequest,
) -> Result<FeatureActionResponse, FeatureHookApiError> {
    if request.message.is_empty() {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::InvalidRequest,
            "chat messages cannot be empty",
        ));
    }
    if request.message.chars().count() > MAX_CHAT_WCHARS {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            format!("chat messages cannot exceed {MAX_CHAT_WCHARS} characters"),
        ));
    }
    let trigger = export_address(
        sessions,
        backend,
        hooks,
        &request.session_id,
        FeatureHookExport::SendTrigger,
    )?;
    ensure_action_idle(sessions, backend, &request.session_id, trigger, "chat send")?;
    let structure = export_address(
        sessions,
        backend,
        hooks,
        &request.session_id,
        FeatureHookExport::SendStruct,
    )?;
    let encoded = request.message.encode_utf16().collect::<Vec<_>>();
    if encoded.len() > MAX_CHAT_WCHARS {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            format!("chat messages cannot exceed {MAX_CHAT_WCHARS} UTF-16 code units"),
        ));
    }
    let mut value = [0u8; 0x28];
    if encoded.len() <= 7 {
        for (index, character) in encoded.iter().enumerate() {
            value[index * 2..index * 2 + 2].copy_from_slice(&character.to_le_bytes());
        }
        value[0x18..0x20].copy_from_slice(&7u64.to_le_bytes());
    } else {
        value[0x18..0x20].copy_from_slice(&(encoded.len() as u64).to_le_bytes());
    }
    value[0x10..0x18].copy_from_slice(&(encoded.len() as u64).to_le_bytes());
    value[0x20..0x28].copy_from_slice(&request.target_gid.to_le_bytes());
    let buffer = private_chat_buffer_address(hooks, &request.session_id)?;
    let mut message_bytes = Vec::with_capacity((encoded.len() + 1) * 2);
    for character in encoded {
        message_bytes.extend_from_slice(&character.to_le_bytes());
    }
    message_bytes.extend_from_slice(&[0, 0]);
    write_at(
        sessions,
        backend,
        &request.session_id,
        buffer,
        message_bytes,
    )?;
    write_at(
        sessions,
        backend,
        &request.session_id,
        structure,
        value.to_vec(),
    )?;
    let response = trigger_and_wait(sessions, backend, &request.session_id, trigger);
    if response.is_ok() {
        write_at(
            sessions,
            backend,
            &request.session_id,
            structure,
            vec![0; 0x28],
        )?;
    }
    response
}

fn private_chat_buffer_address(
    hooks: &HookState,
    session_id: &ProcessSessionId,
) -> Result<usize, FeatureHookApiError> {
    hooks
        .export_address(
            session_id,
            &hook_key(FeatureHook::ChatSend),
            "chat_message_buffer",
        )
        .map(|(address, _)| address)
        .ok_or_else(|| {
            FeatureHookApiError::request(
                RpcErrorCode::InvalidRequest,
                "chat-send hook is not active",
            )
        })
}

pub fn add_buddy<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    hooks: &HookState,
    request: &FeatureBuddyAddRequest,
) -> Result<FeatureActionResponse, FeatureHookApiError> {
    let trigger = export_address(
        sessions,
        backend,
        hooks,
        &request.session_id,
        FeatureHookExport::BuddyTrigger,
    )?;
    ensure_action_idle(sessions, backend, &request.session_id, trigger, "buddy add")?;
    let object = export_address(
        sessions,
        backend,
        hooks,
        &request.session_id,
        FeatureHookExport::BuddyObject,
    )?;
    write_at(
        sessions,
        backend,
        &request.session_id,
        object + 0xe0,
        request.target_gid.to_le_bytes().to_vec(),
    )?;
    trigger_and_wait(sessions, backend, &request.session_id, trigger)
}

fn trigger_and_wait<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    trigger: usize,
) -> Result<FeatureActionResponse, FeatureHookApiError> {
    write_at(sessions, backend, session_id, trigger, vec![1])?;
    if sessions.process_kind(session_id) == Some(ProcessKind::MemoryFixture) {
        write_at(sessions, backend, session_id, trigger, vec![0])?;
    }
    wait_for_zero(sessions, backend, session_id, trigger, 4_000)?;
    Ok(action_response(session_id, true))
}

fn ensure_action_idle<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    trigger: usize,
    action: &str,
) -> Result<(), FeatureHookApiError> {
    if read_at(sessions, backend, session_id, trigger, 1)?[0] != 0 {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::InvalidRequest,
            format!("the previous {action} action is still pending"),
        ));
    }
    Ok(())
}

fn export_address<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    hooks: &HookState,
    session_id: &ProcessSessionId,
    export: FeatureHookExport,
) -> Result<usize, FeatureHookApiError> {
    let response = read_export(
        sessions,
        backend,
        hooks,
        &FeatureHookExportRequest {
            session_id: session_id.clone(),
            export,
        },
    )?;
    parse_address(&response.address)
}

fn write_at<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    address: usize,
    bytes: Vec<u8>,
) -> Result<(), FeatureHookApiError> {
    mutation::write(
        sessions,
        backend,
        &MemoryWriteRequest {
            session_id: session_id.clone(),
            address: format_address(address),
            bytes,
        },
    )?;
    Ok(())
}

fn read_at<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    address: usize,
    size: usize,
) -> Result<Vec<u8>, FeatureHookApiError> {
    Ok(memory::read(
        sessions,
        backend,
        &MemoryReadRequest {
            session_id: session_id.clone(),
            address: format_address(address),
            size,
        },
    )?
    .bytes)
}

fn wait_for_zero<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    address: usize,
    timeout_ms: u32,
) -> Result<(), FeatureHookApiError> {
    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
    loop {
        if read_at(sessions, backend, session_id, address, 1)?[0] == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(FeatureHookApiError::request(
                RpcErrorCode::Timeout,
                "the feature hook did not complete before its timeout",
            ));
        }
        thread::sleep(ACTION_POLL);
    }
}

fn action_response(session_id: &ProcessSessionId, completed: bool) -> FeatureActionResponse {
    FeatureActionResponse {
        session_id: session_id.clone(),
        completed,
    }
}

fn hook_key(hook: FeatureHook) -> String {
    format!(
        "wizwalker.feature.{}",
        match hook {
            FeatureHook::MovementTeleport => "movement_teleport",
            FeatureHook::MouselessCursor => "mouseless_cursor",
            FeatureHook::Chat => "chat",
            FeatureHook::ChatSend => "chat_send",
            FeatureHook::DanceGameMoves => "dance_game_moves",
        }
    )
}

fn export_hook(export: FeatureHookExport) -> FeatureHook {
    match export {
        FeatureHookExport::TeleportHelper => FeatureHook::MovementTeleport,
        FeatureHookExport::MousePosition => FeatureHook::MouselessCursor,
        FeatureHookExport::ChatOwner
        | FeatureHookExport::ReceiveSourceGid
        | FeatureHookExport::ReceiveMessageBuffer
        | FeatureHookExport::ReceiveMessageLength
        | FeatureHookExport::ReceiveCounter => FeatureHook::Chat,
        FeatureHookExport::SendTrigger
        | FeatureHookExport::SendStruct
        | FeatureHookExport::BuddyTrigger
        | FeatureHookExport::BuddyObject => FeatureHook::ChatSend,
        FeatureHookExport::DanceGameMoves => FeatureHook::DanceGameMoves,
    }
}

fn export_name(export: FeatureHookExport) -> &'static str {
    match export {
        FeatureHookExport::TeleportHelper => "teleport_helper",
        FeatureHookExport::MousePosition => "mouse_position",
        FeatureHookExport::ChatOwner => "chat_owner",
        FeatureHookExport::ReceiveSourceGid => "recv_source_gid",
        FeatureHookExport::ReceiveMessageBuffer => "recv_message_buf",
        FeatureHookExport::ReceiveMessageLength => "recv_message_len",
        FeatureHookExport::ReceiveCounter => "recv_counter",
        FeatureHookExport::SendTrigger => "send_trigger",
        FeatureHookExport::SendStruct => "send_struct",
        FeatureHookExport::BuddyTrigger => "buddy_trigger",
        FeatureHookExport::BuddyObject => "buddy_obj",
        FeatureHookExport::DanceGameMoves => "dance_game_moves",
    }
}

fn template_for_target<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    hook: FeatureHook,
    fixture: bool,
) -> Result<Template, FeatureHookApiError> {
    if fixture {
        return fixture_template(sessions, backend, session_id, hook);
    }
    match hook {
        FeatureHook::MovementTeleport => movement_template(sessions, backend, session_id),
        FeatureHook::ChatSend => {
            let send = resolve_send_function(sessions, backend, session_id)?;
            let buddy = resolve_buddy_function(sessions, backend, session_id)?;
            let operator_new = resolve_relative_call(sessions, backend, session_id, send + 0xf4)?;
            let target = resolve_unique_pattern(
                sessions,
                backend,
                session_id,
                "38 9F ?? ?? ?? ?? 74 ?? E8 ?? ?? ?? ?? 83 F8 64 0F 8F",
                module_scope(),
            )?;
            let kind = PayloadKind::ChatSend {
                send,
                buddy,
                operator_new,
            };
            let (payload, exports, quiescence_offset) = build_payload(kind, 0);
            Ok(Template {
                signature: exact_signature(sessions, backend, session_id, target, 18)?,
                scope: MemoryScanScope::Process,
                target_offset: 0,
                overwrite_size: 6,
                payload,
                exports,
                resolved_target: Some(target),
                auxiliary_patches: Vec::new(),
                movement_action_patches: None,
                payload_kind: kind,
                replay_original: true,
                quiescence_offset,
            })
        }
        FeatureHook::Chat => {
            let target = resolve_chat_target(sessions, backend, session_id)?;
            resolved_template(sessions, backend, session_id, target, 7, PayloadKind::Chat)
        }
        FeatureHook::DanceGameMoves => {
            let target = resolve_unique_pattern(
                sessions,
                backend,
                session_id,
                "48 8B F8 48 39 70 10",
                module_scope(),
            )?;
            resolved_template(sessions, backend, session_id, target, 7, PayloadKind::Dance)
        }
        FeatureHook::MouselessCursor => mouse_template(sessions, backend, session_id),
    }
}

fn resolved_template<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    target: usize,
    overwrite_size: usize,
    payload_kind: PayloadKind,
) -> Result<Template, FeatureHookApiError> {
    let signature = exact_signature(sessions, backend, session_id, target, 32)?;
    let (payload, exports, quiescence_offset) = build_payload(payload_kind, 0);
    Ok(Template {
        signature,
        scope: MemoryScanScope::Process,
        target_offset: 0,
        overwrite_size,
        payload,
        exports,
        resolved_target: Some(target),
        auxiliary_patches: Vec::new(),
        movement_action_patches: None,
        payload_kind,
        replay_original: true,
        quiescence_offset,
    })
}

fn fixture_template<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    hook: FeatureHook,
) -> Result<Template, FeatureHookApiError> {
    let marker = match hook {
        FeatureHook::MovementTeleport => 1,
        FeatureHook::MouselessCursor => 2,
        FeatureHook::Chat => 3,
        FeatureHook::ChatSend => 4,
        FeatureHook::DanceGameMoves => 5,
    };
    let target = resolve_unique_pattern(
        sessions,
        backend,
        session_id,
        &format!("B8 {marker:02X} D1 C0 00 90 90 90 90 90 90 90 90 90 90 C3"),
        MemoryScanScope::Process,
    )?;
    let mut auxiliary_patches = Vec::new();
    let mut movement_action_patches = None;
    let payload_kind = match hook {
        FeatureHook::MovementTeleport => {
            let first = resolve_fixture_patch(sessions, backend, session_id, 0x11)?;
            let second = resolve_fixture_patch(sessions, backend, session_id, 0x12)?;
            let collision_one = resolve_fixture_patch(sessions, backend, session_id, 0x13)?;
            let collision_two = resolve_fixture_patch(sessions, backend, session_id, 0x14)?;
            let first_original = array8(read_at(sessions, backend, session_id, first, 8)?)?;
            let second_original = array8(read_at(sessions, backend, session_id, second, 8)?)?;
            auxiliary_patches.push(patch(
                collision_one,
                2,
                vec![0x90; 2],
                true,
                sessions,
                backend,
                session_id,
            )?);
            auxiliary_patches.push(patch(
                collision_two,
                2,
                vec![0x90; 2],
                true,
                sessions,
                backend,
                session_id,
            )?);
            auxiliary_patches.push(HookPatch {
                address: first,
                expected_bytes: first_original.to_vec(),
                replacement_bytes: [vec![0x90; 6], first_original[6..].to_vec()].concat(),
                apply_on_activation: false,
                keep_writable: true,
            });
            auxiliary_patches.push(HookPatch {
                address: second,
                expected_bytes: second_original.to_vec(),
                replacement_bytes: [vec![0x90; 6], second_original[6..].to_vec()].concat(),
                apply_on_activation: false,
                keep_writable: true,
            });
            movement_action_patches = Some((2, 3));
            PayloadKind::Movement {
                first_je: first,
                second_je: second,
                first_original,
                second_original,
            }
        }
        FeatureHook::MouselessCursor => {
            for selected in [0x21, 0x22, 0x23] {
                let address = resolve_fixture_patch(sessions, backend, session_id, selected)?;
                let (size, replacement) = if selected == 0x21 {
                    (6, vec![0xc3, 0x90, 0x90, 0x90, 0x90, 0x90])
                } else {
                    (1, vec![1])
                };
                auxiliary_patches.push(patch(
                    address,
                    size,
                    replacement,
                    true,
                    sessions,
                    backend,
                    session_id,
                )?);
            }
            PayloadKind::Mouse
        }
        FeatureHook::Chat => PayloadKind::Chat,
        FeatureHook::ChatSend => PayloadKind::ChatSend {
            send: 0,
            buddy: 0,
            operator_new: 0,
        },
        FeatureHook::DanceGameMoves => PayloadKind::Dance,
    };
    let (payload, exports, quiescence_offset) = build_payload(payload_kind, 0);
    Ok(Template {
        signature: exact_signature(sessions, backend, session_id, target, 16)?,
        scope: MemoryScanScope::Process,
        target_offset: 0,
        overwrite_size: 16,
        payload,
        exports,
        resolved_target: Some(target),
        auxiliary_patches,
        movement_action_patches,
        payload_kind,
        replay_original: hook != FeatureHook::MouselessCursor,
        quiescence_offset,
    })
}

fn module_scope() -> MemoryScanScope {
    MemoryScanScope::Module {
        name: MODULE.to_string(),
    }
}

fn resolve_unique_pattern<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    signature: &str,
    scope: MemoryScanScope,
) -> Result<usize, FeatureHookApiError> {
    let response = memory::scan(
        sessions,
        backend,
        &MemoryScanRequest {
            session_id: session_id.clone(),
            signature: signature.to_string(),
            required: true,
            unique: true,
            max_matches: 2,
            scope,
        },
    )?;
    parse_address(
        response
            .matches
            .first()
            .expect("required unique scan result"),
    )
}

fn resolve_unique_patterns<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    signatures: &[&str],
    scope: MemoryScanScope,
) -> Result<Vec<usize>, FeatureHookApiError> {
    memory::scan_optional_unique_signatures(sessions, backend, session_id, &scope, signatures)?
        .into_iter()
        .enumerate()
        .map(|(index, address)| {
            address.ok_or_else(|| {
                FeatureHookApiError::request(
                    RpcErrorCode::MemoryRequiredMatchNotFound,
                    format!("required feature-hook signature at index {index} was not found"),
                )
            })
        })
        .collect()
}

fn resolve_chat_target<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
) -> Result<usize, FeatureHookApiError> {
    let base = resolve_disambiguated(
        sessions,
        backend,
        session_id,
        "48 89 5C 24 18 48 89 74 24 20 55 57 41 56 48 8D AC 24 40 FF FF FF 48 81 EC C0 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 B0 00 00 00 48 8B FA 48 8B F1 45 33 F6",
        &[(0x7e, CHAT_TYPE_MARKER), (0x379, CHAT_HOOK_SITE)],
    )?;
    base.checked_add(0x379).ok_or_else(|| {
        FeatureHookApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "chat hook target overflowed the agent address width",
        )
    })
}

fn resolve_send_function<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
) -> Result<usize, FeatureHookApiError> {
    resolve_disambiguated(
        sessions,
        backend,
        session_id,
        "48 89 5C 24 18 55 56 57 48 8D AC 24 30 FF FF FF 48 81 EC D0 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 C0 00 00 00 48 8B DA 48 8B F9",
        &[(0x33, SEND_FUNCTION_MARKER)],
    )
}

fn resolve_buddy_function<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
) -> Result<usize, FeatureHookApiError> {
    let response = memory::scan(
        sessions,
        backend,
        &MemoryScanRequest {
            session_id: session_id.clone(),
            signature: "48 81 EC A0 00 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 90 00 00 00 48 8B D9 48 89 54 24 20 BA 10 00 00 00 48 8D 4C 24 30".to_string(),
            required: true,
            unique: false,
            max_matches: 64,
            scope: module_scope(),
        },
    )?;
    let mut selected = None;
    for candidate in response.matches {
        let candidate = parse_address(&candidate)?;
        let instruction = candidate + 0x70;
        if read_at(sessions, backend, session_id, instruction, 3)? != [0x0f, 0x10, 0x05] {
            continue;
        }
        let displacement = i32::from_le_bytes(
            read_at(sessions, backend, session_id, instruction + 3, 4)?
                .try_into()
                .expect("four-byte displacement read"),
        );
        let string_address = usize::try_from((instruction + 7) as i128 + displacement as i128)
            .map_err(|_| {
                FeatureHookApiError::request(
                    RpcErrorCode::MemoryInvalidAddress,
                    "buddy function string address exceeded the agent address width",
                )
            })?;
        if read_at(sessions, backend, session_id, string_address, 19)? != b"MSG_BUDDYREQUESTADD" {
            continue;
        }
        if selected.replace(candidate).is_some() {
            return Err(FeatureHookApiError::request(
                RpcErrorCode::MemoryAmbiguousMatch,
                "more than one buddy-add function passed string verification",
            ));
        }
    }
    let base = selected.ok_or_else(|| {
        FeatureHookApiError::request(
            RpcErrorCode::MemoryRequiredMatchNotFound,
            "buddy-add function could not be verified against MSG_BUDDYREQUESTADD",
        )
    })?;
    base.checked_sub(2).ok_or_else(|| {
        FeatureHookApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "buddy hook function address underflowed",
        )
    })
}

fn resolve_disambiguated<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    signature: &str,
    probes: &[(usize, &[u8])],
) -> Result<usize, FeatureHookApiError> {
    let response = memory::scan(
        sessions,
        backend,
        &MemoryScanRequest {
            session_id: session_id.clone(),
            signature: signature.to_string(),
            required: true,
            unique: false,
            max_matches: 64,
            scope: module_scope(),
        },
    )?;
    let candidates = response
        .matches
        .iter()
        .map(|candidate| parse_address(candidate))
        .collect::<Result<Vec<_>, _>>()?;
    select_disambiguated_candidate(&candidates, probes, &mut |address, size| {
        read_at(sessions, backend, session_id, address, size)
    })?
    .ok_or_else(|| {
        FeatureHookApiError::request(
            RpcErrorCode::MemoryRequiredMatchNotFound,
            "feature-hook function marker was not found",
        )
    })
}

fn select_disambiguated_candidate(
    candidates: &[usize],
    probes: &[(usize, &[u8])],
    read: &mut dyn FnMut(usize, usize) -> Result<Vec<u8>, FeatureHookApiError>,
) -> Result<Option<usize>, FeatureHookApiError> {
    let mut selected = None;
    for candidate in candidates {
        let mut matches = true;
        for (offset, expected) in probes {
            let address = candidate.checked_add(*offset).ok_or_else(|| {
                FeatureHookApiError::request(
                    RpcErrorCode::MemoryInvalidAddress,
                    "feature-hook disambiguation address overflowed the agent address width",
                )
            })?;
            if read(address, expected.len())? != *expected {
                matches = false;
                break;
            }
        }
        if matches && selected.replace(*candidate).is_some() {
            return Err(FeatureHookApiError::request(
                RpcErrorCode::MemoryAmbiguousMatch,
                "feature-hook disambiguation matched more than one function",
            ));
        }
    }
    Ok(selected)
}

fn resolve_relative_call<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    call_address: usize,
) -> Result<usize, FeatureHookApiError> {
    let instruction = read_at(sessions, backend, session_id, call_address, 5)?;
    if instruction.first() != Some(&0xe8) {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::MemoryRequiredMatchNotFound,
            format!("expected a relative call at {call_address:#x}"),
        ));
    }
    let displacement = i32::from_le_bytes(
        instruction[1..5]
            .try_into()
            .expect("a five-byte call contains a four-byte displacement"),
    );
    let continuation = call_address.checked_add(5).ok_or_else(|| {
        FeatureHookApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "relative call continuation overflowed the agent address width",
        )
    })?;
    usize::try_from((continuation as i128) + (displacement as i128)).map_err(|_| {
        FeatureHookApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "relative call target exceeded the agent address width",
        )
    })
}

fn resolve_remote_export<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    module: &str,
    symbol: &str,
    depth: usize,
) -> Result<usize, FeatureHookApiError> {
    let modules = sessions.modules(backend, session_id)?.modules;
    resolve_export_from_modules(
        &modules,
        module,
        ExportLookup::Name(symbol.to_string()),
        depth,
        &mut |address, size| read_at(sessions, backend, session_id, address, size),
    )
}

#[derive(Clone, Debug)]
enum ExportLookup {
    Name(String),
    Ordinal(u32),
}

fn resolve_export_from_modules(
    modules: &[ModuleDescriptor],
    module_name: &str,
    lookup: ExportLookup,
    depth: usize,
    read: &mut dyn FnMut(usize, usize) -> Result<Vec<u8>, FeatureHookApiError>,
) -> Result<usize, FeatureHookApiError> {
    if depth > MAX_EXPORT_FORWARD_DEPTH {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            "remote export forwarder chain exceeded the supported depth",
        ));
    }
    let module = find_module(modules, module_name).ok_or_else(|| {
        FeatureHookApiError::request(
            RpcErrorCode::MemoryRequiredMatchNotFound,
            format!("target process has no loaded module named {module_name}"),
        )
    })?;
    let base = parse_address(&module.base_address)?;
    let image_size = module.size as usize;
    let dos = read_image(read, base, image_size, 0, 0x40, &module.name)?;
    if dos.get(0..2) != Some(b"MZ") {
        return Err(malformed_export(&module.name, "DOS signature is not MZ"));
    }
    let pe_offset = read_u32(&dos, 0x3c, &module.name, "e_lfanew")? as usize;
    let nt = read_image(read, base, image_size, pe_offset, 0x90, &module.name)?;
    if nt.get(0..4) != Some(b"PE\0\0") {
        return Err(malformed_export(&module.name, "PE signature is invalid"));
    }
    let optional_magic = read_u16(&nt, 24, &module.name, "optional-header magic")?;
    let (data_directory, number_of_directories) = match optional_magic {
        0x10b => (24 + 96, 24 + 92),
        0x20b => (24 + 112, 24 + 108),
        _ => {
            return Err(malformed_export(
                &module.name,
                "optional-header magic is neither PE32 nor PE32+",
            ))
        }
    };
    let optional_size = read_u16(&nt, 20, &module.name, "optional-header size")? as usize;
    if optional_size < data_directory - 24 + 8 {
        return Err(malformed_export(
            &module.name,
            "optional header does not contain the export data directory",
        ));
    }
    if read_u32(
        &nt,
        number_of_directories,
        &module.name,
        "data-directory count",
    )? == 0
    {
        return Err(malformed_export(
            &module.name,
            "optional header reports no data directories",
        ));
    }
    let declared_image_size = read_u32(&nt, 24 + 56, &module.name, "image size")? as usize;
    if declared_image_size == 0 || declared_image_size > image_size {
        return Err(malformed_export(
            &module.name,
            "optional-header image size exceeds the loaded module bounds",
        ));
    }
    let export_rva = read_u32(&nt, data_directory, &module.name, "export RVA")? as usize;
    let export_size = read_u32(&nt, data_directory + 4, &module.name, "export size")? as usize;
    if export_rva == 0 || export_size < 40 {
        return Err(FeatureHookApiError::request(
            RpcErrorCode::MemoryRequiredMatchNotFound,
            format!(
                "target module {} has no usable export directory",
                module.name
            ),
        ));
    }
    checked_rva(
        image_size,
        export_rva,
        export_size,
        &module.name,
        "export directory",
    )?;
    let directory = read_image(read, base, image_size, export_rva, 40, &module.name)?;
    let ordinal_base = read_u32(&directory, 16, &module.name, "ordinal base")?;
    let function_count = table_count(
        read_u32(&directory, 20, &module.name, "function count")?,
        &module.name,
    )?;
    if function_count == 0 {
        return Err(malformed_export(
            &module.name,
            "export function table is empty",
        ));
    }
    let name_count = table_count(
        read_u32(&directory, 24, &module.name, "name count")?,
        &module.name,
    )?;
    let functions_rva = read_u32(&directory, 28, &module.name, "function table RVA")? as usize;
    let names_rva = read_u32(&directory, 32, &module.name, "name table RVA")? as usize;
    let ordinals_rva = read_u32(&directory, 36, &module.name, "ordinal table RVA")? as usize;
    checked_rva(
        image_size,
        functions_rva,
        function_count
            .checked_mul(4)
            .ok_or_else(|| malformed_export(&module.name, "function table size overflowed"))?,
        &module.name,
        "function table",
    )?;

    let function_index = match lookup {
        ExportLookup::Ordinal(ordinal) => {
            if ordinal < ordinal_base {
                return Err(malformed_export(
                    &module.name,
                    "export ordinal is below the module ordinal base",
                ));
            }
            usize::try_from(ordinal - ordinal_base).map_err(|_| {
                malformed_export(&module.name, "export ordinal exceeded agent width")
            })?
        }
        ExportLookup::Name(name) => {
            checked_rva(
                image_size,
                names_rva,
                name_count
                    .checked_mul(4)
                    .ok_or_else(|| malformed_export(&module.name, "name table size overflowed"))?,
                &module.name,
                "name table",
            )?;
            checked_rva(
                image_size,
                ordinals_rva,
                name_count.checked_mul(2).ok_or_else(|| {
                    malformed_export(&module.name, "ordinal table size overflowed")
                })?,
                &module.name,
                "ordinal table",
            )?;
            let mut selected = None;
            for index in 0..name_count {
                let name_rva = read_image_u32(
                    read,
                    base,
                    image_size,
                    names_rva + index * 4,
                    &module.name,
                    "export name RVA",
                )? as usize;
                let candidate =
                    read_image_c_string(read, base, image_size, name_rva, &module.name)?;
                if candidate == name {
                    selected = Some(read_image_u16(
                        read,
                        base,
                        image_size,
                        ordinals_rva + index * 2,
                        &module.name,
                        "export name ordinal",
                    )? as usize);
                    break;
                }
            }
            selected.ok_or_else(|| {
                FeatureHookApiError::request(
                    RpcErrorCode::MemoryRequiredMatchNotFound,
                    format!("target module {} does not export {name}", module.name),
                )
            })?
        }
    };
    if function_index >= function_count {
        return Err(malformed_export(
            &module.name,
            "export ordinal indexes past the function table",
        ));
    }
    let function_rva = read_image_u32(
        read,
        base,
        image_size,
        functions_rva + function_index * 4,
        &module.name,
        "export function RVA",
    )? as usize;
    if function_rva == 0 {
        return Err(malformed_export(
            &module.name,
            "export function RVA is null",
        ));
    }
    let export_end = export_rva
        .checked_add(export_size)
        .expect("validated export directory end");
    if function_rva >= export_rva && function_rva < export_end {
        let forwarder = read_image_c_string_limited(
            read,
            base,
            image_size,
            function_rva,
            export_end - function_rva,
            &module.name,
        )?;
        let (forward_module, forward_symbol) = forwarder.rsplit_once('.').ok_or_else(|| {
            malformed_export(
                &module.name,
                "export forwarder does not contain a module and symbol",
            )
        })?;
        let forwarded_lookup = if let Some(ordinal) = forward_symbol.strip_prefix('#') {
            ExportLookup::Ordinal(ordinal.parse::<u32>().map_err(|_| {
                malformed_export(&module.name, "forwarded export ordinal is invalid")
            })?)
        } else {
            ExportLookup::Name(forward_symbol.to_string())
        };
        return resolve_export_from_modules(
            modules,
            forward_module,
            forwarded_lookup,
            depth + 1,
            read,
        );
    }
    checked_rva(image_size, function_rva, 1, &module.name, "export function")?;
    base.checked_add(function_rva).ok_or_else(|| {
        FeatureHookApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "remote export address overflowed the agent address width",
        )
    })
}

fn find_module<'a>(
    modules: &'a [ModuleDescriptor],
    requested: &str,
) -> Option<&'a ModuleDescriptor> {
    let requested = normalize_module_name(requested);
    modules
        .iter()
        .find(|module| normalize_module_name(&module.name) == requested)
}

fn normalize_module_name(value: &str) -> String {
    let name = value.rsplit(['\\', '/']).next().unwrap_or(value);
    let lower = name.to_ascii_lowercase();
    if lower.contains('.') {
        lower
    } else {
        format!("{lower}.dll")
    }
}

fn read_image(
    read: &mut dyn FnMut(usize, usize) -> Result<Vec<u8>, FeatureHookApiError>,
    base: usize,
    image_size: usize,
    rva: usize,
    size: usize,
    module: &str,
) -> Result<Vec<u8>, FeatureHookApiError> {
    checked_rva(image_size, rva, size, module, "read")?;
    let address = base
        .checked_add(rva)
        .ok_or_else(|| malformed_export(module, "remote image address overflowed"))?;
    let bytes = read(address, size)?;
    if bytes.len() != size {
        return Err(malformed_export(
            module,
            "remote image read returned a short buffer",
        ));
    }
    Ok(bytes)
}

fn read_image_u32(
    read: &mut dyn FnMut(usize, usize) -> Result<Vec<u8>, FeatureHookApiError>,
    base: usize,
    image_size: usize,
    rva: usize,
    module: &str,
    field: &str,
) -> Result<u32, FeatureHookApiError> {
    read_u32(
        &read_image(read, base, image_size, rva, 4, module)?,
        0,
        module,
        field,
    )
}

fn read_image_u16(
    read: &mut dyn FnMut(usize, usize) -> Result<Vec<u8>, FeatureHookApiError>,
    base: usize,
    image_size: usize,
    rva: usize,
    module: &str,
    field: &str,
) -> Result<u16, FeatureHookApiError> {
    read_u16(
        &read_image(read, base, image_size, rva, 2, module)?,
        0,
        module,
        field,
    )
}

fn read_image_c_string(
    read: &mut dyn FnMut(usize, usize) -> Result<Vec<u8>, FeatureHookApiError>,
    base: usize,
    image_size: usize,
    rva: usize,
    module: &str,
) -> Result<String, FeatureHookApiError> {
    checked_rva(image_size, rva, 1, module, "export string")?;
    let available = (image_size - rva).min(MAX_EXPORT_NAME_BYTES);
    let bytes = read_image(read, base, image_size, rva, available, module)?;
    let end = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
        malformed_export(
            module,
            "export string is not null-terminated within its image bounds",
        )
    })?;
    std::str::from_utf8(&bytes[..end])
        .map(str::to_string)
        .map_err(|_| malformed_export(module, "export string is not valid ASCII-compatible UTF-8"))
}

fn read_image_c_string_limited(
    read: &mut dyn FnMut(usize, usize) -> Result<Vec<u8>, FeatureHookApiError>,
    base: usize,
    image_size: usize,
    rva: usize,
    limit: usize,
    module: &str,
) -> Result<String, FeatureHookApiError> {
    checked_rva(image_size, rva, 1, module, "export forwarder")?;
    let available = (image_size - rva).min(limit).min(MAX_EXPORT_NAME_BYTES);
    let bytes = read_image(read, base, image_size, rva, available, module)?;
    let end = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
        malformed_export(
            module,
            "export forwarder is not null-terminated inside the export directory",
        )
    })?;
    std::str::from_utf8(&bytes[..end])
        .map(str::to_string)
        .map_err(|_| {
            malformed_export(
                module,
                "export forwarder is not valid ASCII-compatible UTF-8",
            )
        })
}

fn checked_rva(
    image_size: usize,
    rva: usize,
    size: usize,
    module: &str,
    field: &str,
) -> Result<(), FeatureHookApiError> {
    let outside_image = match rva.checked_add(size) {
        Some(end) => end > image_size,
        None => true,
    };
    if size == 0 || outside_image {
        return Err(malformed_export(
            module,
            &format!("{field} extends outside the remote image"),
        ));
    }
    Ok(())
}

fn table_count(value: u32, module: &str) -> Result<usize, FeatureHookApiError> {
    let value = value as usize;
    if value > MAX_EXPORT_TABLE_ENTRIES {
        return Err(malformed_export(
            module,
            "export table count exceeds its safety limit",
        ));
    }
    Ok(value)
}

fn read_u32(
    bytes: &[u8],
    offset: usize,
    module: &str,
    field: &str,
) -> Result<u32, FeatureHookApiError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| malformed_export(module, &format!("{field} is truncated")))
}

fn read_u16(
    bytes: &[u8],
    offset: usize,
    module: &str,
    field: &str,
) -> Result<u16, FeatureHookApiError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| malformed_export(module, &format!("{field} is truncated")))
}

fn malformed_export(module: &str, reason: &str) -> FeatureHookApiError {
    FeatureHookApiError::request(
        RpcErrorCode::MemoryInvalidAddress,
        format!("target module {module} has a malformed PE export directory: {reason}"),
    )
}

fn movement_template<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
) -> Result<Template, FeatureHookApiError> {
    let resolved = resolve_unique_patterns(
        sessions,
        backend,
        session_id,
        &[
            "48 89 5C 24 08 57 48 83 EC 20 48 8B 99 B8 01 00 00 48 85 DB 74 2F",
            "8B 5F 70 F3",
            "74 24 F3 0F 10 44 24 58 F3 0F 11 44 24 78 48 8B 06",
        ],
        module_scope(),
    )?;
    let [target, movement_state, collision]: [usize; 3] = resolved
        .try_into()
        .expect("movement scan resolves exactly three signatures");
    let first_je = movement_state + 15;
    let second_je = movement_state + 24;
    let first_original = array8(read_at(sessions, backend, session_id, first_je, 8)?)?;
    let second_original = array8(read_at(sessions, backend, session_id, second_je, 8)?)?;
    let mut auxiliary_patches = vec![patch(
        collision,
        2,
        vec![0x90; 2],
        true,
        sessions,
        backend,
        session_id,
    )?];
    let first_action_patch = auxiliary_patches.len();
    auxiliary_patches.push(HookPatch {
        address: first_je,
        expected_bytes: first_original.to_vec(),
        replacement_bytes: [vec![0x90; 6], first_original[6..].to_vec()].concat(),
        apply_on_activation: false,
        keep_writable: true,
    });
    let second_action_patch = auxiliary_patches.len();
    auxiliary_patches.push(HookPatch {
        address: second_je,
        expected_bytes: second_original.to_vec(),
        replacement_bytes: [vec![0x90; 6], second_original[6..].to_vec()].concat(),
        apply_on_activation: false,
        keep_writable: true,
    });
    let payload_kind = PayloadKind::Movement {
        first_je,
        second_je,
        first_original,
        second_original,
    };
    let (payload, exports, quiescence_offset) = build_payload(payload_kind, 0);
    Ok(Template {
        signature: exact_signature(sessions, backend, session_id, target, 32)?,
        scope: MemoryScanScope::Process,
        target_offset: 0,
        overwrite_size: 6,
        payload,
        exports,
        resolved_target: Some(target),
        auxiliary_patches,
        movement_action_patches: Some((first_action_patch, second_action_patch)),
        payload_kind,
        replay_original: true,
        quiescence_offset,
    })
}

fn mouse_template<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
) -> Result<Template, FeatureHookApiError> {
    let get_cursor = resolve_remote_export(
        sessions,
        backend,
        session_id,
        "user32.dll",
        "GetCursorPos",
        0,
    )?;
    let set_cursor = resolve_remote_export(
        sessions,
        backend,
        session_id,
        "user32.dll",
        "SetCursorPos",
        0,
    )?;
    let bool_one = resolve_unique_pattern(
        sessions,
        backend,
        session_id,
        "00 FF 50 18 66 C7",
        module_scope(),
    )?;
    let bool_two = resolve_unique_pattern(
        sessions,
        backend,
        session_id,
        "C6 86 ?? ?? ?? 00 00 33 FF 89",
        module_scope(),
    )? + 6;
    let payload_kind = PayloadKind::Mouse;
    let (payload, exports, quiescence_offset) = build_payload(payload_kind, 0);
    Ok(Template {
        signature: exact_signature(sessions, backend, session_id, get_cursor, 16)?,
        scope: MemoryScanScope::Process,
        target_offset: 0,
        overwrite_size: 5,
        payload,
        exports,
        resolved_target: Some(get_cursor),
        auxiliary_patches: vec![
            patch(
                set_cursor,
                6,
                vec![0xc3, 0x90, 0x90, 0x90, 0x90, 0x90],
                true,
                sessions,
                backend,
                session_id,
            )?,
            patch(bool_one, 1, vec![1], true, sessions, backend, session_id)?,
            patch(bool_two, 1, vec![1], true, sessions, backend, session_id)?,
        ],
        movement_action_patches: None,
        payload_kind,
        replay_original: false,
        quiescence_offset,
    })
}

fn patch<B: MutationBackend>(
    address: usize,
    size: usize,
    replacement_bytes: Vec<u8>,
    apply_on_activation: bool,
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
) -> Result<HookPatch, FeatureHookApiError> {
    Ok(HookPatch {
        address,
        expected_bytes: read_at(sessions, backend, session_id, address, size)?,
        replacement_bytes,
        apply_on_activation,
        keep_writable: false,
    })
}

fn array8(bytes: Vec<u8>) -> Result<[u8; 8], FeatureHookApiError> {
    bytes.try_into().map_err(|_| {
        FeatureHookApiError::request(
            RpcErrorCode::Internal,
            "an eight-byte hook read returned an unexpected length",
        )
    })
}

fn exact_signature<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    target: usize,
    size: usize,
) -> Result<String, FeatureHookApiError> {
    Ok(read_at(sessions, backend, session_id, target, size)?
        .iter()
        .map(|value| format!("{value:02X}"))
        .collect::<Vec<_>>()
        .join(" "))
}

fn resolve_fixture_patch<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    marker: u8,
) -> Result<usize, FeatureHookApiError> {
    resolve_unique_pattern(
        sessions,
        backend,
        session_id,
        &format!("B8 {marker:02X} F1 C7 00 90 90 90"),
        MemoryScanScope::Process,
    )
}

fn build_payload(
    kind: PayloadKind,
    allocation: usize,
) -> (Vec<u8>, BTreeMap<FeatureHookExport, (usize, usize)>, usize) {
    let public = match kind {
        PayloadKind::Movement { .. } => vec![(FeatureHookExport::TeleportHelper, 21)],
        PayloadKind::Mouse => vec![(FeatureHookExport::MousePosition, 8)],
        PayloadKind::Chat => vec![
            (FeatureHookExport::ChatOwner, 8),
            (FeatureHookExport::ReceiveSourceGid, 8),
            (FeatureHookExport::ReceiveMessageBuffer, 160),
            (FeatureHookExport::ReceiveMessageLength, 8),
            (FeatureHookExport::ReceiveCounter, 8),
        ],
        PayloadKind::ChatSend { .. } => vec![
            (FeatureHookExport::SendTrigger, 1),
            (FeatureHookExport::SendStruct, 0x28),
            (FeatureHookExport::BuddyTrigger, 1),
            (FeatureHookExport::BuddyObject, 0xe8),
        ],
        PayloadKind::Dance => vec![(FeatureHookExport::DanceGameMoves, 8)],
    };
    let dummy = BTreeMap::new();
    let code_len = payload_code(kind, &dummy, 0, 0).len();
    let mut offsets = BTreeMap::new();
    let mut cursor = code_len + 5;
    for (export, size) in &public {
        offsets.insert(*export, (cursor, *size));
        cursor += size;
    }
    let private_chat_buffer = if matches!(kind, PayloadKind::ChatSend { .. }) {
        let offset = cursor;
        cursor += (MAX_CHAT_WCHARS + 1) * 2;
        offset
    } else {
        0
    };
    let quiescence_offset = cursor;
    cursor += size_of::<u64>();
    let addresses = offsets
        .iter()
        .map(|(export, (offset, _))| (*export, allocation + *offset))
        .collect::<BTreeMap<_, _>>();
    let mut payload = payload_code(
        kind,
        &addresses,
        allocation + private_chat_buffer,
        allocation + quiescence_offset,
    );
    debug_assert_eq!(payload.len(), code_len);
    payload.push(0xe9);
    payload.extend_from_slice(
        &i32::try_from(cursor - code_len - 5)
            .expect("feature storage fits rel32")
            .to_le_bytes(),
    );
    payload.resize(cursor, 0);
    (payload, offsets, quiescence_offset)
}

fn payload_code(
    kind: PayloadKind,
    exports: &BTreeMap<FeatureHookExport, usize>,
    private_chat_buffer: usize,
    quiescence: usize,
) -> Vec<u8> {
    let mut code = quiescence_counter_code(quiescence, true);
    let body = match kind {
        PayloadKind::Movement {
            first_je,
            second_je,
            first_original,
            second_original,
        } => movement_code(
            export(exports, FeatureHookExport::TeleportHelper),
            first_je,
            second_je,
            first_original,
            second_original,
        ),
        PayloadKind::Mouse => mouse_code(export(exports, FeatureHookExport::MousePosition)),
        PayloadKind::Chat => chat_code(exports),
        PayloadKind::ChatSend {
            send,
            buddy,
            operator_new,
        } => chat_send_code(exports, private_chat_buffer, send, buddy, operator_new),
        PayloadKind::Dance => dance_code(export(exports, FeatureHookExport::DanceGameMoves)),
    };
    code.extend_from_slice(&body);
    code.extend_from_slice(&quiescence_counter_code(quiescence, false));
    if matches!(kind, PayloadKind::Mouse) {
        code.push(0xc3);
    }
    code
}

fn quiescence_counter_code(address: usize, increment: bool) -> Vec<u8> {
    let mut code = vec![0x50, 0x48, 0xb8];
    code.extend_from_slice(&(address as u64).to_le_bytes());
    code.extend_from_slice(&[0xf0, 0x48, 0xff, if increment { 0x00 } else { 0x08 }, 0x58]);
    code
}

fn export(exports: &BTreeMap<FeatureHookExport, usize>, selected: FeatureHookExport) -> usize {
    exports.get(&selected).copied().unwrap_or(0)
}

fn movement_code(
    helper: usize,
    first_je: usize,
    second_je: usize,
    first_original: [u8; 8],
    second_original: [u8; 8],
) -> Vec<u8> {
    let mut code = BranchCode::default();
    code.bytes(&[0x50, 0x48, 0xa1]);
    code.qword(helper + 13);
    code.bytes(&[0x48, 0x39, 0xc1, 0x58]);
    code.jcc(0x85, "done");
    code.bytes(&[0x50, 0xa0]);
    code.qword(helper + 12);
    code.bytes(&[0x84, 0xc0, 0x58]);
    code.jcc(0x84, "done");
    code.bytes(&[0x50, 0x48, 0xa1]);
    code.qword(helper);
    code.bytes(&[0x48, 0x89, 0x02, 0xa1]);
    code.qword(helper + 8);
    code.bytes(&[0x89, 0x42, 0x08]);
    code.bytes(&[0x48, 0xb8]);
    code.bytes(&first_original);
    code.bytes(&[0x48, 0xa3]);
    code.qword(first_je);
    code.bytes(&[0x48, 0xb8]);
    code.bytes(&second_original);
    code.bytes(&[0x48, 0xa3]);
    code.qword(second_je);
    code.bytes(&[0x30, 0xc0, 0xa2]);
    code.qword(helper + 12);
    code.bytes(&[0x58]);
    code.label("done");
    code.finish()
}

fn mouse_code(position: usize) -> Vec<u8> {
    let mut code = vec![0x48, 0xa1];
    code.extend_from_slice(&(position as u64).to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0x01, 0xb8, 0x01, 0, 0, 0]);
    code
}

fn chat_code(exports: &BTreeMap<FeatureHookExport, usize>) -> Vec<u8> {
    let mut code = vec![
        0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x50, 0x48, 0x89, 0xf0, 0x48, 0xa3,
    ];
    code.extend_from_slice(&(export(exports, FeatureHookExport::ChatOwner) as u64).to_le_bytes());
    code.extend_from_slice(&[0x58, 0x50, 0x48, 0x8b, 0x45, 0x80, 0x48, 0xa3]);
    code.extend_from_slice(
        &(export(exports, FeatureHookExport::ReceiveSourceGid) as u64).to_le_bytes(),
    );
    code.extend_from_slice(&[0x58, 0x50, 0x48, 0x8b, 0x40, 0x10, 0x48, 0xa3]);
    code.extend_from_slice(
        &(export(exports, FeatureHookExport::ReceiveMessageLength) as u64).to_le_bytes(),
    );
    code.extend_from_slice(&[
        0x58, 0x48, 0x8b, 0xd0, 0x48, 0x83, 0x78, 0x18, 0x08, 0x72, 0x03, 0x48, 0x8b, 0x10, 0x49,
        0xb8,
    ]);
    code.extend_from_slice(
        &(export(exports, FeatureHookExport::ReceiveMessageBuffer) as u64).to_le_bytes(),
    );
    code.extend_from_slice(&[
        0x41, 0xb9, 0x14, 0, 0, 0, 0x48, 0x8b, 0x0a, 0x49, 0x89, 0x08, 0x48, 0x83, 0xc2, 0x08,
        0x49, 0x83, 0xc0, 0x08, 0x41, 0xff, 0xc9, 0x75, 0xed, 0x50, 0x48, 0xa1,
    ]);
    code.extend_from_slice(
        &(export(exports, FeatureHookExport::ReceiveCounter) as u64).to_le_bytes(),
    );
    code.extend_from_slice(&[0x48, 0xff, 0xc0, 0x48, 0xa3]);
    code.extend_from_slice(
        &(export(exports, FeatureHookExport::ReceiveCounter) as u64).to_le_bytes(),
    );
    code.extend_from_slice(&[0x58, 0x41, 0x59, 0x41, 0x58, 0x5a, 0x59]);
    code
}

fn chat_send_code(
    exports: &BTreeMap<FeatureHookExport, usize>,
    message_buffer: usize,
    send: usize,
    buddy: usize,
    operator_new: usize,
) -> Vec<u8> {
    let send_trigger = export(exports, FeatureHookExport::SendTrigger);
    let send_struct = export(exports, FeatureHookExport::SendStruct);
    let buddy_trigger = export(exports, FeatureHookExport::BuddyTrigger);
    let buddy_object = export(exports, FeatureHookExport::BuddyObject);
    let chat_body = action_body(send_trigger, |code| {
        code.bytes(&[0x48, 0xa1]);
        code.qword(send_struct + 0x10);
        code.bytes(&[0x48, 0x83, 0xf8, 0x07]);
        code.jcc(0x86, "chat_ready");
        code.bytes(&[0x48, 0x8d, 0x4c, 0x00, 0x02, 0x48, 0xb8]);
        code.qword(operator_new);
        code.bytes(&[0xff, 0xd0, 0x49, 0x89, 0xc3, 0x49, 0xba]);
        code.qword(message_buffer);
        code.bytes(&[0x48, 0xa1]);
        code.qword(send_struct + 0x10);
        code.bytes(&[0x48, 0x8d, 0x4c, 0x00, 0x02]);
        code.label("copy_loop");
        code.bytes(&[
            0x41, 0x8a, 0x02, 0x41, 0x88, 0x03, 0x49, 0xff, 0xc2, 0x49, 0xff, 0xc3, 0x48, 0xff,
            0xc9,
        ]);
        code.jcc(0x85, "copy_loop");
        code.bytes(&[0x48, 0xb8]);
        code.qword(send_struct);
        code.bytes(&[0x4c, 0x89, 0x18]);
        code.label("chat_ready");
        code.bytes(&[0x48, 0x89, 0xf9, 0x48, 0xba]);
        code.qword(send_struct);
        code.bytes(&[0x48, 0xb8]);
        code.qword(send);
        code.bytes(&[0xff, 0xd0]);
    });
    let buddy_body = action_body(buddy_trigger, |code| {
        code.bytes(&[0x48, 0xb9]);
        code.qword(buddy_object);
        code.bytes(&[
            0x48, 0x89, 0x79, 0x18, 0x48, 0x8b, 0x91, 0xe0, 0, 0, 0, 0x48, 0xb8,
        ]);
        code.qword(buddy);
        code.bytes(&[0xff, 0xd0]);
    });
    [chat_body, buddy_body].concat()
}

fn action_body(trigger: usize, call: impl FnOnce(&mut BranchCode)) -> Vec<u8> {
    let mut code = BranchCode::default();
    code.bytes(&[0x50, 0xa0]);
    code.qword(trigger);
    code.bytes(&[0x84, 0xc0, 0x58]);
    code.jcc(0x84, "done");
    code.bytes(&[
        0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0x81, 0xec, 0x28,
        0, 0, 0,
    ]);
    call(&mut code);
    code.bytes(&[
        0x48, 0x81, 0xc4, 0x28, 0, 0, 0, 0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5a,
        0x59, 0x58, 0x50, 0x30, 0xc0, 0xa2,
    ]);
    code.qword(trigger);
    code.bytes(&[0x58]);
    code.label("done");
    code.finish()
}

fn dance_code(moves: usize) -> Vec<u8> {
    let mut code = vec![0x50, 0x51, 0x48, 0x8b, 0x08, 0x48, 0xb8];
    code.extend_from_slice(&(moves as u64).to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0x08, 0x59, 0x58]);
    code
}

#[derive(Default)]
struct BranchCode {
    bytes: Vec<u8>,
    labels: BTreeMap<&'static str, usize>,
    fixups: Vec<(usize, &'static str)>,
}

impl BranchCode {
    fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }
    fn qword(&mut self, value: usize) {
        self.bytes.extend_from_slice(&(value as u64).to_le_bytes());
    }
    fn label(&mut self, label: &'static str) {
        self.labels.insert(label, self.bytes.len());
    }
    fn jcc(&mut self, condition: u8, label: &'static str) {
        self.bytes.extend_from_slice(&[0x0f, condition, 0, 0, 0, 0]);
        self.fixups.push((self.bytes.len() - 4, label));
    }
    fn finish(mut self) -> Vec<u8> {
        for (offset, label) in self.fixups {
            let target = *self.labels.get(label).expect("branch label must exist");
            let displacement = i32::try_from(target as isize - (offset + 4) as isize)
                .expect("feature branch fits rel32");
            self.bytes[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
        }
        self.bytes
    }
}

fn parse_address(value: &str) -> Result<usize, FeatureHookApiError> {
    let digits = value.strip_prefix("0x").ok_or_else(|| {
        FeatureHookApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "feature-hook address was not hexadecimal",
        )
    })?;
    usize::from_str_radix(digits, 16).map_err(|_| {
        FeatureHookApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "feature-hook address exceeded the agent address width",
        )
    })
}

fn format_address(address: usize) -> String {
    format!("{address:#x}")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use deimos_core::memory::{
        CoreHook, CoreHookRequest, FeatureBuddyAddRequest, FeatureChatSendRequest, FeatureHook,
        FeatureHookExport, FeatureHookExportRequest, FeatureHookRequest,
        FeatureMousePositionRequest, FeatureTeleportRequest,
    };
    use deimos_core::process::ModuleDescriptor;
    use deimos_core::rpc::RpcErrorCode;

    use super::{
        activate, add_buddy, build_payload, dance_code, deactivate, movement_code,
        quiescence_counter_code, read_export, resolve_export_from_modules,
        select_disambiguated_candidate, send_chat, set_mouse_position, teleport, write_at,
        ExportLookup, FeatureHookApiError, PayloadKind, CHAT_HOOK_SITE, CHAT_TYPE_MARKER,
    };
    use crate::hook::tests::{registry, Backend, Failure};
    use crate::hook::{self, HookState, HOOK_LEASE};
    use crate::mutation::MutationState;

    fn activate_client_base(
        sessions: &mut crate::process::ProcessSessionRegistry<crate::hook::tests::Handle>,
        backend: &Backend,
        mutations: &mut MutationState<crate::hook::tests::Thread>,
        hooks: &mut HookState,
        session_id: &deimos_core::process::ProcessSessionId,
        address: usize,
    ) {
        crate::core_hook::activate(
            sessions,
            backend,
            mutations,
            hooks,
            &CoreHookRequest {
                session_id: session_id.clone(),
                hook: CoreHook::Client,
            },
            Instant::now(),
        )
        .expect("client core hook should activate");
        let allocation = hooks
            .allocation_address(session_id, "wizwalker.core.client")
            .expect("client core hook allocation");
        write_at(
            sessions,
            backend,
            session_id,
            allocation + 14,
            (address as u64).to_le_bytes().to_vec(),
        )
        .expect("client core hook fixture export should be writable");
    }

    fn deactivate_client_base(
        sessions: &mut crate::process::ProcessSessionRegistry<crate::hook::tests::Handle>,
        backend: &Backend,
        mutations: &mut MutationState<crate::hook::tests::Thread>,
        hooks: &mut HookState,
        session_id: &deimos_core::process::ProcessSessionId,
    ) {
        crate::core_hook::deactivate(
            sessions,
            backend,
            mutations,
            hooks,
            &CoreHookRequest {
                session_id: session_id.clone(),
                hook: CoreHook::Client,
            },
        )
        .expect("client core hook should deactivate");
    }

    const IMAGE_SIZE: usize = 0x1000;

    #[test]
    fn target_process_pe_resolver_finds_a_named_export() {
        let (modules, images) = images_with_export("user32.dll", 0x1000, "GetCursorPos", "", 0x500);
        let address = resolve(&modules, &images, "user32.dll", "GetCursorPos")
            .expect("named export should resolve");
        assert_eq!(address, 0x1500);
    }

    #[test]
    fn chat_selector_requires_hook_site_when_type_markers_are_duplicated() {
        let candidates = [0x1000, 0x2000];
        let memory = BTreeMap::from([
            (candidates[0] + 0x7e, CHAT_TYPE_MARKER.to_vec()),
            (candidates[1] + 0x7e, CHAT_TYPE_MARKER.to_vec()),
            (candidates[0] + 0x379, CHAT_HOOK_SITE.to_vec()),
            (
                candidates[1] + 0x379,
                vec![0x48, 0x8b, 0x10, 0x4c, 0x8b, 0x40, 0x10],
            ),
        ]);
        let mut read = |address, size| {
            let bytes = memory.get(&address).expect("probe address should exist");
            assert_eq!(bytes.len(), size);
            Ok(bytes.clone())
        };

        let error =
            select_disambiguated_candidate(&candidates, &[(0x7e, CHAT_TYPE_MARKER)], &mut read)
                .expect_err("the legacy type marker alone should remain ambiguous");
        assert!(error_message(error).contains("more than one function"));

        let selected = select_disambiguated_candidate(
            &candidates,
            &[(0x7e, CHAT_TYPE_MARKER), (0x379, CHAT_HOOK_SITE)],
            &mut read,
        )
        .expect("the hook-site instructions should disambiguate the candidates");
        assert_eq!(selected, Some(candidates[0]));
    }

    #[test]
    fn target_process_pe_resolver_rejects_out_of_bounds_tables() {
        let (modules, mut images) =
            images_with_export("user32.dll", 0x1000, "GetCursorPos", "", 0x500);
        images.get_mut(&0x1000).expect("image")[0x200 + 28..0x200 + 32]
            .copy_from_slice(&0xfffu32.to_le_bytes());
        let error = resolve(&modules, &images, "user32.dll", "GetCursorPos")
            .expect_err("out-of-bounds function table must fail");
        assert!(error_message(error).contains("function table extends outside"));
    }

    #[test]
    fn target_process_pe_resolver_follows_forwarders_and_bounds_recursion() {
        let (mut modules, mut images) =
            images_with_export("user32.dll", 0x1000, "GetCursorPos", "win32u.RealCursor", 0);
        let (forwarded_modules, forwarded_images) =
            images_with_export("win32u.dll", 0x3000, "RealCursor", "", 0x600);
        modules.extend(forwarded_modules);
        images.extend(forwarded_images);
        assert_eq!(
            resolve(&modules, &images, "user32.dll", "GetCursorPos")
                .expect("forwarded export should resolve"),
            0x3600
        );

        let (loop_modules, loop_images) =
            images_with_export("loop.dll", 0x5000, "Again", "loop.Again", 0);
        let error = resolve(&loop_modules, &loop_images, "loop.dll", "Again")
            .expect_err("forwarder cycles must hit the strict depth bound");
        assert!(error_message(error).contains("forwarder chain exceeded"));
    }

    #[test]
    fn every_feature_payload_has_private_exports_and_behavior_code() {
        for kind in [
            PayloadKind::Movement {
                first_je: 0x2000,
                second_je: 0x2010,
                first_original: [0x74; 8],
                second_original: [0x75; 8],
            },
            PayloadKind::Mouse,
            PayloadKind::Chat,
            PayloadKind::ChatSend {
                send: 0x3000,
                buddy: 0x4000,
                operator_new: 0x5000,
            },
            PayloadKind::Dance,
        ] {
            let (payload, exports, quiescence_offset) = build_payload(kind, 0x7000);
            assert!(!exports.is_empty());
            assert!(payload.len() > exports.values().map(|(_, size)| size).sum::<usize>() + 5);
            for (offset, size) in exports.values() {
                assert_eq!(&payload[*offset..*offset + *size], vec![0; *size]);
            }
            assert_eq!(
                &payload[quiescence_offset..quiescence_offset + std::mem::size_of::<u64>()],
                &[0; std::mem::size_of::<u64>()]
            );
            let quiescence = 0x7000 + quiescence_offset;
            assert!(payload.starts_with(&quiescence_counter_code(quiescence, true)));
            assert!(payload
                .windows(quiescence_counter_code(quiescence, false).len())
                .any(|bytes| bytes == quiescence_counter_code(quiescence, false)));
        }
    }

    #[test]
    fn replacement_payloads_preserve_registers_and_publish_completion_state() {
        let (mouse, exports, _) = build_payload(PayloadKind::Mouse, 0x7000);
        let mouse_code_end = exports[&FeatureHookExport::MousePosition].0 - 5;
        assert!(mouse[..mouse_code_end]
            .windows(5)
            .any(|bytes| bytes == [0xb8, 1, 0, 0, 0]));
        assert_eq!(mouse[mouse_code_end - 1], 0xc3);

        let dance = dance_code(0x5678);
        assert!(dance.starts_with(&[0x50, 0x51]));
        assert!(dance.ends_with(&[0x59, 0x58]));

        let helper = 0x7000;
        let movement = movement_code(helper, 0x8000, 0x9000, [0x74; 8], [0x75; 8]);
        let mut completion = vec![0x30, 0xc0, 0xa2];
        completion.extend_from_slice(&((helper + 12) as u64).to_le_bytes());
        completion.push(0x58);
        assert!(movement.ends_with(&completion));
    }

    #[test]
    fn teleport_action_failures_restore_owned_bytes_and_deactivation_restores_protection() {
        let backend = Backend::feature(Some(Failure::FeatureActionWrite));
        let before_activation = backend.primary();
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let request = FeatureHookRequest {
            session_id: session_id.clone(),
            hook: FeatureHook::MovementTeleport,
        };
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            Instant::now(),
        )
        .expect("movement feature should activate");
        activate_client_base(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
            0x1234,
        );
        let before_action = backend.primary();
        teleport(
            &mut sessions,
            &backend,
            &mut hooks,
            &FeatureTeleportRequest {
                session_id: session_id.clone(),
                object_address: "0x1234".to_string(),
                position: [1.0, 2.0, 3.0],
                wait_on_inuse: true,
                wait_timeout_ms: 10,
                purge_after_timeout: true,
                purge_timeout_ms: 10,
            },
        )
        .expect_err("forced helper write failure should be reported");
        assert_eq!(backend.primary(), before_action);
        assert_eq!(
            backend.target_protection(),
            deimos_core::memory::MemoryProtection::ExecuteReadWrite
        );
        deactivate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
        )
        .expect("movement cleanup should remain retryable");
        deactivate_client_base(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
        );
        assert_eq!(backend.primary(), before_activation);
        assert_eq!(
            backend.target_protection(),
            deimos_core::memory::MemoryProtection::ReadOnly
        );
    }

    #[test]
    fn teleport_rejects_a_stale_client_object_before_mutating_action_patches() {
        let backend = Backend::feature(None);
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let request = FeatureHookRequest {
            session_id: session_id.clone(),
            hook: FeatureHook::MovementTeleport,
        };
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            Instant::now(),
        )
        .expect("movement feature should activate");
        activate_client_base(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
            0x5678,
        );
        let before_action = backend.primary();

        let error = teleport(
            &mut sessions,
            &backend,
            &mut hooks,
            &FeatureTeleportRequest {
                session_id: session_id.clone(),
                object_address: "0x1234".to_string(),
                position: [1.0, 2.0, 3.0],
                wait_on_inuse: true,
                wait_timeout_ms: 10,
                purge_after_timeout: true,
                purge_timeout_ms: 10,
            },
        )
        .expect_err("a stale client object must fail closed");

        assert_eq!(
            error.into_rpc_error(1, "feature.teleport").code,
            RpcErrorCode::InvalidRequest
        );
        assert_eq!(backend.primary(), before_action);
    }

    #[test]
    fn teleport_rejects_non_finite_coordinates_without_mutating_action_state() {
        let backend = Backend::feature(None);
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &FeatureHookRequest {
                session_id: session_id.clone(),
                hook: FeatureHook::MovementTeleport,
            },
            Instant::now(),
        )
        .expect("movement feature should activate");
        activate_client_base(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
            0x1234,
        );
        let helper = super::export_address(
            &mut sessions,
            &backend,
            &hooks,
            &session_id,
            FeatureHookExport::TeleportHelper,
        )
        .expect("teleport helper export");
        let helper_before = super::read_at(&mut sessions, &backend, &session_id, helper, 21)
            .expect("teleport helper state");
        let patches_before = backend.primary();

        let error = teleport(
            &mut sessions,
            &backend,
            &mut hooks,
            &FeatureTeleportRequest {
                session_id: session_id.clone(),
                object_address: "0x1234".to_string(),
                position: [f32::NAN, 2.0, 3.0],
                wait_on_inuse: true,
                wait_timeout_ms: 10,
                purge_after_timeout: true,
                purge_timeout_ms: 10,
            },
        )
        .expect_err("non-finite coordinates must fail closed");

        assert_eq!(
            error.into_rpc_error(1, "feature.teleport").code,
            RpcErrorCode::InvalidRequest
        );
        assert_eq!(backend.primary(), patches_before);
        assert_eq!(
            super::read_at(&mut sessions, &backend, &session_id, helper, 21)
                .expect("teleport helper state after rejection"),
            helper_before
        );
    }

    #[test]
    fn pending_main_thread_actions_block_reuse_and_deactivation() {
        let backend = Backend::feature(None);
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let request = FeatureHookRequest {
            session_id: session_id.clone(),
            hook: FeatureHook::ChatSend,
        };
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            Instant::now(),
        )
        .expect("chat-send feature should activate");
        let (trigger, _) = hooks
            .export_address(
                &session_id,
                &super::hook_key(FeatureHook::ChatSend),
                "send_trigger",
            )
            .expect("send trigger should be tracked");
        write_at(&mut sessions, &backend, &session_id, trigger, vec![1])
            .expect("test should mark the action pending");
        let error = send_chat(
            &mut sessions,
            &backend,
            &hooks,
            &FeatureChatSendRequest {
                session_id: session_id.clone(),
                message: "hello".to_string(),
                target_gid: 55,
            },
        )
        .expect_err("a pending send must reject shared-buffer reuse");
        assert!(error_message(error).contains("still pending"));
        let error = deactivate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
        )
        .expect_err("a pending action must retain trampoline ownership");
        assert!(error_message(error).contains("still pending"));
        write_at(&mut sessions, &backend, &session_id, trigger, vec![0])
            .expect("test should publish action completion");
        deactivate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
        )
        .expect("completed action should allow deactivation");
    }

    #[test]
    fn every_cleanup_path_retains_execution_ownership_until_quiescent() {
        let backend = Backend::feature(None);
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let request = FeatureHookRequest {
            session_id: session_id.clone(),
            hook: FeatureHook::ChatSend,
        };
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            Instant::now(),
        )
        .expect("chat-send feature should activate");
        backend.fail_next(Failure::TrampolineExecuting);
        let key = super::hook_key(FeatureHook::ChatSend);
        hook::cleanup_session(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
        )
        .expect_err("cleanup must retain a trampoline that is still executing");
        assert_eq!(hooks.tracked_count(&session_id), 1);
        assert_eq!(backend.allocation_count(), 1);
        assert!(hooks.allocation_address(&session_id, &key).is_some());

        hook::cleanup_session(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
        )
        .expect("quiescent cleanup should release the trampoline");
        assert_eq!(hooks.tracked_count(&session_id), 0);
        assert_eq!(backend.allocation_count(), 0);
    }

    #[test]
    fn external_trampoline_calls_retain_ownership_until_the_counter_is_clear() {
        let backend = Backend::feature(None);
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let request = FeatureHookRequest {
            session_id: session_id.clone(),
            hook: FeatureHook::ChatSend,
        };
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            Instant::now(),
        )
        .expect("chat-send feature should activate");
        let key = super::hook_key(FeatureHook::ChatSend);
        let counter = hooks
            .quiescence_address(&session_id, &key)
            .expect("feature hook should publish its execution counter");
        write_at(
            &mut sessions,
            &backend,
            &session_id,
            counter,
            1u64.to_le_bytes().to_vec(),
        )
        .expect("test should mark an external call in flight");

        let error = hook::cleanup_session(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
        )
        .expect_err("an external trampoline frame must retain ownership");
        assert!(error_message(error.into()).contains("external trampoline call"));
        assert_eq!(hooks.tracked_count(&session_id), 1);
        assert_eq!(backend.allocation_count(), 1);

        write_at(
            &mut sessions,
            &backend,
            &session_id,
            counter,
            0u64.to_le_bytes().to_vec(),
        )
        .expect("test should publish external-call completion");
        hook::cleanup_session(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
        )
        .expect("cleanup should release a quiescent trampoline");
        assert_eq!(hooks.tracked_count(&session_id), 0);
        assert_eq!(backend.allocation_count(), 0);
    }

    #[test]
    fn feature_deactivation_retries_after_a_retirement_failure() {
        let backend = Backend::feature(Some(Failure::Free));
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let request = FeatureHookRequest {
            session_id: session_id.clone(),
            hook: FeatureHook::MovementTeleport,
        };
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            Instant::now(),
        )
        .expect("movement feature should activate");

        let error = deactivate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
        )
        .expect_err("a failed release must retain cleanup ownership");
        assert!(error_message(error).contains("free"));
        assert_eq!(hooks.tracked_count(&session_id), 1);
        assert_eq!(backend.allocation_count(), 1);

        deactivate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
        )
        .expect("feature deactivation should retry inactive cleanup directly");
        assert_eq!(hooks.tracked_count(&session_id), 0);
        assert_eq!(backend.allocation_count(), 0);
    }

    #[test]
    fn active_feature_records_serve_every_export_and_fixture_action_without_rescanning() {
        let backend = Backend::feature(None);
        let before = backend.primary();
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        for selected in FeatureHook::ALL {
            let request = FeatureHookRequest {
                session_id: session_id.clone(),
                hook: selected,
            };
            activate(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                &request,
                Instant::now(),
            )
            .expect("feature hook should activate");
            activate(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                &request,
                Instant::now(),
            )
            .expect("feature activation should be idempotent");
        }
        for export in [
            FeatureHookExport::TeleportHelper,
            FeatureHookExport::MousePosition,
            FeatureHookExport::ChatOwner,
            FeatureHookExport::ReceiveSourceGid,
            FeatureHookExport::ReceiveMessageBuffer,
            FeatureHookExport::ReceiveMessageLength,
            FeatureHookExport::ReceiveCounter,
            FeatureHookExport::SendTrigger,
            FeatureHookExport::SendStruct,
            FeatureHookExport::BuddyTrigger,
            FeatureHookExport::BuddyObject,
            FeatureHookExport::DanceGameMoves,
        ] {
            let response = read_export(
                &mut sessions,
                &backend,
                &hooks,
                &FeatureHookExportRequest {
                    session_id: session_id.clone(),
                    export,
                },
            )
            .expect("active feature export should use stored metadata");
            assert!(response.address.starts_with("0x"));
        }
        set_mouse_position(
            &mut sessions,
            &backend,
            &hooks,
            &FeatureMousePositionRequest {
                session_id: session_id.clone(),
                x: 40,
                y: 80,
            },
        )
        .expect("fixture mouse action should complete");
        activate_client_base(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
            0x1234,
        );
        teleport(
            &mut sessions,
            &backend,
            &mut hooks,
            &FeatureTeleportRequest {
                session_id: session_id.clone(),
                object_address: "0x1234".to_string(),
                position: [1.0, 2.0, 3.0],
                wait_on_inuse: true,
                wait_timeout_ms: 10,
                purge_after_timeout: true,
                purge_timeout_ms: 10,
            },
        )
        .expect("fixture teleport should complete");
        send_chat(
            &mut sessions,
            &backend,
            &hooks,
            &FeatureChatSendRequest {
                session_id: session_id.clone(),
                message: "a message longer than seven".to_string(),
                target_gid: 55,
            },
        )
        .expect("fixture chat send should complete");
        add_buddy(
            &mut sessions,
            &backend,
            &hooks,
            &FeatureBuddyAddRequest {
                session_id: session_id.clone(),
                target_gid: 77,
            },
        )
        .expect("fixture buddy action should complete");

        for selected in FeatureHook::ALL.into_iter().rev() {
            deactivate(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                &FeatureHookRequest {
                    session_id: session_id.clone(),
                    hook: selected,
                },
            )
            .expect("feature hook should deactivate");
        }
        deactivate_client_base(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
        );
        assert_eq!(backend.primary(), before);
        assert_eq!(
            backend.target_protection(),
            deimos_core::memory::MemoryProtection::ReadOnly
        );
        assert_eq!(backend.allocation_count(), 0);
        assert_eq!(mutations.tracked_count(&session_id), 0);
        assert_eq!(hooks.tracked_count(&session_id), 0);
    }

    #[test]
    fn feature_auxiliary_patches_restore_on_expiry_cleanup_and_partial_activation_failure() {
        for selected in [FeatureHook::MovementTeleport, FeatureHook::MouselessCursor] {
            let backend = Backend::feature(None);
            let before = backend.primary();
            let (mut sessions, session_id) = registry(&backend);
            let mut mutations = MutationState::new();
            let mut hooks = HookState::default();
            activate(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                &FeatureHookRequest {
                    session_id: session_id.clone(),
                    hook: selected,
                },
                Instant::now(),
            )
            .expect("feature hook should activate");
            assert_ne!(backend.primary(), before);
            hook::expire_at(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                Instant::now() + HOOK_LEASE + Duration::from_millis(1),
            )
            .expect("lease expiry should restore feature ownership");
            assert_eq!(backend.primary(), before);
            assert_eq!(backend.allocation_count(), 0);
        }

        let backend = Backend::feature(None);
        let before = backend.primary();
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &FeatureHookRequest {
                session_id: session_id.clone(),
                hook: FeatureHook::MouselessCursor,
            },
            Instant::now(),
        )
        .expect("mouseless hook should activate");
        hook::cleanup_session(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
        )
        .expect("session cleanup should restore feature ownership");
        assert_eq!(backend.primary(), before);
        assert_eq!(backend.allocation_count(), 0);

        let backend = Backend::feature(Some(Failure::SecondTargetWrite));
        let before = backend.primary();
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        assert!(activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &FeatureHookRequest {
                session_id: session_id.clone(),
                hook: FeatureHook::MovementTeleport,
            },
            Instant::now(),
        )
        .is_err());
        assert_eq!(backend.primary(), before);
        assert_eq!(
            backend.target_protection(),
            deimos_core::memory::MemoryProtection::ReadOnly
        );
        assert_eq!(backend.allocation_count(), 0);
        assert_eq!(mutations.tracked_count(&session_id), 0);
        assert_eq!(hooks.tracked_count(&session_id), 0);
    }

    fn resolve(
        modules: &[ModuleDescriptor],
        images: &BTreeMap<usize, Vec<u8>>,
        module: &str,
        symbol: &str,
    ) -> Result<usize, FeatureHookApiError> {
        resolve_export_from_modules(
            modules,
            module,
            ExportLookup::Name(symbol.to_string()),
            0,
            &mut |address, size| {
                let (base, image) = images
                    .iter()
                    .find(|(base, image)| {
                        **base <= address && address + size <= **base + image.len()
                    })
                    .ok_or_else(|| {
                        FeatureHookApiError::request(
                            deimos_core::rpc::RpcErrorCode::MemoryInvalidAddress,
                            "synthetic image read was out of bounds",
                        )
                    })?;
                Ok(image[address - *base..address - *base + size].to_vec())
            },
        )
    }

    fn images_with_export(
        name: &str,
        base: usize,
        symbol: &str,
        forwarder: &str,
        function_rva: u32,
    ) -> (Vec<ModuleDescriptor>, BTreeMap<usize, Vec<u8>>) {
        let mut image = vec![0u8; IMAGE_SIZE];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        image[0xd0..0xd4].copy_from_slice(&(IMAGE_SIZE as u32).to_le_bytes());
        image[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
        image[0x108..0x10c].copy_from_slice(&0x200u32.to_le_bytes());
        image[0x10c..0x110].copy_from_slice(&0x100u32.to_le_bytes());
        image[0x210..0x214].copy_from_slice(&1u32.to_le_bytes());
        image[0x214..0x218].copy_from_slice(&1u32.to_le_bytes());
        image[0x218..0x21c].copy_from_slice(&1u32.to_le_bytes());
        image[0x21c..0x220].copy_from_slice(&0x240u32.to_le_bytes());
        image[0x220..0x224].copy_from_slice(&0x244u32.to_le_bytes());
        image[0x224..0x228].copy_from_slice(&0x248u32.to_le_bytes());
        image[0x244..0x248].copy_from_slice(&0x260u32.to_le_bytes());
        image[0x248..0x24a].copy_from_slice(&0u16.to_le_bytes());
        image[0x260..0x260 + symbol.len()].copy_from_slice(symbol.as_bytes());
        if forwarder.is_empty() {
            image[0x240..0x244].copy_from_slice(&function_rva.to_le_bytes());
        } else {
            image[0x240..0x244].copy_from_slice(&0x280u32.to_le_bytes());
            image[0x280..0x280 + forwarder.len()].copy_from_slice(forwarder.as_bytes());
        }
        (
            vec![ModuleDescriptor {
                name: name.to_string(),
                executable_path: format!(r"C:\fixture\{name}"),
                base_address: format!("{base:#x}"),
                size: IMAGE_SIZE as u32,
            }],
            BTreeMap::from([(base, image)]),
        )
    }

    fn error_message(error: FeatureHookApiError) -> String {
        match error {
            FeatureHookApiError::Request { message, .. } => message,
            other => format!("{other:?}"),
        }
    }
}
