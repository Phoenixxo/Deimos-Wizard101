//! Built-in WizWalker hooks for telemetry and UI access.

use std::time::Instant;

use deimos_core::memory::{
    CoreHook, CoreHookBaseResponse, CoreHookDeactivateResponse, CoreHookRequest, CoreHookResponse,
    CoreHookSessionRequest, CoreHooksResponse, HookActivateRequest, HookDeactivateRequest,
    HookHeartbeatRequest, MemoryReadRequest, MemoryScanScope,
};
use deimos_core::process::ProcessKind;
use deimos_core::rpc::RpcErrorCode;

use crate::hook::{self, HookApiError, HookState};
use crate::memory;
use crate::mutation::MutationState;
use crate::process::{MutationBackend, ProcessSessionRegistry};

const MODULE: &str = "WizardGraphicalClient.exe";

struct Template {
    signature: &'static str,
    target_offset: usize,
    overwrite_size: usize,
    payload: Vec<u8>,
    export_offset: usize,
}

pub fn activate<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    request: &CoreHookRequest,
    now: Instant,
) -> Result<CoreHookResponse, HookApiError> {
    let fixture = sessions.process_kind(&request.session_id) == Some(ProcessKind::MemoryFixture);
    let template = template_for_target(request.hook, fixture);
    hook::activate_template(
        sessions,
        backend,
        mutations,
        hooks,
        &HookActivateRequest {
            session_id: request.session_id.clone(),
            hook_key: hook_key(request.hook),
            signature: template.signature.to_string(),
            scope: if fixture {
                MemoryScanScope::Process
            } else {
                MemoryScanScope::Module {
                    name: MODULE.to_string(),
                }
            },
            payload: template.payload,
        },
        template.target_offset,
        Some(template.overwrite_size),
        now,
    )?;
    Ok(CoreHookResponse {
        session_id: request.session_id.clone(),
        hook: request.hook,
        active: true,
    })
}

pub fn activate_all<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    request: &CoreHookSessionRequest,
    now: Instant,
) -> Result<CoreHooksResponse, HookApiError> {
    let mut activated = Vec::new();
    let mut responses = Vec::new();
    for selected in CoreHook::ALL {
        let key = hook_key(selected);
        let was_active = hooks
            .allocation_address(&request.session_id, &key)
            .is_some();
        match activate(
            sessions,
            backend,
            mutations,
            hooks,
            &CoreHookRequest {
                session_id: request.session_id.clone(),
                hook: selected,
            },
            now,
        ) {
            Ok(response) => {
                if !was_active {
                    activated.push(selected);
                }
                responses.push(response);
            }
            Err(activation_error) => {
                let mut rollback_failures = Vec::new();
                for rollback_hook in activated.into_iter().rev() {
                    if let Err(error) = deactivate(
                        sessions,
                        backend,
                        mutations,
                        hooks,
                        &CoreHookRequest {
                            session_id: request.session_id.clone(),
                            hook: rollback_hook,
                        },
                    ) {
                        rollback_failures.push(format!("{rollback_hook:?}: {error:?}"));
                    }
                }
                if !rollback_failures.is_empty() {
                    return Err(HookApiError::request(
                        RpcErrorCode::MemoryWriteFailed,
                        format!(
                            "core-hook activation failed and rollback could not be verified for {} hook(s); failed records remain agent-owned and process-session cleanup will retry: {}",
                            rollback_failures.len(),
                            rollback_failures.join("; ")
                        ),
                    ));
                }
                return Err(activation_error);
            }
        }
    }
    Ok(CoreHooksResponse {
        session_id: request.session_id.clone(),
        hooks: responses,
    })
}

pub fn deactivate<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    request: &CoreHookRequest,
) -> Result<CoreHookDeactivateResponse, HookApiError> {
    let response = hook::deactivate(
        sessions,
        backend,
        mutations,
        hooks,
        &HookDeactivateRequest {
            session_id: request.session_id.clone(),
            hook_key: hook_key(request.hook),
        },
    )?;
    Ok(CoreHookDeactivateResponse {
        session_id: request.session_id.clone(),
        hook: request.hook,
        deactivated: response.deactivated,
    })
}

pub fn deactivate_all<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    request: &CoreHookSessionRequest,
) -> Result<CoreHooksResponse, HookApiError> {
    let mut responses = Vec::new();
    let mut first_error = None;
    for selected in CoreHook::ALL.into_iter().rev() {
        match deactivate(
            sessions,
            backend,
            mutations,
            hooks,
            &CoreHookRequest {
                session_id: request.session_id.clone(),
                hook: selected,
            },
        ) {
            Ok(response) => responses.push(CoreHookResponse {
                session_id: response.session_id,
                hook: response.hook,
                active: false,
            }),
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    responses.reverse();
    Ok(CoreHooksResponse {
        session_id: request.session_id.clone(),
        hooks: responses,
    })
}

pub fn heartbeat_all(
    hooks: &mut HookState,
    request: &CoreHookSessionRequest,
    now: Instant,
) -> Result<CoreHooksResponse, HookApiError> {
    let mut responses = Vec::new();
    for selected in CoreHook::ALL {
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
        responses.push(CoreHookResponse {
            session_id: request.session_id.clone(),
            hook: selected,
            active: true,
        });
    }
    Ok(CoreHooksResponse {
        session_id: request.session_id.clone(),
        hooks: responses,
    })
}

pub fn read_base<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    hooks: &HookState,
    request: &CoreHookRequest,
) -> Result<CoreHookBaseResponse, HookApiError> {
    let template = template(request.hook);
    let allocation_address = hooks
        .allocation_address(&request.session_id, &hook_key(request.hook))
        .ok_or_else(|| {
            HookApiError::request(
                RpcErrorCode::InvalidRequest,
                format!("core hook {:?} is not active", request.hook),
            )
        })?;
    let export_address = allocation_address
        .checked_add(template.export_offset)
        .ok_or_else(|| {
            HookApiError::request(
                RpcErrorCode::MemoryInvalidAddress,
                "core-hook export address overflowed the agent address width",
            )
        })?;
    let bytes = memory::read(
        sessions,
        backend,
        &MemoryReadRequest {
            session_id: request.session_id.clone(),
            address: format!("{export_address:#x}"),
            size: 8,
        },
    )?
    .bytes;
    let value = u64::from_le_bytes(
        bytes
            .try_into()
            .expect("an eight-byte agent read must return eight bytes"),
    );
    Ok(CoreHookBaseResponse {
        session_id: request.session_id.clone(),
        hook: request.hook,
        base_address: format!("{value:#x}"),
    })
}

fn hook_key(hook: CoreHook) -> String {
    format!(
        "wizwalker.core.{}",
        match hook {
            CoreHook::Client => "client",
            CoreHook::Player => "player",
            CoreHook::Quest => "quest",
            CoreHook::PlayerStat => "player_stat",
            CoreHook::RootWindow => "root_window",
            CoreHook::RenderContext => "render_context",
        }
    )
}

fn template(hook: CoreHook) -> Template {
    let (signature, target_offset, overwrite_size, capture) = match hook {
        CoreHook::Client => (
            "18 48 ?? ?? ?? ?? ?? ?? 48 8B 7C 24 ?? 48 85 FF 74 29 8B C6 F0 0F C1 47 08 83 F8 01 75 1D 48 8B 07 48 8B CF FF 50 08 F0 0F C1 77 0C",
            1,
            15,
            &[0x48, 0x89, 0xf8][..], // mov rax, rdi
        ),
        CoreHook::Player => (
            "F2 0F 10 40 58 F2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
            0,
            0,
            &[][..],
        ),
        CoreHook::Quest => (
            "F3 41 0F 10 ?? FC 0C 00 00 F3 0F 11 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
            0,
            0,
            &[0x49, 0x8d, 0x87, 0xfc, 0x0c, 0x00, 0x00][..], // lea rax,[r15+0xcfc]
        ),
        CoreHook::PlayerStat => (
            "2B D8 B8 ?? ?? ?? ?? 0F 49 C3 48 83 C4 20 5B C3",
            0,
            14,
            &[0x48, 0x89, 0xc8][..], // mov rax, rcx
        ),
        CoreHook::RootWindow => (
            "49 8B 8D D8 00 00 00 48 8B 01 ?? ?? ?? ?? ?? ?? ?? FF 50 70 84 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
            0,
            0,
            &[0x49, 0x8b, 0x85, 0xd8, 0x00, 0x00, 0x00][..], // mov rax,[r13+0xd8]
        ),
        CoreHook::RenderContext => (
            "F3 44 0F 10 8B 98 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? F3 41 0F 10 28 F3 0F 10 56 04 48 63 C1 ??",
            0,
            0,
            &[0x48, 0x89, 0xd8][..], // mov rax, rbx
        ),
    };
    let (payload, export_offset) = if hook == CoreHook::Player {
        player_payload()
    } else {
        capture_payload(capture)
    };
    Template {
        signature,
        target_offset,
        overwrite_size,
        payload,
        export_offset,
    }
}

fn template_for_target(hook: CoreHook, controlled_fixture: bool) -> Template {
    if !controlled_fixture {
        return template(hook);
    }
    let marker = match hook {
        CoreHook::Client => 1,
        CoreHook::Player => 2,
        CoreHook::Quest => 3,
        CoreHook::PlayerStat => 4,
        CoreHook::RootWindow => 5,
        CoreHook::RenderContext => 6,
    };
    let mut fixture = template(hook);
    fixture.signature = match marker {
        1 => "B8 01 D0 C0 00 90 90 90 90 90 90 90 90 90 90 C3",
        2 => "B8 02 D0 C0 00 90 90 90 90 90 90 90 90 90 90 C3",
        3 => "B8 03 D0 C0 00 90 90 90 90 90 90 90 90 90 90 C3",
        4 => "B8 04 D0 C0 00 90 90 90 90 90 90 90 90 90 90 C3",
        5 => "B8 05 D0 C0 00 90 90 90 90 90 90 90 90 90 90 C3",
        _ => "B8 06 D0 C0 00 90 90 90 90 90 90 90 90 90 90 C3",
    };
    fixture.target_offset = 0;
    fixture.overwrite_size = 16;
    fixture
}

fn capture_payload(capture: &[u8]) -> (Vec<u8>, usize) {
    let mut payload = Vec::with_capacity(capture.len() + 19);
    payload.push(0x50); // push rax
    payload.extend_from_slice(capture);
    payload.extend_from_slice(&[0x48, 0x89, 0x05, 0x03, 0x00, 0x00, 0x00]); // mov [rip+3],rax
    payload.push(0x58); // pop rax
    payload.extend_from_slice(&[0xeb, 0x08]); // skip the private export slot
    let export_offset = payload.len();
    payload.extend_from_slice(&[0; 8]);
    (payload, export_offset)
}

fn player_payload() -> (Vec<u8>, usize) {
    let mut payload = vec![
        0x51, // push rcx
        0x8b, 0x88, 0x74, 0x04, 0x00, 0x00, // mov ecx,[rax+0x474]
        0x83, 0xf9, 0x08, // cmp ecx,8
        0x59, // pop rcx
        0x75, 0x07, // jne skip_store
        0x48, 0x89, 0x05, 0x02, 0x00, 0x00, 0x00, // mov [rip+2],rax
        0xeb, 0x08, // skip the private export slot
    ];
    let export_offset = payload.len();
    payload.extend_from_slice(&[0; 8]);
    (payload, export_offset)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::{
        activate, activate_all, deactivate, deactivate_all, heartbeat_all, hook_key, template,
    };
    use crate::hook::tests::{registry, Backend, Failure};
    use crate::hook::HookState;
    use crate::mutation::MutationState;
    use deimos_core::memory::{CoreHook, CoreHookRequest, CoreHookSessionRequest};
    use deimos_core::rpc::RpcErrorCode;

    #[test]
    fn every_core_hook_has_an_isolated_definition_and_private_export() {
        for selected in CoreHook::ALL {
            let template = template(selected);
            assert!(template.overwrite_size == 0 || template.overwrite_size >= 14);
            assert!(template.target_offset + template.overwrite_size <= 64);
            assert_eq!(
                &template.payload[template.export_offset..template.export_offset + 8],
                &[0; 8]
            );
            assert!(hook_key(selected).starts_with("wizwalker.core."));
        }
    }

    #[test]
    fn payloads_skip_their_export_slots_before_saved_instructions() {
        for selected in CoreHook::ALL {
            let template = template(selected);
            assert_eq!(
                &template.payload[template.export_offset - 2..template.export_offset],
                &[0xeb, 0x08]
            );
        }
    }

    #[test]
    fn root_window_hook_captures_the_current_r13_root_pointer() {
        let template = template(CoreHook::RootWindow);
        assert!(template.signature.starts_with("49 8B 8D D8 00 00 00"));
        assert_eq!(
            &template.payload[1..8],
            &[0x49, 0x8b, 0x85, 0xd8, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn every_core_hook_is_idempotent_restores_original_bytes_and_releases_ownership() {
        for selected in CoreHook::ALL {
            let backend = Backend::core(None);
            let before = backend.primary();
            let (mut sessions, session_id) = registry(&backend);
            let mut mutations = MutationState::new();
            let mut hooks = HookState::default();
            let request = CoreHookRequest {
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
            .expect("core hook should activate");
            activate(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                &request,
                Instant::now(),
            )
            .expect("core hook activation should be idempotent");
            assert_eq!(hooks.tracked_count(&session_id), 1);
            assert_eq!(mutations.tracked_count(&session_id), 1);
            assert_eq!(backend.allocation_count(), 1);
            assert_ne!(backend.primary(), before);
            assert!(
                deactivate(
                    &mut sessions,
                    &backend,
                    &mut mutations,
                    &mut hooks,
                    &request,
                )
                .expect("core hook should deactivate")
                .deactivated
            );
            assert_eq!(backend.primary(), before);
            assert_eq!(hooks.tracked_count(&session_id), 0);
            assert_eq!(mutations.tracked_count(&session_id), 0);
            assert_eq!(backend.allocation_count(), 0);
            assert!(
                !deactivate(
                    &mut sessions,
                    &backend,
                    &mut mutations,
                    &mut hooks,
                    &request,
                )
                .expect("core hook deactivation should be idempotent")
                .deactivated
            );
        }
    }

    #[test]
    fn every_core_hook_rolls_back_each_transaction_failure_stage() {
        for selected in CoreHook::ALL {
            for failure in [
                Failure::Allocate,
                Failure::TrampolineWrite,
                Failure::TrampolineFlush,
                Failure::TargetProtect,
                Failure::TargetWrite,
                Failure::TargetFlush,
                Failure::TargetRestore,
            ] {
                let backend = Backend::core(Some(failure));
                let before = backend.primary();
                let (mut sessions, session_id) = registry(&backend);
                let mut mutations = MutationState::new();
                let mut hooks = HookState::default();
                assert!(
                    activate(
                        &mut sessions,
                        &backend,
                        &mut mutations,
                        &mut hooks,
                        &CoreHookRequest {
                            session_id: session_id.clone(),
                            hook: selected,
                        },
                        Instant::now(),
                    )
                    .is_err(),
                    "{selected:?} should report the forced {failure:?} failure"
                );
                assert_eq!(backend.primary(), before);
                assert_eq!(hooks.tracked_count(&session_id), 0);
                assert_eq!(mutations.tracked_count(&session_id), 0);
                assert_eq!(backend.allocation_count(), 0);
            }
        }
    }

    #[test]
    fn combined_core_activation_and_cleanup_owns_exactly_six_hooks() {
        let backend = Backend::core(None);
        let before = backend.primary();
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let request = CoreHookSessionRequest {
            session_id: session_id.clone(),
        };
        let response = activate_all(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            Instant::now(),
        )
        .expect("combined activation should succeed");
        assert_eq!(response.hooks.len(), CoreHook::ALL.len());
        assert_eq!(hooks.tracked_count(&session_id), CoreHook::ALL.len());
        assert_eq!(mutations.tracked_count(&session_id), CoreHook::ALL.len());
        assert_eq!(backend.allocation_count(), CoreHook::ALL.len());
        assert_ne!(backend.primary(), before);
        assert_eq!(
            heartbeat_all(&mut hooks, &request, Instant::now())
                .expect("combined heartbeat should renew all hooks")
                .hooks
                .len(),
            CoreHook::ALL.len()
        );
        deactivate_all(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
        )
        .expect("combined cleanup should succeed");
        assert_eq!(backend.primary(), before);
        assert_eq!(hooks.tracked_count(&session_id), 0);
        assert_eq!(mutations.tracked_count(&session_id), 0);
        assert_eq!(backend.allocation_count(), 0);
    }

    #[test]
    fn combined_activation_attempts_every_rollback_after_one_cleanup_failure() {
        let backend = Backend::core(Some(Failure::Free));
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &CoreHookRequest {
                session_id: session_id.clone(),
                hook: CoreHook::Client,
            },
            Instant::now(),
        )
        .expect("pre-existing client hook should activate");

        // Make player-stat activation fail only after player and quest were
        // newly installed by the combined request.
        backend.corrupt_primary_byte(3 * 16);
        let request = CoreHookSessionRequest {
            session_id: session_id.clone(),
        };
        let error = activate_all(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            Instant::now(),
        )
        .expect_err("combined activation should report activation and rollback failure");
        assert_eq!(
            error.into_rpc_error(1, "core_hook.activate_all").code,
            RpcErrorCode::MemoryWriteFailed
        );

        assert!(
            hooks
                .allocation_address(&session_id, &hook_key(CoreHook::Player))
                .is_none(),
            "player rollback must still run after quest cleanup fails"
        );
        assert!(
            hooks
                .allocation_address(&session_id, &hook_key(CoreHook::Quest))
                .is_some(),
            "failed quest cleanup must retain agent ownership for retry"
        );
        assert!(
            hooks
                .allocation_address(&session_id, &hook_key(CoreHook::Client))
                .is_some(),
            "the hook that predated combined activation must remain active"
        );

        deactivate_all(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
        )
        .expect("retained hooks should clean up on retry");
        assert_eq!(hooks.tracked_count(&session_id), 0);
        assert_eq!(mutations.tracked_count(&session_id), 0);
        assert_eq!(backend.allocation_count(), 0);
    }
}
