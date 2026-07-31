#![cfg(windows)]

use std::ffi::c_void;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::mem::size_of;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use deimos_agent::process::ProcessSessionRegistry;
use deimos_agent::windows_process::{WindowsProcessBackend, WindowsProcessHandle};
use deimos_core::memory::{
    ByteOrder, CoreHook, CoreHookRequest, CoreHookSessionRequest, FeatureHook, FeatureHookRequest,
    HookActivateRequest, HookDeactivateRequest, HookHeartbeatRequest, MemoryAllocateRequest,
    MemoryBatchReadRequest, MemoryFreeRequest, MemoryPointerChainRequest, MemoryProtectRequest,
    MemoryReadItem, MemoryReadRequest, MemoryScanRequest, MemoryScanScope, MemorySessionRequest,
    MemoryValueType, MemoryWriteRequest, RemoteThreadStartRequest, TypedMemoryReadRequest,
};
use deimos_core::process::{
    ListProcessesRequest, OpenProcessRequest, ProcessAccessMode, ProcessKind,
    MEMORY_FIXTURE_EXECUTABLE, OP_PROCESS_STATUS,
};
use deimos_core::rpc::RpcErrorCode;
use deimos_memory_fixture::{
    FixtureMetadata, MemoryProtection, MemoryRegionMetadata, FIXTURE_SCHEMA_VERSION,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

const SHUTDOWN_COMMAND: &str = "shutdown";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const FEATURE_HOOK_AUXILIARY_PATTERN_COUNT: usize = 7;

struct FixtureProcess {
    child: Child,
    finished: bool,
}

impl FixtureProcess {
    fn spawn() -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_deimos-memory-fixture"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("fixture should launch");
        Self {
            child,
            finished: false,
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("fixture status should be readable")
            {
                self.finished = true;
                return status;
            }
            if Instant::now() >= deadline {
                let stderr = self.terminate();
                panic!("fixture did not stop within {timeout:?}; stderr: {stderr}");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn terminate(&mut self) -> String {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.finished = true;
        }

        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        stderr.trim().to_string()
    }
}

impl Drop for FixtureProcess {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[test]
fn fixture_publishes_discoverable_read_only_memory_and_stops_cleanly() {
    let mut fixture = FixtureProcess::spawn();
    let metadata = read_metadata(&mut fixture);

    assert_eq!(metadata.schema_version, FIXTURE_SCHEMA_VERSION);
    assert_eq!(metadata.pid, fixture.child.id());
    assert_eq!(metadata.architecture, "x86_64");
    assert_eq!(metadata.pointer_width, 8);
    assert!(metadata.mutation_enabled);

    let backend = WindowsProcessBackend;
    let mut sessions = ProcessSessionRegistry::<WindowsProcessHandle>::new();
    let listed = sessions
        .list(
            &backend,
            &ListProcessesRequest {
                names: vec![MEMORY_FIXTURE_EXECUTABLE.to_string()],
            },
        )
        .expect("agent should enumerate the fixture")
        .processes
        .into_iter()
        .find(|process| process.pid == metadata.pid)
        .expect("agent should discover the fixture by its Windows PID");
    assert_eq!(listed.kind, ProcessKind::MemoryFixture);
    assert!(
        listed
            .executable_path
            .as_deref()
            .is_some_and(|path| path.ends_with(MEMORY_FIXTURE_EXECUTABLE)),
        "agent should publish the fixture executable path"
    );
    let session = sessions
        .open(
            &backend,
            &OpenProcessRequest {
                pid: metadata.pid,
                expected_identity: listed.identity,
                access_mode: deimos_core::process::ProcessAccessMode::ReadOnly,
            },
        )
        .expect("agent should open a read-only fixture session");
    let modules = sessions
        .modules(&backend, &session.session_id)
        .expect("agent should enumerate fixture modules");
    assert!(
        modules.modules.iter().any(|module| {
            module.name.eq_ignore_ascii_case(MEMORY_FIXTURE_EXECUTABLE)
                && !module.executable_path.is_empty()
        }),
        "fixture executable module and path should be present"
    );

    let session_request = MemorySessionRequest {
        session_id: session.session_id.clone(),
    };
    let readable = deimos_agent::memory::regions(&mut sessions, &backend, &session_request)
        .expect("agent should enumerate readable regions")
        .regions;
    for region in &metadata.regions {
        let address = parse_address(&region.address);
        assert!(readable.iter().any(|candidate| {
            parse_address(&candidate.base_address) <= address
                && address < parse_address(&candidate.base_address) + candidate.size
        }));
    }

    let first_primitive = &metadata.primitives[0];
    let first_region = region(&metadata, &first_primitive.region);
    let raw = deimos_agent::memory::read(
        &mut sessions,
        &backend,
        &MemoryReadRequest {
            session_id: session.session_id.clone(),
            address: format!(
                "{:#x}",
                parse_address(&first_region.address) + first_primitive.offset
            ),
            size: first_primitive.size,
        },
    )
    .expect("agent should perform a validated arbitrary read");
    assert_eq!(raw.bytes, decode_hex(&first_primitive.expected_bytes));

    let batch = deimos_agent::memory::read_batch(
        &mut sessions,
        &backend,
        &MemoryBatchReadRequest {
            session_id: session.session_id.clone(),
            reads: metadata
                .primitives
                .iter()
                .map(|primitive| MemoryReadItem {
                    address: format!(
                        "{:#x}",
                        parse_address(&region(&metadata, &primitive.region).address)
                            + primitive.offset
                    ),
                    size: primitive.size,
                })
                .collect(),
        },
    )
    .expect("agent should batch-read fixture primitives");
    assert!(batch.results.iter().all(|result| result.error.is_none()));
    for (primitive, result) in metadata.primitives.iter().zip(batch.results) {
        assert_eq!(
            result
                .bytes
                .expect("successful batch item should contain bytes"),
            decode_hex(&primitive.expected_bytes),
            "{} should match its published value",
            primitive.name
        );
    }

    for primitive in &metadata.primitives {
        let value_type = match primitive.data_type.as_str() {
            "u8" => MemoryValueType::U8,
            "i32" => MemoryValueType::I32,
            "u32" => MemoryValueType::U32,
            "u64" => MemoryValueType::U64,
            "f32" => MemoryValueType::F32,
            "f64" => MemoryValueType::F64,
            other => panic!("unexpected fixture primitive type {other}"),
        };
        let typed = deimos_agent::memory::read_typed(
            &mut sessions,
            &backend,
            &TypedMemoryReadRequest {
                session_id: session.session_id.clone(),
                address: format!(
                    "{:#x}",
                    parse_address(&region(&metadata, &primitive.region).address) + primitive.offset
                ),
                value_type,
                byte_order: ByteOrder::LittleEndian,
            },
        )
        .expect("agent should typed-read fixture primitive");
        assert_eq!(typed.raw_bytes, decode_hex(&primitive.expected_bytes));
    }

    let exact = metadata
        .patterns
        .iter()
        .find(|pattern| pattern.name == "exact_anchor")
        .expect("exact fixture pattern should exist");
    let exact_scan = deimos_agent::memory::scan(
        &mut sessions,
        &backend,
        &MemoryScanRequest {
            session_id: session.session_id.clone(),
            signature: exact.signature.clone(),
            required: true,
            unique: true,
            max_matches: 4,
            scope: MemoryScanScope::Process,
        },
    )
    .expect("exact fixture pattern should have one required match");
    assert_eq!(
        exact_scan.matches,
        vec![format!(
            "{:#x}",
            parse_address(&region(&metadata, &exact.region).address) + exact.offset
        )]
    );

    let wildcard = metadata
        .patterns
        .iter()
        .find(|pattern| pattern.name == "wildcard_anchor")
        .expect("wildcard fixture pattern should exist");
    let wildcard_scan = deimos_agent::memory::scan(
        &mut sessions,
        &backend,
        &MemoryScanRequest {
            session_id: session.session_id.clone(),
            signature: wildcard.signature.clone(),
            required: true,
            unique: true,
            max_matches: 4,
            scope: MemoryScanScope::Process,
        },
    )
    .expect("wildcard fixture pattern should have one required match");
    assert_eq!(
        wildcard_scan.matches,
        vec![format!(
            "{:#x}",
            parse_address(&region(&metadata, &wildcard.region).address) + wildcard.offset
        )]
    );

    let chain = metadata
        .pointer_chains
        .first()
        .expect("fixture should publish a pointer chain");
    let root = metadata
        .patterns
        .iter()
        .find(|pattern| pattern.name == chain.root_pattern)
        .expect("pointer chain root should exist");
    let resolved = deimos_agent::memory::pointer_chain(
        &mut sessions,
        &backend,
        &MemoryPointerChainRequest {
            session_id: session.session_id.clone(),
            signature: root.signature.clone(),
            offsets: chain.offsets.iter().map(|offset| *offset as u64).collect(),
            dereference_count: chain.dereference_count,
            pointer_width: metadata.pointer_width as u8,
            byte_order: ByteOrder::LittleEndian,
            value_type: MemoryValueType::U64,
            scope: MemoryScanScope::Process,
        },
    )
    .expect("agent should resolve the published pointer chain");
    assert_eq!(resolved.raw_bytes, decode_hex(&chain.expected_bytes));
    assert!(
        (parse_address(&region(&metadata, &chain.target_region).address)
            ..parse_address(&region(&metadata, &chain.target_region).address)
                + region(&metadata, &chain.target_region).size)
            .contains(&parse_address(&resolved.target_address))
    );

    let module_name = modules
        .modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(MEMORY_FIXTURE_EXECUTABLE))
        .expect("fixture module should be present")
        .name
        .clone();
    let module_scan = deimos_agent::memory::scan(
        &mut sessions,
        &backend,
        &MemoryScanRequest {
            session_id: session.session_id.clone(),
            signature: exact.signature.clone(),
            required: false,
            unique: true,
            max_matches: 4,
            scope: MemoryScanScope::Module {
                name: module_name.clone(),
            },
        },
    )
    .expect("module scan should stay within the selected module");
    assert!(module_scan.matches.is_empty());
    let required_module_error = deimos_agent::memory::scan(
        &mut sessions,
        &backend,
        &MemoryScanRequest {
            session_id: session.session_id.clone(),
            signature: exact.signature.clone(),
            required: true,
            unique: true,
            max_matches: 4,
            scope: MemoryScanScope::Module { name: module_name },
        },
    )
    .expect_err("required module match should distinguish zero matches");
    let required_module_error = required_module_error.into_rpc_error(1, "memory.scan");
    assert_eq!(
        required_module_error.code,
        RpcErrorCode::MemoryRequiredMatchNotFound
    );

    let ambiguous_error = deimos_agent::memory::scan(
        &mut sessions,
        &backend,
        &MemoryScanRequest {
            session_id: session.session_id.clone(),
            signature: "??".to_string(),
            required: false,
            unique: true,
            max_matches: 4,
            scope: MemoryScanScope::Process,
        },
    )
    .expect_err("a wildcard byte should produce an ambiguous unique result");
    assert_eq!(
        ambiguous_error.into_rpc_error(1, "memory.scan").code,
        RpcErrorCode::MemoryAmbiguousMatch
    );

    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            metadata.pid,
        )
    }
    .map(OwnedHandle)
    .expect("fixture should allow read-only process access");

    verify_region_protections(&process, &metadata);
    verify_patterns(&process, &metadata);
    let first_snapshot = read_primitives(&process, &metadata);
    let first_chain = read_pointer_chain(&process, &metadata);
    thread::sleep(Duration::from_millis(25));
    assert_eq!(read_primitives(&process, &metadata), first_snapshot);
    assert_eq!(read_pointer_chain(&process, &metadata), first_chain);

    let mut stdin = fixture
        .child
        .stdin
        .take()
        .expect("fixture stdin should be piped");
    writeln!(stdin, "{SHUTDOWN_COMMAND}").expect("shutdown command should be writable");
    stdin.flush().expect("shutdown command should flush");
    drop(stdin);

    let status = fixture.wait_for_exit(SHUTDOWN_TIMEOUT);
    assert!(
        status.success(),
        "fixture should exit successfully: {status}"
    );
    let stale = sessions
        .status(&backend, &session.session_id)
        .expect_err("exited fixture session should become stale")
        .into_rpc_error(1, OP_PROCESS_STATUS);
    assert_eq!(stale.code, RpcErrorCode::ProcessExited);
}

#[test]
fn fixture_stops_cleanly_when_stdin_closes() {
    let mut fixture = FixtureProcess::spawn();
    let metadata = read_metadata(&mut fixture);
    assert_eq!(metadata.pid, fixture.child.id());

    drop(
        fixture
            .child
            .stdin
            .take()
            .expect("fixture stdin should be piped"),
    );

    let status = fixture.wait_for_exit(SHUTDOWN_TIMEOUT);
    assert!(
        status.success(),
        "fixture should exit successfully after stdin closes: {status}"
    );
}

#[test]
fn fixture_validates_controlled_mutation_primitives_and_cleanup() {
    let mut fixture = FixtureProcess::spawn();
    let metadata = read_metadata(&mut fixture);
    assert!(metadata.mutation_enabled);

    let backend = WindowsProcessBackend;
    let mut sessions = ProcessSessionRegistry::<WindowsProcessHandle>::new();
    let listed = sessions
        .list(
            &backend,
            &ListProcessesRequest {
                names: vec![MEMORY_FIXTURE_EXECUTABLE.to_string()],
            },
        )
        .expect("agent should enumerate the fixture")
        .processes
        .into_iter()
        .find(|process| process.pid == metadata.pid)
        .expect("fixture should be discoverable");
    let identity = listed
        .identity
        .clone()
        .expect("fixture should have a stable identity");

    let read_only = sessions
        .open(
            &backend,
            &OpenProcessRequest {
                pid: metadata.pid,
                expected_identity: Some(identity.clone()),
                access_mode: ProcessAccessMode::ReadOnly,
            },
        )
        .expect("read-only fixture session should open");
    let sentinel = metadata
        .primitives
        .iter()
        .find(|primitive| primitive.name == "writable_sentinel")
        .expect("fixture should publish a writable sentinel");
    let writable_region = region(&metadata, &sentinel.region);
    let sentinel_address = parse_address(&writable_region.address) + sentinel.offset;
    let original_sentinel = decode_hex(&sentinel.expected_bytes);
    let read_only_error = deimos_agent::mutation::write(
        &mut sessions,
        &backend,
        &MemoryWriteRequest {
            session_id: read_only.session_id.clone(),
            address: format!("{sentinel_address:#x}"),
            bytes: vec![1, 2, 3, 4],
        },
    )
    .expect_err("read-only fixture sessions must not mutate")
    .into_rpc_error(1, "memory.write");
    assert_eq!(read_only_error.code, RpcErrorCode::CapabilityRequired);
    assert_eq!(
        deimos_agent::memory::read(
            &mut sessions,
            &backend,
            &MemoryReadRequest {
                session_id: read_only.session_id.clone(),
                address: format!("{sentinel_address:#x}"),
                size: original_sentinel.len(),
            },
        )
        .expect("sentinel should remain readable")
        .bytes,
        original_sentinel
    );

    let mutation_session = sessions
        .open(
            &backend,
            &OpenProcessRequest {
                pid: metadata.pid,
                expected_identity: Some(identity),
                access_mode: ProcessAccessMode::Mutation,
            },
        )
        .expect("mutation fixture session should open");
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            metadata.pid,
        )
    }
    .map(OwnedHandle)
    .expect("fixture should allow protection and atomicity inspection");
    let before = deimos_agent::memory::read(
        &mut sessions,
        &backend,
        &MemoryReadRequest {
            session_id: mutation_session.session_id.clone(),
            address: format!("{sentinel_address:#x}"),
            size: 12,
        },
    )
    .expect("writable target and guards should be readable")
    .bytes;
    let replacement = 0x1234_5678u32.to_le_bytes();
    deimos_agent::mutation::write(
        &mut sessions,
        &backend,
        &MemoryWriteRequest {
            session_id: mutation_session.session_id.clone(),
            address: format!("{sentinel_address:#x}"),
            bytes: replacement.to_vec(),
        },
    )
    .expect("controlled sentinel write should succeed");
    let after = deimos_agent::memory::read(
        &mut sessions,
        &backend,
        &MemoryReadRequest {
            session_id: mutation_session.session_id.clone(),
            address: format!("{sentinel_address:#x}"),
            size: 12,
        },
    )
    .expect("written target and guards should be readable")
    .bytes;
    assert_eq!(&after[..replacement.len()], &replacement);
    assert_eq!(
        &after[replacement.len()..],
        &before[replacement.len()..],
        "a valid write must not alter adjacent memory"
    );

    let read_only_region = region(&metadata, "read_only_values");
    let read_only_address = parse_address(&read_only_region.address);
    let protected_before = deimos_agent::memory::read(
        &mut sessions,
        &backend,
        &MemoryReadRequest {
            session_id: mutation_session.session_id.clone(),
            address: format!("{read_only_address:#x}"),
            size: 16,
        },
    )
    .expect("protected target should be readable")
    .bytes;
    let invalid_write = deimos_agent::mutation::write(
        &mut sessions,
        &backend,
        &MemoryWriteRequest {
            session_id: mutation_session.session_id.clone(),
            address: format!("{read_only_address:#x}"),
            bytes: vec![0xff; 16],
        },
    )
    .expect_err("write to read-only fixture memory must fail")
    .into_rpc_error(2, "memory.write");
    assert_eq!(invalid_write.code, RpcErrorCode::MemoryWriteFailed);
    assert_eq!(
        deimos_agent::memory::read(
            &mut sessions,
            &backend,
            &MemoryReadRequest {
                session_id: mutation_session.session_id.clone(),
                address: format!("{read_only_address:#x}"),
                size: 16,
            },
        )
        .expect("protected target should remain readable")
        .bytes,
        protected_before,
        "a failed write must not alter the target or adjacent bytes"
    );

    let boundary = metadata
        .mutation_boundary
        .as_ref()
        .expect("mutation-enabled fixture should publish boundary metadata");
    let boundary_write_address = parse_address(&boundary.write_address);
    let writable_page_address = parse_address(&boundary.writable_page_address);
    let read_only_page_address = parse_address(&boundary.read_only_page_address);
    let modified_page_address = parse_address(&boundary.modified_page_address);
    let writable_tail_size = read_only_page_address - boundary_write_address;
    let read_only_head_size = boundary.write_size - writable_tail_size;
    let writable_tail_before = read_memory(&process, boundary_write_address, writable_tail_size);
    let read_only_head_before = read_memory(&process, read_only_page_address, read_only_head_size);
    assert!(
        writable_tail_before
            .iter()
            .chain(&read_only_head_before)
            .all(|byte| *byte == boundary.expected_byte),
        "fixture boundary pages should start with deterministic bytes"
    );
    let crossing_write = deimos_agent::mutation::write(
        &mut sessions,
        &backend,
        &MemoryWriteRequest {
            session_id: mutation_session.session_id.clone(),
            address: boundary.write_address.clone(),
            bytes: vec![0xa5; boundary.write_size],
        },
    )
    .expect_err("write crossing from writable into read-only memory must fail atomically")
    .into_rpc_error(3, "memory.write");
    assert_eq!(crossing_write.code, RpcErrorCode::MemoryWriteFailed);
    assert_eq!(
        read_memory(&process, boundary_write_address, writable_tail_size),
        writable_tail_before,
        "failed crossing write must not change the writable page"
    );
    assert_eq!(
        read_memory(&process, read_only_page_address, read_only_head_size),
        read_only_head_before,
        "failed crossing write must not change the read-only page"
    );

    let writable_protection_before = query_protection(&process, writable_page_address);
    let read_only_protection_before = query_protection(&process, read_only_page_address);
    assert_eq!(writable_protection_before, PAGE_READWRITE.0);
    assert_eq!(read_only_protection_before, PAGE_READONLY.0);
    let mixed_protection = deimos_agent::mutation::protect(
        &mut sessions,
        &backend,
        &MemoryProtectRequest {
            session_id: mutation_session.session_id.clone(),
            address: boundary.write_address.clone(),
            size: boundary.write_size,
            protection: deimos_core::memory::MemoryProtection::ReadWrite,
        },
    )
    .expect_err("protection changes spanning mixed regions must be rejected")
    .into_rpc_error(4, "memory.protect");
    assert_eq!(mixed_protection.code, RpcErrorCode::MemoryProtectionFailed);
    assert_eq!(
        query_protection(&process, writable_page_address),
        writable_protection_before,
        "mixed-region rejection must preserve the writable page protection"
    );
    assert_eq!(
        query_protection(&process, read_only_page_address),
        read_only_protection_before,
        "mixed-region rejection must preserve the read-only page protection"
    );

    let modified_protection_before = query_protection(&process, modified_page_address);
    assert_eq!(modified_protection_before, (PAGE_READWRITE | PAGE_GUARD).0);
    let modified_protection = deimos_agent::mutation::protect(
        &mut sessions,
        &backend,
        &MemoryProtectRequest {
            session_id: mutation_session.session_id.clone(),
            address: boundary.modified_page_address.clone(),
            size: boundary.page_size,
            protection: deimos_core::memory::MemoryProtection::ReadOnly,
        },
    )
    .expect_err("protection changes must reject unrepresentable modifiers")
    .into_rpc_error(5, "memory.protect");
    assert_eq!(
        modified_protection.code,
        RpcErrorCode::MemoryProtectionFailed
    );
    assert_eq!(
        query_protection(&process, modified_page_address),
        modified_protection_before,
        "modifier rejection must preserve the exact page protection"
    );

    let changed = deimos_agent::mutation::protect(
        &mut sessions,
        &backend,
        &MemoryProtectRequest {
            session_id: mutation_session.session_id.clone(),
            address: format!("{read_only_address:#x}"),
            size: read_only_region.size,
            protection: deimos_core::memory::MemoryProtection::ReadWrite,
        },
    )
    .expect("fixture protection should become writable");
    assert_eq!(
        changed.previous_protection,
        deimos_core::memory::MemoryProtection::ReadOnly
    );
    let restored = deimos_agent::mutation::protect(
        &mut sessions,
        &backend,
        &MemoryProtectRequest {
            session_id: mutation_session.session_id.clone(),
            address: format!("{read_only_address:#x}"),
            size: read_only_region.size,
            protection: deimos_core::memory::MemoryProtection::ReadOnly,
        },
    )
    .expect("fixture protection should be restored");
    assert_eq!(
        restored.previous_protection,
        deimos_core::memory::MemoryProtection::ReadWrite
    );

    let mut mutations = deimos_agent::mutation::MutationState::new();
    let data = deimos_agent::mutation::allocate(
        &mut sessions,
        &backend,
        &mut mutations,
        &MemoryAllocateRequest {
            session_id: mutation_session.session_id.clone(),
            size: 4096,
            protection: deimos_core::memory::MemoryProtection::ReadWrite,
        },
    )
    .expect("remote data allocation should succeed");
    let code = deimos_agent::mutation::allocate(
        &mut sessions,
        &backend,
        &mut mutations,
        &MemoryAllocateRequest {
            session_id: mutation_session.session_id.clone(),
            size: 4096,
            protection: deimos_core::memory::MemoryProtection::ExecuteReadWrite,
        },
    )
    .expect("remote executable allocation should succeed");
    assert_eq!(mutations.tracked_count(&mutation_session.session_id), 2);

    let remote_code = [
        0x48, 0x89, 0xc8, // mov rax, rcx
        0xc7, 0x00, 0x78, 0x56, 0x34, 0x12, // mov dword ptr [rax], 0x12345678
        0x31, 0xc0, // xor eax, eax
        0xc3, // ret
    ];
    deimos_agent::mutation::write(
        &mut sessions,
        &backend,
        &MemoryWriteRequest {
            session_id: mutation_session.session_id.clone(),
            address: code.address.clone(),
            bytes: remote_code.to_vec(),
        },
    )
    .expect("remote thread body should be writable");
    let thread = deimos_agent::mutation::start_thread(
        &mut sessions,
        &backend,
        &mut mutations,
        &RemoteThreadStartRequest {
            session_id: mutation_session.session_id.clone(),
            start_address: code.address.clone(),
            parameter: Some(data.address.clone()),
            wait_timeout_ms: 4_000,
        },
    )
    .expect("controlled remote thread should start");
    assert!(thread.completed, "controlled remote thread should finish");
    assert_eq!(thread.exit_code, Some(0));
    assert_eq!(
        deimos_agent::memory::read(
            &mut sessions,
            &backend,
            &MemoryReadRequest {
                session_id: mutation_session.session_id.clone(),
                address: data.address.clone(),
                size: 4,
            },
        )
        .expect("remote thread output should be readable")
        .bytes,
        replacement
    );

    deimos_agent::mutation::free(
        &mut sessions,
        &backend,
        &mut mutations,
        &MemoryFreeRequest {
            session_id: mutation_session.session_id.clone(),
            allocation_id: code.allocation_id,
        },
    )
    .expect("explicit free should release executable memory");
    assert_eq!(mutations.tracked_count(&mutation_session.session_id), 1);
    deimos_agent::mutation::cleanup_session(
        &mut sessions,
        &backend,
        &mut mutations,
        &mutation_session.session_id,
    )
    .expect("session cleanup should release remaining allocations");
    assert_eq!(mutations.tracked_count(&mutation_session.session_id), 0);
    let freed_read = deimos_agent::memory::read(
        &mut sessions,
        &backend,
        &MemoryReadRequest {
            session_id: mutation_session.session_id.clone(),
            address: data.address,
            size: 4,
        },
    )
    .expect_err("released remote memory must no longer be readable")
    .into_rpc_error(3, "memory.read");
    assert_eq!(freed_read.code, RpcErrorCode::MemoryReadFailed);

    sessions
        .close(&backend, &mutation_session.session_id)
        .expect("mutation session should close after cleanup");
    sessions
        .close(&backend, &read_only.session_id)
        .expect("read-only session should close");

    let mut stdin = fixture
        .child
        .stdin
        .take()
        .expect("fixture stdin should be piped");
    writeln!(stdin, "{SHUTDOWN_COMMAND}").expect("shutdown command should be writable");
    stdin.flush().expect("shutdown command should flush");
    drop(stdin);
    assert!(fixture.wait_for_exit(SHUTDOWN_TIMEOUT).success());
}

#[test]
fn fixture_validates_transactional_hook_lifecycle() {
    let mut fixture = FixtureProcess::spawn();
    let metadata = read_metadata(&mut fixture);
    let backend = WindowsProcessBackend;
    let mut sessions = ProcessSessionRegistry::<WindowsProcessHandle>::new();
    let listed = sessions
        .list(
            &backend,
            &ListProcessesRequest {
                names: vec![MEMORY_FIXTURE_EXECUTABLE.to_string()],
            },
        )
        .expect("agent should enumerate fixture")
        .processes
        .into_iter()
        .find(|process| process.pid == metadata.pid)
        .expect("fixture should be discoverable");
    let session = sessions
        .open(
            &backend,
            &OpenProcessRequest {
                pid: metadata.pid,
                expected_identity: listed.identity,
                access_mode: ProcessAccessMode::Mutation,
            },
        )
        .expect("mutation fixture session should open");
    // A private executable allocation keeps the hook test independent of the
    // fixture's data signatures and proves the trampoline is executable. The
    // original body stores 0x11111111 at [rcx], clears [rcx + 4], returns, and
    // is exactly 16 complete position-independent x64 bytes.
    let original_code = [
        0xc7, 0x01, 0x11, 0x11, 0x11, 0x11, // mov dword ptr [rcx], 0x11111111
        0xc7, 0x41, 0x04, 0, 0, 0, 0, // mov dword ptr [rcx + 4], 0
        0x31, 0xc0, // xor eax, eax
        0xc3, // ret
    ];
    let mut mutations = deimos_agent::mutation::MutationState::new();
    let target_allocation = deimos_agent::mutation::allocate(
        &mut sessions,
        &backend,
        &mut mutations,
        &MemoryAllocateRequest {
            session_id: session.session_id.clone(),
            size: original_code.len(),
            protection: deimos_core::memory::MemoryProtection::ExecuteReadWrite,
        },
    )
    .expect("fixture hook target allocation should succeed");
    let output_allocation = deimos_agent::mutation::allocate(
        &mut sessions,
        &backend,
        &mut mutations,
        &MemoryAllocateRequest {
            session_id: session.session_id.clone(),
            size: 12,
            protection: deimos_core::memory::MemoryProtection::ReadWrite,
        },
    )
    .expect("fixture hook output allocation should succeed");
    deimos_agent::mutation::write(
        &mut sessions,
        &backend,
        &MemoryWriteRequest {
            session_id: session.session_id.clone(),
            address: target_allocation.address.clone(),
            bytes: original_code.to_vec(),
        },
    )
    .expect("fixture hook target should be writable");
    let target = parse_address(&target_allocation.address);
    let before = deimos_agent::memory::read(
        &mut sessions,
        &backend,
        &MemoryReadRequest {
            session_id: session.session_id.clone(),
            address: format!("{target:#x}"),
            size: original_code.len(),
        },
    )
    .expect("hook target should be readable")
    .bytes;
    let request = HookActivateRequest {
        session_id: session.session_id.clone(),
        hook_key: "fixture.lifecycle".to_string(),
        signature: "C7 01 11 11 11 11 C7 41 04 00 00 00 00 31 C0 C3".to_string(),
        scope: MemoryScanScope::Process,
        // This payload runs before the copied original code and writes a
        // separate output slot that the original body does not touch.
        payload: vec![0xc7, 0x41, 0x08, 0x22, 0x22, 0x22, 0x22],
    };
    let mut hooks = deimos_agent::hook::HookState::default();
    let activated = deimos_agent::hook::activate(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        &request,
        Instant::now(),
    )
    .expect("fixture hook should activate");
    assert_eq!(activated.target_address, format!("{target:#x}"));
    assert_eq!(hooks.tracked_count(&session.session_id), 1);
    assert_eq!(mutations.tracked_count(&session.session_id), 3);
    assert_ne!(
        deimos_agent::memory::read(
            &mut sessions,
            &backend,
            &MemoryReadRequest {
                session_id: session.session_id.clone(),
                address: format!("{target:#x}"),
                size: before.len(),
            },
        )
        .expect("active detour should be readable")
        .bytes,
        before
    );
    let repeated = deimos_agent::hook::activate(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        &request,
        Instant::now(),
    )
    .expect("identical activation should be idempotent");
    assert_eq!(repeated.allocation_id, activated.allocation_id);
    assert_eq!(mutations.tracked_count(&session.session_id), 3);
    let hooked = deimos_agent::mutation::start_thread(
        &mut sessions,
        &backend,
        &mut mutations,
        &RemoteThreadStartRequest {
            session_id: session.session_id.clone(),
            start_address: target_allocation.address.clone(),
            parameter: Some(output_allocation.address.clone()),
            wait_timeout_ms: 4_000,
        },
    )
    .expect("hooked fixture target should execute");
    assert!(hooked.completed);
    assert_eq!(
        deimos_agent::memory::read(
            &mut sessions,
            &backend,
            &MemoryReadRequest {
                session_id: session.session_id.clone(),
                address: output_allocation.address.clone(),
                size: 12,
            },
        )
        .expect("hooked output should be readable")
        .bytes,
        [
            0x11, 0x11, 0x11, 0x11, // copied original body
            0, 0, 0, 0, // copied original body
            0x22, 0x22, 0x22, 0x22, // hook payload
        ],
        "payload, saved original instructions, and continuation must execute in order"
    );
    deimos_agent::hook::heartbeat(
        &mut hooks,
        &HookHeartbeatRequest {
            session_id: session.session_id.clone(),
            hook_key: request.hook_key.clone(),
        },
        Instant::now(),
    )
    .expect("heartbeat should renew active hook");
    deimos_agent::hook::deactivate(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        &HookDeactivateRequest {
            session_id: session.session_id.clone(),
            hook_key: request.hook_key.clone(),
        },
    )
    .expect("deactivation should restore fixture bytes");
    assert_eq!(hooks.tracked_count(&session.session_id), 0);
    assert_eq!(mutations.tracked_count(&session.session_id), 2);
    assert_eq!(
        deimos_agent::memory::read(
            &mut sessions,
            &backend,
            &MemoryReadRequest {
                session_id: session.session_id.clone(),
                address: format!("{target:#x}"),
                size: before.len(),
            },
        )
        .expect("deactivated target should be readable")
        .bytes,
        before
    );
    deimos_agent::mutation::write(
        &mut sessions,
        &backend,
        &MemoryWriteRequest {
            session_id: session.session_id.clone(),
            address: output_allocation.address.clone(),
            bytes: vec![0; 12],
        },
    )
    .expect("fixture output should reset");
    deimos_agent::mutation::start_thread(
        &mut sessions,
        &backend,
        &mut mutations,
        &RemoteThreadStartRequest {
            session_id: session.session_id.clone(),
            start_address: target_allocation.address.clone(),
            parameter: Some(output_allocation.address.clone()),
            wait_timeout_ms: 4_000,
        },
    )
    .expect("unhooked fixture target should execute");
    assert_eq!(
        deimos_agent::memory::read(
            &mut sessions,
            &backend,
            &MemoryReadRequest {
                session_id: session.session_id.clone(),
                address: output_allocation.address.clone(),
                size: 12,
            },
        )
        .expect("unhooked output should be readable")
        .bytes,
        [0x11, 0x11, 0x11, 0x11, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    for allocation_id in [
        target_allocation.allocation_id,
        output_allocation.allocation_id,
    ] {
        deimos_agent::mutation::free(
            &mut sessions,
            &backend,
            &mut mutations,
            &MemoryFreeRequest {
                session_id: session.session_id.clone(),
                allocation_id,
            },
        )
        .expect("fixture hook test allocation should be released");
    }
    sessions
        .close(&backend, &session.session_id)
        .expect("fixture session should close");
    let mut stdin = fixture
        .child
        .stdin
        .take()
        .expect("fixture stdin should be piped");
    writeln!(stdin, "{SHUTDOWN_COMMAND}").expect("shutdown command should be writable");
    stdin.flush().expect("shutdown command should flush");
    drop(stdin);
    assert!(fixture.wait_for_exit(SHUTDOWN_TIMEOUT).success());
}

#[test]
fn fixture_validates_every_core_hook_and_combined_cleanup() {
    let mut fixture = FixtureProcess::spawn();
    let metadata = read_metadata(&mut fixture);
    let backend = WindowsProcessBackend;
    let mut sessions = ProcessSessionRegistry::<WindowsProcessHandle>::new();
    let listed = sessions
        .list(
            &backend,
            &ListProcessesRequest {
                names: vec![MEMORY_FIXTURE_EXECUTABLE.to_string()],
            },
        )
        .expect("agent should enumerate the fixture")
        .processes
        .into_iter()
        .find(|process| process.pid == metadata.pid)
        .expect("fixture should be discoverable");
    let session = sessions
        .open(
            &backend,
            &OpenProcessRequest {
                pid: metadata.pid,
                expected_identity: listed.identity,
                access_mode: ProcessAccessMode::Mutation,
            },
        )
        .expect("mutation fixture session should open");
    let read_only = metadata
        .regions
        .iter()
        .find(|region| region.name == "read_only_values")
        .expect("fixture should publish its core-hook region");
    let region_base = parse_address(&read_only.address);
    let mut targets = Vec::new();
    for name in [
        "core_hook_client",
        "core_hook_player",
        "core_hook_quest",
        "core_hook_player_stat",
        "core_hook_root_window",
        "core_hook_render_context",
    ] {
        let pattern = metadata
            .patterns
            .iter()
            .find(|pattern| pattern.name == name)
            .expect("fixture should publish every core-hook target");
        targets.push((region_base + pattern.offset, pattern.signature.clone()));
    }

    let mut mutations = deimos_agent::mutation::MutationState::new();
    let mut hooks = deimos_agent::hook::HookState::default();
    for (selected, (target, signature)) in CoreHook::ALL.into_iter().zip(&targets) {
        let before = deimos_agent::memory::read(
            &mut sessions,
            &backend,
            &MemoryReadRequest {
                session_id: session.session_id.clone(),
                address: format!("{target:#x}"),
                size: 16,
            },
        )
        .expect("fixture target should be readable")
        .bytes;
        assert_eq!(signature, &signature_bytes(&before));
        let request = CoreHookRequest {
            session_id: session.session_id.clone(),
            hook: selected,
        };
        deimos_agent::core_hook::activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            Instant::now(),
        )
        .expect("core hook should activate");
        deimos_agent::core_hook::activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            Instant::now(),
        )
        .expect("core hook activation should be idempotent");
        assert_ne!(
            deimos_agent::memory::read(
                &mut sessions,
                &backend,
                &MemoryReadRequest {
                    session_id: session.session_id.clone(),
                    address: format!("{target:#x}"),
                    size: 16,
                },
            )
            .expect("active target should be readable")
            .bytes,
            before
        );
        deimos_agent::core_hook::deactivate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
        )
        .expect("core hook should deactivate");
        assert_eq!(
            deimos_agent::memory::read(
                &mut sessions,
                &backend,
                &MemoryReadRequest {
                    session_id: session.session_id.clone(),
                    address: format!("{target:#x}"),
                    size: 16,
                },
            )
            .expect("restored target should be readable")
            .bytes,
            before
        );
        assert!(
            !deimos_agent::core_hook::deactivate(
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

    let combined = CoreHookSessionRequest {
        session_id: session.session_id.clone(),
    };
    deimos_agent::core_hook::activate_all(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        &combined,
        Instant::now(),
    )
    .expect("combined core hooks should activate atomically");
    assert_eq!(
        hooks.tracked_count(&session.session_id),
        CoreHook::ALL.len()
    );
    deimos_agent::core_hook::deactivate_all(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        &combined,
    )
    .expect("combined core hooks should clean up");
    assert_eq!(hooks.tracked_count(&session.session_id), 0);
    assert_eq!(mutations.tracked_count(&session.session_id), 0);

    sessions
        .close(&backend, &session.session_id)
        .expect("fixture session should close");
    let mut stdin = fixture
        .child
        .stdin
        .take()
        .expect("fixture stdin should be piped");
    writeln!(stdin, "{SHUTDOWN_COMMAND}").expect("shutdown command should be writable");
    stdin.flush().expect("shutdown command should flush");
    drop(stdin);
    assert!(fixture.wait_for_exit(SHUTDOWN_TIMEOUT).success());
}

#[test]
fn fixture_restores_feature_auxiliary_patches_for_deactivate_expiry_and_session_cleanup() {
    let mut fixture = FixtureProcess::spawn();
    let metadata = read_metadata(&mut fixture);
    let backend = WindowsProcessBackend;
    let mut sessions = ProcessSessionRegistry::<WindowsProcessHandle>::new();
    let listed = sessions
        .list(
            &backend,
            &ListProcessesRequest {
                names: vec![MEMORY_FIXTURE_EXECUTABLE.to_string()],
            },
        )
        .expect("agent should enumerate the fixture")
        .processes
        .into_iter()
        .find(|process| process.pid == metadata.pid)
        .expect("fixture should be discoverable");
    let session = sessions
        .open(
            &backend,
            &OpenProcessRequest {
                pid: metadata.pid,
                expected_identity: listed.identity,
                access_mode: ProcessAccessMode::Mutation,
            },
        )
        .expect("mutation fixture session should open");
    let read_only = region(&metadata, "read_only_values");
    let region_base = parse_address(&read_only.address);
    let tracked = [
        "feature_hook_movement_teleport",
        "feature_movement_forward",
        "feature_movement_backward",
        "feature_movement_collision_one",
        "feature_movement_collision_two",
        "feature_hook_mouseless_cursor",
        "feature_mouse_set_cursor",
        "feature_mouse_toggle_one",
        "feature_mouse_toggle_two",
    ]
    .into_iter()
    .map(|name| {
        let pattern = metadata
            .patterns
            .iter()
            .find(|pattern| pattern.name == name)
            .expect("fixture should publish every feature target");
        let address = region_base + pattern.offset;
        let size = pattern.signature.split_whitespace().count();
        let original = deimos_agent::memory::read(
            &mut sessions,
            &backend,
            &MemoryReadRequest {
                session_id: session.session_id.clone(),
                address: format!("{address:#x}"),
                size,
            },
        )
        .expect("feature target should be readable")
        .bytes;
        (name, address, original)
    })
    .collect::<Vec<_>>();
    let mut mutations = deimos_agent::mutation::MutationState::new();
    let mut hooks = deimos_agent::hook::HookState::default();

    let movement = FeatureHookRequest {
        session_id: session.session_id.clone(),
        hook: FeatureHook::MovementTeleport,
    };
    deimos_agent::feature_hook::activate(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        &movement,
        Instant::now(),
    )
    .expect("movement feature should activate");
    assert_feature_target_changed(&mut sessions, &backend, &session.session_id, &tracked[3]);
    assert_feature_target_changed(&mut sessions, &backend, &session.session_id, &tracked[4]);
    deimos_agent::feature_hook::deactivate(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        &movement,
    )
    .expect("movement feature should deactivate");
    assert_feature_targets_restored(&mut sessions, &backend, &session.session_id, &tracked[..5]);

    let mouseless = FeatureHookRequest {
        session_id: session.session_id.clone(),
        hook: FeatureHook::MouselessCursor,
    };
    deimos_agent::feature_hook::activate(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        &mouseless,
        Instant::now(),
    )
    .expect("mouseless feature should activate");
    for target in &tracked[6..] {
        assert_feature_target_changed(&mut sessions, &backend, &session.session_id, target);
    }
    deimos_agent::hook::expire_at(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        Instant::now() + deimos_agent::hook::HOOK_LEASE + Duration::from_millis(1),
    )
    .expect("lease expiry should restore mouseless ownership");
    assert_feature_targets_restored(&mut sessions, &backend, &session.session_id, &tracked[5..]);

    deimos_agent::feature_hook::activate(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        &movement,
        Instant::now(),
    )
    .expect("movement feature should reactivate");
    deimos_agent::hook::cleanup_session(
        &mut sessions,
        &backend,
        &mut mutations,
        &mut hooks,
        &session.session_id,
    )
    .expect("session cleanup should restore movement ownership");
    assert_feature_targets_restored(&mut sessions, &backend, &session.session_id, &tracked[..5]);
    assert_eq!(hooks.tracked_count(&session.session_id), 0);
    assert_eq!(mutations.tracked_count(&session.session_id), 0);
    let regions = deimos_agent::memory::regions(
        &mut sessions,
        &backend,
        &MemorySessionRequest {
            session_id: session.session_id.clone(),
        },
    )
    .expect("fixture regions should remain readable");
    assert!(regions.regions.iter().any(|candidate| {
        parse_address(&candidate.base_address) == region_base
            && candidate.protection == deimos_core::memory::MemoryProtection::ReadOnly
    }));

    sessions
        .close(&backend, &session.session_id)
        .expect("fixture session should close");
    let mut stdin = fixture
        .child
        .stdin
        .take()
        .expect("fixture stdin should be piped");
    writeln!(stdin, "{SHUTDOWN_COMMAND}").expect("shutdown command should be writable");
    stdin.flush().expect("shutdown command should flush");
    drop(stdin);
    assert!(fixture.wait_for_exit(SHUTDOWN_TIMEOUT).success());
}

fn assert_feature_target_changed(
    sessions: &mut ProcessSessionRegistry<WindowsProcessHandle>,
    backend: &WindowsProcessBackend,
    session_id: &deimos_core::process::ProcessSessionId,
    target: &(&str, usize, Vec<u8>),
) {
    let actual = deimos_agent::memory::read(
        sessions,
        backend,
        &MemoryReadRequest {
            session_id: session_id.clone(),
            address: format!("{:#x}", target.1),
            size: target.2.len(),
        },
    )
    .expect("active feature target should be readable")
    .bytes;
    assert_ne!(actual, target.2, "{} should be patched", target.0);
}

fn assert_feature_targets_restored(
    sessions: &mut ProcessSessionRegistry<WindowsProcessHandle>,
    backend: &WindowsProcessBackend,
    session_id: &deimos_core::process::ProcessSessionId,
    targets: &[(&str, usize, Vec<u8>)],
) {
    for target in targets {
        let actual = deimos_agent::memory::read(
            sessions,
            backend,
            &MemoryReadRequest {
                session_id: session_id.clone(),
                address: format!("{:#x}", target.1),
                size: target.2.len(),
            },
        )
        .expect("restored feature target should be readable")
        .bytes;
        assert_eq!(actual, target.2, "{} should be restored exactly", target.0);
    }
}

fn signature_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_metadata(fixture: &mut FixtureProcess) -> FixtureMetadata {
    let stdout = fixture
        .child
        .stdout
        .take()
        .expect("fixture stdout should be piped");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).and_then(|count| {
            if count == 0 {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "fixture exited before publishing metadata",
                ))
            } else {
                Ok(line)
            }
        });
        let _ = sender.send(result);
    });

    let line = match receiver.recv_timeout(STARTUP_TIMEOUT) {
        Ok(Ok(line)) => line,
        Ok(Err(error)) => startup_failure(fixture, format!("failed to read metadata: {error}")),
        Err(mpsc::RecvTimeoutError::Timeout) => startup_failure(
            fixture,
            format!("fixture did not publish metadata within {STARTUP_TIMEOUT:?}"),
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            startup_failure(fixture, "metadata reader stopped unexpectedly".to_string())
        }
    };

    serde_json::from_str(line.trim_end()).unwrap_or_else(|error| {
        startup_failure(
            fixture,
            format!("fixture metadata should be valid JSON: {error}"),
        )
    })
}

fn startup_failure(fixture: &mut FixtureProcess, message: String) -> ! {
    let stderr = fixture.terminate();
    panic!("{message}; stderr: {stderr}");
}

fn verify_region_protections(process: &OwnedHandle, metadata: &FixtureMetadata) {
    assert_eq!(metadata.regions.len(), 4);
    for region in &metadata.regions {
        let mut information = MEMORY_BASIC_INFORMATION::default();
        let result = unsafe {
            VirtualQueryEx(
                process.0,
                Some(parse_address(&region.address) as *const c_void),
                &mut information,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        assert_eq!(
            result,
            size_of::<MEMORY_BASIC_INFORMATION>(),
            "VirtualQueryEx should describe {}",
            region.name
        );
        assert!(information.RegionSize >= region.size);
        let expected = match region.protection {
            MemoryProtection::ReadOnly => PAGE_READONLY,
            MemoryProtection::ReadWrite => PAGE_READWRITE,
        };
        assert_eq!(
            information.Protect, expected,
            "{} protection should match metadata",
            region.name
        );
    }
}

fn query_protection(process: &OwnedHandle, address: usize) -> u32 {
    let mut information = MEMORY_BASIC_INFORMATION::default();
    let result = unsafe {
        VirtualQueryEx(
            process.0,
            Some(address as *const c_void),
            &mut information,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    assert_eq!(
        result,
        size_of::<MEMORY_BASIC_INFORMATION>(),
        "VirtualQueryEx should describe {address:#x}"
    );
    information.Protect.0
}

fn verify_patterns(process: &OwnedHandle, metadata: &FixtureMetadata) {
    assert_eq!(
        metadata.patterns.len(),
        2 + CoreHook::ALL.len() + FeatureHook::ALL.len() + FEATURE_HOOK_AUXILIARY_PATTERN_COUNT
    );
    let executable = fs::read(env!("CARGO_BIN_EXE_deimos-memory-fixture"))
        .expect("fixture PE should be readable");
    for pattern in &metadata.patterns {
        let signature = parse_signature(&pattern.signature);
        assert!(
            scan(&executable, &signature).is_empty(),
            "{} must be generated at runtime rather than embedded in the PE",
            pattern.name
        );

        let region = region(metadata, &pattern.region);
        let bytes = read_memory(process, parse_address(&region.address), region.size);
        let matches = scan(&bytes, &signature);
        assert_eq!(matches.len(), pattern.expected_matches);
        assert_eq!(matches, vec![pattern.offset]);
    }
}

fn read_primitives(process: &OwnedHandle, metadata: &FixtureMetadata) -> Vec<Vec<u8>> {
    assert!(metadata.primitives.len() >= 6);
    metadata
        .primitives
        .iter()
        .map(|primitive| {
            let region = region(metadata, &primitive.region);
            let actual = read_memory(
                process,
                parse_address(&region.address) + primitive.offset,
                primitive.size,
            );
            assert_eq!(
                actual,
                decode_hex(&primitive.expected_bytes),
                "{} should match its published {} value",
                primitive.name,
                primitive.expected
            );
            actual
        })
        .collect()
}

fn read_pointer_chain(process: &OwnedHandle, metadata: &FixtureMetadata) -> Vec<u8> {
    let chain = metadata
        .pointer_chains
        .first()
        .expect("fixture should publish a pointer chain");
    let root_pattern = metadata
        .patterns
        .iter()
        .find(|pattern| pattern.name == chain.root_pattern)
        .expect("pointer chain root pattern should exist");
    let root_region = region(metadata, &root_pattern.region);
    let region_bytes = read_memory(
        process,
        parse_address(&root_region.address),
        root_region.size,
    );
    let matches = scan(&region_bytes, &parse_signature(&root_pattern.signature));
    assert_eq!(matches.len(), root_pattern.expected_matches);
    assert_eq!(chain.offsets.len(), chain.dereference_count + 1);

    let mut address = parse_address(&root_region.address) + matches[0];
    for offset in &chain.offsets[..chain.dereference_count] {
        let pointer_bytes = read_memory(process, address + offset, metadata.pointer_width);
        address = usize::from_le_bytes(
            pointer_bytes
                .try_into()
                .expect("pointer bytes should match the platform width"),
        );
        assert_ne!(address, 0, "pointer chain should not contain null");
    }
    address += chain
        .offsets
        .last()
        .expect("pointer chain should have a target offset");
    let expected = decode_hex(&chain.expected_bytes);
    let actual = read_memory(process, address, expected.len());
    let target_region = region(metadata, &chain.target_region);
    let target_region_start = parse_address(&target_region.address);
    assert!(
        (target_region_start..target_region_start + target_region.size).contains(&address),
        "pointer chain target should remain inside its published region"
    );
    assert_eq!(
        actual, expected,
        "pointer chain should resolve to {}",
        chain.expected
    );
    actual
}

fn read_memory(process: &OwnedHandle, address: usize, size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    let mut bytes_read = 0usize;
    unsafe {
        ReadProcessMemory(
            process.0,
            address as *const c_void,
            bytes.as_mut_ptr().cast::<c_void>(),
            bytes.len(),
            Some(&mut bytes_read),
        )
    }
    .unwrap_or_else(|error| panic!("ReadProcessMemory at {address:#x} failed: {error}"));
    assert_eq!(bytes_read, size);
    bytes
}

fn region<'a>(metadata: &'a FixtureMetadata, name: &str) -> &'a MemoryRegionMetadata {
    metadata
        .regions
        .iter()
        .find(|region| region.name == name)
        .unwrap_or_else(|| panic!("region {name} should exist"))
}

fn parse_address(address: &str) -> usize {
    usize::from_str_radix(
        address
            .strip_prefix("0x")
            .expect("address should use hexadecimal notation"),
        16,
    )
    .expect("address should be valid hexadecimal")
}

fn parse_signature(signature: &str) -> Vec<Option<u8>> {
    signature
        .split_whitespace()
        .map(|token| {
            if token == "??" {
                None
            } else {
                Some(u8::from_str_radix(token, 16).expect("signature byte should be hexadecimal"))
            }
        })
        .collect()
}

fn scan(bytes: &[u8], signature: &[Option<u8>]) -> Vec<usize> {
    bytes
        .windows(signature.len())
        .enumerate()
        .filter_map(|(offset, window)| {
            window
                .iter()
                .zip(signature)
                .all(|(actual, expected)| expected.is_none() || expected.as_ref() == Some(actual))
                .then_some(offset)
        })
        .collect()
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(
        value.len() % 2,
        0,
        "hex byte string should have even length"
    );
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16)
                .expect("expected bytes should be hexadecimal")
        })
        .collect()
}
