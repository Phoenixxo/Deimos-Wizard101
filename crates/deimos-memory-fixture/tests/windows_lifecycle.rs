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
    ByteOrder, MemoryBatchReadRequest, MemoryPointerChainRequest, MemoryReadItem,
    MemoryReadRequest, MemoryScanRequest, MemoryScanScope, MemorySessionRequest, MemoryValueType,
    TypedMemoryReadRequest,
};
use deimos_core::process::{
    ListProcessesRequest, OpenProcessRequest, ProcessKind, MEMORY_FIXTURE_EXECUTABLE,
    OP_PROCESS_STATUS,
};
use deimos_core::rpc::RpcErrorCode;
use deimos_memory_fixture::{
    FixtureMetadata, MemoryProtection, MemoryRegionMetadata, FIXTURE_SCHEMA_VERSION,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_READONLY, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

const SHUTDOWN_COMMAND: &str = "shutdown";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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
    assert!(!metadata.mutation_enabled, "DMS-014 owns mutation support");

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
    assert_eq!(metadata.regions.len(), 2);
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

fn verify_patterns(process: &OwnedHandle, metadata: &FixtureMetadata) {
    assert_eq!(metadata.patterns.len(), 2);
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
