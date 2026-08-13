use std::collections::{BTreeMap, HashMap, HashSet};
use std::thread;
use std::time::{Duration, Instant};

use deimos_core::client::ClientId;
use deimos_core::game::{
    login_associated_data, GameLoginRequest, GameLoginResponse, MAX_GAME_OPERATION_TIMEOUT_MS,
};
use deimos_core::lifecycle::AgentIdentity;
use deimos_core::memory::MemoryProtection;
use deimos_core::process::{ProcessAccessMode, ProcessIdentity, WIZARD101_EXECUTABLE};
use deimos_core::rpc::{AuthToken, RpcError, RpcErrorCode};
use deimos_core::secret::{open_credential, CredentialSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::hook::validate_relocatable_x64;
use crate::process::{
    ClientRegistry, ClientWindowTarget, MutationBackend, ProcessBackendError,
    ProcessBackendErrorKind,
};

const LOGIN_PATTERN: &[Option<u8>] = &[
    Some(0x41),
    Some(0xb1),
    Some(0x01),
    Some(0x45),
    Some(0x33),
    Some(0xc0),
    Some(0x48),
    Some(0x8d),
    Some(0x55),
    Some(0xcf),
    Some(0x48),
    Some(0x8b),
    Some(0x0d),
    None,
    None,
    None,
    None,
    Some(0xe8),
    None,
    None,
    None,
    None,
];
const HOOK_PATTERN: &[Option<u8>] = &[
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(0x48),
    Some(0x8b),
    Some(0x01),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(0xff),
    Some(0x50),
    Some(0x70),
    Some(0x84),
];
const HOOK_OVERWRITE_BYTES: usize = 7;
const MAX_MODULE_BYTES: usize = 256 * 1024 * 1024;
const MAX_USED_TRANSFERS: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

pub struct LoginState<H> {
    records: HashMap<ClientId, LoginRecord<H>>,
    used_transfers: HashSet<String>,
}

impl<H> Default for LoginState<H> {
    fn default() -> Self {
        Self {
            records: HashMap::new(),
            used_transfers: HashSet::new(),
        }
    }
}

struct LoginRecord<H> {
    handle: H,
    identity: ProcessIdentity,
    hook_address: usize,
    original_bytes: Vec<u8>,
    original_protection: Option<MemoryProtection>,
    patch_may_be_active: bool,
    allocations: Vec<RemoteAllocation>,
    code_range: Option<(usize, usize)>,
    execution_flag: Option<usize>,
}

struct RemoteAllocation {
    address: usize,
    size: usize,
    sensitive: bool,
}

#[derive(Debug)]
pub struct GameLoginError {
    code: RpcErrorCode,
    message: String,
    details: BTreeMap<String, String>,
}

impl GameLoginError {
    fn request(message: impl Into<String>) -> Self {
        Self {
            code: RpcErrorCode::InvalidRequest,
            message: message.into(),
            details: BTreeMap::new(),
        }
    }

    fn failed(message: impl Into<String>) -> Self {
        Self {
            code: RpcErrorCode::GameLoginFailed,
            message: message.into(),
            details: BTreeMap::new(),
        }
    }

    fn timeout(timeout_ms: u32) -> Self {
        let mut details = BTreeMap::new();
        details.insert("timeout_ms".to_string(), timeout_ms.to_string());
        Self {
            code: RpcErrorCode::GameLoginTimeout,
            message: format!("automatic login did not complete within {timeout_ms} ms"),
            details,
        }
    }

    fn backend(action: &str, error: ProcessBackendError) -> Self {
        let mut details = BTreeMap::new();
        if let Some(native_code) = error.native_code {
            details.insert("native_code".to_string(), native_code.to_string());
        }
        Self {
            code: match error.kind {
                ProcessBackendErrorKind::NotFound => RpcErrorCode::ClientNotFound,
                ProcessBackendErrorKind::AccessDenied => RpcErrorCode::ProcessAccessDenied,
                ProcessBackendErrorKind::Exited | ProcessBackendErrorKind::IdentityMismatch => {
                    RpcErrorCode::ProcessExited
                }
                ProcessBackendErrorKind::Native => RpcErrorCode::GameLoginFailed,
            },
            message: format!("{action}: {}", error.message),
            details,
        }
    }

    fn cleanup(primary: &GameLoginError, failures: &[String]) -> Self {
        let mut details = BTreeMap::new();
        details.insert("cleanup_failures".to_string(), failures.len().to_string());
        Self {
            code: RpcErrorCode::GameLoginFailed,
            message: format!(
                "{}; cleanup could not be fully verified and remains agent-owned for retry",
                primary.message
            ),
            details,
        }
    }

    pub fn into_rpc_error(self, request_id: u64, operation: &str) -> RpcError {
        let mut error = RpcError::new(self.code, self.message, request_id, operation, None);
        error.details = self.details;
        error
    }
}

pub fn login<B: MutationBackend>(
    state: &mut LoginState<B::Handle>,
    clients: &mut ClientRegistry,
    backend: &B,
    token: &AuthToken,
    identity: &AgentIdentity,
    request: &GameLoginRequest,
    cancelled: impl Fn() -> bool,
) -> Result<GameLoginResponse, GameLoginError> {
    let credential = authenticate_transfer(state, token, identity, request)?;
    if let Some(mut previous) = state.records.remove(&request.client_id) {
        let failures = cleanup_record(backend, &mut previous);
        if !failures.is_empty() {
            state.records.insert(request.client_id.clone(), previous);
            return Err(GameLoginError::failed(
                "a previous automatic login cleanup is still pending for this client",
            ));
        }
    }

    let target = clients
        .resolve(backend, &request.client_id)
        .map_err(|error| GameLoginError::backend("could not resolve the selected client", error))?;
    let mut record = prepare_record(backend, &target, &credential)?;
    let result = execute_login(
        backend,
        &mut record,
        &credential,
        request.timeout_ms,
        cancelled,
    );
    let failures = cleanup_record(backend, &mut record);
    if !failures.is_empty() {
        let fallback = GameLoginError::failed("automatic login cleanup failed");
        let primary = result.as_ref().err().unwrap_or(&fallback);
        let error = GameLoginError::cleanup(primary, &failures);
        state.records.insert(request.client_id.clone(), record);
        return Err(error);
    }
    result?;
    Ok(GameLoginResponse {
        client_id: request.client_id.clone(),
        authenticated: true,
        cleanup_complete: true,
    })
}

fn authenticate_transfer<H>(
    state: &mut LoginState<H>,
    token: &AuthToken,
    identity: &AgentIdentity,
    request: &GameLoginRequest,
) -> Result<CredentialSecret, GameLoginError> {
    validate_request(state, identity, request)?;
    let associated_data = login_associated_data(
        &request.agent_instance_id,
        &request.client_id,
        &request.transfer_id,
    );
    let credential = open_credential(token, &request.credential, &associated_data)
        .map_err(|_| GameLoginError::failed("secure account data could not be authenticated"))?;
    state.used_transfers.insert(request.transfer_id.clone());
    Ok(credential)
}

pub fn cleanup_all<B: MutationBackend>(
    state: &mut LoginState<B::Handle>,
    backend: &B,
) -> Result<(), GameLoginError> {
    let client_ids = state.records.keys().cloned().collect::<Vec<_>>();
    let mut failed = Vec::new();
    for client_id in client_ids {
        let mut record = state
            .records
            .remove(&client_id)
            .expect("listed login record must exist");
        let failures = cleanup_record(backend, &mut record);
        if failures.is_empty() {
            continue;
        }
        failed.push(format!(
            "{}: {} cleanup step(s)",
            client_id.0,
            failures.len()
        ));
        state.records.insert(client_id, record);
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(GameLoginError::failed(format!(
            "automatic login cleanup failed for {} client(s); records remain tracked for retry",
            failed.len()
        )))
    }
}

fn validate_request<H>(
    state: &LoginState<H>,
    identity: &AgentIdentity,
    request: &GameLoginRequest,
) -> Result<(), GameLoginError> {
    if request.timeout_ms == 0 || request.timeout_ms > MAX_GAME_OPERATION_TIMEOUT_MS {
        return Err(GameLoginError::request(format!(
            "timeout_ms must be between 1 and {MAX_GAME_OPERATION_TIMEOUT_MS}"
        )));
    }
    if request.agent_instance_id != identity.instance_id {
        return Err(GameLoginError::failed(
            "secure account data was sealed for a different agent instance",
        ));
    }
    if request.transfer_id.len() != 64
        || !request
            .transfer_id
            .bytes()
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err(GameLoginError::request(
            "credential transfer ID must be a 64-character hexadecimal value",
        ));
    }
    if state.used_transfers.contains(&request.transfer_id) {
        return Err(GameLoginError::failed(
            "this one-time credential transfer has already been consumed",
        ));
    }
    if state.used_transfers.len() >= MAX_USED_TRANSFERS {
        return Err(GameLoginError::failed(
            "the agent has reached its one-time credential transfer limit; restart the agent",
        ));
    }
    Ok(())
}

fn prepare_record<B: MutationBackend>(
    backend: &B,
    target: &ClientWindowTarget,
    credential: &CredentialSecret,
) -> Result<LoginRecord<B::Handle>, GameLoginError> {
    let opened = backend
        .open_process_for_access(target.process_identity.pid, ProcessAccessMode::Mutation)
        .map_err(|error| GameLoginError::backend("could not open the selected client", error))?;
    backend
        .validate_process(&opened.handle, &target.process_identity)
        .map_err(|error| GameLoginError::backend("client identity changed before login", error))?;
    let modules = backend
        .enumerate_modules(&opened.handle, &target.process_identity)
        .map_err(|error| GameLoginError::backend("could not inspect the game module", error))?;
    let module = modules
        .into_iter()
        .find(|module| module.name.eq_ignore_ascii_case(WIZARD101_EXECUTABLE))
        .ok_or_else(|| GameLoginError::failed("Wizard101 executable module was not found"))?;
    let module_base = parse_address(&module.base_address)?;
    let module_size = usize::try_from(module.size)
        .ok()
        .filter(|size| *size > LOGIN_PATTERN.len() && *size <= MAX_MODULE_BYTES)
        .ok_or_else(|| GameLoginError::failed("Wizard101 module size is outside safe limits"))?;
    let module_bytes = backend
        .read_memory(&opened.handle, module_base, module_size)
        .map_err(|error| GameLoginError::backend("could not read the game module", error))?;
    let login_offset = unique_match(&module_bytes, LOGIN_PATTERN, "login dispatcher")?;
    let hook_offset = unique_match(&module_bytes, HOOK_PATTERN, "login hook")?;
    let hook_address = module_base
        .checked_add(hook_offset)
        .ok_or_else(|| GameLoginError::failed("login hook address overflowed"))?;
    let original_bytes = module_bytes
        .get(hook_offset..hook_offset + HOOK_OVERWRITE_BYTES)
        .ok_or_else(|| GameLoginError::failed("login hook bytes are incomplete"))?
        .to_vec();
    validate_relocatable_x64(&original_bytes).map_err(|_| {
        GameLoginError::failed("login hook does not span complete relocatable instructions")
    })?;

    let login_address = module_base
        .checked_add(login_offset)
        .ok_or_else(|| GameLoginError::failed("login dispatcher address overflowed"))?;
    let dat_disp = read_i32(&module_bytes, login_offset + 13)?;
    let func_disp = read_i32(&module_bytes, login_offset + 18)?;
    let dat_address = relative_address(login_address, 17, dat_disp)?;
    let function_address = relative_address(login_address, 22, func_disp)?;
    let _ = backend
        .read_memory(&opened.handle, dat_address, 8)
        .map_err(|error| GameLoginError::backend("login client pointer is unreadable", error))?;
    let _ = backend
        .read_memory(&opened.handle, function_address, 1)
        .map_err(|error| GameLoginError::backend("login dispatcher is unreadable", error))?;

    let _ = login_command_size(credential)?;
    let record = LoginRecord {
        handle: opened.handle,
        identity: target.process_identity.clone(),
        hook_address,
        original_bytes,
        original_protection: None,
        patch_may_be_active: false,
        allocations: Vec::new(),
        code_range: None,
        execution_flag: None,
    };
    let _ = (dat_address, function_address);
    Ok(record)
}

fn execute_login<B: MutationBackend>(
    backend: &B,
    record: &mut LoginRecord<B::Handle>,
    credential: &CredentialSecret,
    timeout_ms: u32,
    cancelled: impl Fn() -> bool,
) -> Result<(), GameLoginError> {
    backend
        .validate_process(&record.handle, &record.identity)
        .map_err(|error| {
            GameLoginError::backend("client identity changed before mutation", error)
        })?;
    allocate(
        backend,
        record,
        login_command_size(credential)?,
        MemoryProtection::ReadWrite,
        true,
    )?;
    allocate(backend, record, 32, MemoryProtection::ReadWrite, false)?;
    allocate(backend, record, 8, MemoryProtection::ReadWrite, false)?;
    let code_address = backend
        .allocate_memory_near(
            &record.handle,
            record.hook_address,
            512,
            MemoryProtection::ExecuteReadWrite,
        )
        .map_err(|error| GameLoginError::backend("could not allocate login code", error))?;
    record.allocations.push(RemoteAllocation {
        address: code_address,
        size: 512,
        sensitive: false,
    });
    record.code_range = Some((code_address, 512));
    let command_address = record.allocations[0].address;
    let struct_address = record.allocations[1].address;
    let flag_address = record.allocations[2].address;
    let code_address = record.allocations[3].address;
    record.execution_flag = Some(flag_address);

    let modules = backend
        .enumerate_modules(&record.handle, &record.identity)
        .map_err(|error| GameLoginError::backend("could not revalidate the game module", error))?;
    let module = modules
        .into_iter()
        .find(|module| module.name.eq_ignore_ascii_case(WIZARD101_EXECUTABLE))
        .ok_or_else(|| GameLoginError::failed("Wizard101 executable module was not found"))?;
    let module_base = parse_address(&module.base_address)?;
    let module_size = usize::try_from(module.size)
        .ok()
        .filter(|size| *size > LOGIN_PATTERN.len() && *size <= MAX_MODULE_BYTES)
        .ok_or_else(|| GameLoginError::failed("Wizard101 module size is outside safe limits"))?;
    let module_bytes = backend
        .read_memory(&record.handle, module_base, module_size)
        .map_err(|error| GameLoginError::backend("could not revalidate login patterns", error))?;
    let login_offset = unique_match(&module_bytes, LOGIN_PATTERN, "login dispatcher")?;
    let hook_offset = unique_match(&module_bytes, HOOK_PATTERN, "login hook")?;
    let current_hook = module_bytes
        .get(hook_offset..hook_offset + record.original_bytes.len())
        .ok_or_else(|| GameLoginError::failed("login hook bytes are incomplete"))?;
    let current_hook_address = module_base
        .checked_add(hook_offset)
        .ok_or_else(|| GameLoginError::failed("login hook address overflowed"))?;
    if current_hook != record.original_bytes || current_hook_address != record.hook_address {
        return Err(GameLoginError::failed(
            "login hook changed after validation and before mutation",
        ));
    }
    let login_address = module_base + login_offset;
    let dat_address = relative_address(
        login_address,
        17,
        read_i32(&module_bytes, login_offset + 13)?,
    )?;
    let function_address = relative_address(
        login_address,
        22,
        read_i32(&module_bytes, login_offset + 18)?,
    )?;

    let mut command = build_login_command(credential)?;
    backend
        .write_memory(&record.handle, command_address, &command)
        .map_err(|error| GameLoginError::backend("could not write the login command", error))?;
    let command_len = command.len() - 1;
    command.zeroize();
    let string_struct = build_string_struct(command_address, command_len);
    backend
        .write_memory(&record.handle, struct_address, &string_struct)
        .map_err(|error| GameLoginError::backend("could not write the login string", error))?;
    backend
        .write_memory(&record.handle, flag_address, &[0u8; 8])
        .map_err(|error| GameLoginError::backend("could not initialize automatic login", error))?;
    let mut code = build_login_code(
        code_address,
        flag_address,
        struct_address,
        dat_address,
        function_address,
        &record.original_bytes,
        record.hook_address + record.original_bytes.len(),
    )?;
    backend
        .write_memory(&record.handle, code_address, &code)
        .map_err(|error| GameLoginError::backend("could not write automatic login code", error))?;
    backend
        .flush_instruction_cache(&record.handle, code_address, code.len())
        .map_err(|error| {
            GameLoginError::backend("could not publish automatic login code", error)
        })?;
    code.zeroize();
    backend
        .write_memory(&record.handle, flag_address, &[1])
        .map_err(|error| GameLoginError::backend("could not arm automatic login", error))?;

    let previous = backend
        .protect_memory(
            &record.handle,
            record.hook_address,
            record.original_bytes.len(),
            MemoryProtection::ExecuteReadWrite,
        )
        .map_err(|error| GameLoginError::backend("could not unlock the login hook", error))?;
    record.original_protection = Some(previous);
    record.patch_may_be_active = true;
    let detour = relative_detour(
        record.hook_address,
        code_address,
        record.original_bytes.len(),
    )?;
    backend
        .write_memory(&record.handle, record.hook_address, &detour)
        .map_err(|error| GameLoginError::backend("could not activate automatic login", error))?;
    backend
        .flush_instruction_cache(
            &record.handle,
            record.hook_address,
            record.original_bytes.len(),
        )
        .map_err(|error| GameLoginError::backend("could not publish the login hook", error))?;
    backend
        .protect_memory(
            &record.handle,
            record.hook_address,
            record.original_bytes.len(),
            previous,
        )
        .map_err(|error| GameLoginError::backend("could not relock the login hook", error))?;

    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
    loop {
        if cancelled() {
            return Err(GameLoginError::failed(
                "the agent began shutting down during automatic login",
            ));
        }
        let flag = backend
            .read_memory(&record.handle, flag_address, 1)
            .map_err(|error| GameLoginError::backend("could not observe automatic login", error))?;
        if flag.first() == Some(&0) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(GameLoginError::timeout(timeout_ms));
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn cleanup_record<B: MutationBackend>(
    backend: &B,
    record: &mut LoginRecord<B::Handle>,
) -> Vec<String> {
    if let Err(error) = backend.validate_process(&record.handle, &record.identity) {
        if matches!(
            error.kind,
            ProcessBackendErrorKind::Exited | ProcessBackendErrorKind::NotFound
        ) {
            record.allocations.clear();
            record.patch_may_be_active = false;
            return Vec::new();
        }
        return vec!["target identity could not be revalidated".to_string()];
    }
    let mut failures = Vec::new();
    let suspended = if record.patch_may_be_active {
        let suspended = match backend.suspend_process_threads(&record.handle) {
            Ok(suspended) => suspended,
            Err(_) => return vec!["target threads could not be suspended".to_string()],
        };
        let target_is_executing = suspended
            .executes_range(record.hook_address, record.original_bytes.len())
            || record
                .code_range
                .is_some_and(|(address, size)| suspended.executes_range(address, size));
        if target_is_executing {
            failures.push("target code was still executing".to_string());
            if suspended.resume().is_err() {
                failures.push("target threads could not be resumed".to_string());
            }
            return failures;
        }
        if let Some(flag_address) = record.execution_flag {
            match backend.read_memory(&record.handle, flag_address, 1) {
                Ok(value) if matches!(value.first(), Some(0) | Some(1)) => {}
                Ok(value) if value.first() == Some(&2) => {
                    failures.push("the game login dispatcher was still executing".to_string());
                    if suspended.resume().is_err() {
                        failures.push("target threads could not be resumed".to_string());
                    }
                    return failures;
                }
                Ok(_) | Err(_) => {
                    failures
                        .push("automatic login execution state could not be verified".to_string());
                    if suspended.resume().is_err() {
                        failures.push("target threads could not be resumed".to_string());
                    }
                    return failures;
                }
            }
        }
        Some(suspended)
    } else {
        None
    };

    if record.patch_may_be_active {
        let restore = (|| {
            let original_protection = record.original_protection.ok_or(())?;
            backend
                .protect_memory(
                    &record.handle,
                    record.hook_address,
                    record.original_bytes.len(),
                    MemoryProtection::ExecuteReadWrite,
                )
                .map_err(|_| ())?;
            backend
                .write_memory(&record.handle, record.hook_address, &record.original_bytes)
                .map_err(|_| ())?;
            backend
                .flush_instruction_cache(
                    &record.handle,
                    record.hook_address,
                    record.original_bytes.len(),
                )
                .map_err(|_| ())?;
            backend
                .protect_memory(
                    &record.handle,
                    record.hook_address,
                    record.original_bytes.len(),
                    original_protection,
                )
                .map_err(|_| ())?;
            Ok::<(), ()>(())
        })();
        if restore.is_ok() {
            record.patch_may_be_active = false;
        } else {
            failures.push("temporary login patch could not be restored".to_string());
        }
    }

    if !record.patch_may_be_active {
        let mut retained = Vec::new();
        for allocation in record.allocations.drain(..) {
            if allocation.sensitive
                && backend
                    .write_memory(
                        &record.handle,
                        allocation.address,
                        &vec![0u8; allocation.size],
                    )
                    .is_err()
            {
                failures.push("sensitive remote memory could not be cleared".to_string());
                retained.push(allocation);
                continue;
            }
            if backend
                .free_memory(&record.handle, allocation.address)
                .is_err()
            {
                failures.push("remote login memory could not be released".to_string());
                retained.push(allocation);
            }
        }
        record.allocations = retained;
        if record.execution_flag.is_some_and(|flag| {
            !record
                .allocations
                .iter()
                .any(|allocation| allocation.address == flag)
        }) {
            record.execution_flag = None;
        }
        if record.code_range.is_some_and(|(address, _)| {
            !record
                .allocations
                .iter()
                .any(|allocation| allocation.address == address)
        }) {
            record.code_range = None;
        }
    }
    if let Some(suspended) = suspended {
        if suspended.resume().is_err() {
            failures.push("target threads could not be resumed".to_string());
        }
    }
    failures
}

fn allocate<B: MutationBackend>(
    backend: &B,
    record: &mut LoginRecord<B::Handle>,
    size: usize,
    protection: MemoryProtection,
    sensitive: bool,
) -> Result<(), GameLoginError> {
    let address = backend
        .allocate_memory(&record.handle, size, protection)
        .map_err(|error| {
            GameLoginError::backend("could not allocate automatic login memory", error)
        })?;
    record.allocations.push(RemoteAllocation {
        address,
        size,
        sensitive,
    });
    Ok(())
}

fn unique_match(
    bytes: &[u8],
    pattern: &[Option<u8>],
    label: &str,
) -> Result<usize, GameLoginError> {
    let matches = bytes
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(index, window)| {
            window
                .iter()
                .zip(pattern)
                .all(|(actual, expected)| match expected {
                    Some(value) => *actual == *value,
                    None => true,
                })
                .then_some(index)
        })
        .take(2)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [address] => Ok(*address),
        [] => Err(GameLoginError::failed(format!(
            "the required {label} pattern was not found"
        ))),
        _ => Err(GameLoginError::failed(format!(
            "the required {label} pattern matched more than once"
        ))),
    }
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, GameLoginError> {
    let end = offset
        .checked_add(4)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| GameLoginError::failed("login displacement is incomplete"))?;
    Ok(i32::from_le_bytes(bytes[offset..end].try_into().map_err(
        |_| GameLoginError::failed("login displacement is invalid"),
    )?))
}

fn relative_address(
    base: usize,
    instruction_end: usize,
    displacement: i32,
) -> Result<usize, GameLoginError> {
    let base = base
        .checked_add(instruction_end)
        .ok_or_else(|| GameLoginError::failed("login relative address overflowed"))?;
    usize::try_from((base as i128) + i128::from(displacement))
        .map_err(|_| GameLoginError::failed("login relative address is invalid"))
}

fn parse_address(value: &str) -> Result<usize, GameLoginError> {
    value
        .strip_prefix("0x")
        .and_then(|digits| usize::from_str_radix(digits, 16).ok())
        .ok_or_else(|| GameLoginError::failed("game module address is invalid"))
}

fn login_command_size(credential: &CredentialSecret) -> Result<usize, GameLoginError> {
    8usize
        .checked_add(credential.username().len())
        .and_then(|size| size.checked_add(credential.password().len()))
        .ok_or_else(|| GameLoginError::failed("login command size overflowed"))
}

fn build_login_command(
    credential: &CredentialSecret,
) -> Result<Zeroizing<Vec<u8>>, GameLoginError> {
    if credential
        .username()
        .iter()
        .chain(credential.password())
        .any(|byte| byte.is_ascii_control())
    {
        return Err(GameLoginError::failed(
            "the saved account contains characters that cannot be used by automatic login",
        ));
    }
    let mut command = Zeroizing::new(Vec::with_capacity(login_command_size(credential)?));
    command.extend_from_slice(b"login ");
    command.extend_from_slice(credential.username());
    command.push(b' ');
    command.extend_from_slice(credential.password());
    command.push(0);
    Ok(command)
}

fn build_string_struct(data_address: usize, length: usize) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&(data_address as u64).to_le_bytes());
    bytes[16..24].copy_from_slice(&(length as u64).to_le_bytes());
    bytes[24..32].copy_from_slice(&(length as u64).to_le_bytes());
    bytes
}

fn relative_detour(
    source: usize,
    destination: usize,
    size: usize,
) -> Result<Vec<u8>, GameLoginError> {
    let continuation = source
        .checked_add(5)
        .ok_or_else(|| GameLoginError::failed("login detour address overflowed"))?;
    let displacement = i32::try_from((destination as i128) - (continuation as i128))
        .map_err(|_| GameLoginError::failed("login code is outside relative jump range"))?;
    let mut bytes = vec![0x90; size];
    bytes[0] = 0xe9;
    bytes[1..5].copy_from_slice(&displacement.to_le_bytes());
    Ok(bytes)
}

fn build_login_code(
    block_address: usize,
    flag_address: usize,
    string_struct_address: usize,
    client_pointer_address: usize,
    function_address: usize,
    original: &[u8],
    return_address: usize,
) -> Result<Vec<u8>, GameLoginError> {
    let mut code = Vec::with_capacity(256);
    code.extend_from_slice(&[0x9c, 0x50, 0x51, 0x52]);
    code.extend_from_slice(&[0x48, 0xba]);
    code.extend_from_slice(&(flag_address as u64).to_le_bytes());
    code.extend_from_slice(&[0xb0, 0x01, 0xb1, 0x02, 0xf0, 0x0f, 0xb0, 0x0a, 0x0f, 0x85]);
    let inactive_fixup = code.len();
    code.extend_from_slice(&[0; 4]);
    code.extend_from_slice(&[0x5a, 0x59, 0x58]);
    code.extend_from_slice(&[
        0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
    ]);
    code.extend_from_slice(&[0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00]);
    for register in 0..6 {
        emit_xmm_stack_move(&mut code, 0x7f, register);
    }
    code.extend_from_slice(&[0x41, 0xb1, 0x01, 0x45, 0x33, 0xc0, 0x48, 0xba]);
    code.extend_from_slice(&(string_struct_address as u64).to_le_bytes());
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&(client_pointer_address as u64).to_le_bytes());
    code.extend_from_slice(&[0x48, 0x8b, 0x08, 0x48, 0xb8]);
    code.extend_from_slice(&(function_address as u64).to_le_bytes());
    code.extend_from_slice(&[0xff, 0xd0]);
    for register in 0..6 {
        emit_xmm_stack_move(&mut code, 0x6f, register);
    }
    code.extend_from_slice(&[0x48, 0x81, 0xc4, 0x80, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[
        0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5a, 0x59, 0x58,
    ]);
    code.extend_from_slice(&[0x50, 0x48, 0xb8]);
    code.extend_from_slice(&(flag_address as u64).to_le_bytes());
    code.extend_from_slice(&[0xc6, 0x00, 0x00, 0x58, 0x9d, 0xe9]);
    let replay_fixup = code.len();
    code.extend_from_slice(&[0; 4]);
    let inactive_target = code.len();
    code.extend_from_slice(&[0x5a, 0x59, 0x58, 0x9d]);
    let replay_target = code.len();
    let inactive = i32::try_from(inactive_target as i128 - (inactive_fixup + 4) as i128)
        .map_err(|_| GameLoginError::failed("login branch displacement overflowed"))?;
    code[inactive_fixup..inactive_fixup + 4].copy_from_slice(&inactive.to_le_bytes());
    let replay = i32::try_from(replay_target as i128 - (replay_fixup + 4) as i128)
        .map_err(|_| GameLoginError::failed("login branch displacement overflowed"))?;
    code[replay_fixup..replay_fixup + 4].copy_from_slice(&replay.to_le_bytes());
    code.extend_from_slice(original);
    code.push(0xe9);
    let jump_end = block_address
        .checked_add(code.len())
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| GameLoginError::failed("login return address overflowed"))?;
    let displacement = i32::try_from((return_address as i128) - (jump_end as i128))
        .map_err(|_| GameLoginError::failed("login return is outside relative jump range"))?;
    code.extend_from_slice(&displacement.to_le_bytes());
    Ok(code)
}

fn emit_xmm_stack_move(code: &mut Vec<u8>, opcode: u8, register: u8) {
    let offset = 0x20 + register * 0x10;
    code.extend_from_slice(&[0xf3, 0x0f, opcode, 0x44 + register * 8, 0x24, offset]);
}

#[cfg(test)]
mod tests {
    use super::{
        authenticate_transfer, build_login_code, build_login_command, cleanup_record, unique_match,
        LoginRecord, LoginState, RemoteAllocation, LOGIN_PATTERN,
    };
    use deimos_core::client::ClientId;
    use deimos_core::game::{login_associated_data, GameLoginRequest};
    use deimos_core::lifecycle::AgentIdentity;
    use deimos_core::memory::{MemoryProtection, MemoryRegionDescriptor};
    use deimos_core::process::{ModuleDescriptor, ProcessDescriptor, ProcessIdentity};
    use deimos_core::rpc::AuthToken;
    use deimos_core::secret::{open_credential, seal_credential};
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::sync::Mutex;

    use crate::process::{
        MemoryBackend, MutationBackend, OpenedProcess, ProcessBackend, ProcessBackendError,
        RemoteThreadPoll, StartedRemoteThread, SuspendedProcess,
    };

    #[derive(Default)]
    struct CleanupBackend {
        writes: Mutex<Vec<(usize, Vec<u8>)>>,
        frees: Mutex<Vec<usize>>,
        fail_free_once: AtomicBool,
        execution_state: AtomicU8,
    }

    impl ProcessBackend for CleanupBackend {
        type Handle = ();

        fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError> {
            Ok(Vec::new())
        }

        fn open_process(
            &self,
            _pid: u32,
        ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
            unreachable!("cleanup test does not open a process")
        }

        fn validate_process(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<(), ProcessBackendError> {
            Ok(())
        }

        fn enumerate_modules(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<Vec<ModuleDescriptor>, ProcessBackendError> {
            Ok(Vec::new())
        }
    }

    impl MemoryBackend for CleanupBackend {
        fn enumerate_memory_regions(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<Vec<MemoryRegionDescriptor>, ProcessBackendError> {
            Ok(Vec::new())
        }

        fn read_memory(
            &self,
            _handle: &Self::Handle,
            _address: usize,
            size: usize,
        ) -> Result<Vec<u8>, ProcessBackendError> {
            Ok(vec![self.execution_state.load(Ordering::SeqCst); size])
        }
    }

    impl MutationBackend for CleanupBackend {
        type ThreadHandle = ();

        fn write_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
            bytes: &[u8],
        ) -> Result<(), ProcessBackendError> {
            self.writes.lock().unwrap().push((address, bytes.to_vec()));
            Ok(())
        }

        fn allocate_memory(
            &self,
            _handle: &Self::Handle,
            _size: usize,
            _protection: MemoryProtection,
        ) -> Result<usize, ProcessBackendError> {
            unreachable!("cleanup test does not allocate")
        }

        fn free_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
        ) -> Result<(), ProcessBackendError> {
            if self.fail_free_once.swap(false, Ordering::SeqCst) {
                return Err(ProcessBackendError::new(
                    crate::process::ProcessBackendErrorKind::Native,
                    "forced free failure",
                ));
            }
            self.frees.lock().unwrap().push(address);
            Ok(())
        }

        fn suspend_process_threads(
            &self,
            _handle: &Self::Handle,
        ) -> Result<SuspendedProcess, ProcessBackendError> {
            Ok(SuspendedProcess::new(Vec::new(), ()))
        }

        fn protect_memory(
            &self,
            _handle: &Self::Handle,
            _address: usize,
            _size: usize,
            _protection: MemoryProtection,
        ) -> Result<MemoryProtection, ProcessBackendError> {
            Ok(MemoryProtection::ExecuteRead)
        }

        fn start_remote_thread(
            &self,
            _handle: &Self::Handle,
            _start_address: usize,
            _parameter: Option<usize>,
        ) -> Result<StartedRemoteThread<Self::ThreadHandle>, ProcessBackendError> {
            unreachable!("cleanup test does not create threads")
        }

        fn poll_remote_thread(
            &self,
            _thread: &Self::ThreadHandle,
            _wait_timeout_ms: u32,
        ) -> Result<RemoteThreadPoll, ProcessBackendError> {
            unreachable!("cleanup test does not poll threads")
        }

        fn flush_instruction_cache(
            &self,
            _handle: &Self::Handle,
            _address: usize,
            _size: usize,
        ) -> Result<(), ProcessBackendError> {
            Ok(())
        }
    }

    #[test]
    fn login_pattern_must_be_unique() {
        let bytes = LOGIN_PATTERN
            .iter()
            .map(|value| value.unwrap_or(0x11))
            .collect::<Vec<_>>();
        assert_eq!(unique_match(&bytes, LOGIN_PATTERN, "login").unwrap(), 0);
        let repeated = [bytes.clone(), bytes].concat();
        assert!(unique_match(&repeated, LOGIN_PATTERN, "login").is_err());
    }

    #[test]
    fn command_buffers_and_envelopes_are_redacted() {
        let token = AuthToken::generate().expect("token");
        let sealed = seal_credential(&token, b"user", b"secret-value", b"context").expect("seal");
        let credential = open_credential(&token, &sealed, b"context").expect("open");
        let command = build_login_command(&credential).expect("command");
        assert!(command.ends_with(b"secret-value\0"));
        assert!(!format!("{credential:?} {sealed:?}").contains("secret-value"));
        let _: LoginState<()> = LoginState::default();
    }

    #[test]
    fn login_trampoline_claims_once_and_preserves_volatile_machine_state() {
        let code = build_login_code(
            0x1000,
            0x2000,
            0x3000,
            0x4000,
            0x5000,
            &[0x48, 0x8b, 0x01, 0x90, 0x90, 0x90, 0x90],
            0x1100,
        )
        .expect("login trampoline");
        assert!(code.starts_with(&[0x9c, 0x50, 0x51, 0x52]));
        assert!(code
            .windows(4)
            .any(|bytes| bytes == [0xf0, 0x0f, 0xb0, 0x0a]));
        assert_eq!(code.iter().filter(|byte| **byte == 0x9d).count(), 2);
        for register in 0..6u8 {
            let offset = 0x20 + register * 0x10;
            assert!(code
                .windows(6)
                .any(|bytes| { bytes == [0xf3, 0x0f, 0x7f, 0x44 + register * 8, 0x24, offset] }));
            assert!(code
                .windows(6)
                .any(|bytes| { bytes == [0xf3, 0x0f, 0x6f, 0x44 + register * 8, 0x24, offset] }));
        }
    }

    #[test]
    fn credential_transfers_are_instance_bound_and_one_shot() {
        let token = AuthToken::generate().expect("token");
        let identity = AgentIdentity {
            instance_id: "agent-instance".to_string(),
            version: "test".to_string(),
            build_id: "test".to_string(),
            process_id: 1,
        };
        let client_id = ClientId("client-1".to_string());
        let transfer_id = "01".repeat(32);
        let context = login_associated_data(&identity.instance_id, &client_id, &transfer_id);
        let request = GameLoginRequest {
            client_id,
            agent_instance_id: identity.instance_id.clone(),
            transfer_id,
            credential: seal_credential(&token, b"user", b"secret-value", &context).expect("seal"),
            timeout_ms: 1_000,
        };
        let mut state: LoginState<()> = LoginState::default();
        authenticate_transfer(&mut state, &token, &identity, &request).expect("first use");
        assert!(authenticate_transfer(&mut state, &token, &identity, &request).is_err());

        let mut wrong_identity = identity;
        wrong_identity.instance_id = "replacement-agent".to_string();
        let mut fresh_state: LoginState<()> = LoginState::default();
        assert!(
            authenticate_transfer(&mut fresh_state, &token, &wrong_identity, &request).is_err()
        );
    }

    #[test]
    fn unauthenticated_envelopes_do_not_consume_the_replay_registry() {
        let token = AuthToken::generate().expect("token");
        let identity = AgentIdentity {
            instance_id: "agent-instance".to_string(),
            version: "test".to_string(),
            build_id: "test".to_string(),
            process_id: 1,
        };
        let client_id = ClientId("client-1".to_string());
        let transfer_id = "02".repeat(32);
        let context = login_associated_data(&identity.instance_id, &client_id, &transfer_id);
        let mut request = GameLoginRequest {
            client_id,
            agent_instance_id: identity.instance_id.clone(),
            transfer_id,
            credential: seal_credential(&token, b"user", b"secret-value", &context).expect("seal"),
            timeout_ms: 1_000,
        };
        request.credential.ciphertext[0] ^= 1;
        let mut state: LoginState<()> = LoginState::default();

        assert!(authenticate_transfer(&mut state, &token, &identity, &request).is_err());
        assert!(authenticate_transfer(&mut state, &token, &identity, &request).is_err());
        assert!(state.used_transfers.is_empty());
    }

    #[test]
    fn cleanup_restores_patch_clears_secret_memory_and_retries_failed_free() {
        let backend = CleanupBackend {
            fail_free_once: AtomicBool::new(true),
            ..CleanupBackend::default()
        };
        let mut record = LoginRecord {
            handle: (),
            identity: ProcessIdentity {
                pid: 7,
                creation_time_100ns: "9".to_string(),
                executable_path: "WizardGraphicalClient.exe".to_string(),
            },
            hook_address: 0x1000,
            original_bytes: vec![0x48, 0x8b, 0x01, 0x90, 0x90, 0x90, 0x90],
            original_protection: Some(MemoryProtection::ExecuteRead),
            patch_may_be_active: true,
            allocations: vec![RemoteAllocation {
                address: 0x2000,
                size: 16,
                sensitive: true,
            }],
            code_range: Some((0x3000, 64)),
            execution_flag: Some(0x4000),
        };

        let first = cleanup_record(&backend, &mut record);
        assert_eq!(first.len(), 1);
        assert!(!record.patch_may_be_active);
        assert_eq!(record.allocations.len(), 1);
        let second = cleanup_record(&backend, &mut record);
        assert!(second.is_empty());
        assert!(record.allocations.is_empty());
        assert_eq!(*backend.frees.lock().unwrap(), vec![0x2000]);
        let writes = backend.writes.lock().unwrap();
        assert!(writes
            .iter()
            .any(|(address, bytes)| { *address == 0x1000 && bytes == &record.original_bytes }));
        assert!(writes.iter().any(|(address, bytes)| {
            *address == 0x2000 && bytes.iter().all(|value| *value == 0)
        }));
    }

    #[test]
    fn cleanup_retains_code_while_the_external_dispatcher_can_return_to_it() {
        let backend = CleanupBackend {
            execution_state: AtomicU8::new(2),
            ..CleanupBackend::default()
        };
        let mut record = LoginRecord {
            handle: (),
            identity: ProcessIdentity {
                pid: 7,
                creation_time_100ns: "9".to_string(),
                executable_path: "WizardGraphicalClient.exe".to_string(),
            },
            hook_address: 0x1000,
            original_bytes: vec![0x48, 0x8b, 0x01, 0x90, 0x90, 0x90, 0x90],
            original_protection: Some(MemoryProtection::ExecuteRead),
            patch_may_be_active: true,
            allocations: vec![RemoteAllocation {
                address: 0x3000,
                size: 512,
                sensitive: false,
            }],
            code_range: Some((0x3000, 512)),
            execution_flag: Some(0x4000),
        };

        let pending = cleanup_record(&backend, &mut record);
        assert_eq!(pending, ["the game login dispatcher was still executing"]);
        assert!(record.patch_may_be_active);
        assert!(backend.frees.lock().unwrap().is_empty());

        backend.execution_state.store(0, Ordering::SeqCst);
        assert!(cleanup_record(&backend, &mut record).is_empty());
        assert!(!record.patch_may_be_active);
        assert!(record.allocations.is_empty());
    }
}
