use std::collections::HashSet;
use std::thread;
use std::time::{Duration, Instant};

use deimos_core::client::{
    ClientId, ClientInputResponse, ClientKeyCombinationRequest, ClientKeyEventRequest,
    ClientMouseClickRequest, ClientMouseMoveRequest, ClientTimedKeyRequest, ClientToScreenRequest,
    ClientToScreenResponse, ClientWindowFocusResponse, ClientWindowRequest,
    ClientWindowSetTitleRequest, ClientWindowSetTitleResponse, ClientWindowStateResponse,
    CoordinateSpace, KeyAction, MAX_INPUT_DURATION_MS, MAX_KEY_COMBINATION_MODIFIERS,
    MAX_WINDOW_TITLE_CHARS,
};
use deimos_core::rpc::{RpcError, RpcErrorCode};

use crate::process::{
    ClientRegistry, ClientWindowTarget, ProcessBackend, ProcessBackendError,
    ProcessBackendErrorKind,
};

const KEY_REPEAT_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub struct WindowInputError {
    code: RpcErrorCode,
    message: String,
    native_code: Option<i32>,
}

impl WindowInputError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: RpcErrorCode::InvalidRequest,
            message: message.into(),
            native_code: None,
        }
    }

    fn client(error: ProcessBackendError) -> Self {
        let code = match error.kind {
            ProcessBackendErrorKind::Exited | ProcessBackendErrorKind::IdentityMismatch => {
                RpcErrorCode::ClientNotFound
            }
            ProcessBackendErrorKind::NotFound => RpcErrorCode::ClientNotFound,
            ProcessBackendErrorKind::AccessDenied => RpcErrorCode::WindowOperationFailed,
            ProcessBackendErrorKind::Native => RpcErrorCode::WindowOperationFailed,
        };
        Self {
            code,
            message: error.message,
            native_code: error.native_code,
        }
    }

    fn input(error: ProcessBackendError) -> Self {
        let code = match error.kind {
            ProcessBackendErrorKind::NotFound
            | ProcessBackendErrorKind::Exited
            | ProcessBackendErrorKind::IdentityMismatch => RpcErrorCode::ClientNotFound,
            ProcessBackendErrorKind::AccessDenied | ProcessBackendErrorKind::Native => {
                RpcErrorCode::InputFailed
            }
        };
        Self {
            code,
            message: error.message,
            native_code: error.native_code,
        }
    }

    fn cancelled() -> Self {
        Self {
            code: RpcErrorCode::InputFailed,
            message: "input operation was cancelled because agent shutdown started".to_string(),
            native_code: None,
        }
    }

    pub fn into_rpc_error(self, request_id: u64, operation: &str) -> RpcError {
        let mut error = RpcError::new(self.code, self.message, request_id, operation, None);
        if let Some(native_code) = self.native_code {
            error
                .details
                .insert("native_code".to_string(), native_code.to_string());
        }
        error
    }
}

pub fn state<B: ProcessBackend>(
    clients: &mut ClientRegistry,
    backend: &B,
    request: &ClientWindowRequest,
) -> Result<ClientWindowStateResponse, WindowInputError> {
    let target = resolve(clients, backend, &request.client_id)?;
    let snapshot = backend
        .inspect_client_window(&target)
        .map_err(WindowInputError::client)?;
    Ok(ClientWindowStateResponse {
        client_id: request.client_id.clone(),
        title: snapshot.title,
        is_foreground: snapshot.is_foreground,
        rectangle: snapshot.rectangle,
        client_origin: snapshot.client_origin,
        client_size: snapshot.client_size,
    })
}

pub fn focus<B: ProcessBackend>(
    clients: &mut ClientRegistry,
    backend: &B,
    request: &ClientWindowRequest,
) -> Result<ClientWindowFocusResponse, WindowInputError> {
    let target = resolve(clients, backend, &request.client_id)?;
    let is_foreground = backend
        .focus_client_window(&target)
        .map_err(WindowInputError::client)?;
    Ok(ClientWindowFocusResponse {
        client_id: request.client_id.clone(),
        is_foreground,
    })
}

pub fn set_title<B: ProcessBackend>(
    clients: &mut ClientRegistry,
    backend: &B,
    request: &ClientWindowSetTitleRequest,
) -> Result<ClientWindowSetTitleResponse, WindowInputError> {
    if request.title.chars().count() > MAX_WINDOW_TITLE_CHARS {
        return Err(WindowInputError::invalid(format!(
            "window title exceeds the {MAX_WINDOW_TITLE_CHARS} character limit"
        )));
    }
    if request.title.contains('\0') {
        return Err(WindowInputError::invalid(
            "window title must not contain a null character",
        ));
    }
    let target = resolve(clients, backend, &request.client_id)?;
    backend
        .set_client_window_title(&target, &request.title)
        .map_err(WindowInputError::client)?;
    Ok(ClientWindowSetTitleResponse {
        client_id: request.client_id.clone(),
        title: request.title.clone(),
    })
}

pub fn client_to_screen<B: ProcessBackend>(
    clients: &mut ClientRegistry,
    backend: &B,
    request: &ClientToScreenRequest,
) -> Result<ClientToScreenResponse, WindowInputError> {
    let target = resolve(clients, backend, &request.client_id)?;
    let point = backend
        .client_to_screen(&target, request.point)
        .map_err(WindowInputError::client)?;
    Ok(ClientToScreenResponse {
        client_id: request.client_id.clone(),
        point,
    })
}

pub fn key_event<B: ProcessBackend>(
    backend: &B,
    target: &ClientWindowTarget,
    request: &ClientKeyEventRequest,
) -> Result<ClientInputResponse, WindowInputError> {
    validate_virtual_key(request.virtual_key)?;
    backend
        .send_client_key_event(
            target,
            request.virtual_key,
            request.action,
            request.delivery,
        )
        .map_err(WindowInputError::input)?;
    delivered(&request.client_id)
}

pub fn timed_key<B: ProcessBackend, F: Fn() -> bool>(
    backend: &B,
    target: &ClientWindowTarget,
    request: &ClientTimedKeyRequest,
    should_cancel: F,
) -> Result<ClientInputResponse, WindowInputError> {
    validate_virtual_key(request.virtual_key)?;
    validate_duration(request.duration_ms, "key duration")?;
    backend
        .send_client_key_event(
            target,
            request.virtual_key,
            KeyAction::Down,
            request.delivery,
        )
        .map_err(WindowInputError::input)?;

    let action_result = repeat_key_down(
        backend,
        target,
        request.virtual_key,
        request.duration_ms,
        request.delivery,
        &should_cancel,
    );
    let release_result =
        backend.send_client_key_event(target, request.virtual_key, KeyAction::Up, request.delivery);
    let cancelled = combine_input_results(action_result, release_result)?;
    if cancelled {
        return Err(WindowInputError::cancelled());
    }
    delivered(&request.client_id)
}

pub fn key_combination<B: ProcessBackend>(
    backend: &B,
    target: &ClientWindowTarget,
    request: &ClientKeyCombinationRequest,
) -> Result<ClientInputResponse, WindowInputError> {
    validate_virtual_key(request.virtual_key)?;
    if request.modifiers.len() > MAX_KEY_COMBINATION_MODIFIERS {
        return Err(WindowInputError::invalid(format!(
            "key combination exceeds the {MAX_KEY_COMBINATION_MODIFIERS} modifier limit"
        )));
    }
    let mut unique = HashSet::new();
    for modifier in &request.modifiers {
        validate_virtual_key(*modifier)?;
        if *modifier == request.virtual_key || !unique.insert(*modifier) {
            return Err(WindowInputError::invalid(
                "key combination modifiers must be unique and must not repeat the primary key",
            ));
        }
    }

    let mut pressed = Vec::new();
    for modifier in &request.modifiers {
        if let Err(error) =
            backend.send_client_key_event(target, *modifier, KeyAction::Down, request.delivery)
        {
            let cleanup = release_keys(backend, target, &pressed, request.delivery);
            return combine_input_results::<()>(Err(error), cleanup)
                .and_then(|_| delivered(&request.client_id));
        }
        pressed.push(*modifier);
    }

    if let Err(error) = backend.send_client_key_event(
        target,
        request.virtual_key,
        KeyAction::Down,
        request.delivery,
    ) {
        let cleanup = release_keys(backend, target, &pressed, request.delivery);
        return combine_input_results::<()>(Err(error), cleanup)
            .and_then(|_| delivered(&request.client_id));
    }
    let primary_release =
        backend.send_client_key_event(target, request.virtual_key, KeyAction::Up, request.delivery);
    let modifier_release =
        release_keys_in_order(backend, target, &request.modifiers, request.delivery);
    combine_input_results(primary_release, modifier_release)?;
    delivered(&request.client_id)
}

pub fn mouse_move<B: ProcessBackend>(
    backend: &B,
    target: &ClientWindowTarget,
    request: &ClientMouseMoveRequest,
) -> Result<ClientInputResponse, WindowInputError> {
    let point = client_message_point(backend, target, request.point, request.coordinate_space)?;
    validate_message_point(point)?;
    backend
        .send_client_mouse_move(target, point, request.delivery)
        .map_err(WindowInputError::input)?;
    delivered(&request.client_id)
}

pub fn mouse_click<B: ProcessBackend, F: Fn() -> bool>(
    backend: &B,
    target: &ClientWindowTarget,
    request: &ClientMouseClickRequest,
    should_cancel: F,
) -> Result<ClientInputResponse, WindowInputError> {
    validate_duration(request.hold_ms, "mouse button duration")?;
    let point = client_message_point(backend, target, request.point, request.coordinate_space)?;
    validate_message_point(point)?;
    backend
        .send_client_mouse_move(target, point, request.delivery)
        .map_err(WindowInputError::input)?;
    backend
        .send_client_mouse_button(target, point, request.button, true, request.delivery)
        .map_err(WindowInputError::input)?;
    let cancelled = sleep_interruptibly(request.hold_ms, &should_cancel);
    let release_result = backend
        .send_client_mouse_button(target, point, request.button, false, request.delivery)
        .map_err(WindowInputError::input);
    release_result?;
    if cancelled {
        return Err(WindowInputError::cancelled());
    }
    delivered(&request.client_id)
}

pub fn resolve<B: ProcessBackend>(
    clients: &mut ClientRegistry,
    backend: &B,
    client_id: &ClientId,
) -> Result<ClientWindowTarget, WindowInputError> {
    if client_id.0.trim().is_empty() {
        return Err(WindowInputError::invalid("client_id must not be empty"));
    }
    clients
        .resolve(backend, client_id)
        .map_err(WindowInputError::client)
}

fn validate_virtual_key(virtual_key: u16) -> Result<(), WindowInputError> {
    if !(1..=0xff).contains(&virtual_key) {
        return Err(WindowInputError::invalid(
            "virtual key must be between 1 and 255",
        ));
    }
    Ok(())
}

fn validate_duration(duration_ms: u32, name: &str) -> Result<(), WindowInputError> {
    if duration_ms > MAX_INPUT_DURATION_MS {
        return Err(WindowInputError::invalid(format!(
            "{name} exceeds the {MAX_INPUT_DURATION_MS} millisecond limit"
        )));
    }
    Ok(())
}

fn validate_message_point(point: deimos_core::client::WindowPoint) -> Result<(), WindowInputError> {
    if i16::try_from(point.x).is_err() || i16::try_from(point.y).is_err() {
        return Err(WindowInputError::invalid(
            "mouse coordinates must fit the signed 16-bit Windows message range",
        ));
    }
    Ok(())
}

fn client_message_point<B: ProcessBackend>(
    backend: &B,
    target: &ClientWindowTarget,
    point: deimos_core::client::WindowPoint,
    coordinate_space: CoordinateSpace,
) -> Result<deimos_core::client::WindowPoint, WindowInputError> {
    match coordinate_space {
        CoordinateSpace::Client => Ok(point),
        CoordinateSpace::Screen => backend
            .screen_to_client(target, point)
            .map_err(WindowInputError::input),
    }
}

fn repeat_key_down<B: ProcessBackend, F: Fn() -> bool>(
    backend: &B,
    target: &ClientWindowTarget,
    virtual_key: u16,
    duration_ms: u32,
    delivery: deimos_core::client::MessageDelivery,
    should_cancel: &F,
) -> Result<bool, ProcessBackendError> {
    let deadline = Instant::now() + Duration::from_millis(u64::from(duration_ms));
    while Instant::now() < deadline {
        if should_cancel() {
            return Ok(true);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(KEY_REPEAT_INTERVAL));
        if should_cancel() {
            return Ok(true);
        }
        if Instant::now() < deadline {
            backend.send_client_key_event(target, virtual_key, KeyAction::Down, delivery)?;
        }
    }
    Ok(false)
}

fn sleep_interruptibly<F: Fn() -> bool>(duration_ms: u32, should_cancel: &F) -> bool {
    let deadline = Instant::now() + Duration::from_millis(u64::from(duration_ms));
    while Instant::now() < deadline {
        if should_cancel() {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(KEY_REPEAT_INTERVAL));
    }
    should_cancel()
}

fn release_keys<B: ProcessBackend>(
    backend: &B,
    target: &ClientWindowTarget,
    keys: &[u16],
    delivery: deimos_core::client::MessageDelivery,
) -> Result<(), ProcessBackendError> {
    let mut first_error = None;
    for key in keys.iter().rev() {
        if let Err(error) = backend.send_client_key_event(target, *key, KeyAction::Up, delivery) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn release_keys_in_order<B: ProcessBackend>(
    backend: &B,
    target: &ClientWindowTarget,
    keys: &[u16],
    delivery: deimos_core::client::MessageDelivery,
) -> Result<(), ProcessBackendError> {
    let mut first_error = None;
    for key in keys {
        if let Err(error) = backend.send_client_key_event(target, *key, KeyAction::Up, delivery) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn combine_input_results<T>(
    action: Result<T, ProcessBackendError>,
    cleanup: Result<(), ProcessBackendError>,
) -> Result<T, WindowInputError> {
    match (action, cleanup) {
        (Err(error), _) => Err(WindowInputError::input(error)),
        (Ok(_), Err(error)) => Err(WindowInputError::input(error)),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn delivered(client_id: &ClientId) -> Result<ClientInputResponse, WindowInputError> {
    Ok(ClientInputResponse {
        client_id: client_id.clone(),
        delivered: true,
    })
}

#[cfg(test)]
mod tests {
    use super::{validate_duration, validate_message_point, validate_virtual_key};
    use deimos_core::client::{WindowPoint, MAX_INPUT_DURATION_MS};

    #[test]
    fn rejects_out_of_range_keys_durations_and_message_coordinates() {
        assert!(validate_virtual_key(0).is_err());
        assert!(validate_virtual_key(0x100).is_err());
        assert!(validate_duration(MAX_INPUT_DURATION_MS + 1, "duration").is_err());
        assert!(validate_message_point(WindowPoint { x: 32_768, y: 0 }).is_err());
        assert!(validate_message_point(WindowPoint { x: 0, y: -32_769 }).is_err());
    }
}
