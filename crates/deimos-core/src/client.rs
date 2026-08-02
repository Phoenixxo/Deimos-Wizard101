use serde::{Deserialize, Serialize};

use crate::process::ProcessDescriptor;

pub const CAPABILITY_CLIENT_DISCOVERY: &str = "client.discovery.v1";
pub const CAPABILITY_CLIENT_WINDOW: &str = "client.window.v1";
pub const CAPABILITY_CLIENT_INPUT: &str = "client.input.v1";
pub const OP_CLIENT_LIST: &str = "client.list";
pub const OP_CLIENT_WINDOW_STATE: &str = "client.window.state";
pub const OP_CLIENT_WINDOW_FOCUS: &str = "client.window.focus";
pub const OP_CLIENT_WINDOW_SET_TITLE: &str = "client.window.set_title";
pub const OP_CLIENT_TO_SCREEN: &str = "client.window.client_to_screen";
pub const OP_CLIENT_KEY_EVENT: &str = "client.input.key_event";
pub const OP_CLIENT_TIMED_KEY: &str = "client.input.timed_key";
pub const OP_CLIENT_KEY_COMBINATION: &str = "client.input.key_combination";
pub const OP_CLIENT_MOUSE_MOVE: &str = "client.input.mouse_move";
pub const OP_CLIENT_MOUSE_CLICK: &str = "client.input.mouse_click";

pub const MAX_WINDOW_TITLE_CHARS: usize = 512;
pub const MAX_INPUT_DURATION_MS: u32 = 30_000;
pub const MAX_KEY_COMBINATION_MODIFIERS: usize = 8;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ClientId(pub String);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientDescriptor {
    /// Agent-owned identity for one top-level Wizard101 client window.
    ///
    /// Native window handles stay inside the Windows/Wine agent and must not
    /// be inferred from this value.
    pub client_id: ClientId,
    pub process: ProcessDescriptor,
    pub is_foreground: bool,
    /// Zero-based top-to-bottom, then left-to-right screen position.
    pub screen_order: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListClientsRequest {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListClientsResponse {
    /// Clients remain in native discovery order. Consumers that need visual
    /// screen order should sort by `screen_order`.
    pub clients: Vec<ClientDescriptor>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDelivery {
    Send,
    Post,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAction {
    Down,
    Up,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinateSpace {
    Client,
    Screen,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowPoint {
    pub x: i32,
    pub y: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowRectangle {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowSize {
    pub width: i32,
    pub height: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientWindowRequest {
    pub client_id: ClientId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientWindowStateResponse {
    pub client_id: ClientId,
    pub title: String,
    pub is_foreground: bool,
    pub rectangle: WindowRectangle,
    pub client_origin: WindowPoint,
    pub client_size: WindowSize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientWindowFocusResponse {
    pub client_id: ClientId,
    pub is_foreground: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientWindowSetTitleRequest {
    pub client_id: ClientId,
    pub title: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientWindowSetTitleResponse {
    pub client_id: ClientId,
    pub title: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientToScreenRequest {
    pub client_id: ClientId,
    pub point: WindowPoint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientToScreenResponse {
    pub client_id: ClientId,
    pub point: WindowPoint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientKeyEventRequest {
    pub client_id: ClientId,
    pub virtual_key: u16,
    pub action: KeyAction,
    pub delivery: MessageDelivery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientTimedKeyRequest {
    pub client_id: ClientId,
    pub virtual_key: u16,
    pub duration_ms: u32,
    pub delivery: MessageDelivery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientKeyCombinationRequest {
    pub client_id: ClientId,
    pub modifiers: Vec<u16>,
    pub virtual_key: u16,
    pub delivery: MessageDelivery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientMouseMoveRequest {
    pub client_id: ClientId,
    pub point: WindowPoint,
    pub coordinate_space: CoordinateSpace,
    pub delivery: MessageDelivery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientMouseClickRequest {
    pub client_id: ClientId,
    pub point: WindowPoint,
    pub coordinate_space: CoordinateSpace,
    pub button: MouseButton,
    pub hold_ms: u32,
    pub delivery: MessageDelivery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientInputResponse {
    pub client_id: ClientId,
    pub delivered: bool,
}

#[cfg(test)]
mod tests {
    use super::{ClientDescriptor, ClientId, ClientKeyCombinationRequest, MessageDelivery};
    use crate::process::{ProcessDescriptor, ProcessKind};

    #[test]
    fn client_descriptor_does_not_expose_a_native_window_handle() {
        let descriptor = ClientDescriptor {
            client_id: ClientId("client-1".to_string()),
            process: ProcessDescriptor {
                pid: 448,
                name: "WizardGraphicalClient.exe".to_string(),
                kind: ProcessKind::Wizard101,
                executable_path: None,
                identity: None,
            },
            is_foreground: true,
            screen_order: 0,
        };

        let value = serde_json::to_value(descriptor).expect("descriptor should serialize");
        assert!(value.get("client_id").is_some());
        assert!(value.get("window_handle").is_none());
        assert!(value.get("hwnd").is_none());
    }

    #[test]
    fn input_contract_carries_only_agent_owned_client_identity() {
        let request = ClientKeyCombinationRequest {
            client_id: ClientId("client-1".to_string()),
            modifiers: vec![0x11],
            virtual_key: 0x43,
            delivery: MessageDelivery::Post,
        };

        let value = serde_json::to_value(request).expect("request should serialize");
        assert_eq!(value["client_id"], "client-1");
        assert!(value.get("window_handle").is_none());
        assert!(value.get("hwnd").is_none());
    }
}
