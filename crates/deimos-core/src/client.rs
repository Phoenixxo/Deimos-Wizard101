use serde::{Deserialize, Serialize};

use crate::process::ProcessDescriptor;

pub const CAPABILITY_CLIENT_DISCOVERY: &str = "client.discovery.v1";
pub const OP_CLIENT_LIST: &str = "client.list";

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

#[cfg(test)]
mod tests {
    use super::{ClientDescriptor, ClientId};
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
}
