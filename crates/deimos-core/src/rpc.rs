use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::lifecycle::AgentIdentity;

pub const CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
pub const HANDSHAKE_OPERATION: &str = "handshake";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeContext {
    pub component: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthToken(String);

impl AuthToken {
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|error| {
            io::Error::other(format!("failed to generate authentication token: {error}"))
        })?;

        let mut token = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use fmt::Write as _;
            write!(token, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Ok(Self(token))
    }

    pub fn from_string(token: impl Into<String>) -> Result<Self, AuthTokenError> {
        let token = token.into();
        if token.is_empty() || token.len() > 256 {
            return Err(AuthTokenError::InvalidLength);
        }
        Ok(Self(token))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthTokenError {
    InvalidLength,
}

impl fmt::Display for AuthTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authentication token must contain between 1 and 256 bytes")
    }
}

impl std::error::Error for AuthTokenError {}

fn constant_time_token_eq(expected: &str, actual: &str) -> bool {
    let mut difference = expected.len() ^ actual.len();
    for (expected_byte, actual_byte) in expected.bytes().zip(actual.bytes()) {
        difference |= usize::from(expected_byte ^ actual_byte);
    }
    difference == 0
}

#[derive(Clone, Copy, Debug)]
pub struct RpcConfig {
    pub max_message_size: usize,
    pub io_timeout: Duration,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            max_message_size: MAX_MESSAGE_SIZE,
            io_timeout: DEFAULT_IO_TIMEOUT,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HelloRequest {
    pub request_id: u64,
    pub protocol: ProtocolVersion,
    pub token: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_context: Option<NativeContext>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RpcCall {
    pub request_id: u64,
    pub operation: String,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_context: Option<NativeContext>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RpcRequest {
    Hello(HelloRequest),
    Call(RpcCall),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HelloResponse {
    pub request_id: u64,
    pub protocol: ProtocolVersion,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RpcResult {
    pub request_id: u64,
    pub operation: String,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_context: Option<NativeContext>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcErrorCode {
    AuthenticationFailed,
    InvalidMessage,
    MessageTooLarge,
    VersionMismatch,
    Timeout,
    InvalidRequest,
    UnsupportedOperation,
    ProcessNotFound,
    ProcessAccessDenied,
    ProcessExited,
    SessionNotFound,
    AgentShuttingDown,
    MemoryInvalidAddress,
    MemoryReadFailed,
    MemoryRequiredMatchNotFound,
    MemoryAmbiguousMatch,
    MemoryLimitExceeded,
    MemoryPatternInvalid,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RpcError {
    pub code: RpcErrorCode,
    pub message: String,
    pub request_id: u64,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_context: Option<NativeContext>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

impl RpcError {
    pub fn new(
        code: RpcErrorCode,
        message: impl Into<String>,
        request_id: u64,
        operation: impl Into<String>,
        native_context: Option<NativeContext>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            request_id,
            operation: operation.into(),
            native_context,
            details: BTreeMap::new(),
        }
    }

    fn for_protocol(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message, 0, HANDSHAKE_OPERATION, None)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RpcResponse {
    Hello(HelloResponse),
    Result(RpcResult),
    Error { error: RpcError },
}

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    TooLarge { size: usize, maximum: usize },
    Empty,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::TooLarge { size, maximum } => {
                write!(
                    formatter,
                    "message is {size} bytes; maximum is {maximum} bytes"
                )
            }
            Self::Empty => formatter.write_str("message frame is empty"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8], maximum: usize) -> io::Result<()> {
    if payload.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "message frame is empty",
        ));
    }
    if payload.len() > maximum || payload.len() > u32::MAX as usize {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "message is {} bytes; maximum is {maximum} bytes",
                payload.len()
            ),
        ));
    }

    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

pub fn read_frame<R: Read>(reader: &mut R, maximum: usize) -> Result<Vec<u8>, FrameError> {
    let mut length_bytes = [0u8; 4];
    reader.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;

    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > maximum {
        return Err(FrameError::TooLarge {
            size: length,
            maximum,
        });
    }

    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

fn write_message<W: Write, T: Serialize>(
    writer: &mut W,
    message: &T,
    maximum: usize,
) -> io::Result<()> {
    let payload = serde_json::to_vec(message)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))?;
    write_frame(writer, &payload, maximum)
}

fn decode_message<T: DeserializeOwned>(payload: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(payload)
}

pub fn loopback_address(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn is_allowed_address(address: SocketAddr) -> bool {
    address.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)
}

pub struct RpcServer {
    auth_token: AuthToken,
    capabilities: Vec<String>,
    agent: Option<AgentIdentity>,
    supported_versions: Vec<ProtocolVersion>,
    config: RpcConfig,
}

impl RpcServer {
    pub fn new(auth_token: AuthToken, capabilities: Vec<String>, config: RpcConfig) -> Self {
        Self {
            auth_token,
            capabilities,
            agent: None,
            supported_versions: vec![CURRENT_PROTOCOL_VERSION],
            config,
        }
    }

    pub fn with_agent_identity(
        auth_token: AuthToken,
        capabilities: Vec<String>,
        agent: AgentIdentity,
        config: RpcConfig,
    ) -> Self {
        Self {
            auth_token,
            capabilities,
            agent: Some(agent),
            supported_versions: vec![CURRENT_PROTOCOL_VERSION],
            config,
        }
    }

    pub fn bind(
        port: u16,
        auth_token: AuthToken,
        capabilities: Vec<String>,
        config: RpcConfig,
    ) -> io::Result<(Self, TcpListener)> {
        let listener = TcpListener::bind(loopback_address(port))?;
        Ok((Self::new(auth_token, capabilities, config), listener))
    }

    pub fn serve_connection<F>(&self, stream: TcpStream, handler: F) -> io::Result<()>
    where
        F: Fn(&RpcCall) -> Result<Value, Box<RpcError>>,
    {
        stream.set_read_timeout(Some(self.config.io_timeout))?;
        stream.set_write_timeout(Some(self.config.io_timeout))?;

        let mut stream = stream;
        let hello = match read_frame(&mut stream, self.config.max_message_size) {
            Ok(payload) => match decode_message::<RpcRequest>(&payload) {
                Ok(RpcRequest::Hello(hello)) => hello,
                Ok(_) => {
                    self.send_error(
                        &mut stream,
                        RpcError::for_protocol(
                            RpcErrorCode::InvalidMessage,
                            "first request must be a hello message",
                        ),
                    )?;
                    return Ok(());
                }
                Err(error) => {
                    self.send_error(
                        &mut stream,
                        RpcError::for_protocol(
                            RpcErrorCode::InvalidMessage,
                            format!("hello message is not valid JSON RPC: {error}"),
                        ),
                    )?;
                    return Ok(());
                }
            },
            Err(error) => {
                if is_disconnect_frame_error(&error) {
                    return Ok(());
                }
                self.send_frame_error(&mut stream, error)?;
                return Ok(());
            }
        };

        if !constant_time_token_eq(self.auth_token.as_str(), &hello.token) {
            self.send_error(
                &mut stream,
                RpcError::new(
                    RpcErrorCode::AuthenticationFailed,
                    "authentication failed; start a new launch and use its token",
                    hello.request_id,
                    HANDSHAKE_OPERATION,
                    hello.native_context,
                ),
            )?;
            return Ok(());
        }

        let protocol = match self.negotiate(hello.protocol) {
            Some(protocol) => protocol,
            None => {
                let mut error = RpcError::new(
                    RpcErrorCode::VersionMismatch,
                    format!(
                        "protocol version {} is incompatible; upgrade Deimos or the Wine agent",
                        hello.protocol
                    ),
                    hello.request_id,
                    HANDSHAKE_OPERATION,
                    hello.native_context,
                );
                error.details.insert(
                    "supported_versions".to_string(),
                    self.supported_versions
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                self.send_error(&mut stream, error)?;
                return Ok(());
            }
        };

        let capabilities = self
            .capabilities
            .iter()
            .filter(|capability| hello.capabilities.contains(capability))
            .cloned()
            .collect();
        write_message(
            &mut stream,
            &RpcResponse::Hello(HelloResponse {
                request_id: hello.request_id,
                protocol,
                capabilities,
                agent: self.agent.clone(),
            }),
            self.config.max_message_size,
        )?;

        loop {
            let payload = match read_frame(&mut stream, self.config.max_message_size) {
                Ok(payload) => payload,
                Err(error) => {
                    if is_disconnect_frame_error(&error) {
                        return Ok(());
                    }
                    self.send_frame_error(&mut stream, error)?;
                    return Ok(());
                }
            };
            let request = match decode_message::<RpcRequest>(&payload) {
                Ok(request) => request,
                Err(error) => {
                    self.send_error(
                        &mut stream,
                        RpcError::for_protocol(
                            RpcErrorCode::InvalidMessage,
                            format!("request is not valid JSON RPC: {error}"),
                        ),
                    )?;
                    return Ok(());
                }
            };

            let call = match request {
                RpcRequest::Call(call) => call,
                RpcRequest::Hello(_) => {
                    self.send_error(
                        &mut stream,
                        RpcError::for_protocol(
                            RpcErrorCode::InvalidRequest,
                            "hello may only be sent once per connection",
                        ),
                    )?;
                    return Ok(());
                }
            };

            if call.request_id == 0 || call.operation.trim().is_empty() {
                self.send_error(
                    &mut stream,
                    RpcError::new(
                        RpcErrorCode::InvalidRequest,
                        "request_id must be non-zero and operation must not be empty",
                        call.request_id,
                        call.operation,
                        call.native_context,
                    ),
                )?;
                continue;
            }

            let response = match handler(&call) {
                Ok(payload) => RpcResponse::Result(RpcResult {
                    request_id: call.request_id,
                    operation: call.operation,
                    payload,
                    native_context: call.native_context,
                }),
                Err(error) => {
                    let mut error = *error;
                    error.request_id = call.request_id;
                    error.operation = call.operation;
                    error.native_context = call.native_context;
                    RpcResponse::Error { error }
                }
            };
            write_message(&mut stream, &response, self.config.max_message_size)?;
        }
    }

    fn negotiate(&self, requested: ProtocolVersion) -> Option<ProtocolVersion> {
        self.supported_versions
            .iter()
            .copied()
            .filter(|supported| {
                supported.major == requested.major && requested.minor <= supported.minor
            })
            .max_by_key(|version| version.minor)
    }

    fn send_error(&self, stream: &mut TcpStream, error: RpcError) -> io::Result<()> {
        write_message(
            stream,
            &RpcResponse::Error { error },
            self.config.max_message_size,
        )
    }

    fn send_frame_error(&self, stream: &mut TcpStream, error: FrameError) -> io::Result<()> {
        let (code, message) = match error {
            FrameError::TooLarge { size, maximum } => (
                RpcErrorCode::MessageTooLarge,
                format!("message is {size} bytes; maximum is {maximum} bytes"),
            ),
            FrameError::Empty => (
                RpcErrorCode::InvalidMessage,
                "message frame is empty".to_string(),
            ),
            FrameError::Io(error) if is_timeout_error(&error) => (
                RpcErrorCode::Timeout,
                "request timed out while reading a message".to_string(),
            ),
            FrameError::Io(error) => (RpcErrorCode::InvalidMessage, error.to_string()),
        };
        self.send_error(stream, RpcError::for_protocol(code, message))
    }
}

#[derive(Debug)]
pub enum RpcClientError {
    Io(io::Error),
    Timeout,
    Protocol(Box<RpcError>),
    InvalidMessage(String),
    Token(AuthTokenError),
}

impl fmt::Display for RpcClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Timeout => formatter.write_str("RPC request timed out"),
            Self::Protocol(error) => write!(formatter, "{}: {}", error.code, error.message),
            Self::InvalidMessage(message) => formatter.write_str(message),
            Self::Token(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RpcClientError {}

impl From<io::Error> for RpcClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<AuthTokenError> for RpcClientError {
    fn from(error: AuthTokenError) -> Self {
        Self::Token(error)
    }
}

impl fmt::Display for RpcErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::AuthenticationFailed => "authentication_failed",
            Self::InvalidMessage => "invalid_message",
            Self::MessageTooLarge => "message_too_large",
            Self::VersionMismatch => "version_mismatch",
            Self::Timeout => "timeout",
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::ProcessNotFound => "process_not_found",
            Self::ProcessAccessDenied => "process_access_denied",
            Self::ProcessExited => "process_exited",
            Self::SessionNotFound => "session_not_found",
            Self::AgentShuttingDown => "agent_shutting_down",
            Self::MemoryInvalidAddress => "memory_invalid_address",
            Self::MemoryReadFailed => "memory_read_failed",
            Self::MemoryRequiredMatchNotFound => "memory_required_match_not_found",
            Self::MemoryAmbiguousMatch => "memory_ambiguous_match",
            Self::MemoryLimitExceeded => "memory_limit_exceeded",
            Self::MemoryPatternInvalid => "memory_pattern_invalid",
            Self::Internal => "internal",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug)]
pub struct RpcClient {
    stream: TcpStream,
    next_request_id: u64,
    pub protocol: ProtocolVersion,
    pub capabilities: Vec<String>,
    pub agent: Option<AgentIdentity>,
    config: RpcConfig,
}

impl RpcClient {
    pub fn connect(
        address: SocketAddr,
        token: AuthToken,
        capabilities: Vec<String>,
        native_context: Option<NativeContext>,
        config: RpcConfig,
    ) -> Result<Self, RpcClientError> {
        Self::connect_with_version(
            address,
            token,
            CURRENT_PROTOCOL_VERSION,
            capabilities,
            native_context,
            config,
        )
    }

    pub fn connect_with_version(
        address: SocketAddr,
        token: AuthToken,
        protocol: ProtocolVersion,
        capabilities: Vec<String>,
        native_context: Option<NativeContext>,
        config: RpcConfig,
    ) -> Result<Self, RpcClientError> {
        if !is_allowed_address(address) {
            return Err(RpcClientError::Io(io::Error::new(
                ErrorKind::PermissionDenied,
                "Deimos RPC only accepts 127.0.0.1 addresses",
            )));
        }

        let mut stream = TcpStream::connect_timeout(&address, config.io_timeout)?;
        stream.set_read_timeout(Some(config.io_timeout))?;
        stream.set_write_timeout(Some(config.io_timeout))?;
        let request_id = 1;
        write_message(
            &mut stream,
            &RpcRequest::Hello(HelloRequest {
                request_id,
                protocol,
                token: token.as_str().to_string(),
                capabilities,
                native_context,
            }),
            config.max_message_size,
        )?;

        let response = read_response(&mut stream, config.max_message_size)?;
        let RpcResponse::Hello(response) = response else {
            return Err(response_error(response, request_id, HANDSHAKE_OPERATION));
        };
        if response.request_id != request_id {
            return Err(RpcClientError::InvalidMessage(format!(
                "hello response request_id {} does not match {request_id}",
                response.request_id
            )));
        }

        Ok(Self {
            stream,
            next_request_id: 2,
            protocol: response.protocol,
            capabilities: response.capabilities,
            agent: response.agent,
            config,
        })
    }

    pub fn call(
        &mut self,
        operation: impl Into<String>,
        payload: Value,
        native_context: Option<NativeContext>,
    ) -> Result<Value, RpcClientError> {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).ok_or_else(|| {
            RpcClientError::InvalidMessage("request ID space exhausted".to_string())
        })?;
        let operation = operation.into();
        write_message(
            &mut self.stream,
            &RpcRequest::Call(RpcCall {
                request_id,
                operation: operation.clone(),
                payload,
                native_context,
            }),
            self.config.max_message_size,
        )?;

        match read_response(&mut self.stream, self.config.max_message_size)? {
            RpcResponse::Result(result) => {
                if result.request_id != request_id || result.operation != operation {
                    return Err(RpcClientError::InvalidMessage(
                        "response does not match the request".to_string(),
                    ));
                }
                Ok(result.payload)
            }
            RpcResponse::Error { error } => {
                if error.request_id != request_id && error.request_id != 0 {
                    return Err(RpcClientError::InvalidMessage(
                        "error response does not match the request".to_string(),
                    ));
                }
                Err(RpcClientError::Protocol(Box::new(error)))
            }
            RpcResponse::Hello(_) => Err(RpcClientError::InvalidMessage(
                "received an unexpected hello response".to_string(),
            )),
        }
    }
}

fn read_response(stream: &mut TcpStream, maximum: usize) -> Result<RpcResponse, RpcClientError> {
    let payload = read_frame(stream, maximum).map_err(|error| match error {
        FrameError::Io(error) if is_timeout_error(&error) => RpcClientError::Timeout,
        FrameError::Io(error) => RpcClientError::Io(error),
        FrameError::TooLarge { size, maximum } => RpcClientError::InvalidMessage(format!(
            "response is {size} bytes; maximum is {maximum} bytes"
        )),
        FrameError::Empty => RpcClientError::InvalidMessage("response frame is empty".to_string()),
    })?;
    decode_message(&payload).map_err(|error| {
        RpcClientError::InvalidMessage(format!("response is not valid JSON RPC: {error}"))
    })
}

fn is_timeout_error(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

fn is_disconnect_frame_error(error: &FrameError) -> bool {
    matches!(
        error,
        FrameError::Io(error)
            if matches!(
                error.kind(),
                ErrorKind::UnexpectedEof
                    | ErrorKind::BrokenPipe
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
            )
    )
}

fn response_error(response: RpcResponse, request_id: u64, operation: &str) -> RpcClientError {
    match response {
        RpcResponse::Error { error } => RpcClientError::Protocol(Box::new(error)),
        _ => RpcClientError::InvalidMessage(format!(
            "response for request {request_id} ({operation}) was not a hello or error"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn context() -> NativeContext {
        NativeContext {
            component: "deimos-native-test".to_string(),
            version: "test".to_string(),
            native_pid: Some(42),
            launch_id: Some("launch-test".to_string()),
        }
    }

    fn start_server<F>(
        handler: F,
        config: RpcConfig,
    ) -> (SocketAddr, AuthToken, thread::JoinHandle<io::Result<()>>)
    where
        F: Fn(&RpcCall) -> Result<Value, Box<RpcError>> + Send + 'static,
    {
        let token = AuthToken::generate().expect("token generation should work");
        let (server, listener) =
            RpcServer::bind(0, token.clone(), vec!["echo".to_string()], config)
                .expect("server should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let thread = thread::spawn(move || {
            let (stream, _) = listener.accept()?;
            server.serve_connection(stream, handler)
        });
        (address, token, thread)
    }

    #[test]
    fn valid_round_trip_preserves_request_context() {
        let (address, token, thread) =
            start_server(|call| Ok(call.payload.clone()), RpcConfig::default());
        let mut client = RpcClient::connect(
            address,
            token,
            vec!["echo".to_string()],
            Some(context()),
            RpcConfig::default(),
        )
        .expect("client should complete the handshake");
        let payload = serde_json::json!({"message": "round-trip"});
        assert_eq!(
            client
                .call("echo", payload.clone(), Some(context()))
                .unwrap(),
            payload
        );
        drop(client);
        thread
            .join()
            .expect("server should not panic")
            .expect("server should finish");
    }

    #[test]
    fn unauthenticated_client_is_rejected() {
        let (address, _token, thread) = start_server(|_| Ok(Value::Null), RpcConfig::default());
        let bad_token = AuthToken::from_string("wrong-token").unwrap();
        let error = RpcClient::connect(address, bad_token, vec![], None, RpcConfig::default())
            .expect_err("bad token must be rejected");
        assert!(matches!(
            error,
            RpcClientError::Protocol(error) if error.code == RpcErrorCode::AuthenticationFailed
        ));
        thread
            .join()
            .expect("server should not panic")
            .expect("server should finish");
    }

    #[test]
    fn incompatible_version_returns_actionable_error() {
        let (address, token, thread) = start_server(|_| Ok(Value::Null), RpcConfig::default());
        let error = RpcClient::connect_with_version(
            address,
            token,
            ProtocolVersion { major: 9, minor: 0 },
            vec![],
            None,
            RpcConfig::default(),
        )
        .expect_err("incompatible version must be rejected");
        match error {
            RpcClientError::Protocol(error) => {
                assert_eq!(error.code, RpcErrorCode::VersionMismatch);
                assert!(error.message.contains("upgrade"));
                assert_eq!(
                    error.details.get("supported_versions"),
                    Some(&"1.0".to_string())
                );
            }
            other => panic!("unexpected error: {other}"),
        }
        thread
            .join()
            .expect("server should not panic")
            .expect("server should finish");
    }

    #[test]
    fn oversized_frame_is_rejected_without_allocating_the_frame() {
        let mut bytes = (MAX_MESSAGE_SIZE as u32 + 1).to_be_bytes().to_vec();
        bytes.extend_from_slice(b"not read");
        let error = read_frame(&mut bytes.as_slice(), MAX_MESSAGE_SIZE)
            .expect_err("frame should be too large");
        assert!(matches!(error, FrameError::TooLarge { .. }));
    }

    #[test]
    fn malformed_and_oversized_wire_messages_return_errors_without_panicking() {
        for payload in [b"not-json".as_slice(), &[b'x'; 513][..]] {
            let token = AuthToken::generate().expect("token generation should work");
            let config = RpcConfig {
                max_message_size: 512,
                ..RpcConfig::default()
            };
            let (server, listener) =
                RpcServer::bind(0, token, vec![], config).expect("server should bind");
            let address = listener
                .local_addr()
                .expect("listener should have an address");
            let server_thread = thread::spawn(move || {
                let (stream, _) = listener.accept().expect("server should accept");
                server.serve_connection(stream, |_| Ok(Value::Null))
            });

            let mut stream = TcpStream::connect(address).expect("client should connect");
            write_frame(&mut stream, payload, MAX_MESSAGE_SIZE).expect("test frame should write");
            let response: RpcResponse = read_response(&mut stream, MAX_MESSAGE_SIZE)
                .expect("server should return a structured error");
            assert!(matches!(response, RpcResponse::Error { error } if matches!(
                error.code,
                RpcErrorCode::InvalidMessage | RpcErrorCode::MessageTooLarge
            )));
            drop(stream);
            server_thread
                .join()
                .expect("server should not panic")
                .expect("server should handle the malformed message");
        }
    }

    #[test]
    fn timeout_is_reported_by_the_client() {
        let server_config = RpcConfig {
            io_timeout: Duration::from_secs(1),
            ..RpcConfig::default()
        };
        let (address, token, thread) = start_server(
            |_| {
                thread::sleep(Duration::from_millis(100));
                Ok(Value::Null)
            },
            server_config,
        );
        let client_config = RpcConfig {
            io_timeout: Duration::from_millis(20),
            ..RpcConfig::default()
        };
        let mut client = RpcClient::connect(address, token, vec![], None, client_config)
            .expect("handshake should finish before timeout");
        let error = client
            .call("slow", Value::Null, Some(context()))
            .expect_err("slow operation should time out");
        assert!(matches!(error, RpcClientError::Timeout));
        drop(client);
        let _ = thread.join();
    }
}
