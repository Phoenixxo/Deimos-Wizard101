use std::io;
use std::net::{TcpListener, TcpStream};

use deimos_core::rpc::{RpcCall, RpcConfig, RpcError, RpcErrorCode, RpcServer};
use deimos_core::{ProbeReport, ProbeRequest};
use serde_json::Value;

#[cfg(not(windows))]
use deimos_core::WINDOWS_AGENT_TARGET;

pub const CAPABILITY_PROBE: &str = "probe";

#[cfg(windows)]
mod windows_probe;

#[cfg(windows)]
pub fn run(request: &ProbeRequest) -> ProbeReport {
    windows_probe::run(request)
}

#[cfg(not(windows))]
pub fn run(request: &ProbeRequest) -> ProbeReport {
    let mut report = ProbeReport::new(request);
    report.errors.push(
        "This probe must be built for Windows and run inside the Wizard101 CrossOver bottle."
            .to_string(),
    );
    report.build_target = Some(WINDOWS_AGENT_TARGET.to_string());
    report
}

pub fn serve(
    listener: TcpListener,
    token: deimos_core::rpc::AuthToken,
    config: RpcConfig,
) -> io::Result<()> {
    let server = RpcServer::new(token, vec![CAPABILITY_PROBE.to_string()], config);
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("Deimos agent failed to accept a connection: {error}");
                continue;
            }
        };

        if let Err(error) = serve_connection(&server, stream) {
            eprintln!("Deimos agent connection failed: {error}");
        }
    }
    Ok(())
}

pub fn serve_connection(server: &RpcServer, stream: TcpStream) -> io::Result<()> {
    server.serve_connection(stream, handle_call)
}

fn handle_call(call: &RpcCall) -> Result<Value, Box<RpcError>> {
    if call.operation != CAPABILITY_PROBE {
        return Err(Box::new(RpcError::new(
            RpcErrorCode::UnsupportedOperation,
            format!("unsupported operation: {}", call.operation),
            call.request_id,
            call.operation.clone(),
            call.native_context.clone(),
        )));
    }

    let request: ProbeRequest = serde_json::from_value(call.payload.clone()).map_err(|error| {
        Box::new(RpcError::new(
            RpcErrorCode::InvalidRequest,
            format!("probe payload is invalid: {error}"),
            call.request_id,
            call.operation.clone(),
            call.native_context.clone(),
        ))
    })?;

    serde_json::to_value(run(&request)).map_err(|error| {
        Box::new(RpcError::new(
            RpcErrorCode::Internal,
            format!("failed to serialize probe report: {error}"),
            call.request_id,
            call.operation.clone(),
            call.native_context.clone(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{serve_connection, CAPABILITY_PROBE};
    use deimos_core::rpc::{
        AuthToken, NativeContext, RpcClient, RpcClientError, RpcConfig, RpcErrorCode,
    };
    use deimos_core::{ProbeRequest, PROTOCOL_SCHEMA_VERSION};
    use serde_json::to_value;
    use std::thread;

    #[test]
    fn probe_round_trip_uses_the_authenticated_protocol() {
        let token = AuthToken::generate().expect("token generation should work");
        let (server, listener) = deimos_core::rpc::RpcServer::bind(
            0,
            token.clone(),
            vec![CAPABILITY_PROBE.to_string()],
            RpcConfig::default(),
        )
        .expect("server should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("server should accept");
            serve_connection(&server, stream).expect("server should serve the request");
        });

        let context = NativeContext {
            component: "deimos-native".to_string(),
            version: "test".to_string(),
            native_pid: Some(7),
            launch_id: Some("launch-7".to_string()),
        };
        let mut client = RpcClient::connect(
            address,
            token,
            vec![CAPABILITY_PROBE.to_string()],
            Some(context.clone()),
            RpcConfig::default(),
        )
        .expect("authenticated client should connect");
        assert_eq!(client.capabilities, vec![CAPABILITY_PROBE.to_string()]);

        let report: deimos_core::ProbeReport = serde_json::from_value(
            client
                .call(
                    CAPABILITY_PROBE,
                    to_value(ProbeRequest::default()).expect("request should serialize"),
                    Some(context),
                )
                .expect("probe should return a report"),
        )
        .expect("response should be a probe report");
        assert_eq!(report.schema_version, PROTOCOL_SCHEMA_VERSION);
        server_thread.join().expect("server should not panic");
    }

    #[test]
    fn invalid_probe_and_unknown_operation_return_structured_errors() {
        let token = AuthToken::generate().expect("token generation should work");
        let (server, listener) = deimos_core::rpc::RpcServer::bind(
            0,
            token.clone(),
            vec![CAPABILITY_PROBE.to_string()],
            RpcConfig::default(),
        )
        .expect("server should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("server should accept");
            serve_connection(&server, stream).expect("server should serve requests");
        });
        let context = NativeContext {
            component: "deimos-native".to_string(),
            version: "test".to_string(),
            native_pid: None,
            launch_id: Some("launch-errors".to_string()),
        };
        let mut client = RpcClient::connect(address, token, vec![], None, RpcConfig::default())
            .expect("client should connect");
        let error = client
            .call("unknown", serde_json::Value::Null, Some(context.clone()))
            .expect_err("unknown operation should fail");
        match error {
            RpcClientError::Protocol(error) => {
                assert_eq!(error.code, RpcErrorCode::UnsupportedOperation);
                assert_eq!(error.operation, "unknown");
                assert_eq!(error.native_context, Some(context.clone()));
            }
            other => panic!("unexpected error: {other}"),
        }
        let error = client
            .call(
                CAPABILITY_PROBE,
                serde_json::Value::Null,
                Some(context.clone()),
            )
            .expect_err("invalid probe should fail");
        match error {
            RpcClientError::Protocol(error) => {
                assert_eq!(error.code, RpcErrorCode::InvalidRequest);
                assert_eq!(error.operation, CAPABILITY_PROBE);
                assert_eq!(error.native_context, Some(context));
            }
            other => panic!("unexpected error: {other}"),
        }
        drop(client);
        server_thread.join().expect("server should not panic");
    }
}
