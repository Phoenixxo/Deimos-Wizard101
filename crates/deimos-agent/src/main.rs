use deimos_agent::instance::AgentInstanceGuard;
use deimos_agent::run;
use deimos_core::rpc::{loopback_address, AuthToken, RpcConfig};
use deimos_core::ProbeRequest;
use std::io::Read;
use std::net::TcpListener;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if let Some(token) = managed_token(&args) {
        let _instance_guard = AgentInstanceGuard::acquire().unwrap_or_else(|error| {
            exit_with_error(&format!("failed to acquire agent instance: {error}"))
        });
        let port = argument_value(&args, "--listen-port")
            .unwrap_or_else(|| "0".to_string())
            .parse::<u16>()
            .unwrap_or_else(|error| exit_with_error(&format!("invalid --listen-port: {error}")));
        let token = AuthToken::from_string(token)
            .unwrap_or_else(|error| exit_with_error(&format!("invalid --token: {error}")));
        let listener = TcpListener::bind(loopback_address(port))
            .unwrap_or_else(|error| exit_with_error(&format!("failed to bind agent: {error}")));
        let address = listener.local_addr().unwrap_or_else(|error| {
            exit_with_error(&format!("failed to inspect agent listener: {error}"))
        });
        println!("DEIMOS_AGENT_LISTEN={address}");
        eprintln!(
            "{}",
            serde_json::json!({
                "component": "deimos-agent",
                "event": "listening",
                "address": address.to_string(),
                "version": env!("CARGO_PKG_VERSION"),
                "process_id": std::process::id(),
                "ready": false
            })
        );
        if let Err(error) = deimos_agent::serve(listener, token, RpcConfig::default()) {
            exit_with_error(&format!("agent server stopped: {error}"));
        }
        return;
    }

    let target_process = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| deimos_core::DEFAULT_TARGET_PROCESS.to_string());
    let request = ProbeRequest::new(target_process);
    let report = run(&request);
    let success = report.success;

    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to serialize probe report: {error}");
            std::process::exit(3);
        }
    }

    if !success {
        std::process::exit(2);
    }
}

fn argument_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn managed_token(args: &[String]) -> Option<String> {
    if let Some(token) = argument_value(args, "--token") {
        return Some(token);
    }
    if !args.iter().any(|argument| argument == "--token-stdin") {
        return None;
    }

    let mut token = String::new();
    std::io::stdin()
        .take(257)
        .read_to_string(&mut token)
        .unwrap_or_else(|error| {
            exit_with_error(&format!(
                "failed to read the managed authentication token from stdin: {error}"
            ))
        });
    Some(normalize_stdin_token(&token).unwrap_or_else(|message| exit_with_error(message)))
}

fn normalize_stdin_token(token: &str) -> Result<String, &'static str> {
    let token = token.trim_end_matches(['\r', '\n']);
    if token.is_empty() || token.len() > 256 {
        return Err("managed authentication token from stdin has an invalid length");
    }
    Ok(token.to_string())
}

fn exit_with_error(message: &str) -> ! {
    eprintln!(
        "{}",
        serde_json::json!({
            "component": "deimos-agent",
            "event": "fatal_error",
            "message": message,
            "process_id": std::process::id()
        })
    );
    std::process::exit(3);
}

#[cfg(test)]
mod tests {
    use super::{argument_value, normalize_stdin_token};

    #[test]
    fn managed_token_argument_remains_backward_compatible() {
        let args = vec![
            "deimos-agent".to_string(),
            "--token".to_string(),
            "legacy-token".to_string(),
        ];
        assert_eq!(
            argument_value(&args, "--token").as_deref(),
            Some("legacy-token")
        );
    }

    #[test]
    fn stdin_tokens_trim_only_line_endings() {
        assert_eq!(
            normalize_stdin_token("  token value  \r\n").unwrap(),
            "  token value  "
        );
    }

    #[test]
    fn stdin_tokens_are_bounded_and_nonempty() {
        assert!(normalize_stdin_token("\n").is_err());
        assert!(normalize_stdin_token(&"a".repeat(256)).is_ok());
        assert!(normalize_stdin_token(&"a".repeat(257)).is_err());
    }
}
