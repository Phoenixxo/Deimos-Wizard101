use deimos_agent::run;
use deimos_core::rpc::{loopback_address, AuthToken, RpcConfig};
use deimos_core::ProbeRequest;
use std::net::TcpListener;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if let Some(token) = argument_value(&args, "--token") {
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

fn exit_with_error(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(3);
}
