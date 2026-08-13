use std::time::Instant;

use serde_json::{Map, Value};

pub(crate) fn hook_timing(
    operation: &str,
    phase: &str,
    started: Instant,
    outcome: &str,
    details: Value,
) {
    let mut event = match details {
        Value::Object(details) => details,
        _ => Map::new(),
    };
    event.insert(
        "component".to_string(),
        Value::String("deimos-agent".to_string()),
    );
    event.insert(
        "event".to_string(),
        Value::String("hook_timing".to_string()),
    );
    event.insert(
        "operation".to_string(),
        Value::String(operation.to_string()),
    );
    event.insert("phase".to_string(), Value::String(phase.to_string()));
    event.insert("outcome".to_string(), Value::String(outcome.to_string()));
    event.insert(
        "elapsed_ms".to_string(),
        Value::from(started.elapsed().as_secs_f64() * 1000.0),
    );
    event.insert("process_id".to_string(), Value::from(std::process::id()));
    eprintln!("{}", Value::Object(event));
}

pub(crate) struct HookTimingSpan {
    operation: String,
    phase: String,
    started: Instant,
    completed: bool,
}

impl HookTimingSpan {
    pub(crate) fn new(operation: impl Into<String>, phase: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            phase: phase.into(),
            started: Instant::now(),
            completed: false,
        }
    }

    pub(crate) fn finish(mut self, outcome: &str, details: Value) {
        hook_timing(&self.operation, &self.phase, self.started, outcome, details);
        self.completed = true;
    }
}

impl Drop for HookTimingSpan {
    fn drop(&mut self) {
        if !self.completed {
            hook_timing(
                &self.operation,
                &self.phase,
                self.started,
                "error",
                Value::Object(Map::new()),
            );
        }
    }
}
