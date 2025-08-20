/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#![allow(clippy::disallowed_macros)]
use std::thread;

use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};
use tracing::Value;
use tracing_core::Field;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

use once_cell::sync::Lazy;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use opentelemetry::{global};
//use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};
use opentelemetry_otlp::SpanExporter;

use hyperlight_host::sandbox::SandboxConfiguration;
#[cfg(gdb)]
use hyperlight_host::sandbox::config::DebugInfo;
// A simple exporter that writes events to a file.
pub struct GuestEventExporter {
    file: Mutex<std::fs::File>,
}

impl GuestEventExporter {
    pub fn new(path: &str) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("Failed to open export file");
        Self {
            file: Mutex::new(file),
        }
    }

    pub fn export_event(&self, guest_timestamp: u128, fields: &str) {
        let mut file = self.file.lock().unwrap();
        writeln!(file, "guest_timestamp={}, fields={}", guest_timestamp, fields).unwrap();
    }
}

// Make a global exporter for demonstration
pub static EXPORTER: Lazy<GuestEventExporter> = Lazy::new(|| GuestEventExporter::new("guest_events.log"));

// Shows how to consume trace events from Hyperlight using the tracing-subscriber crate.
// and also how to consume logs as trace events.

pub struct GuestLayer;

impl<S> Layer<S> for GuestLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        use tracing_core::field::{Visit, Field};
        struct GuestVisitor {
            guest_timestamp: Option<u128>,
            fields: String,
        }
        impl Visit for GuestVisitor {
            fn record_u64(&mut self, field: &Field, value: u64) {
                self.fields.push_str(&format!("{}={:?}; ", field.name(), value));
            }
            fn record_i64(&mut self, field: &Field, value: i64) {
                self.fields.push_str(&format!("{}={:?}; ", field.name(), value));
            }
            fn record_u128(&mut self, field: &Field, value: u128) {
                if field.name() == "guest_timestamp" {
                    self.guest_timestamp = Some(value);
                }
                self.fields.push_str(&format!("{}={:?}; ", field.name(), value));
            }
            fn record_bool(&mut self, field: &Field, value: bool) {
                self.fields.push_str(&format!("{}={:?}; ", field.name(), value));
            }
            fn record_str(&mut self, field: &Field, value: &str) {
                self.fields.push_str(&format!("{}={:?}; ", field.name(), value));
            }
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.fields.push_str(&format!("{}={:?}; ", field.name(), value));
            }
        }
        let mut visitor = GuestVisitor {
            guest_timestamp: None,
            fields: String::new(),
        };
        event.record(&mut visitor);
        if let Some(ts) = visitor.guest_timestamp {
            crate::EXPORTER.export_event(ts, &visitor.fields);
        } else {
            //println!("Guest Layer Event: {}", visitor.fields);
        }
    }
}

pub fn init_otel() {
    // 1) Build an OTLP span exporter (gRPC via tonic).
    //    You can also .with_endpoint("http://localhost:4317") if not default.
    let exporter = SpanExporter::builder()
        .with_tonic()
        .build()
        .expect("build otlp exporter"); // [2](https://docs.rs/opentelemetry-otlp/latest/opentelemetry_otlp/)

    // 2) Create the TracerProvider and attach a batch processor on Tokio runtime.
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter) // batching is recommended with OTLP
        .with_resource(Resource::builder()
            .with_service_name("hyperlight-host")
            .build())
        .build(); // [3](https://docs.rs/opentelemetry_sdk/latest/opentelemetry_sdk/)
    // 3) Make it the global provider.
    global::set_tracer_provider(provider);

    // 4) Bridge `tracing` -> OpenTelemetry.
    //    (Let the layer use the global tracer provider.)
    let otel_layer = tracing_opentelemetry::layer();

    tracing_subscriber::registry()
        .with(otel_layer)
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}


fn main() -> hyperlight_host::Result<()> {
    // Set up the tracing subscriber.
    // tracing_forest uses the tracing subscriber, which, by default, will consume logs as trace events
    // unless the tracing-log feature is disabled.
    let layer = ForestLayer::default()
       .with_filter(EnvFilter::from_default_env());
    Registry::default().with(layer).with(GuestLayer).init();
    // init_otel();

    // env_logger::builder()
    //     .parse_filters("none,hyperlight=info")
    //     .init();

    #[cfg(not(feature = "gdb"))]
    let mut cfg = SandboxConfiguration::default();
    #[cfg(feature = "gdb")]
    let mut cfg = {
    let mut cfg = SandboxConfiguration::default();
    let debug_info = DebugInfo { port: 8080 };
    cfg.set_guest_debug_info(debug_info);

    cfg
    };

    cfg.set_stack_size(1024 * 1024 * 10); // 8 MB stack size
    cfg.set_heap_size(1024 * 1024 * 16); // 8 MB stack size
    cfg.set_input_data_size(1024 * 1024 * 10);

    // Create an uninitialized sandbox with a guest binary
    let mut uninitialized_sandbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        Some(cfg), // default configuration
    )?;

    // Register a host functions
    uninitialized_sandbox.register("Sleep5Secs", || {
        thread::sleep(std::time::Duration::from_secs(5));
        Ok(())
    })?;
    // Note: This function is unused, it's just here for demonstration purposes

    // Initialize sandbox to be able to call host functions
    let mut multi_use_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve()?;

    // Call guest function
    let message = "Hello, World! I am executing inside of a VM :)\n".to_string();
    multi_use_sandbox
        .call::<i32>(
            "PrintOutput", // function must be defined in the guest binary
            message,
        )
        .unwrap();

    Ok(())
}
