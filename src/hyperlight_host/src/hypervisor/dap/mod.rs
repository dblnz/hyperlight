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

//! Debug Adapter Protocol (DAP) support for Hyperlight.
//!
//! This module provides a DAP server that enables debugging of guest code
//! (e.g., JavaScript runtimes) from IDEs like VS Code.
//!
//! # Architecture
//!
//! The DAP server runs in a separate thread and communicates with the
//! Hyperlight VM via channels. Debug events from the guest (e.g., breakpoint
//! hit, step completed) are sent to the DAP server, which then forwards them
//! to the connected debugger client.
//!
//! ```text
//! ┌──────────────┐     DAP/TCP      ┌──────────────┐    Channel    ┌──────────────┐
//! │   VS Code    │ ◄──────────────► │  DAP Server  │ ◄───────────► │ Hyperlight   │
//! │  (Client)    │                  │   Thread     │               │     VM       │
//! └──────────────┘                  └──────────────┘               └──────────────┘
//!                                                                         │
//!                                                                    Host Call
//!                                                                         │
//!                                                                  ┌──────────────┐
//!                                                                  │    Guest     │
//!                                                                  │  (JS Runtime)│
//!                                                                  └──────────────┘
//! ```

mod comm;
mod errors;
mod messages;
mod protocol;
mod server;

pub use comm::DapCommChannel;
pub use errors::DapError;
pub use messages::{
    Breakpoint, DapRequest, DapResponse, Scope, SourceLocation, StackFrame, StopReason, Variable,
};
pub use server::create_dap_thread;
