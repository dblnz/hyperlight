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

//! DAP debug context for sharing between host function and sandbox.

use std::sync::{Arc, Mutex};

use super::comm::DapCommChannel;
use super::host_funcs::{DebugAction, DebugActionType, DebugBreakEvent, handle_debug_break};
use super::messages::{DapRequest, DapResponse};

/// Shared context for DAP debugging.
///
/// This structure is shared between the registered host function and the sandbox.
/// It holds the DAP communication channel which is populated during sandbox evolution.
#[derive(Debug, Default)]
pub struct DapContext {
    /// The DAP communication channel (set during sandbox evolution)
    channel: Mutex<Option<DapCommChannel<DapResponse, DapRequest>>>,
}

impl DapContext {
    /// Creates a new empty DAP context.
    pub fn new() -> Self {
        Self {
            channel: Mutex::new(None),
        }
    }

    /// Sets the DAP channel. Called during sandbox evolution.
    pub fn set_channel(&self, channel: DapCommChannel<DapResponse, DapRequest>) {
        let mut guard = self.channel.lock().unwrap();
        *guard = Some(channel);
    }

    /// Checks if the DAP channel is connected.
    pub fn is_connected(&self) -> bool {
        self.channel.lock().unwrap().is_some()
    }

    /// Handles a debug break event from the guest.
    ///
    /// If DAP is not connected, returns a "continue" action.
    pub fn handle_break(&self, event: DebugBreakEvent) -> DebugAction {
        let guard = self.channel.lock().unwrap();
        if let Some(ref channel) = *guard {
            handle_debug_break(channel, event)
        } else {
            // DAP not connected, just continue
            log::debug!("DAP not connected, continuing execution");
            DebugAction {
                action: DebugActionType::Continue,
                breakpoints: vec![],
            }
        }
    }
}

/// Shared reference to DAP context.
pub type SharedDapContext = Arc<DapContext>;

/// Creates a new shared DAP context.
pub fn create_shared_dap_context() -> SharedDapContext {
    Arc::new(DapContext::new())
}
