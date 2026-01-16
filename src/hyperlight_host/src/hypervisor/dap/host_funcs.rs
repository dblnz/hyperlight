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

//! DAP host functions for guest-to-host debug communication.
//!
//! This module provides the host function that guests call to report debug events
//! (like hitting breakpoints) and receive debugger commands (like continue/step).

use serde::{Deserialize, Serialize};

use super::comm::DapCommChannel;
use super::messages::{DapRequest, DapResponse, SourceLocation, StackFrame, StopReason};

/// Debug event sent from guest to host.
///
/// The guest serializes this to JSON and passes it to the `debug_break` host function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugBreakEvent {
    /// Reason for the debug break
    pub reason: DebugBreakReason,
    /// Current source location
    pub location: DebugLocation,
    /// Current call stack (if available)
    #[serde(default)]
    pub stack_frames: Vec<DebugStackFrame>,
    /// Optional exception message (if reason is Exception)
    #[serde(default)]
    pub exception_message: Option<String>,
}

/// Reason why the guest stopped execution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DebugBreakReason {
    /// Program entry point
    Entry,
    /// Hit a breakpoint
    Breakpoint,
    /// Completed a step operation
    Step,
    /// Paused by request
    Pause,
    /// Exception occurred
    Exception,
}

impl From<DebugBreakReason> for StopReason {
    fn from(reason: DebugBreakReason) -> Self {
        match reason {
            DebugBreakReason::Entry => StopReason::Entry,
            DebugBreakReason::Breakpoint => StopReason::Breakpoint,
            DebugBreakReason::Step => StopReason::Step,
            DebugBreakReason::Pause => StopReason::Pause,
            DebugBreakReason::Exception => StopReason::Exception,
        }
    }
}

/// Source location information from the guest.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DebugLocation {
    /// Source file path/name
    pub filename: String,
    /// Function name (optional)
    #[serde(default)]
    pub function_name: Option<String>,
    /// Line number (1-based)
    pub line: u32,
    /// Column number (1-based, optional)
    #[serde(default)]
    pub column: Option<u32>,
}

impl From<DebugLocation> for SourceLocation {
    fn from(loc: DebugLocation) -> Self {
        SourceLocation {
            filename: loc.filename,
            function_name: loc.function_name,
            line: loc.line,
            column: loc.column,
        }
    }
}

/// Stack frame information from the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugStackFrame {
    /// Frame ID (assigned by guest)
    pub id: u32,
    /// Function name
    pub name: String,
    /// Source location
    pub location: DebugLocation,
}

impl From<DebugStackFrame> for StackFrame {
    fn from(frame: DebugStackFrame) -> Self {
        StackFrame {
            id: frame.id,
            name: frame.name,
            location: frame.location.into(),
        }
    }
}

/// Debug action returned from host to guest.
///
/// The host serializes this to JSON and returns it from the `debug_break` host function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugAction {
    /// The action the guest should take
    pub action: DebugActionType,
    /// Updated breakpoints (if any)
    #[serde(default)]
    pub breakpoints: Vec<DebugBreakpoint>,
}

/// Type of debug action for the guest to perform.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DebugActionType {
    /// Continue execution normally
    Continue,
    /// Step to next statement (step over)
    StepOver,
    /// Step into function calls
    StepInto,
    /// Step out of current function
    StepOut,
    /// Disconnect debugger (continue without debugging)
    Disconnect,
}

/// Breakpoint information sent from host to guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugBreakpoint {
    /// Unique breakpoint ID
    pub id: u32,
    /// Source file
    pub filename: String,
    /// Line number
    pub line: u32,
    /// Whether the breakpoint is enabled
    pub enabled: bool,
}

/// Handles a debug break event from the guest.
///
/// This function:
/// 1. Sends a "stopped" event to the DAP server
/// 2. Waits for debugger commands (continue, step, etc.)
/// 3. Returns the action for the guest to perform
///
/// # Arguments
/// * `channel` - Communication channel to the DAP server
/// * `event` - The debug break event from the guest
///
/// # Returns
/// The action the guest should perform (continue, step, etc.)
pub fn handle_debug_break(
    channel: &DapCommChannel<DapResponse, DapRequest>,
    event: DebugBreakEvent,
) -> DebugAction {
    // Convert and send the stopped event to DAP server
    let stopped_response = DapResponse::Stopped {
        reason: event.reason.into(),
        location: event.location.into(),
        hit_breakpoint_ids: None,
        exception_text: event.exception_message,
    };

    if let Err(e) = channel.send(stopped_response) {
        log::error!("Failed to send stopped event to DAP server: {:?}", e);
        // Return continue on error to avoid hanging
        return DebugAction {
            action: DebugActionType::Continue,
            breakpoints: vec![],
        };
    }

    // Collect breakpoints to send back to guest
    let mut breakpoints = Vec::new();

    // Wait for debugger commands
    loop {
        match channel.recv() {
            Ok(request) => match request {
                DapRequest::Continue => {
                    // Send continued response to DAP
                    let _ = channel.send(DapResponse::Continued);
                    return DebugAction {
                        action: DebugActionType::Continue,
                        breakpoints,
                    };
                }
                DapRequest::Next => {
                    let _ = channel.send(DapResponse::Continued);
                    return DebugAction {
                        action: DebugActionType::StepOver,
                        breakpoints,
                    };
                }
                DapRequest::StepIn => {
                    let _ = channel.send(DapResponse::Continued);
                    return DebugAction {
                        action: DebugActionType::StepInto,
                        breakpoints,
                    };
                }
                DapRequest::StepOut => {
                    let _ = channel.send(DapResponse::Continued);
                    return DebugAction {
                        action: DebugActionType::StepOut,
                        breakpoints,
                    };
                }
                DapRequest::Disconnect { .. } => {
                    let _ = channel.send(DapResponse::Disconnected);
                    return DebugAction {
                        action: DebugActionType::Disconnect,
                        breakpoints,
                    };
                }
                DapRequest::SetBreakpoints { source_path, lines } => {
                    // Update breakpoints list to send back to guest
                    for (i, line) in lines.iter().enumerate() {
                        breakpoints.push(DebugBreakpoint {
                            id: i as u32,
                            filename: source_path.clone(),
                            line: *line,
                            enabled: true,
                        });
                    }
                    // Acknowledge to DAP server
                    let bp_response: Vec<_> = breakpoints
                        .iter()
                        .map(|bp| super::messages::Breakpoint {
                            id: bp.id,
                            verified: true,
                            line: bp.line,
                            message: None,
                        })
                        .collect();
                    let _ = channel.send(DapResponse::BreakpointsSet {
                        breakpoints: bp_response,
                    });
                    // Continue waiting for continue/step command
                }
                DapRequest::StackTrace { .. } => {
                    // Send stack trace from the event
                    let frames: Vec<StackFrame> = event
                        .stack_frames
                        .iter()
                        .cloned()
                        .map(Into::into)
                        .collect();
                    let total = frames.len() as u32;
                    let _ = channel.send(DapResponse::StackTrace {
                        frames,
                        total_frames: total,
                    });
                }
                DapRequest::Scopes { frame_id } => {
                    // For POC, just return a simple "Locals" scope
                    let _ = channel.send(DapResponse::Scopes {
                        scopes: vec![super::messages::Scope {
                            name: "Locals".to_string(),
                            variables_reference: frame_id + 1000, // Simple reference scheme
                            expensive: false,
                        }],
                    });
                }
                DapRequest::Variables { .. } => {
                    // For POC, return empty variables
                    let _ = channel.send(DapResponse::Variables { variables: vec![] });
                }
                DapRequest::Evaluate { expression, .. } => {
                    // For POC, just echo the expression
                    let _ = channel.send(DapResponse::Evaluate {
                        result: format!("(evaluation not implemented: {})", expression),
                        type_name: Some("string".to_string()),
                        variables_reference: 0,
                    });
                }
                _ => {
                    // Ignore other requests while stopped
                    log::debug!("Ignoring DAP request while stopped: {:?}", request);
                }
            },
            Err(e) => {
                log::error!("Error receiving from DAP channel: {:?}", e);
                // Return continue on error to avoid hanging
                return DebugAction {
                    action: DebugActionType::Continue,
                    breakpoints,
                };
            }
        }
    }
}

/// The name of the debug_break host function.
pub const DEBUG_BREAK_FUNC_NAME: &str = "hl_dap_debug_break";
