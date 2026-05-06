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

// Re-export the shared types from hyperlight-debug so that the rest of
// the host crate (and downstream users) can keep importing from here.
pub use hyperlight_debug::dap::types::{
    DebugAction, DebugActionType, DebugBreakEvent, DebugBreakReason, DebugBreakpoint,
    DebugLocation, DebugStackFrame, DebugVariable, DEBUG_BREAK_FUNC_NAME,
};

use super::comm::DapCommChannel;
use super::messages::{
    DapRequest, DapResponse, SourceLocation, StackFrame, StopReason, Variable,
};

// ---------------------------------------------------------------------------
// Conversions from shared types → internal DAP-server types
// ---------------------------------------------------------------------------

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

impl From<DebugStackFrame> for StackFrame {
    fn from(frame: DebugStackFrame) -> Self {
        StackFrame {
            id: frame.id,
            name: frame.name,
            location: frame.location.into(),
        }
    }
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

    // Breakpoints keyed by source file.  Each `SetBreakpoints` call
    // *replaces* all breakpoints for a given file (per DAP spec).
    let mut breakpoints_by_file: std::collections::HashMap<String, Vec<DebugBreakpoint>> =
        std::collections::HashMap::new();
    // Monotonically increasing ID so every breakpoint gets a globally
    // unique identifier across multiple `setBreakpoints` calls.
    let mut next_bp_id: u32 = 1;

    // Wait for debugger commands
    loop {
        // Flatten the per-file map into the vec sent back to the guest.
        let collect_breakpoints = |m: &std::collections::HashMap<String, Vec<DebugBreakpoint>>| -> Vec<DebugBreakpoint> {
            m.values().flatten().cloned().collect()
        };
        match channel.recv() {
            Ok(request) => match request {
                DapRequest::Continue => {
                    let _ = channel.send(DapResponse::Continued);
                    return DebugAction {
                        action: DebugActionType::Continue,
                        breakpoints: collect_breakpoints(&breakpoints_by_file),
                    };
                }
                DapRequest::Next => {
                    let _ = channel.send(DapResponse::Continued);
                    return DebugAction {
                        action: DebugActionType::StepOver,
                        breakpoints: collect_breakpoints(&breakpoints_by_file),
                    };
                }
                DapRequest::StepIn => {
                    let _ = channel.send(DapResponse::Continued);
                    return DebugAction {
                        action: DebugActionType::StepInto,
                        breakpoints: collect_breakpoints(&breakpoints_by_file),
                    };
                }
                DapRequest::StepOut => {
                    let _ = channel.send(DapResponse::Continued);
                    return DebugAction {
                        action: DebugActionType::StepOut,
                        breakpoints: collect_breakpoints(&breakpoints_by_file),
                    };
                }
                DapRequest::Disconnect { .. } => {
                    let _ = channel.send(DapResponse::Disconnected);
                    return DebugAction {
                        action: DebugActionType::Disconnect,
                        breakpoints: collect_breakpoints(&breakpoints_by_file),
                    };
                }
                DapRequest::SetBreakpoints { source_path, lines } => {
                    // Replace all breakpoints for this source file
                    // (DAP spec: setBreakpoints replaces, not accumulates).
                    let file_bps: Vec<DebugBreakpoint> = lines
                        .iter()
                        .map(|&line| {
                            let id = next_bp_id;
                            next_bp_id += 1;
                            DebugBreakpoint {
                                id,
                                filename: source_path.clone(),
                                line,
                                enabled: true,
                            }
                        })
                        .collect();
                    // Acknowledge to DAP server
                    let bp_response: Vec<_> = file_bps
                        .iter()
                        .map(|bp| super::messages::Breakpoint {
                            id: bp.id,
                            verified: true,
                            line: bp.line,
                            message: None,
                        })
                        .collect();
                    breakpoints_by_file.insert(source_path, file_bps);
                    let _ = channel.send(DapResponse::BreakpointsSet {
                        breakpoints: bp_response,
                    });
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
                DapRequest::Variables { variables_reference } => {
                    // Derive frame_id from variables_reference (Scopes uses frame_id + 1000).
                    let frame_id = variables_reference.saturating_sub(1000);
                    let variables: Vec<super::messages::Variable> = event
                        .stack_frames
                        .iter()
                        .find(|f| f.id == frame_id)
                        .map(|f| {
                            f.variables
                                .iter()
                                .map(|v| super::messages::Variable {
                                    name: v.name.clone(),
                                    value: v.value.clone(),
                                    type_name: v.type_name.clone(),
                                    variables_reference: 0,
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let _ = channel.send(DapResponse::Variables { variables });
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
                    breakpoints: collect_breakpoints(&breakpoints_by_file),
                };
            }
        }
    }
}
