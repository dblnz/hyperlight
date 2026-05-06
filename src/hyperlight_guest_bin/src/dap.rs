//! Generic debugger state machine for Hyperlight guests.
//!
//! This module provides a runtime-agnostic debugger that any guest (JS, Python, …)
//! can drive by calling [`on_trace_event`] from its language-level trace hook.
//!
//! The state machine manages breakpoints, stepping modes, and call-stack tracking.
//! It communicates with the host DAP server via the `hl_dap_debug_break` host function
//! using the shared types from [`hyperlight_debug`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use core::cell::OnceCell;
use core::sync::atomic::{AtomicBool, Ordering};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_debug::dap::types::{
    DebugAction, DebugActionType, DebugBreakEvent, DebugBreakReason, DebugBreakpoint,
    DebugLocation, DebugStackFrame, DebugVariable, DEBUG_BREAK_FUNC_NAME,
};

use crate::host_comm::call_host_function;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enable the debugger.
///
/// If `stop_on_entry` is true the debugger will break at the very first
/// trace event (program entry).
pub fn enable(stop_on_entry: bool) {
    let state = debugger_state();
    state.enabled = true;
    state.stop_on_entry = stop_on_entry;
    state.first_op = true;
}

/// Disable the debugger. Execution will continue without interruption.
pub fn disable() {
    debugger_state().enabled = false;
}

/// Reset per-invocation state.
///
/// Call this at the start of each new handler invocation so stale call-stack
/// and stepping state from a previous invocation is cleared. Configuration
/// (`enabled`, `stop_on_entry`, breakpoints) is preserved.
pub fn reset() {
    let state = debugger_state();
    state.call_stack.clear();
    state.step_depth = 0;
    state.first_op = true;
    state.mode = DebugMode::Running;
    state.last_line = None;
    state.last_file = None;
    state.current_function = None;
}

/// Returns `true` when the debugger is active.
pub fn is_enabled() -> bool {
    debugger_state().enabled
}

/// Re-export the shared variable type for use by runtime adapters.
pub type Variable = DebugVariable;

/// Install a runtime-specific callback that collects local variables
/// at a given stack depth.
///
/// The provider function receives a 0-based stack level and returns
/// the variables visible at that level.
pub fn set_variables_provider(provider: fn(level: u32) -> Vec<Variable>) {
    VARIABLES_PROVIDER_SET.store(true, Ordering::Release);
    // SAFETY: single-threaded guest — only one writer.
    unsafe {
        VARIABLES_PROVIDER = provider;
    }
}

/// Main entry point called by the runtime trace hook.
///
/// `filename`, `funcname`, `line`, and `col` describe the current source
/// location. Returns 0 to continue execution normally.
///
/// Uses the global variables provider installed via [`set_variables_provider`].
pub fn on_trace_event(filename: &str, funcname: &str, line: i32, col: i32) -> i32 {
    let has_vars = VARIABLES_PROVIDER_SET.load(Ordering::Acquire);
    let provider = |level: u32| -> Vec<DebugVariable> {
        if !has_vars {
            return Vec::new();
        }
        // SAFETY: single-threaded guest, provider pointer is stable.
        unsafe { VARIABLES_PROVIDER(level) }
    };
    on_trace_event_inner(filename, funcname, line, col, &provider)
}

/// Like [`on_trace_event`] but with an explicit variables provider closure.
///
/// Use this when the provider needs to capture runtime-specific context
/// (e.g. a QuickJS `Ctx`) that cannot be stored in a static function pointer.
pub fn on_trace_event_with(
    filename: &str,
    funcname: &str,
    line: i32,
    col: i32,
    vars_provider: &dyn Fn(u32) -> Vec<DebugVariable>,
) -> i32 {
    on_trace_event_inner(filename, funcname, line, col, vars_provider)
}

fn on_trace_event_inner(
    filename: &str,
    funcname: &str,
    line: i32,
    col: i32,
    vars_provider: &dyn Fn(u32) -> Vec<DebugVariable>,
) -> i32 {
    let state = debugger_state();

    if !state.enabled {
        return 0;
    }

    // Update call stack based on function-name transitions.
    state.update_call_stack(filename, funcname, line, col);

    // Check whether we should break here.
    let reason = state.should_break(filename, line, funcname);
    state.last_line = Some(line);
    state.last_file = Some(filename.to_string());

    let reason = match reason {
        Some(r) => r,
        None => return 0,
    };

    // Clear first-op flag after checking.
    state.first_op = false;

    // Build stack frames (most recent first for DAP).
    let mut stack_frames: Vec<DebugStackFrame> = state
        .call_stack
        .iter()
        .rev()
        .enumerate()
        .map(|(idx, f)| DebugStackFrame {
            id: idx as u32,
            name: f.name.clone(),
            location: f.location.clone(),
            variables: vars_provider(idx as u32),
        })
        .collect();

    // If the stack is empty, synthesize a single frame from the current location.
    if stack_frames.is_empty() {
        stack_frames.push(DebugStackFrame {
            id: 0,
            name: funcname.to_string(),
            location: DebugLocation {
                filename: filename.to_string(),
                function_name: Some(funcname.to_string()),
                line: line as u32,
                column: Some(col as u32),
            },
            variables: vars_provider(0),
        });
    }

    let event = DebugBreakEvent {
        reason,
        location: DebugLocation {
            filename: filename.to_string(),
            function_name: Some(funcname.to_string()),
            line: line as u32,
            column: Some(col as u32),
        },
        stack_frames,
        exception_message: None,
    };

    // Serialize → call host → deserialize response.
    let event_json = match serde_json::to_string(&event) {
        Ok(j) => j,
        Err(e) => {
            log::error!("Failed to serialize debug break event: {e}");
            return 0;
        }
    };

    let response: String = match call_host_function(
        DEBUG_BREAK_FUNC_NAME,
        Some(vec![ParameterValue::String(event_json)]),
        ReturnType::String,
    ) {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to call debug break host function: {e:?}");
            return 0;
        }
    };

    let action: DebugAction = match serde_json::from_str(&response) {
        Ok(a) => a,
        Err(e) => {
            log::error!("Failed to parse debug action: {e} (response: {response})");
            return 0;
        }
    };

    state.handle_action(action);

    0
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Execution mode of the debugger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DebugMode {
    /// Normal execution — only stop at breakpoints.
    Running,
    /// Stop at the very next trace event (step into).
    Step,
    /// Stop at the next event in the same or a parent frame (step over).
    StepOver,
    /// Stop when returning to the parent frame (step out).
    StepOut,
}

/// Internal stack frame with mutable location tracking.
#[derive(Debug, Clone)]
struct InternalFrame {
    name: String,
    location: DebugLocation,
}

/// Mutable debugger state stored in a process-global singleton.
struct DebuggerState {
    enabled: bool,
    mode: DebugMode,
    breakpoints: Vec<DebugBreakpoint>,
    call_stack: Vec<InternalFrame>,
    step_depth: usize,
    first_op: bool,
    stop_on_entry: bool,
    last_line: Option<i32>,
    last_file: Option<String>,
    current_function: Option<String>,
}

impl Default for DebuggerState {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: DebugMode::Running,
            breakpoints: Vec::new(),
            call_stack: Vec::new(),
            step_depth: 0,
            first_op: true,
            stop_on_entry: false,
            last_line: None,
            last_file: None,
            current_function: None,
        }
    }
}

// Variables provider — function pointer + flag.
static VARIABLES_PROVIDER_SET: AtomicBool = AtomicBool::new(false);
static mut VARIABLES_PROVIDER: fn(u32) -> Vec<Variable> = |_| Vec::new();

fn debugger_state() -> &'static mut DebuggerState {
    #![allow(static_mut_refs)]
    static mut STATE: OnceCell<DebuggerState> = OnceCell::new();
    // SAFETY: Hyperlight guests are single-threaded.
    unsafe {
        STATE.get_or_init(DebuggerState::default);
        STATE.get_mut().unwrap()
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Extract the basename (last component) of a path.
///
/// Handles leading `./`, embedded `./`, trailing `/`, and both
/// forward and back slashes.
fn basename(path: &str) -> &str {
    // Strip trailing separators.
    let path = path.trim_end_matches(|c| c == '/' || c == '\\');
    // Strip any leading `./`.
    let path = path.strip_prefix("./").unwrap_or(path);
    match path.rfind('/').or_else(|| path.rfind('\\')) {
        Some(pos) => &path[pos + 1..],
        None => path,
    }
}

/// Check whether two paths refer to the same file.
///
/// If either path is already a bare filename (no separators) it is compared
/// directly against the other's basename.  Otherwise both basenames are
/// compared so that `/app/src/file.js` matches `file.js`.
fn paths_match(a: &str, b: &str) -> bool {
    let ba = basename(a);
    let bb = basename(b);
    // Fast path: basenames equal.
    if ba == bb {
        return true;
    }
    // If both are absolute / have directories, compare suffixes so that
    // `src/file.js` matches `/app/src/file.js`.
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    long.ends_with(short)
        && long
            .as_bytes()
            .get(long.len() - short.len() - 1)
            .map_or(true, |&c| c == b'/' || c == b'\\')
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

impl DebuggerState {
    /// Decide whether to break at the current location.
    fn should_break(&self, filename: &str, line: i32, funcname: &str) -> Option<DebugBreakReason> {
        if self.first_op && self.stop_on_entry {
            return Some(DebugBreakReason::Entry);
        }

        let line_changed =
            self.last_line != Some(line) || self.last_file.as_deref() != Some(filename);
        let function_changed = self.current_function.as_deref() != Some(funcname);

        match self.mode {
            DebugMode::Running => {
                if line_changed && self.has_breakpoint(filename, line) {
                    Some(DebugBreakReason::Breakpoint)
                } else {
                    None
                }
            }
            DebugMode::Step => {
                if line_changed || function_changed {
                    Some(DebugBreakReason::Step)
                } else {
                    None
                }
            }
            DebugMode::StepOver => {
                if self.call_stack.len() <= self.step_depth {
                    if line_changed {
                        Some(DebugBreakReason::Step)
                    } else {
                        None
                    }
                } else if self.has_breakpoint(filename, line) {
                    Some(DebugBreakReason::Breakpoint)
                } else {
                    None
                }
            }
            DebugMode::StepOut => {
                if self.call_stack.len() < self.step_depth {
                    Some(DebugBreakReason::Step)
                } else if self.has_breakpoint(filename, line) {
                    Some(DebugBreakReason::Breakpoint)
                } else {
                    None
                }
            }
        }
    }

    /// Check whether any breakpoint matches the given location.
    fn has_breakpoint(&self, filename: &str, line: i32) -> bool {
        self.breakpoints.iter().any(|bp| {
            bp.enabled && bp.line as i32 == line && paths_match(&bp.filename, filename)
        })
    }

    /// Track call-stack changes by observing function-name transitions.
    fn update_call_stack(&mut self, filename: &str, funcname: &str, line: i32, col: i32) {
        let function_changed = self.current_function.as_deref() != Some(funcname);

        if !function_changed {
            // Same function — update the top frame's location.
            if let Some(frame) = self.call_stack.last_mut() {
                frame.location.line = line as u32;
                frame.location.column = Some(col as u32);
                frame.location.filename = filename.to_string();
            }
            return;
        }

        let stack_len = self.call_stack.len();

        // Heuristic: if the new function matches the parent frame it's a return.
        let is_return = stack_len >= 2 && self.call_stack[stack_len - 2].name == funcname;

        if is_return {
            self.call_stack.pop();
            if let Some(frame) = self.call_stack.last_mut() {
                frame.location.line = line as u32;
                frame.location.column = Some(col as u32);
                frame.location.filename = filename.to_string();
            }
        } else {
            self.call_stack.push(InternalFrame {
                name: funcname.to_string(),
                location: DebugLocation {
                    filename: filename.to_string(),
                    function_name: Some(funcname.to_string()),
                    line: line as u32,
                    column: Some(col as u32),
                },
            });
        }

        self.current_function = Some(funcname.to_string());
    }

    /// Apply a [`DebugAction`] received from the host.
    fn handle_action(&mut self, action: DebugAction) {
        // Replace breakpoints if the host sent any.
        if !action.breakpoints.is_empty() {
            self.breakpoints = action.breakpoints;
        }

        match action.action {
            DebugActionType::Continue => {
                self.mode = DebugMode::Running;
            }
            DebugActionType::StepInto => {
                self.mode = DebugMode::Step;
            }
            DebugActionType::StepOver => {
                self.mode = DebugMode::StepOver;
                self.step_depth = self.call_stack.len();
            }
            DebugActionType::StepOut => {
                self.mode = DebugMode::StepOut;
                self.step_depth = self.call_stack.len();
            }
            DebugActionType::Disconnect => {
                self.enabled = false;
                self.mode = DebugMode::Running;
            }
        }
    }
}
