//! Shared DAP types for Hyperlight host ↔ guest communication.
//!
//! These types are the canonical definitions used on both sides.
//! The WIT file in `schema/dap.wit` is the specification; these manual
//! definitions add serde support that the WIT macro cannot yet provide.

use alloc::string::String;
use alloc::vec::Vec;

/// Name of the host function used for debug break communication.
pub const DEBUG_BREAK_FUNC_NAME: &str = "hl_dap_debug_break";

// ---------------------------------------------------------------------------
// Guest → Host
// ---------------------------------------------------------------------------

/// Reason why the guest stopped execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DebugBreakReason {
    /// Program entry point.
    Entry,
    /// Hit a breakpoint.
    Breakpoint,
    /// Completed a step operation.
    Step,
    /// Paused by request.
    Pause,
    /// Exception occurred.
    Exception,
}

/// Source location information from the guest.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DebugLocation {
    /// Source file path or name.
    pub filename: String,
    /// Function name (if available).
    #[cfg_attr(feature = "serde", serde(default))]
    pub function_name: Option<String>,
    /// Line number (1-based).
    pub line: u32,
    /// Column number (1-based, if available).
    #[cfg_attr(feature = "serde", serde(default))]
    pub column: Option<u32>,
}

/// A variable captured from a guest stack frame.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DebugVariable {
    /// Variable name.
    pub name: String,
    /// Value as a display string.
    pub value: String,
    /// Type name (e.g. `"number"`, `"string"`, `"object"`).
    #[cfg_attr(feature = "serde", serde(default))]
    pub type_name: Option<String>,
}

/// Stack frame information from the guest.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DebugStackFrame {
    /// Frame ID (assigned by guest).
    pub id: u32,
    /// Function name.
    pub name: String,
    /// Source location of this frame.
    pub location: DebugLocation,
    /// Local variables captured at this frame (eagerly collected).
    #[cfg_attr(feature = "serde", serde(default))]
    pub variables: Vec<DebugVariable>,
}

/// Debug event sent from guest to host.
///
/// The guest serializes this to JSON and passes it to the
/// `hl_dap_debug_break` host function.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DebugBreakEvent {
    /// Reason for the debug break.
    pub reason: DebugBreakReason,
    /// Current source location.
    pub location: DebugLocation,
    /// Current call stack (if available).
    #[cfg_attr(feature = "serde", serde(default))]
    pub stack_frames: Vec<DebugStackFrame>,
    /// Optional exception message (if reason is `Exception`).
    #[cfg_attr(feature = "serde", serde(default))]
    pub exception_message: Option<String>,
}

// ---------------------------------------------------------------------------
// Host → Guest
// ---------------------------------------------------------------------------

/// Type of debug action for the guest to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DebugActionType {
    /// Continue execution normally.
    Continue,
    /// Step to next statement (step over).
    StepOver,
    /// Step into function calls.
    StepInto,
    /// Step out of current function.
    StepOut,
    /// Disconnect debugger (continue without debugging).
    Disconnect,
}

/// Breakpoint information sent from host to guest.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DebugBreakpoint {
    /// Unique breakpoint ID.
    pub id: u32,
    /// Source file.
    pub filename: String,
    /// Line number.
    pub line: u32,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
}

/// Action returned from the host debugger to the guest.
///
/// The host serializes this to JSON and returns it from the
/// `hl_dap_debug_break` host function.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DebugAction {
    /// The action the guest should take.
    pub action: DebugActionType,
    /// Updated breakpoints (if any).
    #[cfg_attr(feature = "serde", serde(default))]
    pub breakpoints: Vec<DebugBreakpoint>,
}
