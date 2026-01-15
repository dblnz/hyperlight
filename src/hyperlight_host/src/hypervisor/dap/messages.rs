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

//! Internal message types for DAP communication between the DAP server thread
//! and the Hyperlight VM.

/// Source location information reported by the guest runtime.
///
/// This represents a position in source code, typically sent from a JavaScript
/// runtime or other interpreted language running in the guest.
#[derive(Debug, Clone, Default)]
pub struct SourceLocation {
    /// The source file path or name
    pub filename: String,
    /// The function name at this location (if available)
    pub function_name: Option<String>,
    /// Line number (1-based)
    pub line: u32,
    /// Column number (1-based, if available)
    pub column: Option<u32>,
}

impl SourceLocation {
    /// Creates a new source location with the given filename and line.
    pub fn new(filename: impl Into<String>, line: u32) -> Self {
        Self {
            filename: filename.into(),
            function_name: None,
            line,
            column: None,
        }
    }

    /// Sets the function name for this location.
    pub fn with_function(mut self, function_name: impl Into<String>) -> Self {
        self.function_name = Some(function_name.into());
        self
    }

    /// Sets the column number for this location.
    pub fn with_column(mut self, column: u32) -> Self {
        self.column = Some(column);
        self
    }
}

/// Represents a stack frame in the call stack.
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Unique identifier for this frame
    pub id: u32,
    /// Name of the frame (typically the function name)
    pub name: String,
    /// Source location of this frame
    pub location: SourceLocation,
}

/// Represents a breakpoint that has been set.
#[derive(Debug, Clone)]
pub struct Breakpoint {
    /// Unique identifier for this breakpoint
    pub id: u32,
    /// Whether the breakpoint was successfully set
    pub verified: bool,
    /// The actual line where the breakpoint was set (may differ from requested)
    pub line: u32,
    /// Optional message (e.g., reason why breakpoint couldn't be verified)
    pub message: Option<String>,
}

/// Represents a scope (e.g., local variables, global variables).
#[derive(Debug, Clone)]
pub struct Scope {
    /// Display name of the scope
    pub name: String,
    /// Reference ID for fetching variables in this scope
    pub variables_reference: u32,
    /// Whether this scope's contents are expensive to retrieve
    pub expensive: bool,
}

/// Represents a variable or property.
#[derive(Debug, Clone)]
pub struct Variable {
    /// Display name of the variable
    pub name: String,
    /// Value as a string representation
    pub value: String,
    /// Type of the variable (if known)
    pub type_name: Option<String>,
    /// Reference ID if this variable has children (0 if no children)
    pub variables_reference: u32,
}

/// Reason why execution stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Stopped at entry point
    Entry,
    /// Hit a breakpoint
    Breakpoint,
    /// Completed a step operation
    Step,
    /// Paused by user request
    Pause,
    /// Exception or error occurred
    Exception,
    /// Data breakpoint hit
    DataBreakpoint,
    /// Function breakpoint hit
    FunctionBreakpoint,
}

impl StopReason {
    /// Returns the DAP protocol string for this stop reason.
    pub fn as_str(&self) -> &'static str {
        match self {
            StopReason::Entry => "entry",
            StopReason::Breakpoint => "breakpoint",
            StopReason::Step => "step",
            StopReason::Pause => "pause",
            StopReason::Exception => "exception",
            StopReason::DataBreakpoint => "data breakpoint",
            StopReason::FunctionBreakpoint => "function breakpoint",
        }
    }
}

/// Requests sent from the DAP server to the Hyperlight VM.
///
/// These represent debugging operations that need to be performed on the guest.
#[derive(Debug)]
pub enum DapRequest {
    /// Initialize the debug session
    Initialize,

    /// Configure the debug session (called after initialize)
    ConfigurationDone,

    /// Set breakpoints in a source file
    SetBreakpoints {
        /// Path to the source file
        source_path: String,
        /// Line numbers where breakpoints should be set
        lines: Vec<u32>,
    },

    /// Set function breakpoints
    SetFunctionBreakpoints {
        /// Function names to break on
        names: Vec<String>,
    },

    /// Continue execution
    Continue,

    /// Step to next line (step over)
    Next,

    /// Step into function call
    StepIn,

    /// Step out of current function
    StepOut,

    /// Pause execution
    Pause,

    /// Get the current call stack
    StackTrace {
        /// Optional: starting frame
        start_frame: Option<u32>,
        /// Optional: maximum number of frames to return
        levels: Option<u32>,
    },

    /// Get scopes for a stack frame
    Scopes {
        /// Frame ID to get scopes for
        frame_id: u32,
    },

    /// Get variables in a scope or container
    Variables {
        /// Reference ID of the scope or container
        variables_reference: u32,
    },

    /// Evaluate an expression
    Evaluate {
        /// Expression to evaluate
        expression: String,
        /// Optional frame context for evaluation
        frame_id: Option<u32>,
        /// Context of evaluation (watch, repl, hover)
        context: Option<String>,
    },

    /// Disconnect the debugger
    Disconnect {
        /// Whether to terminate the debuggee
        terminate: bool,
    },
}

/// Responses sent from the Hyperlight VM to the DAP server.
///
/// These represent the results of debugging operations or events that occurred
/// in the guest.
#[derive(Debug)]
pub enum DapResponse {
    /// Debug session initialized successfully
    Initialized {
        /// Whether the runtime supports configuration done request
        supports_configuration_done: bool,
    },

    /// Configuration completed
    ConfigurationDone,

    /// Breakpoints were set (or attempted to be set)
    BreakpointsSet {
        /// Results for each requested breakpoint
        breakpoints: Vec<Breakpoint>,
    },

    /// Function breakpoints were set
    FunctionBreakpointsSet {
        /// Results for each requested function breakpoint
        breakpoints: Vec<Breakpoint>,
    },

    /// Execution has stopped
    Stopped {
        /// Reason for stopping
        reason: StopReason,
        /// Current source location
        location: SourceLocation,
        /// Optional: ID of the breakpoint that was hit
        hit_breakpoint_ids: Option<Vec<u32>>,
        /// Optional: exception text if stopped due to exception
        exception_text: Option<String>,
    },

    /// Execution has continued
    Continued,

    /// Execution has been paused
    Paused,

    /// Stack trace response
    StackTrace {
        /// Stack frames (most recent first)
        frames: Vec<StackFrame>,
        /// Total number of frames available
        total_frames: u32,
    },

    /// Scopes for a stack frame
    Scopes {
        /// Available scopes
        scopes: Vec<Scope>,
    },

    /// Variables in a scope
    Variables {
        /// Variables in the requested scope
        variables: Vec<Variable>,
    },

    /// Result of expression evaluation
    Evaluate {
        /// Result value as string
        result: String,
        /// Type of the result
        type_name: Option<String>,
        /// Reference if result has children
        variables_reference: u32,
    },

    /// Disconnected from debug session
    Disconnected,

    /// An error occurred
    Error {
        /// Error message
        message: String,
    },

    /// Output from the guest (for console/stdout)
    Output {
        /// Output category (console, stdout, stderr)
        category: String,
        /// Output text
        output: String,
        /// Optional source location
        location: Option<SourceLocation>,
    },

    /// The debuggee has terminated
    Terminated,

    /// The debuggee has exited
    Exited {
        /// Exit code
        exit_code: i32,
    },
}
