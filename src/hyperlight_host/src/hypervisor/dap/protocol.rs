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

//! DAP wire protocol types.
//!
//! This module defines the JSON structures used by the Debug Adapter Protocol.
//! These types are serialized/deserialized for communication with DAP clients.
//!
//! Reference: https://microsoft.github.io/debug-adapter-protocol/specification

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Base protocol message format.
///
/// All DAP messages have a sequence number and type field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Sequence number of the message (unique within a session)
    pub seq: i64,
    /// Message type: "request", "response", or "event"
    #[serde(rename = "type")]
    pub message_type: String,
}

/// A client request message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Sequence number
    pub seq: i64,
    /// Always "request"
    #[serde(rename = "type")]
    pub message_type: String,
    /// The command to execute
    pub command: String,
    /// Command arguments (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
}

impl Request {
    /// Gets the arguments as a specific type.
    pub fn arguments_as<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        let args = self
            .arguments
            .clone()
            .unwrap_or(Value::Object(Default::default()));
        serde_json::from_value(args)
    }
}

/// A server response message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Sequence number
    pub seq: i64,
    /// Always "response"
    #[serde(rename = "type")]
    pub message_type: String,
    /// Sequence number of the request this is responding to
    pub request_seq: i64,
    /// Whether the request was successful
    pub success: bool,
    /// The command that was requested
    pub command: String,
    /// Error message if success is false
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Response body (command-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

impl Response {
    /// Creates a successful response.
    pub fn success(request_seq: i64, command: &str, body: Option<Value>) -> Self {
        Self {
            seq: 0, // Will be set by the server
            message_type: "response".to_string(),
            request_seq,
            success: true,
            command: command.to_string(),
            message: None,
            body,
        }
    }

    /// Creates an error response.
    pub fn error(request_seq: i64, command: &str, message: &str) -> Self {
        Self {
            seq: 0, // Will be set by the server
            message_type: "response".to_string(),
            request_seq,
            success: false,
            command: command.to_string(),
            message: Some(message.to_string()),
            body: None,
        }
    }
}

/// A server event message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Sequence number
    pub seq: i64,
    /// Always "event"
    #[serde(rename = "type")]
    pub message_type: String,
    /// Type of event
    pub event: String,
    /// Event-specific body
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

impl Event {
    /// Creates a new event.
    pub fn new(event: &str, body: Option<Value>) -> Self {
        Self {
            seq: 0, // Will be set by the server
            message_type: "event".to_string(),
            event: event.to_string(),
            body,
        }
    }
}

// ============================================================================
// Request argument types
// ============================================================================

/// Arguments for the 'initialize' request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct InitializeRequestArguments {
    /// The ID of the client (e.g., "vscode")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The human-readable name of the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// The ID of the debug adapter
    pub adapter_id: String,
    /// The locale of the client (e.g., "en-US")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Whether the client supports the 'runInTerminal' request
    #[serde(default)]
    pub supports_run_in_terminal_request: bool,
    /// Whether the client supports progress reporting
    #[serde(default)]
    pub supports_progress_reporting: bool,
    /// Whether the client supports variable type information
    #[serde(default)]
    pub supports_variable_type: bool,
}

/// Arguments for the 'launch' request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LaunchRequestArguments {
    /// Do not launch the debuggee, just connect to it
    #[serde(default)]
    pub no_debug: bool,
    /// Custom arguments (adapter-specific)
    #[serde(flatten)]
    pub additional: Value,
}

/// Arguments for the 'attach' request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AttachRequestArguments {
    /// Custom arguments (adapter-specific)
    #[serde(flatten)]
    pub additional: Value,
}

/// Arguments for the 'setBreakpoints' request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetBreakpointsArguments {
    /// The source location of the breakpoints
    pub source: Source,
    /// The breakpoints to set
    #[serde(default)]
    pub breakpoints: Vec<SourceBreakpoint>,
    /// Deprecated: line numbers for breakpoints
    #[serde(default)]
    pub lines: Vec<i64>,
    /// Source modified flag
    #[serde(default)]
    pub source_modified: bool,
}

/// A source file reference.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    /// Name of the source (short name displayed in UI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Path to the source file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Source reference (for sources without a file path)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_reference: Option<i64>,
}

/// A breakpoint in source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceBreakpoint {
    /// Line number (1-based)
    pub line: i64,
    /// Column (optional, 1-based)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<i64>,
    /// Condition expression
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Hit count condition
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_condition: Option<String>,
    /// Log message (for logpoints)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_message: Option<String>,
}

/// Arguments for 'setFunctionBreakpoints' request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetFunctionBreakpointsArguments {
    /// The function breakpoints to set
    pub breakpoints: Vec<FunctionBreakpoint>,
}

/// A function breakpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionBreakpoint {
    /// Name of the function
    pub name: String,
    /// Condition expression
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Hit count condition
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_condition: Option<String>,
}

/// Arguments for 'stackTrace' request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StackTraceArguments {
    /// Thread ID
    pub thread_id: i64,
    /// Index of first frame to retrieve
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_frame: Option<i64>,
    /// Maximum number of frames to retrieve
    #[serde(skip_serializing_if = "Option::is_none")]
    pub levels: Option<i64>,
}

/// Arguments for 'scopes' request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopesArguments {
    /// Frame ID to get scopes for
    pub frame_id: i64,
}

/// Arguments for 'variables' request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VariablesArguments {
    /// Reference of the container to get variables from
    pub variables_reference: i64,
    /// Filter for type of variables to include
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    /// Start index of variables to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<i64>,
    /// Number of variables to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
}

/// Arguments for 'evaluate' request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluateArguments {
    /// Expression to evaluate
    pub expression: String,
    /// Frame ID for context (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_id: Option<i64>,
    /// Context of evaluation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// Arguments for 'continue' request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ContinueArguments {
    /// Thread to continue (usually the only thread)
    pub thread_id: i64,
    /// Continue only the specified thread
    #[serde(default)]
    pub single_thread: bool,
}

/// Arguments for 'disconnect' request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DisconnectArguments {
    /// Whether to restart after disconnect
    #[serde(default)]
    pub restart: bool,
    /// Whether to terminate the debuggee
    #[serde(default)]
    pub terminate_debuggee: bool,
    /// Whether to suspend the debuggee
    #[serde(default)]
    pub suspend_debuggee: bool,
}

// ============================================================================
// Response body types
// ============================================================================

/// Capabilities returned from 'initialize' request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// Whether the debug adapter supports the configurationDone request
    #[serde(default)]
    pub supports_configuration_done_request: bool,
    /// Whether the debug adapter supports function breakpoints
    #[serde(default)]
    pub supports_function_breakpoints: bool,
    /// Whether the debug adapter supports conditional breakpoints
    #[serde(default)]
    pub supports_conditional_breakpoints: bool,
    /// Whether the debug adapter supports hit count breakpoints
    #[serde(default)]
    pub supports_hit_conditional_breakpoints: bool,
    /// Whether the debug adapter supports evaluate in hover
    #[serde(default)]
    pub supports_evaluate_for_hovers: bool,
    /// Whether the debug adapter supports stepping back
    #[serde(default)]
    pub supports_step_back: bool,
    /// Whether the debug adapter supports setting variable values
    #[serde(default)]
    pub supports_set_variable: bool,
    /// Whether the debug adapter supports restarting frames
    #[serde(default)]
    pub supports_restart_frame: bool,
    /// Whether the debug adapter supports goto targets
    #[serde(default)]
    pub supports_goto_targets_request: bool,
    /// Whether the debug adapter supports step in targets
    #[serde(default)]
    pub supports_step_in_targets_request: bool,
    /// Whether the debug adapter supports completions
    #[serde(default)]
    pub supports_completions_request: bool,
    /// Whether the debug adapter supports modules
    #[serde(default)]
    pub supports_modules_request: bool,
    /// Whether the debug adapter supports terminate request
    #[serde(default)]
    pub supports_terminate_request: bool,
    /// Whether the debug adapter supports exception options
    #[serde(default)]
    pub supports_exception_options: bool,
    /// Whether the debug adapter supports value formatting
    #[serde(default)]
    pub supports_value_formatting_options: bool,
    /// Whether the debug adapter supports exception info
    #[serde(default)]
    pub supports_exception_info_request: bool,
    /// Whether the debug adapter supports terminate debuggee
    #[serde(default)]
    pub support_terminate_debuggee: bool,
    /// Whether the debug adapter supports delayed stack trace loading
    #[serde(default)]
    pub supports_delayed_stack_trace_loading: bool,
    /// Whether the debug adapter supports loaded sources
    #[serde(default)]
    pub supports_loaded_sources_request: bool,
    /// Whether the debug adapter supports log points
    #[serde(default)]
    pub supports_log_points: bool,
    /// Whether the debug adapter supports terminate threads
    #[serde(default)]
    pub supports_terminate_threads_request: bool,
    /// Whether the debug adapter supports set expression
    #[serde(default)]
    pub supports_set_expression: bool,
    /// Whether the debug adapter supports single thread execution
    #[serde(default)]
    pub supports_single_thread_execution_requests: bool,
}

/// Body of 'setBreakpoints' response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetBreakpointsResponseBody {
    /// Breakpoints that were set
    pub breakpoints: Vec<BreakpointInfo>,
}

/// Information about a breakpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BreakpointInfo {
    /// Unique ID of the breakpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// Whether the breakpoint was successfully set
    pub verified: bool,
    /// Error message if not verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Actual source where breakpoint was set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// Actual line where breakpoint was set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<i64>,
    /// Actual column where breakpoint was set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<i64>,
}

/// Body of 'stackTrace' response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackTraceResponseBody {
    /// Stack frames
    pub stack_frames: Vec<StackFrameInfo>,
    /// Total number of frames
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_frames: Option<i64>,
}

/// Information about a stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackFrameInfo {
    /// Unique ID
    pub id: i64,
    /// Name (function name)
    pub name: String,
    /// Source location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// Line number
    pub line: i64,
    /// Column number
    pub column: i64,
}

/// Body of 'scopes' response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopesResponseBody {
    /// Scopes for the frame
    pub scopes: Vec<ScopeInfo>,
}

/// Information about a scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeInfo {
    /// Name of the scope
    pub name: String,
    /// Reference for retrieving variables
    pub variables_reference: i64,
    /// Whether this scope is expensive to retrieve
    #[serde(default)]
    pub expensive: bool,
}

/// Body of 'variables' response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VariablesResponseBody {
    /// Variables in the scope
    pub variables: Vec<VariableInfo>,
}

/// Information about a variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VariableInfo {
    /// Name of the variable
    pub name: String,
    /// Value as string
    pub value: String,
    /// Type of the variable
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub type_name: Option<String>,
    /// Reference for child variables
    pub variables_reference: i64,
}

/// Body of 'evaluate' response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluateResponseBody {
    /// Result value
    pub result: String,
    /// Type of the result
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub type_name: Option<String>,
    /// Reference for child variables
    pub variables_reference: i64,
}

/// Body of 'continue' response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ContinueResponseBody {
    /// Whether all threads continued
    #[serde(default = "default_true")]
    pub all_threads_continued: bool,
}

fn default_true() -> bool {
    true
}

// ============================================================================
// Event body types
// ============================================================================

/// Body of 'stopped' event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoppedEventBody {
    /// Reason for stopping
    pub reason: String,
    /// Additional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Thread that stopped
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<i64>,
    /// Whether all threads stopped
    #[serde(default)]
    pub all_threads_stopped: bool,
    /// IDs of breakpoints that were hit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_breakpoint_ids: Option<Vec<i64>>,
    /// Exception text
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Body of 'continued' event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuedEventBody {
    /// Thread that continued
    pub thread_id: i64,
    /// Whether all threads continued
    #[serde(default)]
    pub all_threads_continued: bool,
}

/// Body of 'output' event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputEventBody {
    /// Output category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Output text
    pub output: String,
    /// Source location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// Line number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<i64>,
    /// Column number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<i64>,
}

/// Body of 'terminated' event.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TerminatedEventBody {
    /// Whether to restart
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart: Option<Value>,
}

/// Body of 'exited' event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitedEventBody {
    /// Exit code
    pub exit_code: i64,
}

/// Body of 'thread' event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadEventBody {
    /// Reason for the event
    pub reason: String,
    /// Thread ID
    pub thread_id: i64,
}

/// Body of 'breakpoint' event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BreakpointEventBody {
    /// Reason for the event
    pub reason: String,
    /// Updated breakpoint info
    pub breakpoint: BreakpointInfo,
}
