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

//! DAP server implementation.
//!
//! This module provides the TCP server that handles Debug Adapter Protocol
//! communication with debugger clients like VS Code.

use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::thread;
use std::time::Duration;

use super::comm::DapCommChannel;
use super::errors::DapError;
use super::messages::{DapRequest, DapResponse};
use super::protocol::*;

/// The main thread ID used by the DAP server.
/// Since Hyperlight guests are single-threaded, we use a constant thread ID.
const MAIN_THREAD_ID: i64 = 1;

/// Creates and starts a DAP server thread.
///
/// This function binds to the specified port and spawns a thread that handles
/// DAP protocol messages. It returns a communication channel that can be used
/// to send requests to the VM and receive responses/events.
///
/// # Arguments
///
/// * `port` - The TCP port to listen on
///
/// # Returns
///
/// A `DapCommChannel` for communication between the DAP server and the VM.
///
/// # Example
///
/// ```ignore
/// let dap_channel = create_dap_thread(4711)?;
///
/// // Wait for a stopped event from the VM
/// let response = dap_channel.recv()?;
/// match response {
///     DapResponse::Stopped { reason, location, .. } => {
///         println!("Stopped at {}:{}", location.filename, location.line);
///     }
///     _ => {}
/// }
/// ```
pub fn create_dap_thread(port: u16) -> Result<DapCommChannel<DapResponse, DapRequest>, DapError> {
    let (dap_conn, vm_conn) = DapCommChannel::unbounded();
    let socket_addr = format!("127.0.0.1:{}", port);

    log::info!("DAP server: binding to {}", socket_addr);
    let listener =
        TcpListener::bind(&socket_addr).map_err(|e| DapError::BindError(e.to_string()))?;

    log::info!("DAP server: starting handler thread");
    let _handle = thread::Builder::new()
        .name("DAP handler".to_string())
        .spawn(move || -> Result<(), DapError> {
            log::info!("DAP server: waiting for connection...");
            let (stream, addr) = listener.accept()?;
            log::info!("DAP server: connected from {}", addr);

            let mut server = DapServer::new(stream, vm_conn)?;
            server.run()
        });

    Ok(dap_conn)
}

/// The DAP server state machine.
struct DapServer {
    /// Reader for incoming messages
    reader: BufReader<TcpStream>,
    /// Writer for outgoing messages
    writer: BufWriter<TcpStream>,
    /// Communication channel to the VM
    vm_channel: DapCommChannel<DapRequest, DapResponse>,
    /// Sequence number for outgoing messages
    seq: AtomicI64,
    /// Whether the session has been initialized
    initialized: AtomicBool,
    /// Whether the session is running (not stopped)
    running: AtomicBool,
    /// Shutdown flag
    shutdown: AtomicBool,
}

impl DapServer {
    /// Creates a new DAP server instance.
    fn new(
        stream: TcpStream,
        vm_channel: DapCommChannel<DapRequest, DapResponse>,
    ) -> Result<Self, DapError> {
        // Set read timeout so we can poll for VM events
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;

        let reader = BufReader::new(stream.try_clone()?);
        let writer = BufWriter::new(stream);

        Ok(Self {
            reader,
            writer,
            vm_channel,
            seq: AtomicI64::new(1),
            initialized: AtomicBool::new(false),
            running: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
        })
    }

    /// Main event loop.
    fn run(&mut self) -> Result<(), DapError> {
        log::info!("DAP server: entering main loop");

        while !self.shutdown.load(Ordering::Relaxed) {
            // Try to read a request from the client
            match self.try_read_request() {
                Ok(Some(request)) => {
                    self.handle_request(request)?;
                }
                Ok(None) => {
                    // No request available, check for VM events
                }
                Err(DapError::ConnectionClosed) => {
                    log::info!("DAP server: connection closed");
                    break;
                }
                Err(e) => {
                    log::error!("DAP server: error reading request: {}", e);
                    break;
                }
            }

            // Check for events from the VM
            self.poll_vm_events()?;
        }

        log::info!("DAP server: exiting main loop");
        Ok(())
    }

    /// Tries to read a request from the client (non-blocking).
    fn try_read_request(&mut self) -> Result<Option<Request>, DapError> {
        // DAP uses a simple framing protocol:
        // Content-Length: <length>\r\n
        // \r\n
        // <JSON payload>

        let mut header_line = String::new();
        match self.reader.read_line(&mut header_line) {
            Ok(0) => return Err(DapError::ConnectionClosed),
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => return Ok(None),
            Err(e) => return Err(DapError::AcceptError(e)),
        }

        // Parse Content-Length header
        let content_length = Self::parse_content_length(&header_line)?;

        // Read the blank line separator
        let mut blank = String::new();
        self.reader.read_line(&mut blank)?;

        // Read the JSON payload
        let mut payload = vec![0u8; content_length];
        self.reader.read_exact(&mut payload)?;

        let payload_str = String::from_utf8_lossy(&payload);
        log::debug!("DAP server: received: {}", payload_str);

        let request: Request = serde_json::from_slice(&payload)?;
        Ok(Some(request))
    }

    /// Parses the Content-Length header value.
    fn parse_content_length(header: &str) -> Result<usize, DapError> {
        let header = header.trim();
        if header.is_empty() {
            return Err(DapError::parse("Empty header"));
        }

        let parts: Vec<&str> = header.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(DapError::parse(format!(
                "Invalid header format: {}",
                header
            )));
        }

        if parts[0].trim().to_lowercase() != "content-length" {
            return Err(DapError::parse(format!(
                "Expected Content-Length header, got: {}",
                parts[0]
            )));
        }

        parts[1]
            .trim()
            .parse()
            .map_err(|_| DapError::parse(format!("Invalid Content-Length value: {}", parts[1])))
    }

    /// Handles a request from the client.
    fn handle_request(&mut self, request: Request) -> Result<(), DapError> {
        log::debug!("DAP server: handling command: {}", request.command);

        let response = match request.command.as_str() {
            "initialize" => self.handle_initialize(&request),
            "launch" => self.handle_launch(&request),
            "attach" => self.handle_attach(&request),
            "configurationDone" => self.handle_configuration_done(&request),
            "setBreakpoints" => self.handle_set_breakpoints(&request),
            "setFunctionBreakpoints" => self.handle_set_function_breakpoints(&request),
            "threads" => self.handle_threads(&request),
            "stackTrace" => self.handle_stack_trace(&request),
            "scopes" => self.handle_scopes(&request),
            "variables" => self.handle_variables(&request),
            "continue" => self.handle_continue(&request),
            "next" => self.handle_next(&request),
            "stepIn" => self.handle_step_in(&request),
            "stepOut" => self.handle_step_out(&request),
            "pause" => self.handle_pause(&request),
            "evaluate" => self.handle_evaluate(&request),
            "disconnect" => self.handle_disconnect(&request),
            _ => {
                log::warn!("DAP server: unknown command: {}", request.command);
                Response::error(request.seq, &request.command, "Unknown command")
            }
        };

        self.send_response(response)
    }

    /// Handles the 'initialize' request.
    fn handle_initialize(&mut self, request: &Request) -> Response {
        if self.initialized.load(Ordering::Relaxed) {
            return Response::error(request.seq, "initialize", "Already initialized");
        }

        // Parse arguments (optional)
        let _args: InitializeRequestArguments = request.arguments_as().unwrap_or_default();

        // Send initialize request to VM
        if let Err(e) = self.vm_channel.send(DapRequest::Initialize) {
            return Response::error(request.seq, "initialize", &e.to_string());
        }

        // Build capabilities response
        let capabilities = Capabilities {
            supports_configuration_done_request: true,
            supports_function_breakpoints: true,
            supports_conditional_breakpoints: false,
            supports_evaluate_for_hovers: true,
            supports_set_variable: false,
            supports_step_back: false,
            support_terminate_debuggee: true,
            supports_delayed_stack_trace_loading: false,
            supports_log_points: false,
            ..Default::default()
        };

        self.initialized.store(true, Ordering::Relaxed);

        let body = serde_json::to_value(capabilities).unwrap();
        Response::success(request.seq, "initialize", Some(body))
    }

    /// Handles the 'launch' request.
    fn handle_launch(&mut self, request: &Request) -> Response {
        // For Hyperlight, launch is essentially a no-op since the guest
        // is already loaded. We just acknowledge and send initialized event.

        // Send 'initialized' event to client
        if let Err(e) = self.send_event(Event::new("initialized", None)) {
            log::error!("Failed to send initialized event: {}", e);
        }

        Response::success(request.seq, "launch", None)
    }

    /// Handles the 'attach' request.
    fn handle_attach(&mut self, request: &Request) -> Response {
        // Similar to launch for Hyperlight
        if let Err(e) = self.send_event(Event::new("initialized", None)) {
            log::error!("Failed to send initialized event: {}", e);
        }

        Response::success(request.seq, "attach", None)
    }

    /// Handles the 'configurationDone' request.
    fn handle_configuration_done(&mut self, request: &Request) -> Response {
        // Notify VM that configuration is complete
        if let Err(e) = self.vm_channel.send(DapRequest::ConfigurationDone) {
            return Response::error(request.seq, "configurationDone", &e.to_string());
        }

        self.running.store(true, Ordering::Relaxed);
        Response::success(request.seq, "configurationDone", None)
    }

    /// Handles the 'setBreakpoints' request.
    fn handle_set_breakpoints(&mut self, request: &Request) -> Response {
        let args: SetBreakpointsArguments = match request.arguments_as() {
            Ok(args) => args,
            Err(e) => {
                return Response::error(request.seq, "setBreakpoints", &e.to_string());
            }
        };

        let source_path = args
            .source
            .path
            .clone()
            .unwrap_or_else(|| args.source.name.clone().unwrap_or_default());

        let lines: Vec<u32> = args.breakpoints.iter().map(|bp| bp.line as u32).collect();

        // Send to VM
        if let Err(e) = self.vm_channel.send(DapRequest::SetBreakpoints {
            source_path: source_path.clone(),
            lines: lines.clone(),
        }) {
            return Response::error(request.seq, "setBreakpoints", &e.to_string());
        }

        // For now, assume all breakpoints are verified
        // In a real implementation, we'd wait for the VM response
        let breakpoints: Vec<BreakpointInfo> = lines
            .iter()
            .enumerate()
            .map(|(i, &line)| BreakpointInfo {
                id: Some(i as i64 + 1),
                verified: true,
                message: None,
                source: Some(Source {
                    path: Some(source_path.clone()),
                    ..Default::default()
                }),
                line: Some(line as i64),
                column: None,
            })
            .collect();

        let body = SetBreakpointsResponseBody { breakpoints };
        Response::success(
            request.seq,
            "setBreakpoints",
            Some(serde_json::to_value(body).unwrap()),
        )
    }

    /// Handles the 'setFunctionBreakpoints' request.
    fn handle_set_function_breakpoints(&mut self, request: &Request) -> Response {
        let args: SetFunctionBreakpointsArguments = match request.arguments_as() {
            Ok(args) => args,
            Err(e) => {
                return Response::error(request.seq, "setFunctionBreakpoints", &e.to_string());
            }
        };

        let names: Vec<String> = args.breakpoints.iter().map(|bp| bp.name.clone()).collect();

        // Send to VM
        if let Err(e) = self.vm_channel.send(DapRequest::SetFunctionBreakpoints {
            names: names.clone(),
        }) {
            return Response::error(request.seq, "setFunctionBreakpoints", &e.to_string());
        }

        // Assume all are verified
        let breakpoints: Vec<BreakpointInfo> = names
            .iter()
            .enumerate()
            .map(|(i, _)| BreakpointInfo {
                id: Some(i as i64 + 1000),
                verified: true,
                message: None,
                source: None,
                line: None,
                column: None,
            })
            .collect();

        let body = SetBreakpointsResponseBody { breakpoints };
        Response::success(
            request.seq,
            "setFunctionBreakpoints",
            Some(serde_json::to_value(body).unwrap()),
        )
    }

    /// Handles the 'threads' request.
    fn handle_threads(&mut self, request: &Request) -> Response {
        // Hyperlight guests are single-threaded
        let body = serde_json::json!({
            "threads": [
                {
                    "id": MAIN_THREAD_ID,
                    "name": "main"
                }
            ]
        });

        Response::success(request.seq, "threads", Some(body))
    }

    /// Handles the 'stackTrace' request.
    fn handle_stack_trace(&mut self, request: &Request) -> Response {
        let args: StackTraceArguments = request.arguments_as().unwrap_or_default();

        // Send to VM
        if let Err(e) = self.vm_channel.send(DapRequest::StackTrace {
            start_frame: args.start_frame.map(|f| f as u32),
            levels: args.levels.map(|l| l as u32),
        }) {
            return Response::error(request.seq, "stackTrace", &e.to_string());
        }

        // Wait for response from VM
        match self.vm_channel.recv() {
            Ok(DapResponse::StackTrace {
                frames,
                total_frames,
            }) => {
                let stack_frames: Vec<StackFrameInfo> = frames
                    .into_iter()
                    .map(|f| StackFrameInfo {
                        id: f.id as i64,
                        name: f.name,
                        source: Some(Source {
                            path: Some(f.location.filename),
                            ..Default::default()
                        }),
                        line: f.location.line as i64,
                        column: f.location.column.unwrap_or(1) as i64,
                    })
                    .collect();

                let body = StackTraceResponseBody {
                    stack_frames,
                    total_frames: Some(total_frames as i64),
                };

                Response::success(
                    request.seq,
                    "stackTrace",
                    Some(serde_json::to_value(body).unwrap()),
                )
            }
            Ok(DapResponse::Error { message }) => {
                Response::error(request.seq, "stackTrace", &message)
            }
            _ => Response::error(request.seq, "stackTrace", "Unexpected response from VM"),
        }
    }

    /// Handles the 'scopes' request.
    fn handle_scopes(&mut self, request: &Request) -> Response {
        let args: ScopesArguments = match request.arguments_as() {
            Ok(args) => args,
            Err(e) => {
                return Response::error(request.seq, "scopes", &e.to_string());
            }
        };

        // Send to VM
        if let Err(e) = self.vm_channel.send(DapRequest::Scopes {
            frame_id: args.frame_id as u32,
        }) {
            return Response::error(request.seq, "scopes", &e.to_string());
        }

        // Wait for response
        match self.vm_channel.recv() {
            Ok(DapResponse::Scopes { scopes }) => {
                let scope_infos: Vec<ScopeInfo> = scopes
                    .into_iter()
                    .map(|s| ScopeInfo {
                        name: s.name,
                        variables_reference: s.variables_reference as i64,
                        expensive: s.expensive,
                    })
                    .collect();

                let body = ScopesResponseBody {
                    scopes: scope_infos,
                };
                Response::success(
                    request.seq,
                    "scopes",
                    Some(serde_json::to_value(body).unwrap()),
                )
            }
            Ok(DapResponse::Error { message }) => Response::error(request.seq, "scopes", &message),
            _ => Response::error(request.seq, "scopes", "Unexpected response from VM"),
        }
    }

    /// Handles the 'variables' request.
    fn handle_variables(&mut self, request: &Request) -> Response {
        let args: VariablesArguments = match request.arguments_as() {
            Ok(args) => args,
            Err(e) => {
                return Response::error(request.seq, "variables", &e.to_string());
            }
        };

        // Send to VM
        if let Err(e) = self.vm_channel.send(DapRequest::Variables {
            variables_reference: args.variables_reference as u32,
        }) {
            return Response::error(request.seq, "variables", &e.to_string());
        }

        // Wait for response
        match self.vm_channel.recv() {
            Ok(DapResponse::Variables { variables }) => {
                let var_infos: Vec<VariableInfo> = variables
                    .into_iter()
                    .map(|v| VariableInfo {
                        name: v.name,
                        value: v.value,
                        type_name: v.type_name,
                        variables_reference: v.variables_reference as i64,
                    })
                    .collect();

                let body = VariablesResponseBody {
                    variables: var_infos,
                };
                Response::success(
                    request.seq,
                    "variables",
                    Some(serde_json::to_value(body).unwrap()),
                )
            }
            Ok(DapResponse::Error { message }) => {
                Response::error(request.seq, "variables", &message)
            }
            _ => Response::error(request.seq, "variables", "Unexpected response from VM"),
        }
    }

    /// Handles the 'continue' request.
    fn handle_continue(&mut self, request: &Request) -> Response {
        if let Err(e) = self.vm_channel.send(DapRequest::Continue) {
            return Response::error(request.seq, "continue", &e.to_string());
        }

        self.running.store(true, Ordering::Relaxed);

        let body = ContinueResponseBody {
            all_threads_continued: true,
        };
        Response::success(
            request.seq,
            "continue",
            Some(serde_json::to_value(body).unwrap()),
        )
    }

    /// Handles the 'next' (step over) request.
    fn handle_next(&mut self, request: &Request) -> Response {
        if let Err(e) = self.vm_channel.send(DapRequest::Next) {
            return Response::error(request.seq, "next", &e.to_string());
        }

        self.running.store(true, Ordering::Relaxed);
        Response::success(request.seq, "next", None)
    }

    /// Handles the 'stepIn' request.
    fn handle_step_in(&mut self, request: &Request) -> Response {
        if let Err(e) = self.vm_channel.send(DapRequest::StepIn) {
            return Response::error(request.seq, "stepIn", &e.to_string());
        }

        self.running.store(true, Ordering::Relaxed);
        Response::success(request.seq, "stepIn", None)
    }

    /// Handles the 'stepOut' request.
    fn handle_step_out(&mut self, request: &Request) -> Response {
        if let Err(e) = self.vm_channel.send(DapRequest::StepOut) {
            return Response::error(request.seq, "stepOut", &e.to_string());
        }

        self.running.store(true, Ordering::Relaxed);
        Response::success(request.seq, "stepOut", None)
    }

    /// Handles the 'pause' request.
    fn handle_pause(&mut self, request: &Request) -> Response {
        if let Err(e) = self.vm_channel.send(DapRequest::Pause) {
            return Response::error(request.seq, "pause", &e.to_string());
        }

        Response::success(request.seq, "pause", None)
    }

    /// Handles the 'evaluate' request.
    fn handle_evaluate(&mut self, request: &Request) -> Response {
        let args: EvaluateArguments = match request.arguments_as() {
            Ok(args) => args,
            Err(e) => {
                return Response::error(request.seq, "evaluate", &e.to_string());
            }
        };

        // Send to VM
        if let Err(e) = self.vm_channel.send(DapRequest::Evaluate {
            expression: args.expression,
            frame_id: args.frame_id.map(|f| f as u32),
            context: args.context,
        }) {
            return Response::error(request.seq, "evaluate", &e.to_string());
        }

        // Wait for response
        match self.vm_channel.recv() {
            Ok(DapResponse::Evaluate {
                result,
                type_name,
                variables_reference,
            }) => {
                let body = EvaluateResponseBody {
                    result,
                    type_name,
                    variables_reference: variables_reference as i64,
                };
                Response::success(
                    request.seq,
                    "evaluate",
                    Some(serde_json::to_value(body).unwrap()),
                )
            }
            Ok(DapResponse::Error { message }) => {
                Response::error(request.seq, "evaluate", &message)
            }
            _ => Response::error(request.seq, "evaluate", "Unexpected response from VM"),
        }
    }

    /// Handles the 'disconnect' request.
    fn handle_disconnect(&mut self, request: &Request) -> Response {
        let args: DisconnectArguments = request.arguments_as().unwrap_or_default();

        // Notify VM
        if let Err(e) = self.vm_channel.send(DapRequest::Disconnect {
            terminate: args.terminate_debuggee,
        }) {
            log::error!("Failed to send disconnect to VM: {}", e);
        }

        self.shutdown.store(true, Ordering::Relaxed);
        Response::success(request.seq, "disconnect", None)
    }

    /// Polls for events from the VM and sends them to the client.
    fn poll_vm_events(&mut self) -> Result<(), DapError> {
        loop {
            match self.vm_channel.try_recv() {
                Ok(response) => {
                    let event = self.response_to_event(response);
                    if let Some(event) = event {
                        self.send_event(event)?;
                    }
                }
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    log::info!("VM channel disconnected");
                    self.shutdown.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Converts a VM response to a DAP event (if applicable).
    fn response_to_event(&mut self, response: DapResponse) -> Option<Event> {
        match response {
            DapResponse::Stopped {
                reason,
                location,
                hit_breakpoint_ids,
                exception_text,
            } => {
                self.running.store(false, Ordering::Relaxed);

                let body = StoppedEventBody {
                    reason: reason.as_str().to_string(),
                    description: Some(format!("Paused at {}:{}", location.filename, location.line)),
                    thread_id: Some(MAIN_THREAD_ID),
                    all_threads_stopped: true,
                    hit_breakpoint_ids: hit_breakpoint_ids
                        .map(|ids| ids.into_iter().map(|id| id as i64).collect()),
                    text: exception_text,
                };

                Some(Event::new(
                    "stopped",
                    Some(serde_json::to_value(body).unwrap()),
                ))
            }

            DapResponse::Continued => {
                self.running.store(true, Ordering::Relaxed);

                let body = ContinuedEventBody {
                    thread_id: MAIN_THREAD_ID,
                    all_threads_continued: true,
                };

                Some(Event::new(
                    "continued",
                    Some(serde_json::to_value(body).unwrap()),
                ))
            }

            DapResponse::Output {
                category,
                output,
                location,
            } => {
                let body = OutputEventBody {
                    category: Some(category),
                    output,
                    source: location.as_ref().map(|loc| Source {
                        path: Some(loc.filename.clone()),
                        ..Default::default()
                    }),
                    line: location.as_ref().map(|loc| loc.line as i64),
                    column: location
                        .as_ref()
                        .and_then(|loc| loc.column.map(|c| c as i64)),
                };

                Some(Event::new(
                    "output",
                    Some(serde_json::to_value(body).unwrap()),
                ))
            }

            DapResponse::Terminated => Some(Event::new("terminated", Some(serde_json::json!({})))),

            DapResponse::Exited { exit_code } => {
                let body = ExitedEventBody {
                    exit_code: exit_code as i64,
                };

                Some(Event::new(
                    "exited",
                    Some(serde_json::to_value(body).unwrap()),
                ))
            }

            _ => None,
        }
    }

    /// Sends a response to the client.
    fn send_response(&mut self, mut response: Response) -> Result<(), DapError> {
        response.seq = self.next_seq();
        self.send_message(&response)
    }

    /// Sends an event to the client.
    fn send_event(&mut self, mut event: Event) -> Result<(), DapError> {
        event.seq = self.next_seq();
        self.send_message(&event)
    }

    /// Sends a JSON message to the client with DAP framing.
    fn send_message<T: serde::Serialize>(&mut self, message: &T) -> Result<(), DapError> {
        let json = serde_json::to_string(message)?;
        log::debug!("DAP server: sending: {}", json);

        let framed = format!("Content-Length: {}\r\n\r\n{}", json.len(), json);
        self.writer
            .write_all(framed.as_bytes())
            .map_err(DapError::AcceptError)?;
        self.writer.flush().map_err(DapError::AcceptError)?;

        Ok(())
    }

    /// Returns the next sequence number.
    fn next_seq(&self) -> i64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_content_length() {
        assert_eq!(
            DapServer::parse_content_length("Content-Length: 123").unwrap(),
            123
        );
        assert_eq!(
            DapServer::parse_content_length("content-length: 456").unwrap(),
            456
        );
        assert_eq!(
            DapServer::parse_content_length("Content-Length:789").unwrap(),
            789
        );

        assert!(DapServer::parse_content_length("").is_err());
        assert!(DapServer::parse_content_length("Invalid").is_err());
        assert!(DapServer::parse_content_length("Content-Length: abc").is_err());
    }
}
