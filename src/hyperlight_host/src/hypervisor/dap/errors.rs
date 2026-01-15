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

//! Error types for the DAP module.

use std::io;

use thiserror::Error;

/// Errors that can occur in the DAP server.
#[derive(Debug, Error)]
pub enum DapError {
    /// Failed to bind to the specified address/port
    #[error("Failed to bind to address: {0}")]
    BindError(String),

    /// Failed to accept a connection
    #[error("Failed to accept connection: {0}")]
    AcceptError(#[from] io::Error),

    /// Error parsing a DAP message
    #[error("Failed to parse DAP message: {0}")]
    ParseError(String),

    /// Error serializing a DAP message
    #[error("Failed to serialize DAP message: {0}")]
    SerializeError(String),

    /// Error sending a message through the channel
    #[error("Failed to send message through channel")]
    ChannelSendError,

    /// Error receiving a message from the channel
    #[error("Failed to receive message from channel")]
    ChannelRecvError,

    /// Received an unexpected message type
    #[error("Received unexpected message: {0}")]
    UnexpectedMessage(String),

    /// The debug session is not initialized
    #[error("Debug session not initialized")]
    NotInitialized,

    /// The debug session has already been initialized
    #[error("Debug session already initialized")]
    AlreadyInitialized,

    /// Invalid request sequence number
    #[error("Invalid sequence number: expected {expected}, got {actual}")]
    InvalidSequence { expected: i64, actual: i64 },

    /// Unknown command received
    #[error("Unknown command: {0}")]
    UnknownCommand(String),

    /// Invalid arguments for a command
    #[error("Invalid arguments for command '{command}': {reason}")]
    InvalidArguments { command: String, reason: String },

    /// Operation not supported
    #[error("Operation not supported: {0}")]
    NotSupported(String),

    /// The connection was closed
    #[error("Connection closed")]
    ConnectionClosed,

    /// Timeout waiting for response
    #[error("Timeout waiting for response")]
    Timeout,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl DapError {
    /// Creates a parse error with the given message.
    pub fn parse(msg: impl Into<String>) -> Self {
        DapError::ParseError(msg.into())
    }

    /// Creates a serialize error with the given message.
    pub fn serialize(msg: impl Into<String>) -> Self {
        DapError::SerializeError(msg.into())
    }

    /// Creates an internal error with the given message.
    pub fn internal(msg: impl Into<String>) -> Self {
        DapError::Internal(msg.into())
    }

    /// Creates an invalid arguments error.
    pub fn invalid_args(command: impl Into<String>, reason: impl Into<String>) -> Self {
        DapError::InvalidArguments {
            command: command.into(),
            reason: reason.into(),
        }
    }
}

impl From<serde_json::Error> for DapError {
    fn from(err: serde_json::Error) -> Self {
        DapError::ParseError(err.to_string())
    }
}
