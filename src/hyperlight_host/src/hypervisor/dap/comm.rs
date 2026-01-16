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

//! Communication channel for DAP message passing between the DAP server thread
//! and the Hyperlight VM.

use crossbeam_channel::{Receiver, Sender, TryRecvError};

use super::errors::DapError;

/// Bidirectional communication channel for DAP messages.
///
/// This channel allows the DAP server thread to send requests to the Hyperlight VM
/// and receive responses/events back. It uses crossbeam channels for thread-safe
/// communication.
///
/// # Type Parameters
///
/// * `T` - The type of messages this end sends
/// * `U` - The type of messages this end receives
///
/// # Example
///
/// ```ignore
/// // Create a pair of connected channels
/// let (server_chan, vm_chan) = DapCommChannel::<DapRequest, DapResponse>::unbounded();
///
/// // Server sends a request
/// server_chan.send(DapRequest::Continue)?;
///
/// // VM receives and processes the request
/// let request = vm_chan.recv()?;
///
/// // VM sends a response
/// vm_chan.send(DapResponse::Continued)?;
///
/// // Server receives the response
/// let response = server_chan.recv()?;
/// ```
#[derive(Debug)]
pub struct DapCommChannel<T, U> {
    /// Transmit channel for sending messages
    tx: Sender<T>,
    /// Receive channel for receiving messages
    rx: Receiver<U>,
}

impl<T, U> DapCommChannel<T, U> {
    /// Creates a pair of connected unbounded channels.
    ///
    /// Returns two `DapCommChannel` instances that are connected to each other.
    /// Messages sent on one channel can be received on the other.
    ///
    /// # Returns
    ///
    /// A tuple of `(channel_a, channel_b)` where:
    /// - `channel_a` sends type `T` and receives type `U`
    /// - `channel_b` sends type `U` and receives type `T`
    pub fn unbounded() -> (DapCommChannel<T, U>, DapCommChannel<U, T>) {
        let (tx_a, rx_b): (Sender<T>, Receiver<T>) = crossbeam_channel::unbounded();
        let (tx_b, rx_a): (Sender<U>, Receiver<U>) = crossbeam_channel::unbounded();

        let channel_a = DapCommChannel { tx: tx_a, rx: rx_a };
        let channel_b = DapCommChannel { tx: tx_b, rx: rx_b };

        (channel_a, channel_b)
    }

    /// Sends a message through the channel.
    ///
    /// This operation never blocks (for unbounded channels).
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to send
    ///
    /// # Errors
    ///
    /// Returns `DapError::ChannelSendError` if the receiving end has been dropped.
    pub fn send(&self, msg: T) -> Result<(), DapError> {
        self.tx.send(msg).map_err(|_| DapError::ChannelSendError)
    }

    /// Receives a message from the channel, blocking until one is available.
    ///
    /// # Errors
    ///
    /// Returns `DapError::ChannelRecvError` if the sending end has been dropped
    /// and no messages are available.
    pub fn recv(&self) -> Result<U, DapError> {
        self.rx.recv().map_err(|_| DapError::ChannelRecvError)
    }

    /// Attempts to receive a message without blocking.
    ///
    /// # Returns
    ///
    /// * `Ok(message)` if a message was available
    /// * `Err(TryRecvError::Empty)` if no message is currently available
    /// * `Err(TryRecvError::Disconnected)` if the sender has been dropped
    pub fn try_recv(&self) -> Result<U, TryRecvError> {
        self.rx.try_recv()
    }

    /// Checks if the channel is empty (no pending messages).
    pub fn is_empty(&self) -> bool {
        self.rx.is_empty()
    }

    /// Returns the number of messages waiting in the channel.
    pub fn len(&self) -> usize {
        self.rx.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypervisor::dap::messages::{DapRequest, DapResponse};

    #[test]
    fn test_channel_send_recv() {
        let (server_chan, vm_chan) = DapCommChannel::<DapRequest, DapResponse>::unbounded();

        // Send from server to VM
        let result = server_chan.send(DapRequest::Continue);
        assert!(result.is_ok());

        // Receive on VM side
        let result = vm_chan.recv();
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), DapRequest::Continue));

        // Send response from VM to server
        let result = vm_chan.send(DapResponse::Continued);
        assert!(result.is_ok());

        // Receive on server side
        let result = server_chan.recv();
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), DapResponse::Continued));
    }

    #[test]
    fn test_try_recv_empty() {
        let (server_chan, _vm_chan) = DapCommChannel::<DapRequest, DapResponse>::unbounded();

        // Should return Empty when no messages
        let result = server_chan.try_recv();
        assert!(matches!(result, Err(TryRecvError::Empty)));
    }

    #[test]
    fn test_try_recv_disconnected() {
        let (server_chan, vm_chan) = DapCommChannel::<DapRequest, DapResponse>::unbounded();

        // Drop the VM channel
        drop(vm_chan);

        // Should return Disconnected
        let result = server_chan.try_recv();
        assert!(matches!(result, Err(TryRecvError::Disconnected)));
    }

    #[test]
    fn test_channel_len_and_empty() {
        let (server_chan, vm_chan) = DapCommChannel::<DapRequest, DapResponse>::unbounded();

        assert!(vm_chan.is_empty());
        assert_eq!(vm_chan.len(), 0);

        server_chan.send(DapRequest::Continue).unwrap();
        server_chan.send(DapRequest::Pause).unwrap();

        assert!(!vm_chan.is_empty());
        assert_eq!(vm_chan.len(), 2);
    }
}
