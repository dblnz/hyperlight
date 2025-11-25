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

#![no_std]

/// Expose invariant TSC module
pub mod invariant_tsc;

/// Defines internal guest state
#[cfg(feature = "trace")]
mod state;

/// Defines guest tracing Subscriber
#[cfg(feature = "trace")]
mod subscriber;

/// Defines a type to iterate over spans/events fields
#[cfg(feature = "trace")]
mod visitor;

/// Type to get the relevant information from the internal state
/// and expose it to the host
#[cfg(feature = "trace")]
pub use state::TraceBatchInfo;
#[cfg(feature = "trace")]
pub use trace::{
    end_trace, flush, init_guest_tracing, is_trace_enabled, new_call, reset, serialized_data,
};

/// This module is gated because some of these types are also used on the host, but we want
/// only the guest to allocate and allow the functionality intended for the guest.
#[cfg(feature = "trace")]
mod trace {
    extern crate alloc;
    use alloc::sync::Arc;
    use hyperlight_common::flatbuffer_wrappers::guest_trace_data::EventsBatchEncoder;

    use spin::Mutex;

    use crate::state::GuestState;
    use crate::subscriber::GuestSubscriber;

    /// Weak reference to the guest state so we can manually trigger flush to host
    static GUEST_STATE: spin::Once<Arc<Mutex<GuestState>>> = spin::Once::new();

    /// Initialize the guest tracing subscriber as global default.
    pub fn init_guest_tracing(guest_start_tsc: u64, encoder: Arc<Mutex<EventsBatchEncoder>>) {
        // Set as global default if not already set.
        if tracing_core::dispatcher::has_been_set() {
            return;
        }

        let state = Arc::new(Mutex::new(GuestState::new(guest_start_tsc, encoder)));
        let sub = GuestSubscriber::new(state);

        // Set global dispatcher
        let _ = tracing_core::dispatcher::set_global_default(tracing_core::Dispatch::new(sub));
    }

    /// Ends the current trace by ending all active spans in the
    /// internal state and storing the end timestamps.
    ///
    /// This expects an outb call to send the spans to the host.
    /// After calling this function, the internal state is marked
    /// for cleaning on the next access.
    pub fn end_trace() {
        if let Some(state_mutex) = GUEST_STATE.get()
            && let Some(mut state) = state_mutex.try_lock()
        {
            state.end_trace();
        }
    }

    /// Flushes the current trace data to prepare it for reading by the host.
    pub fn flush() {
        if let Some(state_mutex) = GUEST_STATE.get()
            && let Some(mut state) = state_mutex.try_lock()
        {
            state.flush();
        }
    }

    /// Resets the internal trace state for a new guest function call.
    /// This clears any existing spans/events from previous calls ensuring a clean state.
    pub fn new_call(guest_start_tsc: u64) {
        if let Some(state_mutex) = GUEST_STATE.get()
            && let Some(mut state) = state_mutex.try_lock()
        {
            state.new_call(guest_start_tsc);
        }
    }

    /// Cleans the internal trace state by removing closed spans and events.
    /// This ensures that after a VM exit, we keep the spans that
    /// are still active (in the stack) and remove all other spans and events.
    pub fn reset() {
        if let Some(state_mutex) = GUEST_STATE.get()
            && let Some(mut state) = state_mutex.try_lock()
        {
            state.reset();
        }
    }

    /// Returns information about the current trace state needed by the host to read the spans.
    /// NOTE: If unable to lock the state, likely due to concurrent access, we skip retrieving the info.
    /// This is to avoid deadlocks in the guest.
    /// Returns None if state is locked or there is no serialized data, otherwise returns Some with
    /// pointer and length of the serialized data slice.
    pub fn serialized_data() -> Option<(u64, u64)> {
        if let Some(state_mutex) = GUEST_STATE.get()
            && let Some(state) = state_mutex.try_lock()
        {
            state.serialized_data()
        } else {
            None
        }
    }

    /// Returns true if tracing is enabled (the guest tracing state is initialized).
    pub fn is_trace_enabled() -> bool {
        GUEST_STATE.get().is_some()
    }
}
