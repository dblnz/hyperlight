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
extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hyperlight_common::flatbuffer_wrappers::guest_trace_data::EventsBatchEncoder;
use hyperlight_common::outb::{EventsEncoder, GuestEvent};
use spin::Mutex;
use tracing_core::Event;
use tracing_core::span::{Attributes, Id, Record};

use crate::invariant_tsc;
use crate::visitor::FieldsVisitor;

pub struct TraceBatchInfo {
    pub serialized_data: Vec<u8>,
}

/// Internal state of the tracing subscriber
pub(crate) struct GuestState {
    /// Encoder for events
    encoder: Arc<Mutex<EventsBatchEncoder>>,
    /// Next span ID to allocate
    next_id: AtomicU64,
    /// Stack of active spans
    stack: Vec<u64>,
}

/// Start with a stack capacity for active spans
const ACTIVE_SPANS_CAPACITY: usize = 64;

impl GuestState {
    pub(crate) fn new(guest_start_tsc: u64, encoder: Arc<Mutex<EventsBatchEncoder>>) -> Self {
        if let Some(mut enc) = encoder.try_lock() {
            enc.encode(&GuestEvent::GuestStart {
                tsc: guest_start_tsc,
            });
        } else {
            // The Guest state is a global Mutex, so we try to lock it.
            // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
            // and potential deadlocks. If we cannot lock the state, something is seriously wrong
            // (e.g. a re-entrant call, a panic that tries to create a
            panic!("GuestState: unable to lock EventsBatchEncoder on initialization");
        }

        Self {
            encoder,
            next_id: AtomicU64::new(1),
            stack: Vec::with_capacity(ACTIVE_SPANS_CAPACITY),
        }
    }

    /// Allocate a new ID for a span
    /// Returns the numeric ID and the tracing ID
    /// This shall return unique IDs for each call
    pub(crate) fn alloc_id(&self) -> (u64, Id) {
        let n = self.next_id.load(Ordering::Relaxed);
        self.next_id.store(n + 1, Ordering::Relaxed);

        (n, Id::from_u64(n))
    }

    /// Flush the current trace by ending all spans and sending the data to the host
    /// This expects at most multiple calls to outb to send the data:
    /// - in case there is not enough space to close all spans
    /// - one to send the final data left
    pub(crate) fn flush(&mut self) {
        // End all spans which serializes them and might require multiple outb calls
        self.end_trace();

        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut enc = self
            .encoder
            .try_lock()
            .expect("GuestState: unable to lock EventsBatchEncoder on flush");

        enc.flush();
    }

    /// Prepare the trace state for a new guest function call
    /// This resets the internal serializer and adds a GuestStart event
    /// with the provided start timestamp counter (TSC)
    pub(crate) fn new_call(&mut self, start_tsc: u64) {
        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut enc = self
            .encoder
            .try_lock()
            .expect("GuestState: unable to lock EventsBatchEncoder on new_call");

        enc.reset();
        enc.encode(&GuestEvent::GuestStart { tsc: start_tsc });
    }

    /// Reset the trace state, clearing all existing spans and events
    /// This is called after the trace has been flushed to the host
    pub(crate) fn reset(&mut self) {
        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut enc = self
            .encoder
            .try_lock()
            .expect("GuestState: unable to lock EventsBatchEncoder on reset");

        enc.reset();
    }

    /// Closes the trace by ending all spans
    /// NOTE: This expects an outb call to send the spans to the host.
    pub(crate) fn end_trace(&mut self) {
        // Empty the stack
        while let Some(id) = self.stack.pop() {
            // Pop all remaining spans from the stack
            let event = GuestEvent::CloseSpan {
                id,
                tsc: invariant_tsc::read_tsc(),
            };

            // The Guest state is a global Mutex, so we try to lock it.
            // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
            // and potential deadlocks. If we cannot lock the state, something is seriously wrong
            // (e.g. a re-entrant call, a panic that tries to create a
            let mut enc = self
                .encoder
                .try_lock()
                .expect("GuestState: unable to lock EventsBatchEncoder on end_trace");

            // Serialize the event
            enc.encode(&event);
        }
    }

    /// Return (ptr, len) for serialized data if any is available
    pub(crate) fn serialized_data(&self) -> Option<(u64, u64)> {
        self.encoder
            .try_lock()
            .map(|enc| {
                let data = enc.finish();

                if data.is_empty() {
                    None
                } else {
                    Some((data.as_ptr() as u64, data.len() as u64))
                }
            })
            .unwrap_or(None)
    }

    /// Create a new span and push it on the stack
    pub(crate) fn new_span(&mut self, attrs: &Attributes) -> Id {
        let (idn, id) = self.alloc_id();

        let md = attrs.metadata();
        let name = String::from(md.name());
        let target = String::from(md.target());

        // Visit fields to collect them
        let mut fields = Vec::new();
        attrs.record(&mut FieldsVisitor { out: &mut fields });

        // Find parent from current stack top (if any)
        let parent_id = self.stack.last().copied();

        let event = GuestEvent::OpenSpan {
            id: idn,
            parent_id,
            name,
            target,
            tsc: invariant_tsc::read_tsc(),
            fields,
        };

        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut enc = self
            .encoder
            .try_lock()
            .expect("GuestState: unable to lock EventsBatchEncoder on new_span");

        // Serialize the event
        enc.encode(&event);

        id
    }

    /// Record an event in the current span (top of the stack)
    pub(crate) fn event(&mut self, event: &Event<'_>) {
        let stack = &mut self.stack;
        let parent_id = stack.last().copied().unwrap_or(0);

        let md = event.metadata();
        let name = String::from(md.name());

        let mut fields = Vec::new();
        event.record(&mut FieldsVisitor { out: &mut fields });

        let event = GuestEvent::LogEvent {
            parent_id,
            name,
            tsc: invariant_tsc::read_tsc(),
            fields,
        };

        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut enc = self
            .encoder
            .try_lock()
            .expect("GuestState: unable to lock EventsBatchEncoder on event");

        // Serialize the event
        enc.encode(&event);
    }

    /// Record new values for an existing span
    pub(crate) fn record(&mut self, s_id: &Id, values: &Record<'_>) {
        let mut v = Vec::new();
        values.record(&mut FieldsVisitor { out: &mut v });

        let event = GuestEvent::EditSpan {
            id: s_id.into_u64(),
            fields: v,
        };

        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut enc = self
            .encoder
            .try_lock()
            .expect("GuestState: unable to lock EventsBatchEncoder on record");

        // Serialize the event
        enc.encode(&event);
    }

    /// Enter a span (push it on the stack)
    pub(crate) fn enter(&mut self, id: &Id) {
        let st = &mut self.stack;
        st.push(id.into_u64());
    }

    /// Exit a span (pop it from the stack)
    pub(crate) fn exit(&mut self, _id: &Id) {
        let st = &mut self.stack;
        let _ = st.pop();
    }

    /// Try to close a span by ID, returning true if successful
    /// Records the end timestamp for the span.
    pub(crate) fn try_close(&mut self, id: Id) -> bool {
        let event = GuestEvent::CloseSpan {
            id: id.into_u64(),
            tsc: invariant_tsc::read_tsc(),
        };

        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut enc = self
            .encoder
            .try_lock()
            .expect("GuestState: unable to lock EventsBatchEncoder on try_close");

        // Serialize the event
        enc.encode(&event);

        true
    }
}
