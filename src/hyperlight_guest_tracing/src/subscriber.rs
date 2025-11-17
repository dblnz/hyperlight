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

use alloc::sync::Arc;

use spin::Mutex;
use tracing_core::span::{Attributes, Id, Record};
use tracing_core::subscriber::Subscriber;
use tracing_core::{Event, Metadata};

use crate::state::GuestState;

/// The subscriber is used to collect spans and events in the guest.
pub(crate) struct GuestSubscriber {
    /// Internal state that holds the spans and events
    /// Protected by a Mutex for inner mutability
    /// A reference to this state is stored in a static variable
    state: Arc<Mutex<GuestState>>,
}

impl GuestSubscriber {
    pub(crate) fn new(guest_start_tsc: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(GuestState::new(guest_start_tsc))),
        }
    }
    pub(crate) fn state(&self) -> &Arc<Mutex<GuestState>> {
        &self.state
    }
}

impl Subscriber for GuestSubscriber {
    fn enabled(&self, _md: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        if let Some(mut state) = self.state.try_lock() {
            state.new_span(attrs)
        } else {
            // The Guest state is a global Mutex, so we try to lock it.
            // The state is used in other places to serialize guest tracing data,
            // to check whether tracing is enabled, etc.
            // In case we cannot lock the state, we panic to avoid inconsistent tracing data,
            // and potential deadlocks. If we cannot lock the state, something is seriously wrong
            // (e.g. a re-entrant call, a panic that tries to create a span/log).
            panic!("GuestSubscriber: unable to lock state in `new_span`");
        }
    }

    fn record(&self, id: &Id, values: &Record<'_>) {
        if let Some(mut state) = self.state.try_lock() {
            state.record(id, values)
        } else {
            // The Guest state is a global Mutex, so we try to lock it.
            // The state is used in other places to serialize guest tracing data,
            // to check whether tracing is enabled, etc.
            // In case we cannot lock the state, we panic to avoid inconsistent tracing data,
            // and potential deadlocks. If we cannot lock the state, something is seriously wrong
            // (e.g. a re-entrant call, a panic that tries to create a span/log).
            panic!("GuestSubscriber: unable to lock state in `record`");
        }
    }

    fn event(&self, event: &Event<'_>) {
        if let Some(mut state) = self.state.try_lock() {
            state.event(event)
        } else {
            // The Guest state is a global Mutex, so we try to lock it.
            // The state is used in other places to serialize guest tracing data,
            // to check whether tracing is enabled, etc.
            // In case we cannot lock the state, we panic to avoid inconsistent tracing data,
            // and potential deadlocks. If we cannot lock the state, something is seriously wrong
            // (e.g. a re-entrant call, a panic that tries to create a span/log).
            panic!("GuestSubscriber: unable to lock state in `event`");
        }
    }

    fn enter(&self, id: &Id) {
        if let Some(mut state) = self.state.try_lock() {
            state.enter(id)
        } else {
            // The Guest state is a global Mutex, so we try to lock it.
            // The state is used in other places to serialize guest tracing data,
            // to check whether tracing is enabled, etc.
            // In case we cannot lock the state, we panic to avoid inconsistent tracing data,
            // and potential deadlocks. If we cannot lock the state, something is seriously wrong
            // (e.g. a re-entrant call, a panic that tries to create a span/log).
            panic!("GuestSubscriber: unable to lock state in `enter`");
        }
    }

    fn exit(&self, id: &Id) {
        if let Some(mut state) = self.state.try_lock() {
            state.exit(id)
        } else {
            // The Guest state is a global Mutex, so we try to lock it.
            // The state is used in other places to serialize guest tracing data,
            // to check whether tracing is enabled, etc.
            // In case we cannot lock the state, we panic to avoid inconsistent tracing data,
            // and potential deadlocks. If we cannot lock the state, something is seriously wrong
            // (e.g. a re-entrant call, a panic that tries to create a span/log).
            panic!("GuestSubscriber: unable to lock state in `exit`");
        }
    }

    fn try_close(&self, id: Id) -> bool {
        if let Some(mut state) = self.state.try_lock() {
            state.try_close(id)
        } else {
            // The Guest state is a global Mutex, so we try to lock it.
            // The state is used in other places to serialize guest tracing data,
            // to check whether tracing is enabled, etc.
            // In case we cannot lock the state, we panic to avoid inconsistent tracing data,
            // and potential deadlocks. If we cannot lock the state, something is seriously wrong
            // (e.g. a re-entrant call, a panic that tries to create a span/log).
            panic!("GuestSubscriber: unable to lock state in `try_close`");
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {
        // no-op: we don't track follows-from relationships
    }
}
