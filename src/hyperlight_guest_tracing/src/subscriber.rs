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
    pub(crate) fn new(state: Arc<Mutex<GuestState>>) -> Self {
        Self { state }
    }
}

impl Subscriber for GuestSubscriber {
    fn enabled(&self, _md: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut state = self
            .state
            .try_lock()
            .expect("GuestState: unable to lock GuestState on new_span");

        state.new_span(attrs)
    }

    fn record(&self, id: &Id, values: &Record<'_>) {
        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut state = self
            .state
            .try_lock()
            .expect("GuestState: unable to lock GuestState on record");

        state.record(id, values)
    }

    fn event(&self, event: &Event<'_>) {
        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut state = self
            .state
            .try_lock()
            .expect("GuestState: unable to lock GuestState on event");

        state.event(event)
    }

    fn enter(&self, id: &Id) {
        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut state = self
            .state
            .try_lock()
            .expect("GuestState: unable to lock GuestState on enter");

        state.enter(id)
    }

    fn exit(&self, id: &Id) {
        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut state = self
            .state
            .try_lock()
            .expect("GuestState: unable to lock GuestState on exit");

        state.exit(id)
    }

    fn try_close(&self, id: Id) -> bool {
        // The Guest state is a global Mutex, so we try to lock it.
        // in case we cannot lock the state, we panic to avoid inconsistent tracing data,
        // and potential deadlocks. If we cannot lock the state, something is seriously wrong
        // (e.g. a re-entrant call, a panic that tries to create a
        let mut state = self
            .state
            .try_lock()
            .expect("GuestState: unable to lock GuestState on try_close");

        state.try_close(id)
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {
        // no-op: we don't track follows-from relationships
    }
}
