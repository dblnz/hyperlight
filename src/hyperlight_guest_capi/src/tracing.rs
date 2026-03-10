/*
Copyright 2025 The Hyperlight Authors.

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

use core::ffi::c_char;

/// Opens a new tracing span and enters it.
///
/// Returns a span ID that must later be passed to `hl_tracing_close_span`
/// when the span's scope ends.
///
/// Returns 0 if tracing is not enabled (either because the `trace_guest`
/// feature was not compiled in, or because tracing was not initialized by
/// the host).
///
/// # Safety
///
/// `name` must be a valid, non-null, NUL-terminated C string.
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn hl_tracing_span_open(name: *const c_char) -> u64 {
    #[cfg(feature = "trace_guest")]
    {
        if !hyperlight_guest_tracing::is_trace_enabled() {
            return 0;
        }
        let name = unsafe { core::ffi::CStr::from_ptr(name).to_string_lossy() };
        hyperlight_guest_tracing::open_span(&name)
    }
    #[cfg(not(feature = "trace_guest"))]
    {
        let _ = name;
        0
    }
}

/// Closes a previously opened span by its ID.
///
/// The span is removed from the active span stack and a close event
/// is recorded with the current timestamp. Does nothing if tracing
/// is not enabled or if the ID is 0.
#[unsafe(no_mangle)]
pub extern "C" fn hl_tracing_close_span(span_id: u64) {
    #[cfg(feature = "trace_guest")]
    {
        if span_id == 0 || !hyperlight_guest_tracing::is_trace_enabled() {
            return;
        }
        hyperlight_guest_tracing::close_span(span_id);
    }
    #[cfg(not(feature = "trace_guest"))]
    {
        let _ = span_id;
    }
}

/// Records a trace event in the context of the current span.
///
/// The event contains the given message. If no span is active,
/// the event is recorded at the root level. Does nothing if
/// tracing is not enabled.
///
/// # Safety
///
/// `message` must be a valid, non-null, NUL-terminated C string.
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn hl_tracing_event(message: *const c_char) {
    #[cfg(feature = "trace_guest")]
    {
        if !hyperlight_guest_tracing::is_trace_enabled() {
            return;
        }
        let message = unsafe { core::ffi::CStr::from_ptr(message).to_string_lossy() };
        hyperlight_guest_tracing::trace_event(&message);
    }
    #[cfg(not(feature = "trace_guest"))]
    {
        let _ = message;
    }
}

/// Returns `true` if guest tracing is enabled and initialized.
///
/// When this returns `false`, all other tracing functions are no-ops.
#[unsafe(no_mangle)]
pub extern "C" fn hl_is_trace_enabled() -> bool {
    #[cfg(feature = "trace_guest")]
    {
        hyperlight_guest_tracing::is_trace_enabled()
    }
    #[cfg(not(feature = "trace_guest"))]
    {
        false
    }
}
