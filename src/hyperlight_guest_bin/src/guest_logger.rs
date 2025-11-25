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

use alloc::sync::Arc;
use hyperlight_common::flatbuffer_wrappers::guest_trace_data::EventsBatchEncoder;
use hyperlight_common::outb::{EventsEncoder, OutBAction};
use spin::Mutex;

use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use log::{LevelFilter, Metadata, Record};

use crate::EVENTS_ENCODER;
use crate::GUEST_HANDLE;

/// TODO: Change these constant to be configurable at runtime by the guest
/// Maybe use a weak symbol that the guest can override at link time?
///
/// Pre-calculated capacity for the encoder buffer
/// This is to avoid reallocations in the guest
const ENCODER_CAPACITY: usize = 4096;

/// Triggers a VM exit to flush the current events to the host.
fn send_to_host(data: &[u8]) {
    unsafe {
        core::arch::asm!("out dx, al",
            // Port value for tracing
            in("dx") OutBAction::GuestEvent as u16,
            in("al") 0u8,
            // Additional magic number to identify the action
            in("r8") OutBAction::GuestEvent as u64,
            in("r9") data.as_ptr() as u64,
            in("r10") data.len() as u64,
        );
    }
}

// this is private on purpose so that `log` can only be called though the `log!` macros.
struct GuestLogger {}

pub(crate) fn init_logger(level: LevelFilter) {
    // Initialize the global events encoder
    EVENTS_ENCODER.call_once(|| {
        Arc::new(Mutex::new(EventsBatchEncoder::new(
            ENCODER_CAPACITY,
            send_to_host,
        )))
    });

    // if this `expect` fails we have no way to recover anyway, so we actually prefer a panic here
    // below temporary guest logger is promoted to static by the compiler.
    log::set_logger(&GuestLogger {}).expect("unable to setup guest logger");
    log::set_max_level(level);
}

impl log::Log for GuestLogger {
    // The various macros like `info!` and `error!` will call the global log::max_level()
    // before calling our `log`. This means that we should log every message we get, because
    // we won't even see the ones that are above the set max level.
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {}
    }

    fn flush(&self) {
        if let Some(enc) = EVENTS_ENCODER.get()
            && let Some(encoder) = enc.try_lock()
        {
            let data = encoder.finish();
            send_to_host(data);
        }
    }
}

pub fn log_message(
    level: LogLevel,
    message: &str,
    module_path: &str,
    target: &str,
    file: &str,
    line: u32,
) {
    let handle = unsafe { GUEST_HANDLE };
    handle.log_message(level, message, module_path, target, file, line);
}
