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

use alloc::format;
use alloc::string::ToString;
use alloc::vec;

use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use hyperlight_common::outb::{EventKeyValue, EventsEncoder, GuestEvent};
use log::{LevelFilter, Metadata, Record};

use crate::{EVENTS_ENCODER, GUEST_HANDLE};

// this is private on purpose so that `log` can only be called though the `log!` macros.
struct GuestLogger {}

pub(crate) fn init_logger(level: LevelFilter) {
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
        if self.enabled(record.metadata()) {
            if let Some(enc) = EVENTS_ENCODER.get()
                && let Some(mut encoder) = enc.try_lock()
            {
                let msg = format!("{}", record.args());
                let event = GuestEvent::LogEvent {
                    parent_id: 0,
                    name: msg.clone(),
                    tsc: 0,
                    fields: vec![
                        EventKeyValue {
                            key: "level".to_string(),
                            value: format!("{}", record.level()),
                        },
                        EventKeyValue {
                            key: "module".to_string(),
                            value: record.module_path().unwrap_or("Unkwnown").to_string(),
                        },
                        EventKeyValue {
                            key: "target".to_string(),
                            value: record.target().to_string(),
                        },
                        EventKeyValue {
                            key: "file".to_string(),
                            value: record.file().unwrap_or("Unknown").to_string(),
                        },
                        EventKeyValue {
                            key: "line".to_string(),
                            value: record.line().unwrap_or(0).to_string(),
                        },
                        EventKeyValue {
                            key: "message".to_string(),
                            value: msg,
                        },
                    ],
                };

                encoder.encode(&event);
            }
        }
    }

    fn flush(&self) {
        if let Some(enc) = EVENTS_ENCODER.get()
            && let Some(mut encoder) = enc.try_lock()
        {
            // Send any pending log events to the host and reset the encoder
            encoder.flush();
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
