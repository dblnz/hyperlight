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

//! Guest trace data structures and (de)serialization logic.
//! This module defines the data structures used for tracing spans and events
//! within a guest environment, along with the logic for serializing and
//! deserializing these structures using FlatBuffers.
//!
//! Schema definitions can be found in `src/schema/guest_trace_data.fbs`.

use alloc::string::ToString;
use alloc::vec::Vec;

use anyhow::{Error, Result, anyhow};
use flatbuffers::size_prefixed_root;

use crate::flatbuffers::hyperlight::generated::{
    CloseSpanType as FbCloseSpanType, CloseSpanTypeArgs as FbCloseSpanTypeArgs,
    EditSpanType as FbEditSpanType, EditSpanTypeArgs as FbEditSpanTypeArgs,
    GuestEventEnvelopeType as FbGuestEventEnvelopeType,
    GuestEventEnvelopeTypeArgs as FbGuestEventEnvelopeTypeArgs, GuestEventType as FbGuestEventType,
    GuestStartType as FbGuestStartType, GuestStartTypeArgs as FbGuestStartTypeArgs,
    KeyValue as FbKeyValue, KeyValueArgs as FbKeyValueArgs, LogEventType as FbLogEventType,
    LogEventTypeArgs as FbLogEventTypeArgs, OpenSpanType as FbOpenSpanType,
    OpenSpanTypeArgs as FbOpenSpanTypeArgs,
};
use crate::outb::{EventKeyValue, EventsDecoder, EventsEncoder, GuestEvent};

impl From<FbKeyValue<'_>> for EventKeyValue {
    fn from(value: FbKeyValue<'_>) -> Self {
        let key = value.key().to_string();
        let value = value.value().to_string();

        EventKeyValue { key, value }
    }
}

impl TryFrom<&[u8]> for EventKeyValue {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let gld_gen = size_prefixed_root::<FbKeyValue>(value)
            .map_err(|e| anyhow!("Error while reading EventKeyValue: {:?}", e))?;
        let key = gld_gen.key().to_string();
        let value = gld_gen.value().to_string();

        Ok(EventKeyValue { key, value })
    }
}

impl From<&EventKeyValue> for Vec<u8> {
    fn from(value: &EventKeyValue) -> Self {
        let mut builder = flatbuffers::FlatBufferBuilder::new();

        let key_offset = builder.create_string(&value.key);
        let value_offset = builder.create_string(&value.value);

        let kv_args = FbKeyValueArgs {
            key: Some(key_offset),
            value: Some(value_offset),
        };

        let kv_fb = FbKeyValue::create(&mut builder, &kv_args);
        builder.finish_size_prefixed(kv_fb, None);

        builder.finished_data().to_vec()
    }
}

impl From<EventKeyValue> for Vec<u8> {
    fn from(value: EventKeyValue) -> Self {
        Vec::from(&value)
    }
}

impl TryFrom<&[u8]> for GuestEvent {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let envelope = size_prefixed_root::<FbGuestEventEnvelopeType>(value)
            .map_err(|e| anyhow!("Error while reading GuestTraceData: {:?}", e))?;
        let event_type = envelope.event_type();

        // Match on the event type to extract the appropriate event data
        let event = match event_type {
            FbGuestEventType::OpenSpan => {
                // Extract OpenSpanType event data
                let ost_fb = envelope
                    .event_as_open_span()
                    .ok_or_else(|| anyhow!("Failed to cast to OpenSpanType"))?;

                // Extract fields
                let id = ost_fb.id();
                let parent = ost_fb.parent();
                let name = ost_fb.name().to_string();
                let target = ost_fb.target().to_string();
                let tsc = ost_fb.tsc();

                // Extract key-value fields
                let mut fields = Vec::new();
                if let Some(fb_fields) = ost_fb.fields() {
                    for j in 0..fb_fields.len() {
                        let kv: EventKeyValue = EventKeyValue::from(fb_fields.get(j));
                        fields.push(kv);
                    }
                }

                // Construct OpenSpan event
                GuestEvent::OpenSpan {
                    id,
                    parent_id: parent,
                    name,
                    target,
                    tsc,
                    fields,
                }
            }
            FbGuestEventType::CloseSpan => {
                // Extract CloseSpanType event data
                let cst_fb = envelope
                    .event_as_close_span()
                    .ok_or_else(|| anyhow!("Failed to cast to CloseSpanType"))?;
                // Extract fields
                let id = cst_fb.id();
                let tsc = cst_fb.tsc();

                // Construct CloseSpan event
                GuestEvent::CloseSpan { id, tsc }
            }
            FbGuestEventType::LogEvent => {
                // Extract LogEventType event data
                let le_fb = envelope
                    .event_as_log_event()
                    .ok_or_else(|| anyhow!("Failed to cast to LogEventType"))?;

                // Extract fields
                let parent_id = le_fb.parent_id();
                let name = le_fb.name().to_string();
                let tsc = le_fb.tsc();

                // Extract key-value fields
                let mut fields = Vec::new();
                if let Some(fb_fields) = le_fb.fields() {
                    for j in 0..fb_fields.len() {
                        let kv: EventKeyValue = EventKeyValue::from(fb_fields.get(j));
                        fields.push(kv);
                    }
                }

                // Construct LogEvent
                GuestEvent::LogEvent {
                    parent_id,
                    name,
                    tsc,
                    fields,
                }
            }
            FbGuestEventType::EditSpan => {
                let est_fb = envelope
                    .event_as_edit_span()
                    .ok_or_else(|| anyhow!("Failed to cast to EditSpanType"))?;
                // Extract fields
                let id = est_fb.id();
                let mut fields = Vec::new();
                if let Some(fb_fields) = est_fb.fields() {
                    for j in 0..fb_fields.len() {
                        let kv: EventKeyValue = EventKeyValue::from(fb_fields.get(j));
                        fields.push(kv);
                    }
                }

                // Construct EditSpan event
                GuestEvent::EditSpan {
                    id,
                    fields: Vec::new(),
                }
            }
            FbGuestEventType::GuestStart => {
                let gst_fb = envelope
                    .event_as_guest_start()
                    .ok_or_else(|| anyhow!("Failed to cast to GuestStartType"))?;

                // Extract fields
                let tsc = gst_fb.tsc();

                // Construct GuestStart event
                GuestEvent::GuestStart { tsc }
            }

            _ => {
                return Err(anyhow!("Unknown GuestEventType={}", event_type.0));
            }
        };

        Ok(event)
    }
}

#[cfg(false)]
mod estimate {
    const ENVELOPE: usize = 20;
    const PER_EVENT_VECTOR_SLOT: usize = 4;

    const KV_TABLE_OVERHEAD: usize = 20;
    const OPEN_TABLE_OVERHEAD: usize = 72;
    const CLOSE_TABLE_OVERHEAD: usize = 32;
    const LOG_TABLE_OVERHEAD: usize = 52;

    /// Round up to next multiple of 4.
    fn pad4(x: usize) -> usize {
        (4 - (x & 3)) & 3
    }

    /// Size of a FlatBuffers string object with `len` UTF-8 bytes.
    fn size_str(len: usize) -> usize {
        4 + len + 1 + pad4(4 + len + 1)
    }

    /// One KeyValue (includes both strings).
    fn size_kv(k_len: usize, v_len: usize) -> usize {
        KV_TABLE_OVERHEAD + size_str(k_len) + size_str(v_len)
    }

    /// Vector of `m` KeyValue tables, using worst-case per-entry key/value lengths.
    fn size_kv_vec(m: usize, k_len_max: usize, v_len_max: usize) -> usize {
        let head = 4 + 4 * m;
        head + pad4(head) + m * size_kv(k_len_max, v_len_max)
    }

    /// OpenSpan event (per-event contribution inside the parent events vector).
    pub fn size_event_open_span(
        name_len: usize,
        target_len: usize,
        m_fields: usize,
        kv_key_max: usize,
        kv_val_max: usize,
    ) -> usize {
        PER_EVENT_VECTOR_SLOT
            + ENVELOPE
            + OPEN_TABLE_OVERHEAD
            + size_str(name_len)
            + size_str(target_len)
            + size_kv_vec(m_fields, kv_key_max, kv_val_max)
    }

    /// CloseSpan event (fixed).
    pub fn size_event_close_span() -> usize {
        PER_EVENT_VECTOR_SLOT + ENVELOPE + CLOSE_TABLE_OVERHEAD
    }

    /// LogEvent event.
    pub fn size_event_log(
        name_len: usize,
        m_fields: usize,
        kv_key_max: usize,
        kv_val_max: usize,
    ) -> usize {
        PER_EVENT_VECTOR_SLOT
            + ENVELOPE
            + LOG_TABLE_OVERHEAD
            + size_str(name_len)
            + size_kv_vec(m_fields, kv_key_max, kv_val_max)
    }

    /// Optional: root + one-time vector header, to add on top of per-event sums.
    pub fn per_chunk_fixed(n_events: usize) -> usize {
        const ROOT_TABLE_OVERHEAD: usize = 32; // GuestTraceDataType
        let vector_header = 4 + pad4(4 + 4 * n_events);
        ROOT_TABLE_OVERHEAD + vector_header
    }

    #[cfg(test)]
    mod tests {
        use alloc::string::String;
        use alloc::vec;

        use super::*;
        use crate::flatbuffer_wrappers::guest_trace_data::{
            GuestEvent, GuestTraceDataSerializer, KeyValue,
        };

        #[test]
        fn test_size_kv() {
            let sz = size_kv(10, 20);
            assert!(sz > 0);
        }

        #[test]
        fn test_size_event_open_span() {
            let sz = size_event_open_span(15, 25, 3, 10, 20);
            assert!(sz > 0);
        }

        #[test]
        fn test_size_event_close_span() {
            let sz = size_event_close_span();
            assert!(sz > 0);
        }

        #[test]
        fn test_size_event_log() {
            let sz = size_event_log(30, 2, 10, 20);
            assert!(sz > 0);
        }

        // Test a builder with one OpenSpan yielding expected size
        #[test]
        fn test_estimate_one_open_span() {
            let mut builder = GuestTraceDataSerializer::new(0, 1024);
            let name = String::from("test_span");
            let target = String::from("test_target");
            let name_len = name.len();
            let target_len = target.len();
            let event = GuestEvent::OpenSpan {
                id: 1,
                parent_id: None,
                name,
                target,
                tsc: 100,
                fields: vec![
                    KeyValue {
                        key: String::from("key1"),
                        value: String::from("value1"),
                    },
                    KeyValue {
                        key: String::from("key2"),
                        value: String::from("value2"),
                    },
                ],
            };

            let estimated_size =
                size_event_open_span(name_len, target_len, 2, 4, 6) + per_chunk_fixed(1);
            builder.serialize_event(&event);
            let serialized = builder.finish();

            // Check estimated size is within 10%-20% of actual serialized size
            assert!(serialized.len() + ((serialized.len() / 10) as usize) < estimated_size);
            assert!(serialized.len() + ((serialized.len() / 5) as usize) >= estimated_size);
        }

        // Test a builder with one CloseSpan yielding expected size
        #[test]
        fn test_estimate_one_close_span() {
            let mut builder = GuestTraceDataSerializer::new(0, 1024);
            let event = GuestEvent::CloseSpan { id: 1, tsc: 200 };
            let estimated_size = size_event_close_span() + per_chunk_fixed(1);
            builder.serialize_event(&event);
            let serialized = builder.finish();

            // Check estimated size is within 10%-20% of actual serialized size
            assert!(serialized.len() + ((serialized.len() / 10) as usize) < estimated_size);
            assert!(serialized.len() + ((serialized.len() / 5) as usize) >= estimated_size);
        }

        // Test a builder with one LogEvent yielding expected size
        #[test]
        fn test_estimate_one_log_event() {
            let mut builder = GuestTraceDataSerializer::new(0, 1024);
            let name = String::from("log_event");
            let name_len = name.len();
            let event = GuestEvent::LogEvent {
                parent_id: 1,
                name,
                tsc: 300,
                fields: vec![
                    KeyValue {
                        key: String::from("log_key1"),
                        value: String::from("log_value1"),
                    },
                    KeyValue {
                        key: String::from("log_key2"),
                        value: String::from("log_value2"),
                    },
                ],
            };
            let estimated_size = size_event_log(name_len, 2, 8, 12) + per_chunk_fixed(1);
            builder.serialize_event(&event);
            let serialized = builder.finish();

            // Check estimated size is within 10%-20% of actual serialized size
            assert!(serialized.len() + ((serialized.len() / 10) as usize) < estimated_size);
            assert!(serialized.len() + ((serialized.len() / 5) as usize) >= estimated_size);
        }

        // Test a builder with no events yielding expected size
        #[test]
        fn test_estimate_no_events() {
            let mut builder = GuestTraceDataSerializer::new(0, 1024);
            let estimated_size = per_chunk_fixed(0);
            let serialized = builder.finish();

            // Check estimated size is within 10%-20% of actual serialized size
            assert!(serialized.len() + ((serialized.len() / 10) as usize) < estimated_size);
            assert!(serialized.len() + ((serialized.len() / 5) as usize) >= estimated_size);
        }

        fn estimate_events(events: &[GuestEvent]) -> usize {
            let mut estimated_size = per_chunk_fixed(events.len());
            for event in events {
                match event {
                    GuestEvent::OpenSpan {
                        name,
                        target,
                        fields,
                        ..
                    } => {
                        let name_len = name.len();
                        let target_len = target.len();
                        let (max_k, max_v) =
                            fields.iter().fold((0usize, 0usize), |(mk, mv), kv| {
                                (mk.max(kv.key.len()), mv.max(kv.value.len()))
                            });
                        estimated_size +=
                            size_event_open_span(name_len, target_len, fields.len(), max_k, max_v);
                    }
                    GuestEvent::CloseSpan { .. } => {
                        estimated_size += size_event_close_span();
                    }
                    GuestEvent::LogEvent { name, fields, .. } => {
                        let name_len = name.len();
                        let (max_k, max_v) =
                            fields.iter().fold((0usize, 0usize), |(mk, mv), kv| {
                                (mk.max(kv.key.len()), mv.max(kv.value.len()))
                            });
                        estimated_size += size_event_log(name_len, fields.len(), max_k, max_v);
                    }
                }
            }
            estimated_size
        }

        // Test a builder with multiple events yielding expected size
        #[test]
        fn test_estimate_multiple_events_00() {
            let mut builder = GuestTraceDataSerializer::new(0, 2048);
            let events = vec![
                GuestEvent::OpenSpan {
                    id: 1,
                    parent_id: None,
                    name: String::from("span1"),
                    target: String::from("target1"),
                    tsc: 100,
                    fields: vec![
                        KeyValue {
                            key: String::from("key1"),
                            value: String::from("value1"),
                        },
                        KeyValue {
                            key: String::from("key2"),
                            value: String::from("value2"),
                        },
                    ],
                },
                GuestEvent::CloseSpan { id: 1, tsc: 200 },
                GuestEvent::LogEvent {
                    parent_id: 1,
                    name: String::from("log1"),
                    tsc: 150,
                    fields: vec![KeyValue {
                        key: String::from("log_key1"),
                        value: String::from("log_value1"),
                    }],
                },
                GuestEvent::OpenSpan {
                    id: 2,
                    parent_id: Some(1),
                    name: String::from("span2"),
                    target: String::from("target2"),
                    tsc: 250,
                    fields: vec![KeyValue {
                        key: String::from("keyA"),
                        value: String::from("valueA"),
                    }],
                },
            ];

            let estimated_size = estimate_events(&events);
            let serialized = builder.finish();

            // Check estimated size is within 10%-20% of actual serialized size
            assert!(serialized.len() + ((serialized.len() / 10) as usize) < estimated_size);
            assert!(serialized.len() + ((serialized.len() / 5) as usize) >= estimated_size);
        }

        // Test a builder with multiple events with empty strings yielding expected size
        #[test]
        fn test_estimate_multiple_events_01() {
            let mut builder = GuestTraceDataSerializer::new(0, 2048);
            let events = vec![
                GuestEvent::OpenSpan {
                    id: 1,
                    parent_id: None,
                    name: String::from(""),
                    target: String::from(""),
                    tsc: 100,
                    fields: vec![
                        KeyValue {
                            key: String::from(""),
                            value: String::from(""),
                        },
                        KeyValue {
                            key: String::from(""),
                            value: String::from(""),
                        },
                    ],
                },
                GuestEvent::CloseSpan { id: 1, tsc: 200 },
                GuestEvent::LogEvent {
                    parent_id: 1,
                    name: String::from(""),
                    tsc: 150,
                    fields: vec![KeyValue {
                        key: String::from(""),
                        value: String::from(""),
                    }],
                },
                GuestEvent::OpenSpan {
                    id: 2,
                    parent_id: Some(1),
                    name: String::from(""),
                    target: String::from(""),
                    tsc: 250,
                    fields: vec![KeyValue {
                        key: String::from(""),
                        value: String::from(""),
                    }],
                },
            ];

            let estimated_size = estimate_events(&events);
            let serialized = builder.finish();

            // Check estimated size is within 10%-20% of actual serialized size
            assert!(serialized.len() + ((serialized.len() / 10) as usize) < estimated_size);
            assert!(serialized.len() + ((serialized.len() / 5) as usize) >= estimated_size);
        }

        // Test a builder with multiple events with long strings yielding expected size
        #[test]
        fn test_estimate_multiple_events_02() {
            let mut builder = GuestTraceDataSerializer::new(0, 2048);
            let events = vec![
                GuestEvent::OpenSpan {
                    id: 1,
                    parent_id: None,
                    name: String::from("A".repeat(100)),
                    target: String::from("B".repeat(100)),
                    tsc: 100,
                    fields: vec![
                        KeyValue {
                            key: String::from("C".repeat(50)),
                            value: String::from("D".repeat(50)),
                        },
                        KeyValue {
                            key: String::from("E".repeat(50)),
                            value: String::from("F".repeat(50)),
                        },
                    ],
                },
                GuestEvent::CloseSpan { id: 1, tsc: 200 },
                GuestEvent::LogEvent {
                    parent_id: 1,
                    name: String::from("G".repeat(100)),
                    tsc: 150,
                    fields: vec![KeyValue {
                        key: String::from("H".repeat(50)),
                        value: String::from("I".repeat(50)),
                    }],
                },
                GuestEvent::OpenSpan {
                    id: 2,
                    parent_id: Some(1),
                    name: String::from("J".repeat(100)),
                    target: String::from("K".repeat(100)),
                    tsc: 250,
                    fields: vec![KeyValue {
                        key: String::from("L".repeat(50)),
                        value: String::from("M".repeat(50)),
                    }],
                },
            ];

            let estimated_size = estimate_events(&events);
            let serialized = builder.finish();

            // Check estimated size is within 10%-20% of actual serialized size
            assert!(serialized.len() + ((serialized.len() / 10) as usize) < estimated_size);
            assert!(serialized.len() + ((serialized.len() / 5) as usize) >= estimated_size);
        }
    }
}

pub struct EventsBatchDecoder;

impl EventsDecoder for EventsBatchDecoder {
    fn decode(&self, data: &[u8]) -> Result<Vec<GuestEvent>, Error> {
        let mut cursor = 0;
        let mut events = Vec::new();

        while data.len() - cursor >= 4 {
            let size_bytes = &data[cursor..cursor + 4];
            // The size_bytes is in little-endian format and the while condition ensures there are
            // at least 4 bytes to read.
            let payload_size = u32::from_le_bytes(size_bytes.try_into().unwrap()) as usize;
            let event_size = 4 + payload_size;
            if data.len() - cursor < event_size {
                return Err(anyhow!(
                    "The serialized buffer does not contain a full set of events",
                ));
            }

            let event_slice = &data[cursor..cursor + event_size];
            let event = GuestEvent::try_from(event_slice)?;
            events.push(event);

            cursor += event_size;
        }

        Ok(events)
    }
}

pub type EventsBatchEncoder = EventsBatchEncoderGeneric<fn(&[u8])>;

/// Encoder for batching and serializing guest events into a buffer.
/// When the buffer reaches its capacity, the provided `report_full` callback
/// is invoked with the current buffer contents.
///
/// This encoder uses FlatBuffers for serialization.
/// This encoder is a lossless encoder; no events are dropped.
pub struct EventsBatchEncoderGeneric<T: Fn(&[u8])> {
    /// Internal buffer for serialized events
    buffer: Vec<u8>,
    /// Maximum capacity of the buffer
    capacity: usize,
    /// Callback function to report when the buffer is full
    report_full: T,
    /// Current used capacity of the buffer
    used_capacity: usize,
}

impl<T: Fn(&[u8])> EventsBatchEncoderGeneric<T> {
    /// Create a new EventsBatchEncoder with the specified initial capacity
    pub fn new(initial_capacity: usize, report_full: T) -> Self {
        Self {
            buffer: Vec::with_capacity(initial_capacity),
            capacity: initial_capacity,
            report_full,
            used_capacity: 0,
        }
    }
}

impl<T: Fn(&[u8])> EventsEncoder for EventsBatchEncoderGeneric<T> {
    /// Serialize a single GuestEvent and append it to the internal buffer.
    /// If the appending of the serialized data exceeds buffer capacity, the
    /// `report_full` callback is invoked with the current buffer contents,
    /// and the buffer is cleared for new data.
    fn encode(&mut self, event: &GuestEvent) {
        // TODO: Estimate size more accurately
        let estimated_size = 1024;
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(estimated_size);

        // Serialize the event based on its type
        let ev = match event {
            GuestEvent::OpenSpan {
                id,
                parent_id,
                name,
                target,
                tsc,
                fields,
            } => {
                // Serialize strings
                let name_offset = builder.create_string(name);
                let target_offset = builder.create_string(target);

                // Serialize key-value fields
                let mut field_offsets = Vec::new();
                for field in fields {
                    let field_offset: flatbuffers::WIPOffset<FbKeyValue> = {
                        let key_offset = builder.create_string(&field.key);
                        let value_offset = builder.create_string(&field.value);
                        let kv_args = FbKeyValueArgs {
                            key: Some(key_offset),
                            value: Some(value_offset),
                        };
                        FbKeyValue::create(&mut builder, &kv_args)
                    };
                    field_offsets.push(field_offset);
                }

                // Create fields vector
                let fields_vector = if !field_offsets.is_empty() {
                    Some(builder.create_vector(&field_offsets))
                } else {
                    None
                };

                let ost_args = FbOpenSpanTypeArgs {
                    id: *id,
                    parent: *parent_id,
                    name: Some(name_offset),
                    target: Some(target_offset),
                    tsc: *tsc,
                    fields: fields_vector,
                };

                // Create the OpenSpanType FlatBuffer object
                let ost_fb = FbOpenSpanType::create(&mut builder, &ost_args);

                // Create the GuestEventEnvelopeType
                let guest_event_fb = FbGuestEventType::OpenSpan;
                let envelope_args = FbGuestEventEnvelopeTypeArgs {
                    event_type: guest_event_fb,
                    event: Some(ost_fb.as_union_value()),
                };

                // Create the envelope using the union value
                FbGuestEventEnvelopeType::create(&mut builder, &envelope_args)
            }
            GuestEvent::CloseSpan { id, tsc } => {
                // Create CloseSpanType FlatBuffer object
                let cst_args = FbCloseSpanTypeArgs { id: *id, tsc: *tsc };
                let cst_fb = FbCloseSpanType::create(&mut builder, &cst_args);

                // Create the GuestEventEnvelopeType
                let guest_event_fb = FbGuestEventType::CloseSpan;
                let envelope_args = FbGuestEventEnvelopeTypeArgs {
                    event_type: guest_event_fb,
                    event: Some(cst_fb.as_union_value()),
                };
                // Create the envelope using the union value
                FbGuestEventEnvelopeType::create(&mut builder, &envelope_args)
            }
            GuestEvent::LogEvent {
                parent_id,
                name,
                tsc,
                fields,
            } => {
                // Serialize strings
                let name_offset = builder.create_string(name);

                // Serialize key-value fields
                let mut field_offsets = Vec::new();
                for field in fields {
                    let field_offset: flatbuffers::WIPOffset<FbKeyValue> = {
                        let key_offset = builder.create_string(&field.key);
                        let value_offset = builder.create_string(&field.value);
                        let kv_args = FbKeyValueArgs {
                            key: Some(key_offset),
                            value: Some(value_offset),
                        };
                        FbKeyValue::create(&mut builder, &kv_args)
                    };
                    field_offsets.push(field_offset);
                }

                let fields_vector = if !field_offsets.is_empty() {
                    Some(builder.create_vector(&field_offsets))
                } else {
                    None
                };

                let le_args = FbLogEventTypeArgs {
                    parent_id: *parent_id,
                    name: Some(name_offset),
                    tsc: *tsc,
                    fields: fields_vector,
                };

                let le_fb = FbLogEventType::create(&mut builder, &le_args);

                // Create the GuestEventEnvelopeType
                let guest_event_fb = FbGuestEventType::LogEvent;
                let envelope_args = FbGuestEventEnvelopeTypeArgs {
                    event_type: guest_event_fb,
                    event: Some(le_fb.as_union_value()),
                };
                // Create the envelope using the union value
                FbGuestEventEnvelopeType::create(&mut builder, &envelope_args)
            }
            GuestEvent::EditSpan { id, fields } => {
                // Serialize key-value fields
                let mut field_offsets = Vec::new();
                for field in fields {
                    let field_offset: flatbuffers::WIPOffset<FbKeyValue> = {
                        let key_offset = builder.create_string(&field.key);
                        let value_offset = builder.create_string(&field.value);
                        let kv_args = FbKeyValueArgs {
                            key: Some(key_offset),
                            value: Some(value_offset),
                        };
                        FbKeyValue::create(&mut builder, &kv_args)
                    };
                    field_offsets.push(field_offset);
                }

                // Create fields vector
                let fields_vector = if !field_offsets.is_empty() {
                    Some(builder.create_vector(&field_offsets))
                } else {
                    None
                };

                let est_args = FbEditSpanTypeArgs {
                    id: *id,
                    fields: fields_vector,
                };

                let es_fb = FbEditSpanType::create(&mut builder, &est_args);

                // Create the GuestEventEnvelopeType
                let guest_event_fb = FbGuestEventType::EditSpan;
                let envelope_args = FbGuestEventEnvelopeTypeArgs {
                    event_type: guest_event_fb,
                    event: Some(es_fb.as_union_value()),
                };

                FbGuestEventEnvelopeType::create(&mut builder, &envelope_args)
            }
            GuestEvent::GuestStart { .. } => {
                let gst_args = FbGuestStartTypeArgs { tsc: 0 };
                let gs_fb = FbGuestStartType::create(&mut builder, &gst_args);
                // Create the GuestEventEnvelopeType
                let guest_event_fb = FbGuestEventType::GuestStart;
                let envelope_args = FbGuestEventEnvelopeTypeArgs {
                    event_type: guest_event_fb,
                    event: Some(gs_fb.as_union_value()),
                };

                FbGuestEventEnvelopeType::create(&mut builder, &envelope_args)
            }
        };

        builder.finish_size_prefixed(ev, None);
        let serialized = builder.finished_data();

        // Check if adding this event would exceed capacity
        if self.used_capacity + serialized.len() > self.capacity {
            (self.report_full)(&self.buffer);
            self.buffer.clear();
            self.used_capacity = 0;
        }
        // Append serialized data to buffer
        self.buffer.extend_from_slice(serialized);
        self.used_capacity += serialized.len();
    }

    /// Get a reference to the internal buffer containing serialized events.
    /// This buffer can be sent or processed as needed.
    fn finish(&self) -> &[u8] {
        &self.buffer
    }

    /// Flush the internal buffer by invoking the `report_full` callback
    /// with the current buffer contents, then resetting the buffer.
    fn flush(&mut self) {
        if !self.buffer.is_empty() {
            (self.report_full)(&self.buffer);
            self.reset();
        }
    }
    /// Reset the internal buffer, clearing all serialized data.
    /// This prepares the encoder for new events.
    fn reset(&mut self) {
        self.buffer.clear();
        self.used_capacity = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outb::{EventKeyValue, GuestEvent};

    /// Utility function to check an original GuestTraceData against a deserialized one
    fn check_fb_guest_trace_data(orig: &[GuestEvent], deserialized: &[GuestEvent]) {
        for (original, deserialized) in orig.iter().zip(deserialized.iter()) {
            match (original, deserialized) {
                (
                    GuestEvent::OpenSpan {
                        id: oid,
                        parent_id: opid,
                        name: oname,
                        target: otarget,
                        tsc: otsc,
                        fields: ofields,
                    },
                    GuestEvent::OpenSpan {
                        id: did,
                        parent_id: dpid,
                        name: dname,
                        target: dtarget,
                        tsc: dtsc,
                        fields: dfields,
                    },
                ) => {
                    assert_eq!(oid, did);
                    assert_eq!(opid, dpid);
                    assert_eq!(oname, dname);
                    assert_eq!(otarget, dtarget);
                    assert_eq!(otsc, dtsc);
                    assert_eq!(ofields.len(), dfields.len());
                    for (o_field, d_field) in ofields.iter().zip(dfields.iter()) {
                        assert_eq!(o_field.key, d_field.key);
                        assert_eq!(o_field.value, d_field.value);
                    }
                }
                (
                    GuestEvent::LogEvent {
                        parent_id: opid,
                        name: oname,
                        tsc: otsc,
                        fields: ofields,
                    },
                    GuestEvent::LogEvent {
                        parent_id: dpid,
                        name: dname,
                        tsc: dtsc,
                        fields: dfields,
                    },
                ) => {
                    assert_eq!(opid, dpid);
                    assert_eq!(oname, dname);
                    assert_eq!(otsc, dtsc);
                    assert_eq!(ofields.len(), dfields.len());
                    for (o_field, d_field) in ofields.iter().zip(dfields.iter()) {
                        assert_eq!(o_field.key, d_field.key);
                        assert_eq!(o_field.value, d_field.value);
                    }
                }
                (
                    GuestEvent::CloseSpan { id: oid, tsc: otsc },
                    GuestEvent::CloseSpan { id: did, tsc: dtsc },
                ) => {
                    assert_eq!(oid, did);
                    assert_eq!(otsc, dtsc);
                }
                _ => panic!("Mismatched event types"),
            }
        }
    }

    #[test]
    fn test_fb_key_value_serialization() {
        let kv = EventKeyValue {
            key: "test_key".to_string(),
            value: "test_value".to_string(),
        };

        let serialized: Vec<u8> = Vec::from(&kv);
        let deserialized: EventKeyValue =
            EventKeyValue::try_from(serialized.as_slice()).expect("Deserialization failed");

        assert_eq!(kv.key, deserialized.key);
        assert_eq!(kv.value, deserialized.value);
    }

    #[test]
    fn test_fb_guest_trace_data_open_span_serialization() {
        let mut serializer = EventsBatchEncoder::new(1024, |_| {});
        let kv1 = EventKeyValue {
            key: "test_key1".to_string(),
            value: "test_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "test_key1".to_string(),
            value: "test_value2".to_string(),
        };

        let events = [
            GuestEvent::GuestStart { tsc: 50 },
            GuestEvent::OpenSpan {
                id: 1,
                parent_id: None,
                name: "span_name".to_string(),
                target: "span_target".to_string(),
                tsc: 100,
                fields: Vec::from([kv1, kv2]),
            },
        ];

        for event in &events {
            serializer.encode(event);
        }

        let serialized = serializer.finish();

        let deserialized: Vec<GuestEvent> = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    #[test]
    fn test_fb_guest_trace_data_close_span_serialization() {
        let events = [GuestEvent::CloseSpan { id: 1, tsc: 200 }];

        let mut serializer = EventsBatchEncoder::new(1024, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();

        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    #[test]
    fn test_fb_guest_trace_data_log_event_serialization() {
        let kv1 = EventKeyValue {
            key: "log_key1".to_string(),
            value: "log_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "log_key2".to_string(),
            value: "log_value2".to_string(),
        };

        let events = [GuestEvent::LogEvent {
            parent_id: 2,
            name: "log_name".to_string(),
            tsc: 300,
            fields: Vec::from([kv1, kv2]),
        }];

        let mut serializer = EventsBatchEncoder::new(1024, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();

        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    /// Test serialization and deserialization of GuestTraceData with multiple events
    /// [OpenSpan, LogEvent, CloseSpan]
    #[test]
    fn test_fb_guest_trace_data_multiple_events_serialization_0() {
        let kv1 = EventKeyValue {
            key: "span_field1".to_string(),
            value: "span_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "log_field1".to_string(),
            value: "log_value1".to_string(),
        };

        let events = [
            GuestEvent::OpenSpan {
                id: 1,
                parent_id: None,
                name: "span_name".to_string(),
                target: "span_target".to_string(),
                tsc: 100,
                fields: Vec::from([kv1]),
            },
            GuestEvent::LogEvent {
                parent_id: 1,
                name: "log_name".to_string(),
                tsc: 150,
                fields: Vec::from([kv2]),
            },
            GuestEvent::CloseSpan { id: 1, tsc: 200 },
        ];

        let mut serializer = EventsBatchEncoder::new(2048, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();
        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    /// Test serialization and deserialization of GuestTraceData with multiple events
    /// [OpenSpan, LogEvent, OpenSpan, LogEvent, CloseSpan]
    #[test]
    fn test_fb_guest_trace_data_multiple_events_serialization_1() {
        let kv1 = EventKeyValue {
            key: "span_field1".to_string(),
            value: "span_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "log_field1".to_string(),
            value: "log_value1".to_string(),
        };

        let events = [
            GuestEvent::OpenSpan {
                id: 1,
                parent_id: None,
                name: "span_name_1".to_string(),
                target: "span_target_1".to_string(),
                tsc: 100,
                fields: Vec::from([kv1]),
            },
            GuestEvent::OpenSpan {
                id: 2,
                parent_id: Some(1),
                name: "span_name_2".to_string(),
                target: "span_target_2".to_string(),
                tsc: 1000,
                fields: Vec::from([kv2.clone()]),
            },
            GuestEvent::LogEvent {
                parent_id: 1,
                name: "log_name_1".to_string(),
                tsc: 150,
                fields: Vec::from([kv2.clone()]),
            },
            GuestEvent::LogEvent {
                parent_id: 2,
                name: "log_name".to_string(),
                tsc: 1050,
                fields: Vec::from([kv2]),
            },
            GuestEvent::CloseSpan { id: 2, tsc: 2000 },
        ];

        let mut serializer = EventsBatchEncoder::new(4096, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();
        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }
}
