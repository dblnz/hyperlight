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

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;

use anyhow::{Error, anyhow};

/// Key-Value pair structure used in tracing spans/events
#[derive(Debug, Clone)]
pub struct EventKeyValue {
    /// Key of the key-value pair
    pub key: String,
    /// Value of the key-value pair
    pub value: String,
}

/// Enum representing different types of guest events for tracing
/// such as opening/closing spans and logging events.
#[derive(Debug)]
pub enum GuestEvent {
    /// Event representing the opening of a new tracing span.
    OpenSpan {
        /// Unique identifier for the span.
        /// This ID is used to correlate open and close events.
        /// It should be unique within the context of a sandboxed guest execution.
        id: u64,
        /// Optional parent span ID, if this span is nested within another span.
        parent_id: Option<u64>,
        /// Name of the span.
        name: String,
        /// Target associated with the span.
        target: String,
        /// Timestamp Counter (TSC) value when the span was opened.
        tsc: u64,
        /// Additional key-value fields associated with the span.
        fields: Vec<EventKeyValue>,
    },
    /// Event representing the closing of a tracing span.
    CloseSpan {
        /// Unique identifier for the span being closed.
        id: u64,
        /// Timestamp Counter (TSC) value when the span was closed.
        tsc: u64,
    },
    /// Event representing a log entry within a tracing span.
    LogEvent {
        /// Identifier of the parent span for this log event.
        parent_id: u64,
        /// Name of the log event.
        name: String,
        /// Timestamp Counter (TSC) value when the log event occurred.
        tsc: u64,
        /// Additional key-value fields associated with the log event.
        fields: Vec<EventKeyValue>,
    },
    /// Event representing an edit to an existing span.
    /// Corresponds to the `record` method in the tracing subscriber trait.
    EditSpan {
        /// Unique identifier for the span to edit.
        id: u64,
        /// Fields to add or modify in the span.
        fields: Vec<EventKeyValue>,
    },
    /// Event representing the start of the guest environment.
    GuestStart {
        /// Timestamp Counter (TSC) value when the guest started.
        tsc: u64,
    },
}

/// Trait defining the interface for encoding guest events.
/// Implementors of this trait should provide methods for encoding events,
/// finishing the encoding process, flushing the buffer, and resetting the encoder.
pub trait EventsEncoder {
    /// Encode a single guest event into the encoder's buffer.
    fn encode(&mut self, event: &GuestEvent);
    /// Finalize the encoding process and return the serialized buffer.
    fn finish(&self) -> &[u8];
    /// Flush the encoder's buffer, typically sending or processing the data.
    fn flush(&mut self);
    /// Reset the encoder's internal state, clearing any buffered data.
    fn reset(&mut self);
}

/// Trait defining the interface for decoding guest events.
/// Implementors of this trait should provide methods for decoding a buffer
/// of bytes into a collection of guest events.
pub trait EventsDecoder {
    /// Decode a buffer of bytes into guest events.
    fn decode(&self, buffer: &[u8]) -> Result<Vec<GuestEvent>, Error>;
}

/// Exception codes for the x86 architecture.
/// These are helpful to identify the type of exception that occurred
/// together with OutBAction::Abort.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Exception {
    DivideByZero = 0,
    Debug = 1,
    NonMaskableInterrupt = 2,
    Breakpoint = 3,
    Overflow = 4,
    BoundRangeExceeded = 5,
    InvalidOpcode = 6,
    DeviceNotAvailable = 7,
    DoubleFault = 8,
    CoprocessorSegmentOverrun = 9,
    InvalidTSS = 10,
    SegmentNotPresent = 11,
    StackSegmentFault = 12,
    GeneralProtectionFault = 13,
    PageFault = 14,
    Reserved = 15,
    X87FloatingPointException = 16,
    AlignmentCheck = 17,
    MachineCheck = 18,
    SIMDFloatingPointException = 19,
    VirtualizationException = 20,
    SecurityException = 30,
    NoException = 0xFF,
}

impl TryFrom<u8> for Exception {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use Exception::*;
        let exception = match value {
            0 => DivideByZero,
            1 => Debug,
            2 => NonMaskableInterrupt,
            3 => Breakpoint,
            4 => Overflow,
            5 => BoundRangeExceeded,
            6 => InvalidOpcode,
            7 => DeviceNotAvailable,
            8 => DoubleFault,
            9 => CoprocessorSegmentOverrun,
            10 => InvalidTSS,
            11 => SegmentNotPresent,
            12 => StackSegmentFault,
            13 => GeneralProtectionFault,
            14 => PageFault,
            15 => Reserved,
            16 => X87FloatingPointException,
            17 => AlignmentCheck,
            18 => MachineCheck,
            19 => SIMDFloatingPointException,
            20 => VirtualizationException,
            30 => SecurityException,
            0xFF => NoException,
            _ => return Err(anyhow!("Unknown exception code: {:#x}", value)),
        };

        Ok(exception)
    }
}

/// Supported actions when issuing an OUTB actions by Hyperlight.
/// - Log: for logging,
/// - CallFunction: makes a call to a host function,
/// - Abort: aborts the execution of the guest,
/// - DebugPrint: prints a message to the host
/// - TraceBatch: reports a batch of spans and events from the guest
/// - TraceMemoryAlloc: records memory allocation events
/// - TraceMemoryFree: records memory deallocation events
pub enum OutBAction {
    Log = 99,
    CallFunction = 101,
    Abort = 102,
    DebugPrint = 103,
    #[cfg(feature = "trace_guest")]
    TraceBatch = 104,
    #[cfg(feature = "mem_profile")]
    TraceMemoryAlloc = 105,
    #[cfg(feature = "mem_profile")]
    TraceMemoryFree = 106,
}

impl TryFrom<u16> for OutBAction {
    type Error = anyhow::Error;
    fn try_from(val: u16) -> anyhow::Result<Self> {
        match val {
            99 => Ok(OutBAction::Log),
            101 => Ok(OutBAction::CallFunction),
            102 => Ok(OutBAction::Abort),
            103 => Ok(OutBAction::DebugPrint),
            #[cfg(feature = "trace_guest")]
            104 => Ok(OutBAction::TraceBatch),
            #[cfg(feature = "mem_profile")]
            105 => Ok(OutBAction::TraceMemoryAlloc),
            #[cfg(feature = "mem_profile")]
            106 => Ok(OutBAction::TraceMemoryFree),
            _ => Err(anyhow::anyhow!("Invalid OutBAction value: {}", val)),
        }
    }
}
