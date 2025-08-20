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

/// Re-export the tracing macros
/// This allows users to use the macros without needing to import them explicitly.
///
/// # Tracing Macros Usage
///
/// ## The `trace_function` macro can be used to trace function calls.
///
/// ```rust
/// #[hyperlight_guest_tracing_macro::trace_function]
/// fn my_function() {
/// //     // Function body
/// }
/// ```
///
/// ## The `trace!` macro can be used to create trace records with a message.
///
/// ```rust
/// use hyperlight_guest_tracing_macro::trace;
/// trace!("message");
/// trace!("message", { /* block of code */ });
/// ```
///
/// ## Basic usage: trace with message only
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// trace!("hello");
/// ```
///
/// ## Trace with a block, returning a value
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// let x = trace!("block", { 42 });
/// assert_eq!(x, 42);
/// ```
///
/// ## Trace with a block using local variables
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// let y = 10;
/// let z = trace!("sum", { y + 5 });
/// assert_eq!(z, 15);
/// ```
///
/// ## Trace with a block that returns a reference
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// let s = String::from("abc");
/// let r: &str = trace!("ref", { &s });
/// assert_eq!(r, "abc");
/// ```
///
/// ## Control flow: `return` inside the block returns from the function
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// fn foo() -> i32 {
///     let _ = trace!("fail", {
///         // This return only exits the closure, not the function `foo`.
///         return 42;
///     });
///     assert!(false, "This should not be reached");
/// }
/// ```
///
/// ## Control flow: `break` inside the block exits the outer loop
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// let mut x = 0;
/// for i in 1..3 {
///     x = i;
///     let _ = trace!("msg", {
///         // This break should exit the loop.
///         break;
///     });
/// }
/// assert_eq!(x, 1, "Loop should break after the first iteration");
/// ```
///
/// ## Flush the trace buffer
/// ```rust
/// hyperlight_guest_tracing_macro::flush!();
/// ```
pub use hyperlight_guest_tracing_macro::*;
#[cfg(feature = "std_trace")]
pub use std_trace::{
    GuestEvent, GuestSpan, GuestTraceContext, Spans, TraceBatchInfo, TraceLevel, init_guest_tracing, guest_trace_info, end_trace,
};
#[cfg(feature = "trace")]
pub use trace::{create_trace_record, flush_trace_buffer};

/// Maximum length of a trace message in bytes.
pub const MAX_TRACE_MSG_LEN: usize = 64;

#[derive(Debug, Copy, Clone)]
/// Represents a trace record of a guest with a number of cycles and a message.
pub struct TraceRecord {
    /// The number of CPU cycles returned by the invariant TSC.
    pub cycles: u64,
    /// The length of the message in bytes.
    pub msg_len: usize,
    /// The message associated with the trace record.
    pub msg: [u8; MAX_TRACE_MSG_LEN],
}

/// Module for checking invariant TSC support and reading the timestamp counter
pub mod invariant_tsc {
    use core::arch::x86_64::{__cpuid, _rdtsc};

    /// Check if the processor supports invariant TSC
    ///
    /// Returns true if CPUID.80000007H:EDX[8] is set, indicating invariant TSC support
    pub fn has_invariant_tsc() -> bool {
        // Check if extended CPUID functions are available
        let max_extended = unsafe { __cpuid(0x80000000) };
        if max_extended.eax < 0x80000007 {
            return false;
        }

        // Query CPUID.80000007H for invariant TSC support
        let cpuid_result = unsafe { __cpuid(0x80000007) };

        // Check bit 8 of EDX register for invariant TSC support
        (cpuid_result.edx & (1 << 8)) != 0
    }

    /// Read the timestamp counter
    ///
    /// This function provides a high-performance timestamp by reading the TSC.
    /// Should only be used when invariant TSC is supported for reliable timing.
    ///
    /// # Safety
    /// This function uses unsafe assembly instructions but is safe to call.
    /// However, the resulting timestamp is only meaningful if invariant TSC is supported.
    pub fn read_tsc() -> u64 {
        unsafe { _rdtsc() }
    }
}

#[cfg(feature = "std_trace")]
mod std_trace {
    extern crate alloc;
    use alloc::sync::{Arc, Weak};
    use core::fmt::Debug;
    use core::str::FromStr;
    // import TryFrom
    use alloc::string::String;
    use core::sync::atomic::{AtomicU64, Ordering};

    use heapless as hl;
    use hyperlight_common::outb::OutBAction;
    use spin::Mutex;
    use tracing_core::field::{Field, Visit};
    use tracing_core::span::{Attributes, Id, Record};
    use tracing_core::subscriber::Subscriber;
    use tracing_core::{Event, Metadata};

    use crate::invariant_tsc;

    const MAX_NO_OF_SPANS: usize = 10;
    const MAX_NO_OF_EVENTS: usize = 10;
    const MAX_NAME_LENGTH: usize = 64;
    const MAX_TARGET_LENGTH: usize = 64;
    const MAX_FIELD_KEY_LENGTH: usize = 32;
    const MAX_FIELD_VALUE_LENGTH: usize = 96;
    const MAX_NO_OF_FIELDS: usize = 8;

    pub type Spans = hl::Vec<
        GuestSpan<MAX_NO_OF_EVENTS, MAX_NAME_LENGTH, MAX_TARGET_LENGTH, MAX_FIELD_KEY_LENGTH, MAX_FIELD_VALUE_LENGTH, MAX_NO_OF_FIELDS>,
        MAX_NO_OF_SPANS,
    >;

    /// Weak reference to the guest state so we can manually trigger export to host
    static GUEST_STATE: spin::Once<Weak<Mutex<GuestState>>> = spin::Once::new();

    pub struct TraceBatchInfo {
        /// The timestamp counter at the start of the guest execution.
        pub guest_start_tsc: u64,
        /// Pointer to the spans in the guest memory.
        pub spans_ptr: u64,
    }

    /// Helper type
    pub type GuestState = TraceState<
        MAX_NO_OF_SPANS,
        MAX_NO_OF_EVENTS,
        MAX_NAME_LENGTH,
        MAX_TARGET_LENGTH,
        MAX_FIELD_KEY_LENGTH,
        MAX_FIELD_VALUE_LENGTH,
        MAX_NO_OF_FIELDS,
    >;

    enum InternalState {
        Tracing,
        Interrupted,
        Finalized,
    }

    pub struct TraceState<
        const SP: usize,
        const EV: usize,
        const N: usize,
        const T: usize,
        const FK: usize,
        const FV: usize,
        const F: usize,
    > {
        // context:
        context: GuestTraceContext,
        state: InternalState,
        mark_for_clearing: bool,
        guest_start_tsc: u64,
        next_id: AtomicU64,
        spans: hl::Vec<GuestSpan<EV, N, T, FK, FV, F>, SP>,
        stack: hl::Vec<u64, SP>,
    }

    pub type HashMap<K, V> = hl::Vec<(K, V), 32>;

    pub struct GuestTraceContext {
        pub metadata: HashMap<hl::String<32>, hl::Vec<hl::String<32>, 32>>,
    }

    impl TryFrom<&[u8]> for GuestTraceContext {
        type Error = alloc::string::FromUtf8Error;
        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            
        }
    }
    struct MetadataExtractor<'a>(pub &'a HashMap<hl::String<32>, hl::Vec<hl::String<32>, 32>>);
    struct MetadataInjector<'a>(pub &'a mut HashMap<hl::String<32>, hl::Vec<hl::String<32>, 32>>);

    use opentelemetry::{global, Context};
    use opentelemetry::propagation::{Extractor, Injector};
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use tracing::Span;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    impl Extractor for MetadataExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            // self.0.get(key).and_then(|v| v.first()).map(|s| s.as_str())
            self.0.iter().find(|(k, _)| k.as_str() == key)
                .and_then(|(_, v)| v.first())
                .map(|s| s.as_str())
        }

        fn keys(&self) -> alloc::vec::Vec<&str> {
            // Collect all keys from the metadata HashMap
            // self.0.keys().map(|k| k.as_str()).collect()
            self.0
                .iter()
                .map(|(k, _)| k.as_str())
                .collect()
        }
    }

    impl Injector for MetadataInjector<'_> {
        fn set(&mut self, key: &str, value: alloc::string::String) {
            // Insert the key-value pair into the metadata HashMap
            if let Some(v) = self.0.iter_mut().find(|(k, _)| k.as_str() == key) {
                let hl_str= hl::String::<32>::from_str(value.as_str()).unwrap();
                v.1.push(hl_str);
            } else {
                let hl_key = hl::String::<32>::from_str(key).unwrap();
                let hl_value = hl::String::<32>::from_str(value.as_str()).unwrap();
                self.0.push((hl::String::<32>::from(hl_key), hl::Vec::from(hl::Vec::from_slice(&[hl_value]).unwrap())));
            }
        }
    }

    impl<
        const SP: usize,
        const EV: usize,
        const N: usize,
        const T: usize,
        const FK: usize,
        const FV: usize,
        const F: usize,
    > TraceState<SP, EV, N, T, FK, FV, F>
    {
        fn new(guest_start_tsc: u64) -> Self {
            Self {
                context: GuestTraceContext {metadata: hl::Vec::new()},
                state: InternalState::Tracing,
                mark_for_clearing: false,
                guest_start_tsc,
                next_id: AtomicU64::new(1),
                spans: hl::Vec::new(),
                stack: hl::Vec::new(),
            }
        }

        fn extract_context(
            &mut self,
        ) -> &[u8] {
            let mut injector = MetadataInjector(&mut self.context.metadata);
            global::get_text_map_propagator(|propagator| {
                propagator.inject_context(&Span::current().context(), &mut injector);
            });
            // Convert the metadata HashMap to a u8 slice
            // I want you to get the metadata as a byte slice, without allocating memory.
            // Just cast the metadata HashMap to a byte slice.
            let len = core::mem::size_of_val(&self.context.metadata);
            let data: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    self.context.metadata.as_ptr() as *const u8,
                    len,
                )
            };

            data
        }

        fn import_context(
            &mut self,
            metadata: &[u8],
        ) {
            // Convert the byte slice back to a metadata HashMap
            let metadata: &HashMap<hl::String<32>, hl::Vec<hl::String<32>, 32>> = unsafe {
                // This doesn't work as the types differ in length
                //core::mem::transmute::<&[u8], HashMap<hl::String<32>, hl::Vec<hl::String<32>, 32>>>(metadata)
                let ptr = metadata.as_ptr() as *mut hl::Vec<(hl::String<32>, hl::Vec<hl::String<32>, 32>), 32>;
                &*ptr
            };
            let extractor = MetadataExtractor(metadata);
            opentelemetry::global::get_text_map_propagator(|propagator| {
                propagator.extract(&extractor)
            });
        }

        fn alloc_id(&self) -> (u64, Id) {
            let n = self.next_id.load(Ordering::Relaxed);
            self.next_id.store(n + 1, Ordering::Relaxed);

            (n, Id::from_u64(n))
        }

        pub fn guest_trace_info(&mut self) -> TraceBatchInfo {
            self.mark_for_clearing = true;
            TraceBatchInfo {
                guest_start_tsc: self.guest_start_tsc,
                spans_ptr: self.spans.as_ptr() as u64,
            }
        }

        // Closes the trace by ending all spans
        // NOTE: This expects an outb call to send the spans to the host.
        fn end_trace(&mut self) {
            self.state = InternalState::Finalized;
            for span in self.spans.iter_mut() {
                if span.end_tsc.is_none() {
                    span.end_tsc = Some(invariant_tsc::read_tsc());
                }
            }

            // Empty the stack
            while self.stack.pop().is_some() {
                // Pop all remaining spans from the stack
            }

            // Mark for clearing when re-entering the VM because we might
            // not enter on the same place as we exited (e.g. halt)
            self.mark_for_clearing = true;
        }

        fn export(&mut self) {
            self.state = InternalState::Interrupted;
            let guest_start_tsc = self.guest_start_tsc;
            let spans_ptr = self.spans.as_ptr() as u64;

            unsafe {
                core::arch::asm!("out dx, al",
                    in("dx") OutBAction::TraceBatch as u16,
                    in("r8") OutBAction::TraceBatch as u64,
                    in("r9") spans_ptr,
                    in("r10") guest_start_tsc,
                );
            }

            self.clear();
        }

        fn verify_and_clear(&mut self) {
            if self.mark_for_clearing {
                self.clear();
                self.mark_for_clearing = false;
            }
        }

        fn clear(&mut self) {
            // used for computing the spans that need to be removed
            let mut ids: hl::Vec<u64, SP> = self.spans.iter().map(|s| s.id).collect();

            for id in self.stack.iter() {
                let position = ids.iter().position(|s| *s == *id).unwrap();
                // remove the span id that is contained in the stack
                ids.remove(position);
            }

            // Remove the spans with the remaining ids
            for id in ids.into_iter() {
                let spans = &mut self.spans;
                let position = spans.iter().position(|s| s.id == id).unwrap();
                spans.remove(position);
            }

            // Remove the events from the remaining spans
            for s in self.spans.iter_mut() {
                s.events.clear();
            }
        }

        pub fn new_span(&mut self, attrs: &Attributes) -> Id {
            self.verify_and_clear();
            let (idn, id) = self.alloc_id();

            let md = attrs.metadata();
            let mut name = hl::String::<N>::new();
            let mut target = hl::String::<T>::new();
            let _ = name.push_str(&md.name()[..usize::min(md.name().len(), name.capacity())]);
            let _ = target.push_str(&md.target()[..usize::min(md.target().len(), target.capacity())]);

            let mut fields = hl::Vec::new();
            attrs.record(&mut FieldsVisitor::<FK, FV, F> { out: &mut fields });

            // Find parent from current stack top (if any)
            let parent_id = self.stack.last().copied();

            let span = GuestSpan::<EV, N, T, FK, FV, F> {
                id: idn,
                parent_id,
                level: (*md.level()).into(),
                name,
                target,
                start_tsc: invariant_tsc::read_tsc(),
                end_tsc: None,
                fields,
                events: hl::Vec::new(),
            };

            let spans = &mut self.spans;
            let _ = spans.push(span);

            // In case the spans Vec is full, we need to report them to the host
            if spans.len() == spans.capacity() {
                self.export();
            }

            id
        }

        pub fn event(&mut self, event: &Event<'_>) {
            self.verify_and_clear();
            let stack = &mut self.stack;
            let parent_id = stack.last().copied().unwrap_or(0);

            let md = event.metadata();
            let mut name = hl::String::<N>::new();
            // Treat error when name is bigger than the space allocated
            let _ = name.push_str(&md.name()[..usize::min(md.name().len(), name.capacity())]);

            let mut fields = hl::Vec::new();
            event.record(&mut FieldsVisitor::<FK, FV, F> { out: &mut fields });

            let ev = GuestEvent {
                level: (*md.level()).into(),
                name,
                tsc: invariant_tsc::read_tsc(),
                fields,
            };

            let spans = &mut self.spans;
            let span = spans.iter_mut().find(|s| s.id == parent_id).expect("There should always be a span");

            let _ = span.events.push(ev);
            // Flush buffer to host if full
            if span.events.len() >= span.events.capacity() {
                self.export();
            }
        }

        fn record(&mut self, id: &Id, values: &Record<'_>) {
            let spans = &mut self.spans;
            if let Some(s) = spans.iter_mut().find(|s| s.id == id.into_u64()) {
                let mut v = hl::Vec::new();
                values.record(&mut FieldsVisitor::<FK, FV, F> { out: &mut v });
                s.fields.extend(v);
            }
        }

        fn enter(&mut self, id: &Id) {
            let st = &mut self.stack;
            let _ = st.push(id.into_u64());
        }

        fn exit(&mut self, _id: &Id) {
            let st = &mut self.stack;
            let _ = st.pop();
        }

        fn try_close(&mut self, id: Id) -> bool {
            let spans = &mut self.spans;
            if let Some(s) = spans.iter_mut().find(|s| s.id == id.into_u64()) {
                s.end_tsc = Some(invariant_tsc::read_tsc());
                true
            } else {
                false
            }
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub enum TraceLevel {
        Error,
        Warn,
        Info,
        Debug,
        Trace,
    }

    impl From<tracing::Level> for TraceLevel {
        fn from(value: tracing::Level) -> Self {
            match value {
                tracing::Level::ERROR => Self::Error,
                tracing::Level::WARN => Self::Warn,
                tracing::Level::INFO => Self::Info,
                tracing::Level::DEBUG => Self::Debug,
                tracing::Level::TRACE => Self::Trace,
            }
        }
    }
    impl Into<tracing::Level> for TraceLevel {
        fn into(self) -> tracing::Level {
            match self {
                Self::Error => tracing::Level::ERROR,
                Self::Warn => tracing::Level::WARN,
                Self::Info => tracing::Level::INFO,
                Self::Debug => tracing::Level::DEBUG,
                Self::Trace => tracing::Level::TRACE,
            }
        }
    }

    pub struct GuestSpan<const EV: usize, const N: usize, const T: usize, const FK: usize, const FV: usize, const F: usize> {
        pub id: u64,
        pub parent_id: Option<u64>,
        pub level: TraceLevel,
        /// Span name
        pub name: hl::String<N>,
        /// Filename
        pub target: hl::String<T>,
        pub start_tsc: u64,
        pub end_tsc: Option<u64>,
        pub fields: hl::Vec<(hl::String<FK>, hl::String<FV>), F>,
        pub events: hl::Vec<GuestEvent<N, FK, FV, F>, EV>,
    }

    pub struct GuestEvent<const N: usize, const FK: usize, const FV: usize, const F: usize> {
        pub level: TraceLevel,
        pub name: hl::String<N>,
        /// Event name
        pub tsc: u64,
        pub fields: hl::Vec<(hl::String<FK>, hl::String<FV>), F>,
    }

    struct FieldsVisitor<'a, const FK: usize, const FV: usize, const F: usize> {
        out: &'a mut hl::Vec<(hl::String<FK>, hl::String<FV>), F>,
    }

    impl<'a, const FK: usize, const FV: usize, const F: usize> Visit for FieldsVisitor<'a, FK, FV, F> {
        fn record_bytes(&mut self, field: &Field, value: &[u8]) {
            let mut k = hl::String::<FK>::new();
            let mut val = hl::String::<FV>::new();
            let _ = k.push_str(&field.name()[..usize::min(field.name().len(), k.capacity())]);
            let _ = val.push_str(&alloc::format!("{value:?}")[..usize::min(value.len(), val.capacity())]);
            let _ = self.out.push((k, val));
        }
        fn record_str(&mut self, f: &Field, v: &str) {
            let mut k = heapless::String::<FK>::new();
            let mut val = heapless::String::<FV>::new();
            let _ = k.push_str(&f.name()[..usize::min(f.name().len(), k.capacity())]);
            let _ = val.push_str(&v[..usize::min(v.len(), val.capacity())]);
            let _ = self.out.push((k, val));
        }
        fn record_debug(&mut self, f: &Field, v: &dyn Debug) {
            use heapless::String;
            let mut k = String::<FK>::new();
            let mut val = String::<FV>::new();
            let _ = k.push_str(&f.name()[..usize::min(f.name().len(), k.capacity())]);
            let v = alloc::format!("{v:?}");
            let _ = val.push_str(&v[..usize::min(v.len(), val.capacity())]);
            let _ = self.out.push((k, val));
        }
    }

    /// This structure holds the tracing state of the guest
    struct GuestSubscriber {
        state: Arc<Mutex<GuestState>>,
    }

    impl GuestSubscriber {
        fn new(guest_start_tsc: u64) -> Self {
            Self {
                state: Arc::new(Mutex::new(GuestState::new(guest_start_tsc))),
            }
        }
        fn state(&self) -> &Arc<Mutex<GuestState>> {
            &self.state
        }
    }

    impl Subscriber for GuestSubscriber {
        fn enabled(&self, _md: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, attrs: &Attributes<'_>) -> Id {
            self.state.lock().new_span(attrs)
        }

        fn record(&self, id: &Id, values: &Record<'_>) {
            self.state.lock().record(id, values)
        }

        fn event(&self, event: &Event<'_>) {
            self.state.lock().event(event)
        }

        fn enter(&self, id: &Id) {
            self.state.lock().enter(id)
        }

        fn exit(&self, id: &Id) {
            self.state.lock().exit(id)
        }

        fn try_close(&self, id: Id) -> bool {
            self.state.lock().try_close(id)
        }

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {
            // no-op: we don't track follows-from relationships
        }
    }

    /// Initialize the guest tracing subscriber as global default.
    pub fn init_guest_tracing(guest_start_tsc: u64) {
        // Set as global default if not already set.
        if tracing_core::dispatcher::has_been_set() {
            return;
        }
        let sub = GuestSubscriber::new(guest_start_tsc);
        let state = sub.state();
        // Store state Weak<GuestState> to use later at runtime
        GUEST_STATE.call_once(|| Arc::downgrade(state));

        // Set global dispatcher
        let _ = tracing_core::dispatcher::set_global_default(tracing_core::Dispatch::new(sub));
    }

    // Flush the trace buffer to send any remaining trace records to the host.
    // This is to be used when the guest is about to exit due to error or normal completion.
    pub fn end_trace() {
        if let Some(w) = GUEST_STATE.get() {
            if let Some(state) = w.upgrade() {
                state.lock().end_trace();
            }
        }
    }

    pub fn guest_trace_info() -> Option<TraceBatchInfo> {
        let mut res = None;
        if let Some(w) = GUEST_STATE.get() {
            if let Some(state) = w.upgrade() {
                res = Some(state.lock().guest_trace_info());
            }
        }
        res
    }

    pub fn import_context(ctx_ptr: u64) {
        if let Some(w) = GUEST_STATE.get() {
            if let Some(state) = w.upgrade() {
                let metadata = unsafe {
                    // SAFETY: The pointer is assumed to be valid and points to a HashMap
                    &*(ctx_ptr as *const HashMap<hl::String<32>, hl::Vec<hl::String<32>, 32>>)
                };
                state.lock().import_context(metadata);
            }
        }
    }
}

#[cfg(feature = "trace")]
mod trace {
    // === Dependencies ===
    extern crate alloc;

    use core::mem::MaybeUninit;

    use hyperlight_common::outb::OutBAction;
    use spin::Mutex;

    use super::{MAX_TRACE_MSG_LEN, TraceRecord, invariant_tsc};

    /// Type alias for the function that sends trace records to the host.
    type SendToHostFn = fn(u64, &[TraceRecord]);

    /// Global trace buffer for storing trace records.
    static TRACE_BUFFER: Mutex<TraceBuffer<SendToHostFn>> =
        Mutex::new(TraceBuffer::new(send_to_host));

    /// Maximum number of entries in the trace buffer.
    /// From local testing, 32 entries seems to be a good balance between performance and memory usage.
    const MAX_NO_OF_ENTRIES: usize = 32;

    impl From<&str> for TraceRecord {
        fn from(mut msg: &str) -> Self {
            if msg.len() > MAX_TRACE_MSG_LEN {
                // If the message is too long, truncate it to fit the maximum length
                msg = &msg[..MAX_TRACE_MSG_LEN];
            }

            let cycles = invariant_tsc::read_tsc();

            TraceRecord {
                cycles,
                msg: {
                    let mut arr = [0u8; MAX_TRACE_MSG_LEN];
                    arr[..msg.len()].copy_from_slice(msg.as_bytes());
                    arr
                },
                msg_len: msg.len(),
            }
        }
    }

    /// A buffer for storing trace records.
    struct TraceBuffer<F: Fn(u64, &[TraceRecord])> {
        /// The entries in the trace buffer.
        entries: [TraceRecord; MAX_NO_OF_ENTRIES],
        /// The index where the next entry will be written.
        write_index: usize,
        /// Function to send the trace records to the host.
        send_to_host: F,
    }

    impl<F: Fn(u64, &[TraceRecord])> TraceBuffer<F> {
        /// Creates a new `TraceBuffer` with uninitialized entries.
        const fn new(f: F) -> Self {
            Self {
                entries: unsafe { [MaybeUninit::zeroed().assume_init(); MAX_NO_OF_ENTRIES] },
                write_index: 0,
                send_to_host: f,
            }
        }

        /// Push a new trace record into the buffer.
        /// If the buffer is full, it sends the records to the host.
        fn push(&mut self, entry: TraceRecord) {
            let mut write_index = self.write_index;

            self.entries[write_index] = entry;
            write_index = (write_index + 1) % MAX_NO_OF_ENTRIES;

            self.write_index = write_index;

            if write_index == 0 {
                // If buffer is full send to host
                (self.send_to_host)(MAX_NO_OF_ENTRIES as u64, &self.entries);
            }
        }

        /// Flush the trace buffer, sending any remaining records to the host.
        fn flush(&mut self) {
            if self.write_index > 0 {
                (self.send_to_host)(self.write_index as u64, &self.entries);
                self.write_index = 0; // Reset write index after flushing
            }
        }
    }

    /// Send the trace records to the host.
    fn send_to_host(len: u64, records: &[TraceRecord]) {
        unsafe {
            core::arch::asm!("out dx, al",
                in("dx") OutBAction::TraceRecord as u16,
                in("rax") len,
                in("rcx") records.as_ptr() as u64);
        }
    }

    /// Create a trace record from the message and push it to the trace buffer.
    ///
    /// **NOTE**: If the message is too long it will be truncated to fit within `MAX_TRACE_MSG_LEN`.
    /// This is useful for ensuring that the trace buffer does not overflow.
    #[inline(always)]
    pub fn create_trace_record(msg: &str) {
        let entry = TraceRecord::from(msg);
        let mut buffer = TRACE_BUFFER.lock();

        buffer.push(entry);
    }

    /// Flush the trace buffer to send any remaining trace records to the host.
    #[inline(always)]
    pub fn flush_trace_buffer() {
        let mut buffer = TRACE_BUFFER.lock();
        buffer.flush();
    }

    #[cfg(test)]
    mod tests {
        use alloc::format;

        use super::*;

        /// This is a mock function for testing purposes.
        /// In a real scenario, this would send the trace records to the host.
        fn mock_send_to_host(_len: u64, _records: &[TraceRecord]) {}

        fn create_test_entry(msg: &str) -> TraceRecord {
            let cycles = invariant_tsc::read_tsc();

            TraceRecord {
                cycles,
                msg: {
                    let mut arr = [0u8; MAX_TRACE_MSG_LEN];
                    arr[..msg.len()].copy_from_slice(msg.as_bytes());
                    arr
                },
                msg_len: msg.len(),
            }
        }

        #[test]
        fn test_push_trace_record() {
            let mut buffer = TraceBuffer::new(mock_send_to_host);

            let msg = "Test message";
            let entry = create_test_entry(msg);

            buffer.push(entry);
            assert_eq!(buffer.write_index, 1);
            assert_eq!(buffer.entries[0].msg_len, msg.len());
            assert_eq!(&buffer.entries[0].msg[..msg.len()], msg.as_bytes());
            assert!(buffer.entries[0].cycles > 0); // Ensure cycles is set
        }

        #[test]
        fn test_flush_trace_buffer() {
            let mut buffer = TraceBuffer::new(mock_send_to_host);

            let msg = "Test message";
            let entry = create_test_entry(msg);

            buffer.push(entry);
            assert_eq!(buffer.write_index, 1);
            assert_eq!(buffer.entries[0].msg_len, msg.len());
            assert_eq!(&buffer.entries[0].msg[..msg.len()], msg.as_bytes());
            assert!(buffer.entries[0].cycles > 0);

            // Flush the buffer
            buffer.flush();

            // After flushing, the entryes should still be intact, we don't clear them
            assert_eq!(buffer.write_index, 0);
            assert_eq!(buffer.entries[0].msg_len, msg.len());
            assert_eq!(&buffer.entries[0].msg[..msg.len()], msg.as_bytes());
            assert!(buffer.entries[0].cycles > 0);
        }

        #[test]
        fn test_auto_flush_on_full() {
            let mut buffer = TraceBuffer::new(mock_send_to_host);

            // Fill the buffer to trigger auto-flush
            for i in 0..MAX_NO_OF_ENTRIES {
                let msg = format!("Message {}", i);
                let entry = create_test_entry(&msg);
                buffer.push(entry);
            }

            // After filling, the write index should be 0 (buffer is full)
            assert_eq!(buffer.write_index, 0);

            // The first entry should still be intact
            assert_eq!(buffer.entries[0].msg_len, "Message 0".len());
        }

        /// Test TraceRecord creation with a valid message
        #[test]
        fn test_trace_record_creation_valid() {
            let msg = "Valid message";
            let entry = TraceRecord::try_from(msg).expect("Failed to create TraceRecord");
            assert_eq!(entry.msg_len, msg.len());
            assert_eq!(&entry.msg[..msg.len()], msg.as_bytes());
            assert!(entry.cycles > 0); // Ensure cycles is set
        }

        /// Test TraceRecord creation with a message that exceeds the maximum length
        #[test]
        fn test_trace_record_creation_too_long() {
            let long_msg = "A".repeat(MAX_TRACE_MSG_LEN + 1);
            let result = TraceRecord::from(long_msg.as_str());
            assert_eq!(result.msg_len, MAX_TRACE_MSG_LEN);
            assert_eq!(
                &result.msg[..MAX_TRACE_MSG_LEN],
                &long_msg.as_bytes()[..MAX_TRACE_MSG_LEN],
            );
        }
    }
}
