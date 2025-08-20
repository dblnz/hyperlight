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

use core::arch::asm;
use core::ffi::{CStr, c_char};
use tracing::{instrument, Span};

use hyperlight_common::outb::OutBAction;

/// Halt the execution of the guest and returns control to the host.
#[inline(never)]
#[hyperlight_guest_tracing::trace_function]
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub fn halt() {
    // Ensure all tracing data is flushed before halting
    hyperlight_guest_tracing::flush!();
    #[cfg(feature = "std_trace_guest")]
    {
        hyperlight_guest_tracing::end_trace();
        if let Some(tbi) = hyperlight_guest_tracing::guest_trace_info() {
            // If tracing is not enabled, we can directly halt
            unsafe { 
                asm!("hlt",
                    in("r8") OutBAction::TraceBatch as u64,
                    in("r9") tbi.spans_ptr,
                    in("r10") tbi.guest_start_tsc,
                    options(nostack)
                )
            };
        } else {
            // If tracing is not enabled, we can directly halt
            unsafe { asm!("hlt", options(nostack)) };
        }
    }

    #[cfg(not(feature = "std_trace_guest"))]
    {
        // If tracing is not enabled, we can directly halt
        unsafe { asm!("hlt", options(nostack)) };
    }
}

/// Exits the VM with an Abort OUT action and code 0.
#[unsafe(no_mangle)]
#[hyperlight_guest_tracing::trace_function]
pub extern "C" fn abort() -> ! {
    abort_with_code(&[0, 0xFF])
}

/// Exits the VM with an Abort OUT action and a specific code.
#[hyperlight_guest_tracing::trace_function]
pub fn abort_with_code(code: &[u8]) -> ! {
    #[cfg(feature = "std_trace_guest")]
    hyperlight_guest_tracing::end_trace();
    outb(OutBAction::Abort as u16, code);
    outb(OutBAction::Abort as u16, &[0xFF]); // send abort terminator (if not included in code)
    unreachable!()
}

/// Aborts the program with a code and a message.
///
/// # Safety
/// This function is unsafe because it dereferences a raw pointer.
#[hyperlight_guest_tracing::trace_function]
pub unsafe fn abort_with_code_and_message(code: &[u8], message_ptr: *const c_char) -> ! {
    #[cfg(feature = "std_trace_guest")]
    hyperlight_guest_tracing::end_trace();
    unsafe {
        // Step 1: Send abort code (typically 1 byte, but `code` allows flexibility)
        outb(OutBAction::Abort as u16, code);

        // Step 2: Convert the C string to bytes
        let message_bytes = CStr::from_ptr(message_ptr).to_bytes(); // excludes null terminator

        // Step 3: Send the message itself in chunks
        outb(OutBAction::Abort as u16, message_bytes);

        // Step 4: Send abort terminator to signal completion (e.g., 0xFF)
        outb(OutBAction::Abort as u16, &[0xFF]);

        // This function never returns
        unreachable!()
    }
}

/// OUT bytes to the host through multiple exits.
#[hyperlight_guest_tracing::trace_function]
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn outb(port: u16, data: &[u8]) {
    // Ensure all tracing data is flushed before sending OUT bytes
    hyperlight_guest_tracing::flush!();
    unsafe {
        let mut i = 0;
        while i < data.len() {
            let remaining = data.len() - i;
            let chunk_len = remaining.min(3);
            let mut chunk = [0u8; 4];
            chunk[0] = chunk_len as u8;
            chunk[1..1 + chunk_len].copy_from_slice(&data[i..i + chunk_len]);
            let val = u32::from_le_bytes(chunk);
            out32(port, val);
            i += chunk_len;
        }
    }
}

/// OUT function for sending a 32-bit value to the host.
#[hyperlight_guest_tracing::trace_function]
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub(crate) unsafe fn out32(port: u16, val: u32) {
    #[cfg(feature = "std_trace_guest")]
    {
        let tbi = hyperlight_guest_tracing::guest_trace_info();
        let context: u64 = 0;
        if let Some(tbi) = tbi {
            // If tracing is enabled, send the trace batch info along with the OUT action
            unsafe {
                asm!("out dx, eax",
                    in("dx") port,
                    in("eax") val,
                    in("r8") OutBAction::TraceBatch as u64,
                    in("r9") tbi.spans_ptr,
                    in("r10") tbi.guest_start_tsc,
                    out("r11") context,
                    options(preserves_flags, nomem, nostack)
                )
            };
            unsafe {
                let guest_handler = GUEST_HANDLE.get().unwrap();
            }
            crate::guest_handle::host_comm::
            hyperlight_guest_tracing::import_context(context);
        } else {
            // If tracing is not enabled, just send the value
            unsafe { asm!("out dx, eax", in("dx") port, in("eax") val, options(preserves_flags, nomem, nostack)) };
        }
    }
    #[cfg(not(feature = "std_trace_guest"))]
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") val, options(preserves_flags, nomem, nostack));
    }
}

/// Prints a message using `OutBAction::DebugPrint`. It transmits bytes of a message
/// through several VMExists and, with such, it is slower than
/// `print_output_with_host_print`.
///
/// This function should be used in debug mode only. This function does not
/// require memory to be setup to be used.
pub fn debug_print(msg: &str) {
    for byte in msg.bytes() {
        unsafe {
            out32(OutBAction::DebugPrint as u16, byte as u32);
        }
    }
}
