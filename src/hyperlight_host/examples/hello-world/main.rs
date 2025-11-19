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
#![allow(clippy::disallowed_macros)]
use std::thread;

use hyperlight_host::func::{ParameterValue, ReturnType, ReturnValue};
use hyperlight_host::sandbox::SandboxConfiguration;
#[cfg(gdb)]
use hyperlight_host::sandbox::config::DebugInfo;
use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};

fn main() -> hyperlight_host::Result<()> {
    let mut cfg = SandboxConfiguration::default();
    // In local tests, 256 KiB stack seemed sufficient for deep recursion
    cfg.set_stack_size(256 * 1024); // 256 KB stack
    #[cfg(gdb)]
    {
        let debug_info = DebugInfo { port: 8080 };
        cfg.set_guest_debug_info(debug_info);
    }

    // Create an uninitialized sandbox with a guest binary
    let mut uninitialized_sandbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        Some(cfg), // default configuration
    )?;

    let max_depth = 178u8; // Example depth for tracing
    let msg = String::from("Hello from fuzzing!");

    // Initialize sandbox to be able to call host functions
    let mut multi_use_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve()?;

    let result = multi_use_sandbox
        .call::<u32>(
            "FuzzGuestTrace", // function must be defined in the guest binary
            (max_depth as u32, msg),
        )
        .unwrap();

    Ok(())
}
