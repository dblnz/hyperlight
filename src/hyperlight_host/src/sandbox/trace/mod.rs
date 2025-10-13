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

#[cfg(feature = "mem_profile")]
use {
    crate::hypervisor::arch::X86_64Regs,
    crate::mem::layout::SandboxMemoryLayout,
    crate::mem::mgr::SandboxMemoryManager,
    crate::mem::shared_mem::HostSharedMemory,
    crate::{Result, new_error},
    fallible_iterator::FallibleIterator,
    framehop::Unwinder,
    std::io::Write,
    std::sync::{Arc, Mutex},
};

/// The type of trace frame being recorded.
/// This is used to identify the type of frame being recorded in the trace file.
#[cfg(feature = "mem_profile")]
enum TraceFrameType {
    /// A frame that records a memory allocation.
    MemAlloc = 2,
    /// A frame that records a memory free.
    MemFree = 3,
}
/// This structure handles the memory profiling trace information.
#[cfg(feature = "mem_profile")]
struct GuestMemProfileProcessor {
    /// The file to which the trace is being written
    pub file: Arc<Mutex<std::fs::File>>,
    /// The unwind information for the current guest
    #[allow(dead_code)]
    pub unwind_module: Arc<dyn crate::mem::exe::UnwindInfo>,
    /// The framehop unwinder for the current guest
    pub unwinder: framehop::x86_64::UnwinderX86_64<Vec<u8>>,
    /// The framehop cache
    pub unwind_cache: Arc<Mutex<framehop::x86_64::CacheX86_64>>,
}

#[cfg(feature = "mem_profile")]
impl GuestMemProfileProcessor {
    fn new(
        unwind_module: Arc<dyn crate::mem::exe::UnwindInfo>,
        start_instant: std::time::Instant,
    ) -> Result<Self> {
        let mut path = std::env::current_dir()?;
        path.push("trace");

        // create directory if it does not exist
        if !path.exists() {
            std::fs::create_dir(&path)?;
        }
        path.push(uuid::Uuid::new_v4().to_string());
        path.set_extension("trace");

        log::info!("Creating trace file at: {}", path.display());
        println!("Creating trace file at: {}", path.display());

        let hash = unwind_module.hash();
        let (unwinder, unwind_cache) = {
            let mut unwinder = framehop::x86_64::UnwinderX86_64::new();
            unwinder.add_module(unwind_module.clone().as_module());
            let cache = framehop::x86_64::CacheX86_64::new();
            (unwinder, Arc::new(Mutex::new(cache)))
        };

        let ret = Self {
            file: Arc::new(Mutex::new(std::fs::File::create_new(path)?)),
            unwind_module,
            unwinder,
            unwind_cache,
        };

        /* write a frame identifying the binary */
        ret.record_trace_frame(start_instant, 0, |f| {
            let _ = f.write_all(hash.as_bytes());
        })?;

        Ok(ret)
    }

    fn unwind(
        &self,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<Vec<u64>> {
        let mut read_stack = |addr| {
            mem_mgr
                .shared_mem
                .read::<u64>((addr - SandboxMemoryLayout::BASE_ADDRESS as u64) as usize)
                .map_err(|_| ())
        };
        let mut cache = self
            .unwind_cache
            .try_lock()
            .map_err(|e| new_error!("could not lock unwinder cache {}\n", e))?;
        let iter = self.unwinder.iter_frames(
            regs.rip,
            framehop::x86_64::UnwindRegsX86_64::new(regs.rip, regs.rsp, regs.rbp),
            &mut *cache,
            &mut read_stack,
        );
        iter.map(|f| Ok(f.address() - mem_mgr.layout.get_guest_code_address() as u64))
            .collect()
            .map_err(|e| new_error!("couldn't unwind: {}", e))
    }

    fn write_stack(&self, out: &mut std::fs::File, stack: &[u64]) {
        let _ = out.write_all(&stack.len().to_ne_bytes());
        for frame in stack {
            let _ = out.write_all(&frame.to_ne_bytes());
        }
    }

    fn record_trace_frame<F: FnOnce(&mut std::fs::File)>(
        &self,
        start_instant: std::time::Instant,
        frame_id: u64,
        write_frame: F,
    ) -> Result<()> {
        let Ok(mut out) = self.file.lock() else {
            return Ok(());
        };
        // frame structure:
        // 16 bytes timestamp
        let now = std::time::Instant::now().saturating_duration_since(start_instant);
        let _ = out.write_all(&now.as_micros().to_ne_bytes());
        // 8 bytes frame type id
        let _ = out.write_all(&frame_id.to_ne_bytes());
        // frame data
        write_frame(&mut out);
        Ok(())
    }

    fn handle_trace(
        &self,
        start_instant: std::time::Instant,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
        trace_identifier: TraceFrameType,
    ) -> Result<()> {
        let Ok(stack) = self.unwind(regs, mem_mgr) else {
            return Ok(());
        };

        let amt = regs.rax;
        let ptr = regs.rcx;

        self.record_trace_frame(start_instant, trace_identifier as u64, |f| {
            let _ = f.write_all(&ptr.to_ne_bytes());
            let _ = f.write_all(&amt.to_ne_bytes());
            self.write_stack(f, &stack);
        })
    }

    fn handle_trace_mem_alloc(
        &self,
        start_instant: std::time::Instant,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        self.handle_trace(start_instant, regs, mem_mgr, TraceFrameType::MemAlloc)
    }

    fn handle_trace_mem_free(
        &self,
        start_instant: std::time::Instant,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        self.handle_trace(start_instant, regs, mem_mgr, TraceFrameType::MemFree)
    }
}

/// The information that trace collection requires in order to write
/// an accurate trace.
pub(crate) struct TraceInfo {
    /// The epoch against which trace events are timed; at least as
    /// early as the creation of the sandbox being traced.
    #[cfg(feature = "mem_profile")]
    epoch: std::time::Instant,
    #[cfg(feature = "mem_profile")]
    mem_profile: GuestMemProfileProcessor,
}

impl TraceInfo {
    /// Create a new TraceInfo by saving the current time as the epoch
    /// and generating a random filename.
    pub(crate) fn new(
        #[cfg(feature = "mem_profile")] unwind_module: Arc<dyn crate::mem::exe::UnwindInfo>,
    ) -> crate::Result<Self> {
        #[cfg(feature = "mem_profile")]
        let epoch = std::time::Instant::now();
        Ok(Self {
            #[cfg(feature = "mem_profile")]
            epoch,
            #[cfg(feature = "mem_profile")]
            mem_profile: GuestMemProfileProcessor::new(unwind_module, epoch)?,
        })
    }

    #[inline(always)]
    #[cfg(feature = "mem_profile")]
    pub(crate) fn handle_trace_mem_alloc(
        &self,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        self.mem_profile
            .handle_trace_mem_alloc(self.epoch, regs, mem_mgr)
    }

    #[inline(always)]
    #[cfg(feature = "mem_profile")]
    pub(crate) fn handle_trace_mem_free(
        &self,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        self.mem_profile
            .handle_trace_mem_free(self.epoch, regs, mem_mgr)
    }
}
