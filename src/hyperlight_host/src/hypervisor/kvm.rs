/*
Copyright 2024 The Hyperlight Authors.

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

use std::convert::TryFrom;
use std::fmt::Debug;
use std::sync::Arc;
#[cfg(gdb)]
use std::sync::Mutex;

use debug::KvmDebug;
use kvm_bindings::{kvm_fpu, kvm_regs, kvm_userspace_memory_region, KVM_MEM_READONLY};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use tracing::{instrument, Span};

use super::fpu::{FP_CONTROL_WORD_DEFAULT, FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
#[cfg(gdb)]
use super::gdb::{self, kvm_target::HyperlightSandboxTarget, GdbConnection};
use super::handlers::{DbgMemAccessHandlerWrapper, MemAccessHandlerWrapper, OutBHandlerWrapper};
use super::{
    HyperlightExit, Hypervisor, VirtualCPU, CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP,
    CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_PAE, EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};
use crate::hypervisor::gdb::DebugAction;
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::ptr::{GuestPtr, RawPtr};
#[cfg(gdb)]
use crate::mem::{mgr::SandboxMemoryManager, shared_mem::GuestSharedMemory};
use crate::{log_then_return, new_error, Result};

/// Return `true` if the KVM API is available, version 12, and has UserMemory capability, or `false` otherwise
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    if let Ok(kvm) = Kvm::new() {
        let api_version = kvm.get_api_version();
        match api_version {
            version if version == 12 && kvm.check_extension(UserMemory) => true,
            12 => {
                log::info!("KVM does not have KVM_CAP_USER_MEMORY capability");
                false
            }
            version => {
                log::info!("KVM GET_API_VERSION returned {}, expected 12", version);
                false
            }
        }
    } else {
        log::info!("Error creating KVM object");
        false
    }
}

#[cfg(gdb)]
mod debug {
    use std::{collections::HashMap, sync::{Arc, Mutex}};

    use crate::{hypervisor::{gdb::{DebugAction, VcpuStopReason}, handlers::DbgMemAccessHandlerCaller}, mem::{layout::SandboxMemoryLayout, mgr::SandboxMemoryManager, shared_mem::{GuestSharedMemory, SharedMemory}}, new_error, HyperlightError};

    use super::KVMDriver;
    use hyperlight_common::mem::PAGE_SIZE;
    use kvm_bindings::{
        kvm_guest_debug, kvm_regs, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP,
        KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP,
    };
    use super::gdb::{GdbTargetError, X86_64Regs};
    use kvm_ioctls::VcpuFd;

    /// Software Breakpoint size in memory
    pub const SW_BP_SIZE: usize = 1;
    /// Software Breakpoinnt opcode
    const SW_BP_OP: u8 = 0xCC;
    /// Software Breakpoint written to memory
    pub const SW_BP: [u8; SW_BP_SIZE] = [SW_BP_OP];

    /// KVM Debug struct
    /// This struct is used to abstract the internal details of the kvm
    /// guest debugging settings
    pub struct KvmDebug {
        /// vCPU stepping state
        single_step: bool,

        /// Array of addresses for HW breakpoints
        hw_breakpoints: Vec<u64>,
        /// Array of addresses for SW breakpoints
        sw_breakpoints: HashMap<u64, [u8; SW_BP_SIZE]>,

        /// Sent to KVM for enabling guest debug
        pub dbg_cfg: kvm_guest_debug,
    }

    impl KvmDebug {
        const MAX_NO_OF_HW_BP: usize = 4;

        pub fn new() -> Self {
            let dbg = kvm_guest_debug {
                control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
                ..Default::default()
            };

            Self {
                single_step: false,
                hw_breakpoints: vec![],
                sw_breakpoints: HashMap::new(),
                dbg_cfg: dbg
            }
        }

        /// Method to set the kvm debugreg fields for breakpoints
        /// The maximum number of supported breakpoints is `Self::MAX_NO_OF_HW_BP`
        pub fn set_breakpoints(
            &mut self,
            vcpu_fd: &VcpuFd, 
            step: bool,
        ) -> Result<bool, GdbTargetError> {
            let addrs: &[u64] = &self.hw_breakpoints;

            if addrs.len() >= Self::MAX_NO_OF_HW_BP {
                return Ok(false);
            }

            self.dbg_cfg.arch.debugreg = [0; 8];
            for (k, addr) in addrs.iter().enumerate() {
                self.dbg_cfg.arch.debugreg[k] = *addr;
                self.dbg_cfg.arch.debugreg[7] |= 1 << (k * 2);
            }

            if !addrs.is_empty() {
                self.dbg_cfg.control |= KVM_GUESTDBG_USE_HW_BP;
            } else {
                self.dbg_cfg.control &= !KVM_GUESTDBG_USE_HW_BP;
            }

            if step {
                self.dbg_cfg.control |= KVM_GUESTDBG_SINGLESTEP;
            } else {
                self.dbg_cfg.control &= !KVM_GUESTDBG_SINGLESTEP;
            }

            log::debug!("Setting bp: {:?} cfg: {:?}", addrs, self.dbg_cfg);
            vcpu_fd
                .set_guest_debug(&self.dbg_cfg)
                .map_err(|_| GdbTargetError::SetGuestDebugError)?;

            self.single_step = step;

            Ok(true)
        }
    }

    impl KVMDriver {
        /// Returns the instruction pointer from the stopped vCPU
        pub fn get_instruction_pointer(&self) -> Result<u64, GdbTargetError> {
            let regs = self
                .vcpu_fd
                .get_regs()
                .map_err(|_| GdbTargetError::InstructionPointerError)?;

            Ok(regs.rip)
        }

        pub fn set_single_step(&mut self, enable: bool) -> Result<(), GdbTargetError> {
            self.debug
                .set_breakpoints(&self.vcpu_fd, enable)?;

            Ok(())
        }

        /// This method provides a way to set a breakpoint at the entrypoint
        /// it does not keep this breakpoint set after the vcpu already stopped at the address
        pub fn set_entrypoint_bp(&mut self) -> Result<bool, GdbTargetError> {
            log::debug!("Setting entrypoint bp {:X}", self.entrypoint);
            let mut entrypoint_debug = KvmDebug::new();
            entrypoint_debug.hw_breakpoints.push(self.entrypoint);
            entrypoint_debug.set_breakpoints(&self.vcpu_fd, false)
        }

        /// Translates the guest address to physical address
        fn translate_gva(&self, gva: u64) -> Result<u64, GdbTargetError> {
            let tr = self
                .vcpu_fd
                .translate_gva(gva)
                .map_err(|_| GdbTargetError::InvalidGva(gva))?;

            if tr.valid == 0 {
                Err(GdbTargetError::InvalidGva(gva))
            } else {
                Ok(tr.physical_address)
            }
        }

        pub fn read_addrs(
            &mut self,
            mut gva: u64,
            mut data: &mut [u8],
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
            ) -> Result<(), HyperlightError> {

            let data_len = data.len();
            log::debug!("Read addr: {:X} len: {:X}", gva, data_len);
        

            while !data.is_empty() {
                let gpa = self.translate_gva(gva).map_err(|_| new_error!("Couldn't translate gva"))?;

                let read_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );
                let offset = gpa as usize - SandboxMemoryLayout::BASE_ADDRESS;

                dbg_mem_access_fn
                    .clone()
                    .try_lock()
                    .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                    .read(offset as usize, &mut data[..read_len])?;

                data = &mut data[read_len..];
                gva += read_len as u64;
            }
        
            log::debug!("data before after {:?}", data);

            Ok(())
        }
        
        pub fn write_addrs(
            &mut self,
            mut gva: u64,
            mut data: &[u8],
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,

            ) -> Result<(), HyperlightError> {
            let data_len = data.len();
            log::debug!("Write addr: {:X} len: {:X}", gva, data_len);
        
            while !data.is_empty() {
                let gpa = self.translate_gva(gva).map_err(|_| new_error!("Couldn't translate gva"))?;

                let write_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );
                let offset = gpa as usize - SandboxMemoryLayout::BASE_ADDRESS;

                dbg_mem_access_fn
                    .clone()
                    .try_lock()
                    .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                    .write(offset as usize, data)?;

                data = &data[write_len..];
                gva += write_len as u64;
            }
        

            Ok(())
        }

        pub fn read_regs(&self, regs: &mut X86_64Regs) -> Result<(), GdbTargetError> {
            log::debug!("Read registers");
            let vcpu_regs = self
                .vcpu_fd
                .get_regs()
                .map_err(|_| GdbTargetError::ReadRegistersError)?;

            regs.rax = vcpu_regs.rax;
            regs.rbx = vcpu_regs.rbx;
            regs.rcx = vcpu_regs.rcx;
            regs.rdx = vcpu_regs.rdx;
            regs.rsi = vcpu_regs.rsi;
            regs.rdi = vcpu_regs.rdi;
            regs.rbp = vcpu_regs.rbp;
            regs.rsp = vcpu_regs.rsp;
            regs.r8 = vcpu_regs.r8;
            regs.r9 = vcpu_regs.r9;
            regs.r10 = vcpu_regs.r10;
            regs.r11 = vcpu_regs.r11;
            regs.r12 = vcpu_regs.r12;
            regs.r13 = vcpu_regs.r13;
            regs.r14 = vcpu_regs.r14;
            regs.r15 = vcpu_regs.r15;

            regs.rip = vcpu_regs.rip;

            regs.rflags =
                u64::try_from(vcpu_regs.rflags).map_err(|_| GdbTargetError::ReadRegistersError)?;

            Ok(())
        }

        pub fn write_regs(&self, regs: &X86_64Regs) -> Result<(), GdbTargetError> {
            log::debug!("Write registers");
            let new_regs = kvm_regs {
                rax: regs.rax,
                rbx: regs.rbx,
                rcx: regs.rcx,
                rdx: regs.rdx,
                rsi: regs.rsi,
                rdi: regs.rdi,
                rbp: regs.rbp,
                rsp: regs.rsp,
                r8: regs.r8,
                r9: regs.r9,
                r10: regs.r10,
                r11: regs.r11,
                r12: regs.r12,
                r13: regs.r13,
                r14: regs.r14,
                r15: regs.r15,

                rip: regs.rip,
                rflags: regs.rflags,
            };

            self.vcpu_fd
                .set_regs(&new_regs)
                .map_err(|_| GdbTargetError::WriteRegistersError)
        }

        pub fn add_hw_breakpoint(&mut self, addr: u64) -> Result<bool, GdbTargetError> {
            let addr = self.translate_gva(addr)?;

            if self.debug.hw_breakpoints.contains(&addr) {
                Ok(true)
            } else if self.debug.hw_breakpoints.len() >= KvmDebug::MAX_NO_OF_HW_BP {
                Ok(false)
            } else {
                self.debug.hw_breakpoints.push(addr);
                self.debug
                    .set_breakpoints(&self.vcpu_fd, false)?;

                Ok(true)
            }
        }

        pub fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<bool, GdbTargetError> {
            let addr = self.translate_gva(addr)?;

            if self.debug.hw_breakpoints.contains(&addr) {
                let index = self.debug.hw_breakpoints.iter().position(|a| *a == addr).unwrap();
                self.debug.hw_breakpoints.copy_within(index + 1.., index);
                self.debug.hw_breakpoints.pop();
                self.debug
                    .set_breakpoints(&self.vcpu_fd, false)?;

                Ok(true)
            } else {
                Ok(false)
            }
        }

        pub fn add_sw_breakpoint(
            &mut self,
            addr: u64,
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
            ) -> Result<bool, HyperlightError> {
            let addr = self.translate_gva(addr).map_err(|_| new_error!("Translate error"))?;

            if self.debug.sw_breakpoints.contains_key(&addr) {
                return Ok(true);
            }

            let mut save_data = [0; SW_BP_SIZE];
            self.read_addrs(addr, &mut save_data[..], dbg_mem_access_fn.clone())?;
            self.write_addrs(addr, &SW_BP, dbg_mem_access_fn.clone())?;

            self.debug.sw_breakpoints.insert(addr, save_data);

            Ok(true)
        }

        pub fn remove_sw_breakpoint(
            &mut self,
            addr: u64,
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
            ) -> Result<bool, HyperlightError> {
            let addr = self.translate_gva(addr).map_err(|_| new_error!("Translate error"))?;

            if self.debug.sw_breakpoints.contains_key(&addr) {
                let save_data = self
                    .debug.sw_breakpoints
                    .remove(&addr)
                    .expect("Expected the hashmap to contain the address");

                self.write_addrs(addr, &save_data, dbg_mem_access_fn.clone())?;

                Ok(true)
            } else {
                Ok(false)
            }
        }

        /// Get the reason the vCPU has stopped
        pub fn get_stop_reason(
            &self,
        ) -> Result<VcpuStopReason, GdbTargetError> {
            if self.debug.single_step {
                return Ok(VcpuStopReason::DoneStep);
            }

            let ip = self.get_instruction_pointer()?;
            let gpa = self.translate_gva(ip)?;
            if self.debug.sw_breakpoints.contains_key(&gpa) {
                return Ok(VcpuStopReason::SwBp);
            }

            if self.debug.hw_breakpoints.contains(&ip) {
                return Ok(VcpuStopReason::HwBp);
            }

            if ip == self.entrypoint {
                return Ok(VcpuStopReason::HwBp);
            }

            Ok(VcpuStopReason::Unknown)
        }
    }
}

/// A Hypervisor driver for KVM on Linux
pub(super) struct KVMDriver {
    _kvm: Kvm,
    _vm_fd: VmFd,
    vcpu_fd: VcpuFd,
    entrypoint: u64,
    orig_rsp: GuestPtr,
    mem_regions: Vec<MemoryRegion>,

    #[cfg(gdb)]
    debug: debug::KvmDebug,
    #[cfg(gdb)]
    gdb_conn: GdbConnection,
}

impl KVMDriver {
    /// Create a new instance of a `KVMDriver`, with only control registers
    /// set. Standard registers will not be set, and `initialise` must
    /// be called to do so.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn new(
        mem_regions: Vec<MemoryRegion>,
        pml4_addr: u64,
        entrypoint: u64,
        rsp: u64,
    ) -> Result<Self> {
        let kvm = Kvm::new()?;

        let vm_fd = kvm.create_vm_with_type(0)?;

        let perm_flags =
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE;

        mem_regions.iter().enumerate().try_for_each(|(i, region)| {
            let perm_flags = perm_flags.intersection(region.flags);
            let kvm_region = kvm_userspace_memory_region {
                slot: i as u32,
                guest_phys_addr: region.guest_region.start as u64,
                memory_size: (region.guest_region.end - region.guest_region.start) as u64,
                userspace_addr: region.host_region.start as u64,
                flags: match perm_flags {
                    MemoryRegionFlags::READ => KVM_MEM_READONLY,
                    _ => 0, // normal, RWX
                },
            };
            unsafe { vm_fd.set_user_memory_region(kvm_region) }
        })?;

        let mut vcpu_fd = vm_fd.create_vcpu(0)?;
        Self::setup_initial_sregs(&mut vcpu_fd, pml4_addr)?;

        #[cfg(gdb)]
        let gdb_conn = Self::enable_gdb_debug()?;

        let rsp_gp = GuestPtr::try_from(RawPtr::from(rsp))?;
        let mut rsp = Self {
            _kvm: kvm,
            _vm_fd: vm_fd,
            vcpu_fd,
            entrypoint,
            orig_rsp: rsp_gp,
            mem_regions,

            #[cfg(gdb)]
            debug: KvmDebug::new(),
            #[cfg(gdb)]
            gdb_conn,
        };
        let r = rsp.set_entrypoint_bp();

        Ok(rsp)
    }

    #[cfg(gdb)]
    fn enable_gdb_debug(
    ) -> Result<GdbConnection> {
        let (gdb_conn, hyp_conn) = GdbConnection::new_pair();

        let target = HyperlightSandboxTarget::new(hyp_conn);
        // TODO: add breakpoint at entrypoint

        gdb::create_gdb_thread(target).map_err(|_| new_error!("Cannot create GDB thread"))?;

        Ok(gdb_conn)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn setup_initial_sregs(vcpu_fd: &mut VcpuFd, pml4_addr: u64) -> Result<()> {
        // setup paging and IA-32e (64-bit) mode
        let mut sregs = vcpu_fd.get_sregs()?;
        sregs.cr3 = pml4_addr;
        sregs.cr4 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
        sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP;
        sregs.efer = EFER_LME | EFER_LMA | EFER_SCE | EFER_NX;
        sregs.cs.l = 1; // required for 64-bit mode
        vcpu_fd.set_sregs(&sregs)?;
        Ok(())
    }
}

impl Debug for KVMDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("KVM Driver");
        // Output each memory region

        for region in &self.mem_regions {
            f.field("Memory Region", &region);
        }

        let regs = self.vcpu_fd.get_regs();
        // check that regs is OK and then set field in debug struct

        if let Ok(regs) = regs {
            f.field("Registers", &regs);
        }

        let sregs = self.vcpu_fd.get_sregs();

        // check that sregs is OK and then set field in debug struct

        if let Ok(sregs) = sregs {
            f.field("Special Registers", &sregs);
        }

        f.finish()
    }
}

impl Hypervisor for KVMDriver {
    /// Implementation of initialise for Hypervisor trait.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        outb_hdl: OutBHandlerWrapper,
        mem_access_hdl: MemAccessHandlerWrapper,
        hv_handler: Option<HypervisorHandler>,
        #[cfg(gdb)]
        dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        let regs = kvm_regs {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,

            // function args
            rcx: peb_addr.into(),
            rdx: seed,
            r8: page_size.into(),
            r9: self.get_max_log_level().into(),

            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs)?;

        VirtualCPU::run(
            self.as_mut_hypervisor(),
            hv_handler,
            outb_hdl,
            mem_access_hdl,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        // reset RSP to what it was before initialise
        self.vcpu_fd.set_regs(&kvm_regs {
            rsp: self.orig_rsp.absolute()?,
            ..Default::default()
        })?;
        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        outb_handle_fn: OutBHandlerWrapper,
        mem_access_fn: MemAccessHandlerWrapper,
        hv_handler: Option<HypervisorHandler>,
        #[cfg(gdb)]
        dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        // Reset general purpose registers except RSP, then set RIP

        let rsp_before = self.vcpu_fd.get_regs()?.rsp;
        let regs = kvm_regs {
            rip: dispatch_func_addr.clone().into(),
            rsp: rsp_before,
            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs)?;

        // reset fpu state
        let fpu = kvm_fpu {
            fcw: FP_CONTROL_WORD_DEFAULT,
            ftwx: FP_TAG_WORD_DEFAULT,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default() // zero out the rest
        };

        self.vcpu_fd.set_fpu(&fpu)?;

        // run
        VirtualCPU::run(
            self.as_mut_hypervisor(),
            hv_handler,
            outb_handle_fn,
            mem_access_fn,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        // reset RSP to what it was before function call
        self.vcpu_fd.set_regs(&kvm_regs {
            rsp: rsp_before,
            ..Default::default()
        })?;
        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn handle_io(
        &mut self,
        port: u16,
        data: Vec<u8>,
        _rip: u64,
        _instruction_length: u64,
        outb_handle_fn: OutBHandlerWrapper,
    ) -> Result<()> {
        // KVM does not need RIP or instruction length, as it automatically sets the RIP

        // The payload param for the outb_handle_fn is the first byte
        // of the data array cast to an u64. Thus, we need to make sure
        // the data array has at least one u8, then convert that to an u64
        if data.is_empty() {
            log_then_return!("no data was given in IO interrupt");
        } else {
            let payload_u64 = u64::from(data[0]);
            outb_handle_fn
                .try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                .call(port, payload_u64)?;
        }

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn run(&mut self) -> Result<HyperlightExit> {
        let result = match self.vcpu_fd.run() {
            Ok(VcpuExit::Hlt) => {
                crate::debug!("KVM - Halt Details : {:#?}", &self);
                HyperlightExit::Halt()
            }
            Ok(VcpuExit::IoOut(port, data)) => {
                // because vcpufd.run() mutably borrows self we cannot pass self to crate::debug! macro here
                crate::debug!("KVM IO Details : \nPort : {}\nData : {:?}", port, data);
                // KVM does not need to set RIP or instruction length so these are set to 0
                HyperlightExit::IoOut(port, data.to_vec(), 0, 0)
            }
            Ok(VcpuExit::MmioRead(addr, _)) => {
                crate::debug!("KVM MMIO Read -Details: Address: {} \n {:#?}", addr, &self);

                match self.get_memory_access_violation(
                    addr as usize,
                    &self.mem_regions,
                    MemoryRegionFlags::READ,
                ) {
                    Some(access_violation_exit) => access_violation_exit,
                    None => HyperlightExit::Mmio(addr),
                }
            }
            Ok(VcpuExit::MmioWrite(addr, _)) => {
                crate::debug!("KVM MMIO Write -Details: Address: {} \n {:#?}", addr, &self);

                match self.get_memory_access_violation(
                    addr as usize,
                    &self.mem_regions,
                    MemoryRegionFlags::WRITE,
                ) {
                    Some(access_violation_exit) => access_violation_exit,
                    None => HyperlightExit::Mmio(addr),
                }
            }
            #[cfg(gdb)]
            Ok(VcpuExit::Debug(_)) => {
                let reason = self.get_stop_reason().map_err(|_| new_error!("Cannot get stop reason"))?;

                HyperlightExit::Debug(reason)
            }
            Err(e) => match e.errno() {
                // we send a signal to the thread to cancel execution this results in EINTR being returned by KVM so we return Cancelled
                libc::EINTR => HyperlightExit::Cancelled(),
                libc::EAGAIN => HyperlightExit::Retry(),
                _ => {
                    crate::debug!("KVM Error -Details: Address: {} \n {:#?}", e, &self);
                    log_then_return!("Error running VCPU {:?}", e);
                }
            },
            Ok(other) => {
                crate::debug!("KVM Other Exit {:?}", other);
                HyperlightExit::Unknown(format!("Unexpected KVM Exit {:?}", other))
            }
        };

        Ok(result)
    }

    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor {
        self as &mut dyn Hypervisor
    }

    #[cfg(crashdump)]
    fn get_memory_regions(&self) -> &[MemoryRegion] {
        &self.mem_regions
    }

    #[cfg(gdb)]
    fn process_dbg_request(&mut self,
        req: DebugAction,
        dbg_mem_access_fn: Arc<Mutex<dyn super::handlers::DbgMemAccessHandlerCaller>>,
    ) -> Result<DebugAction> {
        use crate::hypervisor::gdb::X86_64Regs;

        match req {
            DebugAction::ContinueReq => {
                self.set_single_step(false);
                Ok(DebugAction::ContinueRsp)
            }
            DebugAction::StepReq => {
                self.set_single_step(true);
                Ok(DebugAction::StepRsp)
            }

            DebugAction::ReadRegistersReq => {
                let mut regs = X86_64Regs::default();
                self.read_regs(&mut regs).expect("Read Regs error");
                Ok(DebugAction::ReadRegistersRsp(regs))
            }
            DebugAction::WriteRegistersReq(regs) => {
                self.write_regs(&regs).expect("Write Regs error");
                Ok(DebugAction::WriteRegistersRsp)

            }

            DebugAction::ReadAddrReq(addr, len) => {
                let mut data = vec![0u8; len];

                self.read_addrs(addr, &mut data, dbg_mem_access_fn.clone())?;

                Ok(DebugAction::ReadAddrRsp(data))
            }

            DebugAction::WriteAddrReq(addr, data) => {
                self.write_addrs(addr, &data, dbg_mem_access_fn.clone())?;

                Ok(DebugAction::WriteAddrRsp)
            }

            DebugAction::AddHwBreakpointReq(addr) => {
                let res = self.add_hw_breakpoint(addr).expect("Add hw breakpoint error");
                Ok(DebugAction::AddHwBreakpointRsp(res))
            }
            DebugAction::RemoveHwBreakpointReq(addr) => {
                let res = self.remove_hw_breakpoint(addr).expect("Remove hw breakpoint error");
                Ok(DebugAction::RemoveHwBreakpointRsp(res))
            }

            DebugAction::AddSwBreakpointReq(addr) => {
                let res = self.add_sw_breakpoint(addr, dbg_mem_access_fn.clone()).expect("Add sw breakpoint error");

                Ok(DebugAction::AddSwBreakpointRsp(res))
            }
            DebugAction::RemoveSwBreakpointReq(addr) => {
                let res = self.remove_sw_breakpoint(addr, dbg_mem_access_fn.clone()).expect("Remove sw breakpoint error");
                Ok(DebugAction::RemoveSwBreakpointRsp(res))
            }
            DebugAction::GetCodeSectionOffsetReq => {
                let offset = dbg_mem_access_fn
                    .clone()
                    .try_lock()
                    .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                    .get_code_offset()?;
                
                Ok(DebugAction::GetCodeSectionOffsetRsp(offset as u64))
            }
            _ => {
                log::error!("Invalid action encountered: {:?}", req);
                Err(new_error!("Invalid action encountered: {:?}", req))
            }
        }
    }

    #[cfg(gdb)]
    fn recv_dbg_msg(&mut self) -> Result<DebugAction> {
        self.gdb_conn.recv().map_err(|_| new_error!("Cannot receive"))
    }

    #[cfg(gdb)]
    fn send_dbg_msg(&mut self, cmd: DebugAction) -> Result<()> {
        log::debug!("Sending {:?}", cmd);

        self.gdb_conn.send(cmd).map_err(|_| new_error!("Cannot send"))
    }
}
#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::hypervisor::handlers::{DbgMemAccessHandler, MemAccessHandler, OutBHandler};
    use crate::hypervisor::tests::test_initialise;
    use crate::Result;

    #[test]
    fn test_init() {
        if !super::is_hypervisor_present() {
            return;
        }

        let outb_handler: Arc<Mutex<OutBHandler>> = {
            let func: Box<dyn FnMut(u16, u64) -> Result<()> + Send> =
                Box::new(|_, _| -> Result<()> { Ok(()) });
            Arc::new(Mutex::new(OutBHandler::from(func)))
        };
        let mem_access_handler = {
            let func: Box<dyn FnMut() -> Result<()> + Send> = Box::new(|| -> Result<()> { Ok(()) });
            Arc::new(Mutex::new(MemAccessHandler::from(func)))
        };
        #[cfg(gdb)]
        let dbg_mem_access_handler = {
            let read: Box<dyn FnMut(usize, &mut [u8]) -> Result<()> + Send> = Box::new(|_: usize, _: &mut [u8]| -> Result<()> { Ok(()) });
            let write: Box<dyn FnMut(usize, &[u8]) -> Result<()> + Send> = Box::new(|_: usize, _: &[u8]| -> Result<()> { Ok(()) });
            Arc::new(Mutex::new(DbgMemAccessHandler::from((read, write))))
        };

        test_initialise(
            outb_handler,
            mem_access_handler,
            #[cfg(gdb)]
            dbg_mem_access_handler,
            ).unwrap();
    }
}
