use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crossbeam_channel::TryRecvError;
use gdbstub::arch::{Arch, BreakpointKind};
use gdbstub::common::Signal;
use gdbstub::stub::{BaseStopReason, SingleThreadStopReason};
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps, SingleThreadSingleStep,
    SingleThreadSingleStepOps,
};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps, SwBreakpoint, SwBreakpointOps,
};
use gdbstub::target::ext::section_offsets::{Offsets, SectionOffsets};
use gdbstub::target::{Target, TargetResult};
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use gdbstub_arch::x86::X86_64_SSE as GdbTargetArch;
use hyperlight_common::mem::PAGE_SIZE;
use kvm_bindings::{
    kvm_guest_debug, kvm_regs, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP,
    KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP,
};
use kvm_ioctls::VcpuFd;

use super::{GdbConnection, GdbTargetError};
use crate::hypervisor::gdb::{DebugMessage, GdbDebug};
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::{GuestSharedMemory, SharedMemory};

/// Software Breakpoint size in memory
const SW_BP_SIZE: usize = 1;
/// Software Breakpoinnt opcode
const SW_BP_OP: u8 = 0xCC;
/// Software Breakpoint written to memory
const SW_BP: [u8; SW_BP_SIZE] = [SW_BP_OP];

/// KVM Debug struct
/// This struct is used to abstract the internal details of the kvm
/// guest debugging settings
#[derive(Default)]
struct KvmDebug {
    /// Sent to KVM for enabling guest debug
    pub debug: kvm_guest_debug,
}

impl KvmDebug {
    const MAX_NO_OF_HW_BP: usize = 4;

    pub fn new() -> Self {
        let dbg = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
            ..Default::default()
        };

        Self { debug: dbg }
    }

    /// Method to set the kvm debugreg fields for breakpoints
    /// The maximum number of supported breakpoints is `Self::MAX_NO_OF_HW_BP`
    pub fn set_breakpoints(
        &mut self,
        vcpu_fd: &VcpuFd,
        addrs: &[u64],
        step: bool,
    ) -> Result<bool, GdbTargetError> {
        if addrs.len() >= Self::MAX_NO_OF_HW_BP {
            return Ok(false);
        }

        self.debug.arch.debugreg = [0; 8];
        for (k, addr) in addrs.iter().enumerate() {
            self.debug.arch.debugreg[k] = *addr;
            self.debug.arch.debugreg[7] |= 1 << (k * 2);
        }

        if !addrs.is_empty() {
            self.debug.control |= KVM_GUESTDBG_USE_HW_BP;
        } else {
            self.debug.control &= !KVM_GUESTDBG_USE_HW_BP;
        }

        if step {
            self.debug.control |= KVM_GUESTDBG_SINGLESTEP;
        } else {
            self.debug.control &= !KVM_GUESTDBG_SINGLESTEP;
        }

        vcpu_fd
            .set_guest_debug(&self.debug)
            .map_err(|_| GdbTargetError::SetGuestDebugError)?;

        Ok(true)
    }
}

/// Gdbstub target used by the gdbstub crate to provide GDB protocol implementation
pub struct HyperlightKvmSandboxTarget {
    /// Memory manager that grants access to guest's memory
    mgr: Arc<Mutex<SandboxMemoryManager<GuestSharedMemory>>>,
    /// VcpuFd for access to vCPU state
    vcpu_fd: Arc<RwLock<VcpuFd>>,
    /// Guest entrypoint
    entrypoint: u64,

    /// KVM guest debug information
    debug: KvmDebug,

    /// vCPU paused state
    paused: bool,
    /// vCPU stepping state
    single_step: bool,

    /// Array of addresses for HW breakpoints
    hw_breakpoints: Vec<u64>,
    /// Array of addresses for SW breakpoints
    sw_breakpoints: HashMap<u64, [u8; SW_BP_SIZE]>,

    /// Hypervisor communication channels
    hyp_conn: GdbConnection,
}

impl HyperlightKvmSandboxTarget {
    pub fn new(
        mgr: Arc<Mutex<SandboxMemoryManager<GuestSharedMemory>>>,
        vcpu_fd: Arc<RwLock<VcpuFd>>,
        entrypoint: u64,
        hyp_conn: GdbConnection,
    ) -> Self {
        let kvm_debug = KvmDebug::new();

        HyperlightKvmSandboxTarget {
            mgr,
            vcpu_fd,
            debug: kvm_debug,
            entrypoint,

            paused: false,
            single_step: false,

            hw_breakpoints: vec![],
            sw_breakpoints: HashMap::new(),

            hyp_conn,
        }
    }

    /// Returns the instruction pointer from the stopped vCPU
    fn get_instruction_pointer(&self) -> Result<u64, GdbTargetError> {
        let regs = self
            .vcpu_fd
            .read()
            .unwrap()
            .get_regs()
            .map_err(|_| GdbTargetError::InstructionPointerError)?;

        Ok(regs.rip)
    }

    fn set_single_step(&mut self, enable: bool) -> Result<(), GdbTargetError> {
        self.single_step = enable;

        self.debug
            .set_breakpoints(&self.vcpu_fd.read().unwrap(), &self.hw_breakpoints, enable)?;

        Ok(())
    }

    /// This method provides a way to set a breakpoint at the entrypoint
    /// it does not keep this breakpoint set after the vcpu already stopped at the address
    pub fn set_entrypoint_bp(&mut self) -> Result<bool, GdbTargetError> {
        let mut entrypoint_debug = KvmDebug::new();
        entrypoint_debug.set_breakpoints(&self.vcpu_fd.read().unwrap(), &[self.entrypoint], false)
    }

    /// Translates the guest address to physical address
    fn translate_gva(&self, gva: u64) -> Result<u64, GdbTargetError> {
        let tr = self
            .vcpu_fd
            .read()
            .unwrap()
            .translate_gva(gva)
            .map_err(|_| GdbTargetError::InvalidGva(gva))?;

        if tr.valid == 0 {
            Err(GdbTargetError::InvalidGva(gva))
        } else {
            Ok(tr.physical_address)
        }
    }

    fn read_regs(&self, regs: &mut X86_64CoreRegs) -> Result<(), GdbTargetError> {
        log::debug!("Read registers");
        let vcpu_regs = self
            .vcpu_fd
            .read()
            .unwrap()
            .get_regs()
            .map_err(|_| GdbTargetError::ReadRegistersError)?;

        regs.regs[0] = vcpu_regs.rax;
        regs.regs[1] = vcpu_regs.rbx;
        regs.regs[2] = vcpu_regs.rcx;
        regs.regs[3] = vcpu_regs.rdx;
        regs.regs[4] = vcpu_regs.rsi;
        regs.regs[5] = vcpu_regs.rdi;
        regs.regs[6] = vcpu_regs.rbp;
        regs.regs[7] = vcpu_regs.rsp;
        regs.regs[8] = vcpu_regs.r8;
        regs.regs[9] = vcpu_regs.r9;
        regs.regs[10] = vcpu_regs.r10;
        regs.regs[11] = vcpu_regs.r11;
        regs.regs[12] = vcpu_regs.r12;
        regs.regs[13] = vcpu_regs.r13;
        regs.regs[14] = vcpu_regs.r14;
        regs.regs[15] = vcpu_regs.r15;

        regs.rip = vcpu_regs.rip;

        regs.eflags =
            u32::try_from(vcpu_regs.rflags).map_err(|_| GdbTargetError::ReadRegistersError)?;

        Ok(())
    }

    fn write_regs(&self, regs: &X86_64CoreRegs) -> Result<(), GdbTargetError> {
        log::debug!("Write registers");
        let new_regs = kvm_regs {
            rax: regs.regs[0],
            rbx: regs.regs[1],
            rcx: regs.regs[2],
            rdx: regs.regs[3],
            rsi: regs.regs[4],
            rdi: regs.regs[5],
            rbp: regs.regs[6],
            rsp: regs.regs[7],
            r8: regs.regs[8],
            r9: regs.regs[9],
            r10: regs.regs[10],
            r11: regs.regs[11],
            r12: regs.regs[12],
            r13: regs.regs[13],
            r14: regs.regs[14],
            r15: regs.regs[15],

            rip: regs.rip,
            rflags: regs.eflags as u64,
        };

        self.vcpu_fd
            .read()
            .unwrap()
            .set_regs(&new_regs)
            .map_err(|_| GdbTargetError::WriteRegistersError)
    }
}

impl GdbDebug for HyperlightKvmSandboxTarget {
    fn send(&self, ev: DebugMessage) -> Result<(), Self::Error> {
        self.hyp_conn.send(ev)
    }

    fn recv(&self) -> Result<DebugMessage, Self::Error> {
        self.hyp_conn.recv()
    }

    fn try_recv(&self) -> Result<DebugMessage, TryRecvError> {
        self.hyp_conn.try_recv()
    }

    fn pause_vcpu(&mut self) {
        self.paused = true;
    }

    fn disable_debug(&mut self) -> Result<bool, Self::Error> {
        self.debug = KvmDebug::default();

        self.pause_vcpu();
        self.hw_breakpoints = vec![];

        let sw_bp_addr: Vec<u64> = self.sw_breakpoints.keys().into_iter().map(|a| *a).collect();

        for addr in sw_bp_addr {
            let _ = self.remove_sw_breakpoint(addr, BreakpointKind::from_usize(0).unwrap());
        }
        self.sw_breakpoints = HashMap::new();

        let _ = self.set_single_step(false);
        self.debug.set_breakpoints(&self.vcpu_fd.read().unwrap(), &[], false)
    }

    /// Sends an event to the Hypervisor that tells it to resume vCPU execution
    /// Note: The method waits for a confirmation message
    fn resume_vcpu(&mut self) -> Result<(), Self::Error> {
        if self.paused {
            log::info!("Attempted to resume paused vCPU");

            self.send(DebugMessage::VcpuResumeEv)?;

            let response = self.recv()?;
            log::debug!("Got message {:?}", response);

            if let DebugMessage::RspOk = response {
                self.paused = false;
            } else {
                log::error!("Error when resuming");
                return Err(GdbTargetError::CannotResume);
            }
        }

        Ok(())
    }

    /// Get the reason the vCPU has stopped
    fn get_stop_reason(
        &self,
    ) -> Result<Option<BaseStopReason<(), <Self::Arch as Arch>::Usize>>, Self::Error> {
        if self.single_step {
            return Ok(Some(SingleThreadStopReason::DoneStep));
        }

        let ip = self.get_instruction_pointer()?;
        let gpa = self.translate_gva(ip)?;
        if self.sw_breakpoints.contains_key(&gpa) {
            return Ok(Some(SingleThreadStopReason::SwBreak(())));
        }

        if self.hw_breakpoints.contains(&ip) {
            return Ok(Some(SingleThreadStopReason::HwBreak(())));
        }

        if ip == self.entrypoint {
            return Ok(Some(SingleThreadStopReason::HwBreak(())));
        }

        Ok(None)
    }
}

impl Target for HyperlightKvmSandboxTarget {
    type Arch = GdbTargetArch;
    type Error = GdbTargetError;

    #[inline(always)]
    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        true
    }

    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<Self>> {
        Some(self)
    }

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn support_section_offsets(
        &mut self,
    ) -> Option<gdbstub::target::ext::section_offsets::SectionOffsetsOps<Self>> {
        Some(self)
    }
}

impl SingleThreadBase for HyperlightKvmSandboxTarget {
    fn read_addrs(
        &mut self,
        mut gva: <Self::Arch as Arch>::Usize,
        mut data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let data_len = data.len();
        log::debug!("Read addr: {:X} len: {:X}", gva, data_len);

        let mut mgr = self.mgr.lock().unwrap();
        while !data.is_empty() {
            let gpa = self.translate_gva(gva)?;

            let read_len = std::cmp::min(
                data.len(),
                (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
            );
            let offset = gpa as usize - SandboxMemoryLayout::BASE_ADDRESS;

            let _ = mgr.shared_mem.with_exclusivity(|ex| {
                data[..read_len].copy_from_slice(&ex.as_slice()[offset..offset + read_len]);
            });

            data = &mut data[read_len..];
            gva += read_len as u64;
        }

        Ok(data_len)
    }

    fn write_addrs(
        &mut self,
        mut gva: <Self::Arch as Arch>::Usize,
        mut data: &[u8],
    ) -> TargetResult<(), Self> {
        let data_len = data.len();
        log::debug!("Write addr: {:X} len: {:X}", gva, data_len);

        let mut mgr = self.mgr.lock().unwrap();
        while !data.is_empty() {
            let gpa = self.translate_gva(gva)?;

            let write_len = std::cmp::min(
                data.len(),
                (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
            );
            let offset = gpa as usize - SandboxMemoryLayout::BASE_ADDRESS;

            let _ = mgr
                .shared_mem
                .with_exclusivity(|ex| ex.copy_from_slice(data, offset));

            data = &data[write_len..];
            gva += write_len as u64;
        }

        Ok(())
    }

    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        self.read_regs(regs)?;

        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        self.write_regs(regs)?;

        Ok(())
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
        Some(self)
    }
}

impl SectionOffsets for HyperlightKvmSandboxTarget {
    fn get_section_offsets(&mut self) -> Result<Offsets<<Self::Arch as Arch>::Usize>, Self::Error> {
        let mgr = self.mgr.lock().unwrap();
        let text = mgr.layout.get_guest_code_address();

        log::debug!("Get section offsets text: {:X}", text);
        Ok(Offsets::Segments {
            text_seg: text as u64,
            data_seg: None,
        })
    }
}

impl Breakpoints for HyperlightKvmSandboxTarget {
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<Self>> {
        Some(self)
    }
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl HwBreakpoint for HyperlightKvmSandboxTarget {
    /// Adds a hardware breakpoint to an array that can store a maximum of
    /// `KvmDebug::MAX_NO_OF_HW_BP` breakpoints and updates vCPU debug config
    /// to reflect the newly added breakpoint
    ///
    /// NOTE: The method checks for the address to be valid, checks for the address
    /// to not be already added and checks for the maximum number of breakpoints
    /// to not be exceeded
    fn add_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        log::debug!("Add hw breakpoint at address {:X}", addr);

        let addr = self.translate_gva(addr)?;

        if self.hw_breakpoints.contains(&addr) {
            Ok(true)
        } else if self.hw_breakpoints.len() >= KvmDebug::MAX_NO_OF_HW_BP {
            Ok(false)
        } else {
            self.hw_breakpoints.push(addr);
            self.debug
                .set_breakpoints(&self.vcpu_fd.read().unwrap(), &self.hw_breakpoints, false)?;

            Ok(true)
        }
    }

    /// Removes a hardware breakpoint from the array of breakpoints and updates
    /// the vCPU debug config to reflect the change.
    fn remove_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        log::debug!("Remove hw breakpoint at address {:X}", addr);

        let addr = self.translate_gva(addr)?;

        if self.hw_breakpoints.contains(&addr) {
            let index = self.hw_breakpoints.iter().position(|a| *a == addr).unwrap();
            self.hw_breakpoints.copy_within(index + 1.., index);
            self.hw_breakpoints.pop();
            self.debug
                .set_breakpoints(&self.vcpu_fd.read().unwrap(), &self.hw_breakpoints, false)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl SwBreakpoint for HyperlightKvmSandboxTarget {
    /// Adds a software breakpoint by setting a specific operation code at the
    /// address so when the vCPU hits it, it knows it is a software breakpoint.
    ///
    /// The existing data at the address is saved so it can be restored when
    /// removing the breakpoint
    fn add_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        log::debug!("Add sw breakpoint at address {:X}", addr);
        let addr = self.translate_gva(addr)?;

        if self.sw_breakpoints.contains_key(&addr) {
            return Ok(true);
        }

        let mut save_data = [0u8; SW_BP_SIZE];
        self.read_addrs(addr, &mut save_data)?;
        self.write_addrs(addr, &SW_BP)?;

        self.sw_breakpoints.insert(addr, save_data);

        Ok(true)
    }

    /// Removes a software breakpoint by restoring the saved data at the corresponding
    /// address
    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        log::debug!("Remove sw breakpoint at address {:X}", addr);

        let addr = self.translate_gva(addr)?;

        if self.sw_breakpoints.contains_key(&addr) {
            let save_data = self
                .sw_breakpoints
                .remove(&addr)
                .expect("Expected the hashmap to contain the address");
            self.write_addrs(addr, &save_data)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl SingleThreadResume for HyperlightKvmSandboxTarget {
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        log::debug!("Resume");
        self.set_single_step(false)?;
        self.resume_vcpu()
    }
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for HyperlightKvmSandboxTarget {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        assert!(signal.is_none());

        log::debug!("Step");
        self.set_single_step(true)?;
        self.resume_vcpu()
    }
}
