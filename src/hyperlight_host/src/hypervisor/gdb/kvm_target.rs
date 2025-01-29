
use crossbeam_channel::TryRecvError;
use gdbstub::arch::Arch;
use gdbstub::common::Signal;
use gdbstub::stub::SingleThreadStopReason;
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps, SingleThreadSingleStep,
    SingleThreadSingleStepOps,
};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps, SwBreakpoint, SwBreakpointOps,
};
use gdbstub::target::ext::section_offsets::{Offsets, SectionOffsets};
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub_arch::x86::X86_64_SSE as GdbTargetArch;

use super::{DebugAction, GdbConnection, GdbTargetError, VcpuStopReason, X86_64Regs};
use crate::hypervisor::gdb::GdbDebug;


/// Gdbstub target used by the gdbstub crate to provide GDB protocol implementation
pub struct HyperlightSandboxTarget {
    /// Hypervisor communication channels
    hyp_conn: GdbConnection,
}

impl HyperlightSandboxTarget {
    pub fn new(
        hyp_conn: GdbConnection,
    ) -> Self {

        HyperlightSandboxTarget {
            hyp_conn,
        }
    }

    fn send_command(&self, cmd: DebugAction) -> Result<DebugAction, GdbTargetError> {
        self.send(cmd)?;

        // Wait for response
        Ok(self.hyp_conn.recv()?)
    }
}

impl GdbDebug for HyperlightSandboxTarget {
    fn send(&self, ev: DebugAction) -> Result<(), Self::Error> {
        self.hyp_conn.send(ev)
    }

    fn recv(&self) -> Result<DebugAction, Self::Error> {
        self.hyp_conn.recv()
    }

    fn try_recv(&self) -> Result<DebugAction, TryRecvError> {
        self.hyp_conn.try_recv()
    }

    fn get_stop_reason(
        &self,
        reason: VcpuStopReason,
    ) -> SingleThreadStopReason<<Self::Arch as Arch>::Usize> {

        match reason {
            VcpuStopReason::DoneStep => SingleThreadStopReason::DoneStep,
            VcpuStopReason::SwBp => SingleThreadStopReason::SwBreak(()),
            VcpuStopReason::HwBp => SingleThreadStopReason::HwBreak(()),
        }
    }

    /// Sends an event to the Hypervisor that tells it to resume vCPU execution
    /// Note: The method waits for a confirmation message
    fn resume_vcpu(&mut self) -> Result<(), Self::Error> {
        log::info!("Attempted to resume vCPU");
        if let DebugAction::ContinueRsp = self.send_command(DebugAction::ContinueReq)? {
            Ok(())
        } else {
            log::error!("Didn't receive ContinueRsp");
            Err(GdbTargetError::UnexpectedMessageError)
        }
    }
}

impl Target for HyperlightSandboxTarget {
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

impl SingleThreadBase for HyperlightSandboxTarget {
    fn read_addrs(
        &mut self,
        gva: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        log::debug!("Read addr: {:X} len: {:X}", gva, data.len());

        if let DebugAction::ReadAddrRsp(v) = self.send_command(DebugAction::ReadAddrReq(gva, data.len()))? {
            data.copy_from_slice(&v);

            Ok(v.len())
        } else {
            Err(TargetError::Fatal(GdbTargetError::UnexpectedMessageError))
        }
    }

    fn write_addrs(
        &mut self,
        gva: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        log::debug!("Write addr: {:X} len: {:X}", gva, data.len());
        let v = Vec::from(data);

        if let DebugAction::WriteAddrRsp = self.send_command(DebugAction::WriteAddrReq(gva, v))? {
            Ok(())
        } else {
            Err(TargetError::Fatal(GdbTargetError::UnexpectedMessageError))
        }
    }

    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        if let DebugAction::ReadRegistersRsp(read_regs) = self.send_command(DebugAction::ReadRegistersReq)? {
            log::debug!("Got regs: {:?}", read_regs);
            regs.regs[0] = read_regs.rax;
            regs.regs[1] = read_regs.rbp;
            regs.regs[2] = read_regs.rcx;
            regs.regs[3] = read_regs.rdx;
            regs.regs[4] = read_regs.rsi;
            regs.regs[5] = read_regs.rdi;
            regs.regs[6] = read_regs.rbp;
            regs.regs[7] = read_regs.rsp;
            regs.regs[8] = read_regs.r8;
            regs.regs[9] = read_regs.r9;
            regs.regs[10] = read_regs.r10;
            regs.regs[11] = read_regs.r11;
            regs.regs[12] = read_regs.r12;
            regs.regs[13] = read_regs.r13;
            regs.regs[14] = read_regs.r14;
            regs.regs[15] = read_regs.r15;
            regs.rip = read_regs.rip;
            regs.eflags = u32::try_from(read_regs.rflags).expect("Couldn't convert rflags from u64 to u32");
            log::debug!("filled regs: {:?}", regs);

            Ok(())
        } else {
            Err(TargetError::Fatal(GdbTargetError::UnexpectedMessageError))
        }
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        let regs = X86_64Regs {
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
            rflags: u64::try_from(regs.eflags).expect("Couldn't convert eflags from u32 to u64"),
        };

        if let DebugAction::WriteRegistersRsp = self.send_command(DebugAction::WriteRegistersReq(regs))? {
            Ok(())
        } else {
            Err(TargetError::Fatal(GdbTargetError::UnexpectedMessageError))
        }
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
        Some(self)
    }
}

impl SectionOffsets for HyperlightSandboxTarget {
    fn get_section_offsets(&mut self) -> Result<Offsets<<Self::Arch as Arch>::Usize>, Self::Error> {
        log::debug!("Get section offsets");

        if let DebugAction::GetCodeSectionOffsetRsp(text) = self.send_command(DebugAction::GetCodeSectionOffsetReq)? {
            log::debug!("Get section offsets got {:X}", text);
            Ok(Offsets::Segments {
                text_seg: text as u64,
                data_seg: None,
            })
        } else {
            Err(GdbTargetError::UnexpectedMessageError)
        }

    }
}

impl Breakpoints for HyperlightSandboxTarget {
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<Self>> {
        Some(self)
    }
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl HwBreakpoint for HyperlightSandboxTarget {
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

        if let DebugAction::AddHwBreakpointRsp(rsp) = self.send_command(DebugAction::AddHwBreakpointReq(addr))? {
            Ok(rsp)
        } else {
            Err(TargetError::Fatal(GdbTargetError::UnexpectedMessageError))
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

        if let DebugAction::RemoveHwBreakpointRsp(rsp) = self.send_command(DebugAction::RemoveHwBreakpointReq(addr))? {
            Ok(rsp)
        } else {
            Err(TargetError::Fatal(GdbTargetError::UnexpectedMessageError))
        }
    }
}

impl SwBreakpoint for HyperlightSandboxTarget {
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

        if let DebugAction::AddSwBreakpointRsp(rsp) = self.send_command(DebugAction::AddSwBreakpointReq(addr))? {
            Ok(rsp)
        } else {
            Err(TargetError::Fatal(GdbTargetError::UnexpectedMessageError))
        }
    }

    /// Removes a software breakpoint by restoring the saved data at the corresponding
    /// address
    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        log::debug!("Remove sw breakpoint at address {:X}", addr);

        if let DebugAction::RemoveSwBreakpointRsp(rsp) = self.send_command(DebugAction::RemoveSwBreakpointReq(addr))? {
            Ok(rsp)
        } else {
            Err(TargetError::Fatal(GdbTargetError::UnexpectedMessageError))
        }
    }
}

impl SingleThreadResume for HyperlightSandboxTarget {
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        log::debug!("Resume");
        self.resume_vcpu()
    }
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for HyperlightSandboxTarget {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        assert!(signal.is_none());

        log::debug!("Step");
        if let DebugAction::StepRsp = self.send_command(DebugAction::StepReq)? {
            log::debug!("Got StepRsp");

            Ok(())
        } else {
            Err(GdbTargetError::UnexpectedMessageError)
        }
    }
}
