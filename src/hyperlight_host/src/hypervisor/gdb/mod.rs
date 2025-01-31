mod event_loop;
pub mod kvm_target;

use std::io::{self, ErrorKind};
use std::net::TcpListener;
use std::thread;

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use event_loop::event_loop_thread;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::GdbStub;
use gdbstub::target::{Target, TargetError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GdbTargetError {
    #[error("Bind Error")]
    BindError,
    #[error("Instruction pointer error")]
    InstructionPointerError,
    #[error("Instruction pointer error")]
    ListenerError,
    #[error("Target finished running: {0}")]
    TargetFinished(String),
    #[error("Error encountered when reading registers")]
    ReadRegistersError,
    #[error("Error encountered when waiting to receive message")]
    ReceiveMsgError,
    #[error("Error encountered when resuming vCPU")]
    CannotResume,
    #[error("Error encountered when sending message")]
    SendMsgError,
    #[error("Error encountered when setting guest debug")]
    SetGuestDebugError,
    #[error("Invalid guest virtual address: {0}")]
    InvalidGva(u64),
    #[error("Encountered an unexpected message over communication channel")]
    UnexpectedMessageError,
    #[error("Error encountered when writing registers")]
    WriteRegistersError,
    #[error("Unexpected error encountered")]
    UnexpectedError,
}

impl From<io::Error> for GdbTargetError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            ErrorKind::AddrInUse => Self::BindError,
            ErrorKind::AddrNotAvailable => Self::BindError,
            ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionRefused => Self::ListenerError,
            _ => Self::UnexpectedError,
        }
    }
}

impl From<DebugMsg> for GdbTargetError {
    fn from(_value: DebugMsg) -> Self {
        GdbTargetError::UnexpectedMessageError
    }
}

impl From<GdbTargetError> for TargetError<GdbTargetError> {
    fn from(value: GdbTargetError) -> TargetError<GdbTargetError> {
        match value {
            GdbTargetError::InvalidGva(_) => TargetError::NonFatal,
            e @ GdbTargetError::SetGuestDebugError | 
            e @ GdbTargetError::InstructionPointerError =>
                TargetError::Fatal(e),
            _ => TargetError::Io(std::io::Error::other(value)),
        }
    }
}

/// Trait that provides common communication methods for targets
pub trait GdbDebug: Target {
    /// Sends a message to the Hypervisor
    fn send(&self, ev: DebugAction) -> Result<(), <Self as Target>::Error>;
    /// Waits for a message from the Hypervisor
    fn recv(&self) -> Result<DebugAction, <Self as Target>::Error>;
    /// Checks for a pending message from the Hypervisor
    fn try_recv(&self) -> Result<DebugAction, TryRecvError>;

    /// Resumes the vCPU
    fn resume_vcpu(&mut self) -> Result<(), <Self as Target>::Error>;
}

#[derive(Debug, Default)]
pub struct X86_64Regs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[derive(Debug)]
pub enum VcpuStopReason {
    DoneStep,
    HwBp,
    SwBp,
    Unknown,
}

/// `DebugAction` enumerates the possible actions that a debugger can
/// ask from a Hypervisor
#[derive(Debug)]
pub enum DebugAction {
    ReadRegistersReq,
    ReadRegistersRsp(X86_64Regs),
    WriteRegistersReq(X86_64Regs),
    WriteRegistersRsp,
    ReadAddrReq(u64, usize),
    ReadAddrRsp(Vec<u8>),
    WriteAddrReq(u64, Vec<u8>),
    WriteAddrRsp,
    AddHwBreakpointReq(u64),
    AddHwBreakpointRsp(bool),
    RemoveHwBreakpointReq(u64),
    RemoveHwBreakpointRsp(bool),
    AddSwBreakpointReq(u64),
    AddSwBreakpointRsp(bool),
    RemoveSwBreakpointReq(u64),
    RemoveSwBreakpointRsp(bool),
    ContinueReq,
    ContinueRsp,
    StepReq,
    StepRsp,
    VcpuStopped(VcpuStopReason),
    GetCodeSectionOffsetReq,
    GetCodeSectionOffsetRsp(u64),
}

/// `DebugMsg` is a structure used by the Hypervisor to indicate that
/// the vCPU changed state
#[derive(Debug)]
pub enum DebugMsg {
    /// VCPU stopped in debug
    VcpuStoppedEv,
    /// Resume VCPU execution
    VcpuResumeEv,
    /// Response ok
    RspOk,
    /// Response error
    RspErr,
}

/// Type that takes care of communication between Hypervisor and Gdb
pub struct GdbConnection {
    /// Transmit channel
    tx: Sender<DebugAction>,
    /// Receive channel
    rx: Receiver<DebugAction>,
}

impl GdbConnection {
    pub fn new_pair() -> (Self, Self) {
        let (hyp_tx, gdb_rx): (Sender<DebugAction>, Receiver<DebugAction>) = crossbeam_channel::unbounded();
        let (gdb_tx, hyp_rx): (Sender<DebugAction>, Receiver<DebugAction>) = crossbeam_channel::unbounded();

        let gdb_conn = GdbConnection {
            tx: gdb_tx,
            rx: gdb_rx,
        };

        let hyp_conn = GdbConnection {
            tx: hyp_tx,
            rx: hyp_rx,
        };

        (gdb_conn, hyp_conn)
    }

    /// Sends message over the transmit channel and expects a response
    pub fn send(&self, msg: DebugAction) -> Result<(), GdbTargetError> {
        self.tx.send(msg).map_err(|_| GdbTargetError::SendMsgError)
    }

    /// Waits for a message over the receive channel
    pub fn recv(&self) -> Result<DebugAction, GdbTargetError> {
        self.rx.recv().map_err(|_| GdbTargetError::ReceiveMsgError)
    }

    /// Checks whether there's a message waiting on the receive channel
    pub fn try_recv(&self) -> Result<DebugAction, TryRecvError> {
        self.rx.try_recv()
    }
}

/// Creates a thread that handles gdb protocol
pub fn create_gdb_thread<T: GdbDebug + Send + 'static>(
    mut target: T,
) -> Result<(), <T as Target>::Error>
where
    <T as Target>::Error:
        std::fmt::Debug + Send + From<io::Error> + From<DebugMsg>,
{
    let socket = format!("localhost:{}", 8081);

    log::info!("Listening on {:?}", socket);
    let listener = TcpListener::bind(socket)?;

    log::info!("Starting GDB thread");
    let _handle = thread::Builder::new()
        .name("GDB handler".to_string())
        .spawn(
            move || -> Result<(), <T as gdbstub::target::Target>::Error> {
                log::info!("Waiting for GDB connection ... ");
                let (conn, _) = listener.accept()?;

                let conn: Box<dyn ConnectionExt<Error = io::Error>> = Box::new(conn);
                let debugger = GdbStub::new(conn);

                // Waits for vCPU to stop at entrypoint breakpoint
                let res = target.recv()?;
                if let DebugAction::VcpuStopped(_) = res {
                    event_loop_thread(debugger, &mut target);
                }

                Ok(())
            }
        );

    Ok(())
}
