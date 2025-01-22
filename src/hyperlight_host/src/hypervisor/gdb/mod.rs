mod event_loop;
pub mod kvm_target;

use std::io::{self, ErrorKind};
use std::net::TcpListener;
use std::thread;

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use event_loop::event_loop_thread;
use gdbstub::arch::Arch;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::{BaseStopReason, GdbStub};
use gdbstub::target::Target;

#[derive(Debug)]
pub enum GdbTargetError {
    BindError,
    InstructionPointerError,
    ListenerError,
    QueueError,
    ReadRegistersError,
    ReceiveMsgError,
    CannotResume,
    SendMsgError,
    SetGuestDebugError,
    InvalidGva,
    UnexpectedMessageError,
    WriteRegistersError,
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

impl From<DebugMessage> for GdbTargetError {
    fn from(_value: DebugMessage) -> Self {
        GdbTargetError::UnexpectedMessageError
    }
}

impl From<TryRecvError> for GdbTargetError {
    fn from(_value: TryRecvError) -> Self {
        GdbTargetError::QueueError
    }
}

/// Trait that provides common communication methods for targets
pub trait GdbDebug: Target {
    /// Sends a message to the Hypervisor
    fn send(&self, ev: DebugMessage) -> Result<(), <Self as Target>::Error>;
    /// Waits for a message from the Hypervisor
    fn recv(&self) -> Result<DebugMessage, <Self as Target>::Error>;
    /// Checks for a pending message from the Hypervisor
    fn try_recv(&self) -> Result<DebugMessage, TryRecvError>;

    /// Marks the vCPU as paused
    fn pause_vcpu(&mut self);
    /// Resumes the vCPU
    fn resume_vcpu(&mut self) -> Result<(), <Self as Target>::Error>;
    /// Returns the reason why vCPU stopped
    #[allow(clippy::type_complexity)]
    fn get_stop_reason(
        &self,
    ) -> Result<Option<BaseStopReason<(), <Self::Arch as Arch>::Usize>>, Self::Error>;
}

/// Event sent to the VCPU execution loop
#[derive(Debug)]
pub enum DebugMessage {
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
    tx: Sender<DebugMessage>,
    /// Receive channel
    rx: Receiver<DebugMessage>,
}

impl GdbConnection {
    pub fn new_pair() -> (Self, Self) {
        let (hyp_tx, gdb_rx) = crossbeam_channel::unbounded();
        let (gdb_tx, hyp_rx) = crossbeam_channel::unbounded();

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

    /// Sends message over the transmit channel
    pub fn send(&self, msg: DebugMessage) -> Result<(), GdbTargetError> {
        self.tx.send(msg).map_err(|_| GdbTargetError::SendMsgError)
    }

    /// Waits for a message over the receive channel
    pub fn recv(&self) -> Result<DebugMessage, GdbTargetError> {
        self.rx.recv().map_err(|_| GdbTargetError::ReceiveMsgError)
    }

    /// Checks whether there's a message waiting on the receive channel
    pub fn try_recv(&self) -> Result<DebugMessage, TryRecvError> {
        self.rx.try_recv()
    }
}

/// Creates a thread that handles gdb protocol
pub fn create_gdb_thread<T: GdbDebug + Send + 'static>(
    mut target: T,
) -> Result<(), <T as Target>::Error>
where
    <T as Target>::Error:
        std::fmt::Debug + Send + From<io::Error> + From<DebugMessage> + From<TryRecvError>,
{
    let socket = format!("localhost:{}", 8081);

    log::info!("Listening on {:?}", socket);
    let listener = TcpListener::bind(socket)?;

    log::info!("Starting GDB thread");
    let _handle = thread::Builder::new()
        .name("GDB handler".to_string())
        .spawn(
            move || -> Result<(), <T as gdbstub::target::Target>::Error> {
                let mut initial_conn = true;
                let result = loop {
                    log::info!("Waiting for GDB connection ... ");
                    let (conn, _) = listener.accept().map_err(<T as Target>::Error::from)?;

                    let conn: Box<dyn ConnectionExt<Error = io::Error>> = Box::new(conn);
                    let debugger = GdbStub::new(conn);

                    if initial_conn {
                        // Waits for vCPU to stop at entrypoint breakpoint
                        let res = target.recv()?;
                        if let DebugMessage::VcpuStoppedEv = res {
                            target.pause_vcpu();

                            event_loop_thread(debugger, &mut target);
                            initial_conn = false;
                        } else {
                            break Err(res)?;
                        }
                    } else {
                        log::info!("Reattaching GDB connection ... ");
                        event_loop_thread(debugger, &mut target);
                    }
                };

                result
            },
        );

    Ok(())
}
