#![no_std]

extern crate alloc;
use alloc::format;

use core::str;

use libredox::flag;
use syscall::error::{Error, Result, EINTR};
use syscall::flag::{FobtainFdFlags, SendFdFlags};
use syscall::schemev2::{Cqe, CqeOpcode, NewFdFlags, Opcode, Sqe};

pub mod scheme;

pub struct CallerCtx {
    pub pid: usize,
    pub uid: u32,
    pub gid: u32,
}

pub enum OpenResult {
    ThisScheme { number: usize, flags: NewFdFlags },
    OtherScheme { fd: usize },
}

use core::mem::size_of;

#[repr(transparent)]
#[derive(Debug, Default)]
pub struct Request {
    sqe: Sqe,
}

#[derive(Clone, Copy, Debug, Eq, Ord, Hash, PartialEq, PartialOrd)]
pub struct Id(u32);

#[derive(Debug)]
pub struct CancellationRequest {
    pub id: Id,
}

#[repr(transparent)]
#[derive(Debug)]
pub struct CallRequest {
    inner: Request,
}

#[repr(transparent)]
#[derive(Debug)]
pub struct SendFdRequest {
    inner: Request,
}

pub enum RequestKind {
    Call(CallRequest),
    Cancellation(CancellationRequest),
    SendFd(SendFdRequest),
    MsyncMsg,
    MunmapMsg,
    MmapMsg,
    OnClose { id: usize },
}

impl CallRequest {
    #[inline]
    pub fn request(&self) -> &Request {
        &self.inner
    }
}

impl SendFdRequest {
    #[inline]
    pub fn request(&self) -> &Request {
        &self.inner
    }

    pub fn id(&self) -> usize {
        self.inner.sqe.args[0] as usize
    }

    pub fn flags(&self) -> SendFdFlags {
        SendFdFlags::from_bits_retain(self.inner.sqe.args[1] as usize)
    }

    pub fn obtain_fd(
        &self,
        socket: &Socket,
        flags: FobtainFdFlags,
        dst_fd_or_ptr: Result<usize, &mut usize>,
    ) -> Result<()> {
        assert!(!flags.contains(FobtainFdFlags::MANUAL_FD));
        match dst_fd_or_ptr {
            Ok(dst_fd) => {
                socket.inner.write(&Cqe {
                    flags: CqeOpcode::ObtainFd as u8,
                    extra_raw: usize::to_ne_bytes((flags | FobtainFdFlags::MANUAL_FD).bits())[..3]
                        .try_into()
                        .unwrap(),
                    tag: self.inner.request_id().0,
                    result: dst_fd as u64,
                })?;
            }
            Err(ptr) => {
                socket.inner.write(&Cqe {
                    flags: CqeOpcode::ObtainFd as u8,
                    extra_raw: usize::to_ne_bytes(flags.bits())[..3].try_into().unwrap(),
                    tag: self.inner.request_id().0,
                    result: ptr as *mut usize as u64,
                })?;
            }
        }
        Ok(())
    }
}

impl Request {
    #[inline]
    pub fn context_id(&self) -> usize {
        self.sqe.caller as usize
    }
    #[inline]
    pub fn request_id(&self) -> Id {
        Id(self.sqe.tag)
    }
    pub fn kind(self) -> RequestKind {
        match Opcode::try_from_raw(self.sqe.opcode) {
            Some(Opcode::Cancel) => RequestKind::Cancellation(CancellationRequest {
                id: Id(self.sqe.tag),
            }),
            Some(Opcode::Sendfd) => RequestKind::SendFd(SendFdRequest {
                inner: Request { sqe: self.sqe },
            }),
            Some(Opcode::Msync) => RequestKind::MsyncMsg,
            //Some(Opcode::Munmap) => RequestKind::MunmapMsg,
            Some(Opcode::RequestMmap) => RequestKind::MmapMsg,
            Some(Opcode::CloseMsg) => RequestKind::OnClose {
                id: self.sqe.args[0] as usize,
            },

            _ => RequestKind::Call(CallRequest {
                inner: Request { sqe: self.sqe },
            }),
        }
    }
}

pub struct Socket {
    inner: libredox::Fd,
}

impl Socket {
    fn create_inner(name: &str, nonblock: bool) -> Result<Self> {
        let mut flags = flag::O_FSYNC | 0x0020_0000 /* O_EXLOCK */;

        if nonblock {
            flags |= flag::O_NONBLOCK;
        }

        let fd = libredox::Fd::open(
            &format!(":{name}"),
            flag::O_CLOEXEC | flag::O_CREAT | flags,
            0,
        )?;
        Ok(Self { inner: fd })
    }
    pub fn create(name: impl AsRef<str>) -> Result<Self> {
        Self::create_inner(name.as_ref(), false)
    }
    pub fn nonblock(name: impl AsRef<str>) -> Result<Self> {
        Self::create_inner(name.as_ref(), true)
    }
    pub fn read_requests(&self, buf: &mut [Request], behavior: SignalBehavior) -> Result<usize> {
        read_requests(self.inner.raw(), buf, behavior)
    }
    pub fn next_request(&self, behavior: SignalBehavior) -> Result<Option<Request>> {
        let mut buf = [Request::default()];
        Ok(if self.read_requests(&mut buf, behavior)? > 0 {
            let [req] = buf;
            Some(req)
        } else {
            None
        })
    }
    pub fn write_responses(&self, buf: &[Response], behavior: SignalBehavior) -> Result<usize> {
        write_responses(self.inner.raw(), buf, behavior)
    }
    pub fn write_response(&self, resp: Response, behavior: SignalBehavior) -> Result<bool> {
        Ok(self.write_responses(&[resp], behavior)? > 0)
    }
    pub fn post_fevent(&self, id: usize, flags: usize) -> Result<()> {
        self.inner.write(&Cqe {
            flags: CqeOpcode::SendFevent as u8,
            extra_raw: [0_u8; 3],
            tag: flags as u32,
            result: id as u64,
        })?;
        Ok(())
    }
    pub fn inner(&self) -> &libredox::Fd {
        &self.inner
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Default)]
pub struct Response(Cqe);

impl Response {
    pub fn new(req: CallRequest, status: Result<usize>) -> Self {
        Self(Cqe {
            flags: CqeOpcode::RespondRegular as u8,
            extra_raw: [0_u8; 3],
            result: Error::mux(status) as u64,
            tag: req.inner.sqe.tag,
        })
    }
    pub fn open_dup_like(req: CallRequest, res: Result<OpenResult>) -> Response {
        match res {
            Ok(OpenResult::ThisScheme { number, flags }) => {
                Response::new(req, Ok(number)).with_extra([flags.bits(), 0, 0])
            }
            Err(e) => Response::new(req, Err(e)),
            Ok(OpenResult::OtherScheme { fd }) => Response::return_external_fd(req, fd),
        }
    }
    pub fn return_external_fd(req: CallRequest, fd: usize) -> Self {
        Self(Cqe {
            flags: CqeOpcode::RespondWithFd as u8,
            extra_raw: [0_u8; 3],
            result: fd as u64,
            tag: req.inner.sqe.tag,
        })
    }
    pub fn with_extra(self, extra: [u8; 3]) -> Self {
        Self(Cqe {
            extra_raw: extra,
            ..self.0
        })
    }

    pub fn for_sendfd(req: SendFdRequest, status: Result<usize>) -> Self {
        Self(Cqe {
            flags: CqeOpcode::RespondRegular as u8,
            extra_raw: [0_u8; 3],
            result: Error::mux(status) as u64,
            tag: req.inner.sqe.tag,
        })
    }
}

pub enum SignalBehavior {
    Interrupt,
    Restart,
}

// TODO: Support uninitialized memory
#[inline]
pub fn read_requests(
    socket: usize,
    buf: &mut [Request],
    behavior: SignalBehavior,
) -> Result<usize> {
    let len = buf.len().checked_mul(size_of::<Request>()).unwrap();

    let bytes_read = loop {
        match libredox::call::read(socket, unsafe {
            core::slice::from_raw_parts_mut(buf.as_mut_ptr().cast(), len)
        }) {
            Ok(n) => break n,
            Err(error) if error.errno() == EINTR => match behavior {
                SignalBehavior::Restart => continue,
                SignalBehavior::Interrupt => return Err(error.into()),
            },
            Err(err) => return Err(err.into()),
        }
    };

    debug_assert_eq!(bytes_read % size_of::<Request>(), 0);

    Ok(bytes_read / size_of::<Request>())
}

#[inline]
pub fn write_responses(socket: usize, buf: &[Response], behavior: SignalBehavior) -> Result<usize> {
    let bytes = unsafe {
        core::slice::from_raw_parts(
            buf.as_ptr().cast(),
            buf.len().checked_mul(size_of::<Response>()).unwrap(),
        )
    };

    let bytes_written = loop {
        match libredox::call::write(socket, bytes) {
            Ok(n) => break n,
            Err(error) if error.errno() == EINTR => match behavior {
                SignalBehavior::Restart => continue,
                SignalBehavior::Interrupt => return Err(error.into()),
            },
            Err(err) => return Err(err.into()),
        }
    };
    debug_assert_eq!(bytes_written % size_of::<Response>(), 0);
    Ok(bytes_written / size_of::<Response>())
}
