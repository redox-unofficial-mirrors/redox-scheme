#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::collections::vec_deque::VecDeque;
use alloc::format;
use alloc::vec::Vec;

use core::mem;
use core::str;
use core::task::Poll;

use libredox::flag;
use syscall::error::{Error, Result, EINTR, EWOULDBLOCK};
use syscall::flag::{
    CallFlags, FmoveFdFlags, FobtainFdFlags, RecvFdFlags, SchemeSocketCall, SendFdFlags,
};
use syscall::schemev2::{Cqe, CqeOpcode, NewFdFlags, Opcode, Sqe};

pub mod scheme;

#[cfg(feature = "std")]
pub mod wrappers;

pub struct CallerCtx {
    pub pid: usize,
    pub uid: u32,
    pub gid: u32,
    pub id: Id,
}

pub enum OpenResult {
    ThisScheme { number: usize, flags: NewFdFlags },
    OtherScheme { fd: usize },
    OtherSchemeMultiple { num_fds: usize },
    WouldBlock,
}

use core::mem::{size_of, MaybeUninit};

use self::scheme::IntoTag;

#[repr(transparent)]
#[derive(Debug, Default)]
pub struct Request {
    sqe: Sqe,
}

#[derive(Clone, Copy, Debug, Eq, Ord, Hash, PartialEq, PartialOrd)]
pub struct Id(u32);

#[derive(Debug, Eq, Ord, Hash, PartialEq, PartialOrd)]
pub struct Tag(Id);

impl Tag {
    pub fn id(&self) -> Id {
        self.0
    }
}

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

#[repr(transparent)]
#[derive(Debug)]
pub struct RecvFdRequest {
    inner: Request,
}

pub enum RequestKind {
    Call(CallRequest),
    Cancellation(CancellationRequest),
    SendFd(SendFdRequest),
    RecvFd(RecvFdRequest),
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
    #[inline]
    pub fn request_id(&self) -> Id {
        Id(self.inner.sqe.tag)
    }
}

impl SendFdRequest {
    #[inline]
    pub fn request(&self) -> &Request {
        &self.inner
    }
    #[inline]
    pub fn request_id(&self) -> Id {
        Id(self.inner.sqe.tag)
    }

    pub fn id(&self) -> usize {
        self.inner.sqe.args[0] as usize
    }

    pub fn flags(&self) -> SendFdFlags {
        SendFdFlags::from_bits_retain(self.inner.sqe.args[1] as usize)
    }
    pub fn arg(&self) -> u64 {
        self.inner.sqe.args[2]
    }

    pub fn num_fds(&self) -> usize {
        self.inner.sqe.args[3] as usize
    }

    pub fn obtain_fd(
        &self,
        socket: &Socket,
        flags: FobtainFdFlags,
        dst_fds: &mut [usize],
    ) -> Result<()> {
        assert!(!flags.contains(FobtainFdFlags::MANUAL_FD));

        let request_id = self.request_id().0;
        let metadata: [u64; 2] = [SchemeSocketCall::ObtainFd as u64, request_id as u64];

        let mut call_flags = CallFlags::FD;
        if flags.contains(FobtainFdFlags::EXCLUSIVE) {
            call_flags |= CallFlags::FD_EXCLUSIVE;
        }
        if flags.contains(FobtainFdFlags::UPPER_TBL) {
            call_flags |= CallFlags::FD_UPPER;
        }

        let dst_fds_bytes: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(
                dst_fds.as_mut_ptr() as *mut u8,
                dst_fds.len() * mem::size_of::<usize>(),
            )
        };

        socket.inner.call_ro(dst_fds_bytes, call_flags, &metadata)?;

        Ok(())
    }
}

impl RecvFdRequest {
    #[inline]
    pub fn request(&self) -> &Request {
        &self.inner
    }
    #[inline]
    pub fn request_id(&self) -> Id {
        Id(self.inner.sqe.tag)
    }

    pub fn id(&self) -> usize {
        self.inner.sqe.args[0] as usize
    }

    pub fn flags(&self) -> RecvFdFlags {
        RecvFdFlags::from_bits_retain(self.inner.sqe.args[1] as usize)
    }
    pub fn num_fds(&self) -> usize {
        self.inner.sqe.args[2] as usize
    }

    pub fn move_fd(&self, socket: &Socket, flags: FmoveFdFlags, fds: &[usize]) -> Result<()> {
        let metadata: [u64; 2] = [SchemeSocketCall::MoveFd as u64, self.request_id().0 as u64];

        let fds_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                fds.as_ptr() as *mut u8,
                fds.len() * mem::size_of::<usize>(),
            )
        };

        let mut call_flags = CallFlags::FD;
        if flags.contains(FmoveFdFlags::EXCLUSIVE) {
            call_flags |= CallFlags::FD_EXCLUSIVE;
        }
        if flags.contains(FmoveFdFlags::CLONE) {
            call_flags |= CallFlags::FD_CLONE;
        }

        socket.inner.call_wo(fds_bytes, call_flags, &metadata)?;

        Ok(())
    }
}

impl Request {
    #[inline]
    pub fn context_id(&self) -> usize {
        self.sqe.caller as usize
    }
    pub fn kind(self) -> RequestKind {
        match Opcode::try_from_raw(self.sqe.opcode) {
            Some(Opcode::Cancel) => RequestKind::Cancellation(CancellationRequest {
                id: Id(self.sqe.tag),
            }),
            Some(Opcode::Sendfd) => RequestKind::SendFd(SendFdRequest {
                inner: Request { sqe: self.sqe },
            }),
            Some(Opcode::Recvfd) => RequestKind::RecvFd(RecvFdRequest {
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
    // TODO: trait RequestBuf?
    pub fn read_requests(&self, buf: &mut Vec<Request>, behavior: SignalBehavior) -> Result<()> {
        let num_read = read_requests(self.inner.raw(), buf.spare_capacity_mut(), behavior)?;
        unsafe {
            buf.set_len(buf.len() + num_read);
        }
        Ok(())
    }
    pub fn next_request(&self, behavior: SignalBehavior) -> Result<Option<Request>> {
        let mut buf = MaybeUninit::uninit();
        Ok(
            if read_requests(self.inner.raw(), core::slice::from_mut(&mut buf), behavior)? > 0 {
                Some(unsafe { buf.assume_init() })
            } else {
                None
            },
        )
    }
    // TODO: trait ResponseBuf?
    pub fn write_responses(
        &self,
        buf: &mut VecDeque<Response>,
        behavior: SignalBehavior,
    ) -> Result<()> {
        let (slice, _) = buf.as_slices();

        // NOTE: error only allowed to occur if nothing was written
        let n = unsafe { write_responses(self.inner.raw(), slice, behavior)? };
        assert!(buf.len() >= n);
        buf.drain(..n).for_each(core::mem::forget);

        Ok(())
    }
    pub fn write_response(&self, resp: Response, behavior: SignalBehavior) -> Result<bool> {
        Ok(unsafe { write_responses(self.inner.raw(), &[resp], behavior)? } > 0)
    }
    pub fn inner(&self) -> &libredox::Fd {
        &self.inner
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Default)]
pub struct Response(Cqe);

impl Response {
    #[inline]
    pub fn err(err: i32, req: impl IntoTag) -> Self {
        Self::new(Err(Error::new(err)), req)
    }
    #[inline]
    pub fn ok(status: usize, req: impl IntoTag) -> Self {
        Self::new(Ok(status), req)
    }
    #[inline]
    pub fn ready_ok(status: usize, req: impl IntoTag) -> Poll<Self> {
        Poll::Ready(Self::ok(status, req))
    }
    #[inline]
    pub fn ready_err(err: i32, req: impl IntoTag) -> Poll<Self> {
        Poll::Ready(Self::err(err, req))
    }

    pub fn new(status: Result<usize>, req: impl IntoTag) -> Self {
        Self(Cqe {
            flags: CqeOpcode::RespondRegular as u8,
            extra_raw: [0_u8; 3],
            result: Error::mux(status) as u64,
            tag: req.into_tag().0 .0,
        })
    }
    pub fn open_dup_like(res: Result<OpenResult>, req: impl IntoTag) -> Response {
        match res {
            Ok(OpenResult::ThisScheme { number, flags }) => {
                Response::new(Ok(number), req).with_extra([flags.bits(), 0, 0])
            }
            Err(e) => Response::new(Err(e), req),
            Ok(OpenResult::OtherScheme { fd }) => Response::return_external_fd(fd, req),
            Ok(OpenResult::OtherSchemeMultiple { num_fds }) => {
                Response::return_external_multiple_fds(num_fds, req)
            }
            Ok(OpenResult::WouldBlock) => Response::new(Err(Error::new(EWOULDBLOCK)), req),
        }
    }
    pub fn return_external_fd(fd: usize, req: impl IntoTag) -> Self {
        Self(Cqe {
            flags: CqeOpcode::RespondWithFd as u8,
            extra_raw: [0_u8; 3],
            result: fd as u64,
            tag: req.into_tag().0 .0,
        })
    }
    pub fn return_external_multiple_fds(num_fds: usize, req: impl IntoTag) -> Self {
        Self(Cqe {
            flags: CqeOpcode::RespondWithMultipleFds as u8,
            extra_raw: [0_u8; 3],
            result: num_fds as u64,
            tag: req.into_tag().0 .0,
        })
    }
    pub fn with_extra(self, extra: [u8; 3]) -> Self {
        Self(Cqe {
            extra_raw: extra,
            ..self.0
        })
    }
    pub fn post_fevent(id: usize, flags: usize) -> Self {
        Self(Cqe {
            flags: CqeOpcode::SendFevent as u8,
            extra_raw: [0_u8; 3],
            tag: flags as u32,
            result: id as u64,
        })
    }
}

pub enum SignalBehavior {
    Interrupt,
    Restart,
}

/// Read requests into a possibly uninitialized buffer.
#[inline]
pub fn read_requests(
    socket: usize,
    buf: &mut [MaybeUninit<Request>],
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

// Write responses to a raw socket
//
// SAFETY
//
// Every Response can only be written once, otherwise double frees can occur.
#[inline]
pub unsafe fn write_responses(
    socket: usize,
    buf: &[Response],
    behavior: SignalBehavior,
) -> Result<usize> {
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
