#![feature(async_fn_in_trait)]

use core::{slice, str};

use libredox::flag;
use syscall::{
    Error, Packet, Result, EINTR, ENOSYS, EOPNOTSUPP, ESKMSG, KSMSG_CANCEL, KSMSG_MMAP, KSMSG_MSYNC, KSMSG_MUNMAP, SKMSG_FRETURNFD
};

unsafe fn str_from_raw_parts(ptr: *const u8, len: usize) -> Option<&'static str> {
    let slice = slice::from_raw_parts(ptr, len);
    str::from_utf8(slice).ok()
}

pub mod scheme;

pub struct CallerCtx {
    pub pid: usize,
    pub uid: u32,
    pub gid: u32,
}

pub enum OpenResult {
    ThisScheme { number: usize },
    OtherScheme { fd: usize },
}

impl CallerCtx {
    pub fn from_packet(packet: &Packet) -> Self {
        Self {
            pid: packet.pid,
            uid: packet.uid,
            gid: packet.gid,
        }
    }
}

use core::mem::size_of;

use self::scheme::{Op, Scheme};

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Request {
    packet: Packet,
}

#[derive(Clone, Copy, Debug, Eq, Ord, Hash, PartialEq, PartialOrd)]
pub struct Id(u64);

#[derive(Debug)]
pub struct CancellationRequest {
    pub id: Id,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct CallRequest {
    inner: Request,
}

pub enum RequestKind {
    Call(CallRequest),
    Cancellation(CancellationRequest),
    MsyncMsg,
    MunmapMsg,
    MmapMsg,
}

impl CallRequest {
    #[inline]
    pub fn request(&self) -> Request {
        self.inner
    }

    // TODO: make this fn safe: own ref to scheme socket fd, and ensure it's not possible to reply
    // so long as this future still exists.
    pub async unsafe fn handle(&self, scheme: &mut impl Scheme) -> Response {
        let Some(op) = Op::from_packet_unchecked(self.inner.packet) else {
            return Response::new(&self, Err(Error::new(ENOSYS)));
        };
        match op.handle(scheme).await {
            scheme::Response::Regular(reg) => Response(Packet {
                id: self.inner.packet.id,
                a: reg,
                ..Default::default()
            }),
            scheme::Response::ForwardFd(fd) => Response(Packet {
                id: 0,
                a: Error::mux(Err(Error::new(ESKMSG))),
                b: SKMSG_FRETURNFD,
                c: fd,
                ..Default::default()
            }),
        }
    }
}

impl Request {
    #[inline]
    pub fn context_id(&self) -> usize {
        self.packet.pid
    }
    #[inline]
    pub fn request_id(&self) -> Id {
        Id(self.packet.id)
    }
    pub fn kind(self) -> RequestKind {
        // TODO: Should KSMSG_MMAP_PREP be a regular scheme call?

        match self.packet.a {
            KSMSG_CANCEL => RequestKind::Cancellation(CancellationRequest {
                id: Id((self.packet.b as u64) | ((self.packet.c as u64) << 32)),
            }),
            KSMSG_MSYNC => RequestKind::MsyncMsg,
            KSMSG_MUNMAP => RequestKind::MunmapMsg,
            KSMSG_MMAP => RequestKind::MmapMsg,

            _ => RequestKind::Call(CallRequest { inner: self }),
        }
    }
}

pub struct Socket(libredox::Fd);

impl Socket {
    fn create_inner(name: &str, nonblock: bool) -> Result<Self> {
        let mut flags = 0;

        if nonblock {
            flags |= flag::O_NONBLOCK;
        }

        let fd = libredox::Fd::open(
            &format!(":{name}"),
            flag::O_CLOEXEC | flag::O_CREAT | flags,
            0,
        )?;
        Ok(Self(fd))
    }
    pub fn create(name: impl AsRef<str>) -> Result<Self> {
        Self::create_inner(name.as_ref(), false)
    }
    pub fn nonblock(name: impl AsRef<str>) -> Result<Self> {
        Self::create_inner(name.as_ref(), true)
    }
    pub fn read_requests(&self, buf: &mut [Request], behavior: SignalBehavior) -> Result<usize> {
        read_requests(self.0.raw(), buf, behavior)
    }
    pub fn next_request(&self, behavior: SignalBehavior) -> Result<Option<Request>> {
        let mut buf = [Request::default()];
        Ok(if self.read_requests(&mut buf, behavior)? > 0 {
            Some(buf[0])
        } else {
            None
        })
    }
    pub fn write_responses(&self, buf: &[Response], behavior: SignalBehavior) -> Result<usize> {
        write_responses(self.0.raw(), buf, behavior)
    }
    pub fn write_response(&self, resp: Response, behavior: SignalBehavior) -> Result<bool> {
        Ok(self.write_responses(&[resp], behavior)? > 0)
    }
    pub fn post_fevent(&self, id: usize, flags: usize) -> Result<()> {
        self.0.write(&syscall::Packet {
            a: syscall::SYS_FEVENT,
            b: id,
            c: flags,
            d: 0,
            ..Default::default()
        })?;
        Ok(())
    }
    pub fn inner(&self) -> &libredox::Fd {
        &self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Default)]
pub struct Response(Packet);

impl Response {
    pub fn new(req: &CallRequest, status: Result<usize>) -> Self {
        Self(Packet {
            a: Error::mux(status),
            ..req.inner.packet
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
