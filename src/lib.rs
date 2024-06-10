use core::{slice, str};

use libredox::flag;
use syscall::schemev2::{Cqe, CqeOpcode, Opcode, Sqe};
use syscall::{
    Error, Packet, Result, EINTR, EOPNOTSUPP, ESKMSG, KSMSG_CANCEL, KSMSG_MMAP, KSMSG_MSYNC,
    KSMSG_MUNMAP, SKMSG_FRETURNFD,
};

pub use self::scheme::Scheme;
pub use self::scheme_block::SchemeBlock;
pub use self::scheme_block_mut::SchemeBlockMut;
pub use self::scheme_mut::SchemeMut;
pub use self::seek::*;

unsafe fn str_from_raw_parts(ptr: *const u8, len: usize) -> Option<&'static str> {
    let slice = slice::from_raw_parts(ptr, len);
    str::from_utf8(slice).ok()
}

mod scheme;
mod scheme_block;
mod scheme_block_mut;
mod scheme_mut;
mod seek;

pub struct CallerCtx {
    pub pid: usize,
    pub uid: u32,
    pub gid: u32,
}

pub enum OpenResult {
    ThisScheme { number: usize },
    OtherScheme { fd: usize },
}

// TODO: Find a better solution than generate.sh
pub(crate) fn convert_to_this_scheme(r: Result<usize>) -> Result<OpenResult> {
    r.map(|number| OpenResult::ThisScheme { number })
}
pub(crate) fn convert_to_this_scheme_block(r: Result<Option<usize>>) -> Result<Option<OpenResult>> {
    r.map(|o| o.map(|number| OpenResult::ThisScheme { number }))
}
pub(crate) fn convert_in_scheme_handle_block(
    _: &Packet,
    result: Result<Option<OpenResult>>,
) -> Result<Option<usize>> {
    match result {
        Ok(Some(OpenResult::ThisScheme { number })) => Ok(Some(number)),
        Ok(Some(OpenResult::OtherScheme { .. })) => Err(Error::new(EOPNOTSUPP)),
        Ok(None) => Ok(None),
        Err(err) => Err(err),
    }
}
pub(crate) fn convert_in_scheme_handle(
    packet: &mut Packet,
    result: Result<OpenResult>,
) -> Result<usize> {
    match result {
        Ok(OpenResult::ThisScheme { number }) => Ok(number),
        Ok(OpenResult::OtherScheme { fd }) => {
            packet.b = SKMSG_FRETURNFD;
            packet.c = fd;
            Err(Error::new(ESKMSG))
        }
        Err(err) => Err(err),
    }
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

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Request<V: Version = V2> {
    sqe: V::RawSqe,
}
mod private {
    use super::*;

    pub trait Impl: Copy + Clone + core::fmt::Debug + Default {
        type RawSqe: core::fmt::Debug + Clone + Copy + Default;
        type RawCqe: core::fmt::Debug + Clone + Copy + Default;

        fn sqe_context_id(s: &Self::RawSqe) -> usize;
        fn sqe_request_id(s: &Self::RawSqe) -> Id;
        fn sqe_kind(s: Self::RawSqe) -> RequestKind<Self>;

        fn create_cqe(req: &CallRequest<Self>, status: Result<usize>) -> Self::RawCqe;
    }
}
pub trait Version: private::Impl {}

#[derive(Clone, Copy, Debug)]
pub enum Legacy {}
#[derive(Clone, Copy, Debug)]
pub enum V2 {}
impl Default for Legacy {
    fn default() -> Self {
        unreachable!()
    }
}
impl Default for V2 {
    fn default() -> Self {
        unreachable!()
    }
}
impl<V: private::Impl> Version for V {}

impl private::Impl for Legacy {
    type RawSqe = Packet;
    type RawCqe = Packet;

    fn sqe_context_id(s: &Packet) -> usize {
        s.pid
    }
    fn sqe_request_id(s: &Packet) -> Id {
        Id(s.id as u32)
    }
    fn sqe_kind(packet: Self::RawSqe) -> RequestKind<Self> {
        // TODO: Should KSMSG_MMAP_PREP be a regular scheme call?

        match packet.a {
            KSMSG_CANCEL => RequestKind::Cancellation(CancellationRequest {
                id: Id(packet.b as u32),
            }),
            KSMSG_MSYNC => RequestKind::MsyncMsg,
            KSMSG_MUNMAP => RequestKind::MunmapMsg,
            KSMSG_MMAP => RequestKind::MmapMsg,

            _ => RequestKind::Call(CallRequest { inner: Request { sqe: packet } }),
        }
    }
    fn create_cqe(req: &CallRequest<Self>, status: Result<usize>) -> Packet {
        Packet {
            a: Error::mux(status),
            id: req.inner.sqe.id,
            ..Packet::default()
        }
    }
}
impl private::Impl for V2 {
    type RawSqe = Sqe;
    type RawCqe = Cqe;

    fn sqe_context_id(s: &Sqe) -> usize {
        s.caller as usize
    }
    fn sqe_request_id(s: &Sqe) -> Id {
        Id(s.tag)
    }
    fn sqe_kind(sqe: Self::RawSqe) -> RequestKind<Self> {
        match Opcode::try_from_raw(sqe.opcode) {
            Some(Opcode::Cancel) => RequestKind::Cancellation(CancellationRequest {
                id: Id(sqe.tag),
            }),
            Some(Opcode::Msync) => RequestKind::MsyncMsg,
            Some(Opcode::Munmap) => RequestKind::MunmapMsg,
            Some(Opcode::RequestMmap) => RequestKind::MmapMsg,

            _ => RequestKind::Call(CallRequest { inner: Request { sqe } }),
        }
    }
    fn create_cqe(req: &CallRequest<Self>, status: Result<usize>) -> Cqe {
        Cqe {
            flags: CqeOpcode::RespondRegular as u8,
            extra_raw: [0_u8; 3],
            result: Error::mux(status) as u64,
            tag: req.inner.sqe.tag,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, Hash, PartialEq, PartialOrd)]
pub struct Id(u32);

#[derive(Debug)]
pub struct CancellationRequest {
    pub id: Id,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct CallRequest<V: Version = V2> {
    inner: Request<V>,
}

pub enum RequestKind<V: Version = V2> {
    Call(CallRequest<V>),
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

}
impl CallRequest<Legacy> {
    pub fn handle_scheme(mut self, scheme: &impl Scheme) -> Response<Legacy> {
        unsafe {
            scheme.handle(&mut self.inner.sqe);
        }
        Response::<Legacy>(self.inner.sqe)
    }
    pub fn handle_scheme_mut(mut self, scheme: &mut impl SchemeMut) -> Response<Legacy> {
        unsafe {
            scheme.handle(&mut self.inner.sqe);
        }
        Response::<Legacy>(self.inner.sqe)
    }
    pub fn handle_scheme_block(self, scheme: &mut impl SchemeBlock) -> Result<Response<Legacy>, Self> {
        match unsafe { scheme.handle(&self.inner.sqe) } {
            Some(code) => Ok(Response::<Legacy>(Packet {
                a: code,
                ..self.inner.sqe
            })),
            None => Err(self),
        }
    }
    pub fn handle_scheme_block_mut(
        self,
        scheme: &mut impl SchemeBlockMut,
    ) -> Result<Response<Legacy>, Self> {
        match unsafe { scheme.handle(&self.inner.sqe) } {
            Some(code) => Ok(Response::<Legacy>(Packet {
                a: code,
                ..self.inner.sqe
            })),
            None => Err(self),
        }
    }
}

impl<V: Version> Request<V> {
    #[inline]
    pub fn context_id(&self) -> usize {
        V::sqe_context_id(&self.sqe)
    }
    #[inline]
    pub fn request_id(&self) -> Id {
        V::sqe_request_id(&self.sqe)
    }
    pub fn kind(self) -> RequestKind<V> {
        V::sqe_kind(self.sqe)
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
pub struct Response<V: Version = V2>(V::RawCqe);

impl<V: Version> Response<V> {
    pub fn new(req: &CallRequest<V>, status: Result<usize>) -> Self {
        Self(V::create_cqe(req, status))
    }
}

pub enum SignalBehavior {
    Interrupt,
    Restart,
}

// TODO: Support uninitialized memory
#[inline]
pub fn read_requests<V: Version>(
    socket: usize,
    buf: &mut [Request<V>],
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
