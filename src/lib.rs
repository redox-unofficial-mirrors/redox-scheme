#![no_std]

extern crate alloc;
use alloc::format;

use core::marker::PhantomData;

use core::str;

use libredox::flag;
use syscall::schemev2::{Cqe, CqeOpcode, NewFdFlags, Opcode, Sqe};
use syscall::{Error, Result, EINTR, O_FSYNC};

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
#[derive(Clone, Copy, Debug, Default)]
pub struct Request<V: Version = V2> {
    sqe: V::RawSqe,
}
mod private {
    use core::ops::Deref;

    use super::*;

    pub trait Impl: Copy + Clone + core::fmt::Debug + Default {
        type RawSqe: core::fmt::Debug + Clone + Copy + Default;
        type RawCqe: core::fmt::Debug + Clone + Copy + Default + Deref<Target = [u8]>;
        const OPEN_FLAGS: i32 = 0;

        fn sqe_context_id(s: &Self::RawSqe) -> usize;
        fn sqe_request_id(s: &Self::RawSqe) -> Id;
        fn sqe_kind(s: Self::RawSqe) -> RequestKind<Self>;

        fn create_cqe(req: &CallRequest<Self>, status: Result<usize>) -> Self::RawCqe;
        fn post_fevent_cqe(fd: usize, flags: usize) -> Self::RawCqe;
    }
}
pub trait Version: private::Impl {}

#[derive(Clone, Copy, Debug)]
pub enum V2 {}
impl Default for V2 {
    fn default() -> Self {
        unreachable!()
    }
}
impl<V: private::Impl> Version for V {}

impl private::Impl for V2 {
    type RawSqe = Sqe;
    type RawCqe = Cqe;

    const OPEN_FLAGS: i32 = O_FSYNC as i32;

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
            //Some(Opcode::Munmap) => RequestKind::MunmapMsg,
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
    fn post_fevent_cqe(fd: usize, flags: usize) -> Cqe {
        Cqe {
            flags: CqeOpcode::SendFevent as u8,
            extra_raw: [0_u8; 3],
            tag: flags as u32,
            result: fd as u64,
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

pub struct Socket<V: Version = V2> {
    inner: libredox::Fd,
    _marker: PhantomData<fn() -> V>,
}

impl<V: Version> Socket<V> {
    fn create_inner(name: &str, nonblock: bool) -> Result<Self> {
        let mut flags = V::OPEN_FLAGS;

        if nonblock {
            flags |= flag::O_NONBLOCK;
        }

        let fd = libredox::Fd::open(
            &format!(":{name}"),
            flag::O_CLOEXEC | flag::O_CREAT | flags,
            0,
        )?;
        Ok(Self { inner: fd, _marker: PhantomData })
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
            Some(buf[0])
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
        self.inner.write(&V::post_fevent_cqe(id, flags))?;
        Ok(())
    }
    pub fn inner(&self) -> &libredox::Fd {
        &self.inner
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
