#![no_std]

extern crate alloc;
use alloc::format;

use core::marker::PhantomData;
use core::{slice, str};

use libredox::flag;
use syscall::schemev2::{Cqe, CqeOpcode, NewFdFlags, Opcode, Sqe};
use syscall::{
    Error, EventFlags, MapFlags, MunmapFlags, Packet, Result, Stat, StatVfs, TimeSpec, EBADF,
    EINTR, ENOENT, EOPNOTSUPP, ESKMSG, KSMSG_CANCEL, KSMSG_MMAP, KSMSG_MSYNC, KSMSG_MUNMAP,
    O_FSYNC, SKMSG_FRETURNFD,
};

pub use self::scheme::Scheme;
pub use self::scheme_block::SchemeBlock;
pub use self::scheme_block_mut::SchemeBlockMut;
pub use self::scheme_mut::SchemeMut;

unsafe fn str_from_raw_parts(ptr: *const u8, len: usize) -> Option<&'static str> {
    let slice = slice::from_raw_parts(ptr, len);
    str::from_utf8(slice).ok()
}

mod scheme;
mod scheme_block;
mod scheme_block_mut;
mod scheme_mut;

pub struct CallerCtx {
    pub pid: usize,
    pub uid: u32,
    pub gid: u32,
}

pub enum OpenResult {
    ThisScheme { number: usize, flags: NewFdFlags },
    OtherScheme { fd: usize },
}

// TODO: Find a better solution than generate.sh
pub(crate) fn convert_to_this_scheme(r: Result<usize>) -> Result<OpenResult> {
    r.map(|number| OpenResult::ThisScheme {
        number,
        flags: NewFdFlags::empty(),
    })
}
pub(crate) fn convert_to_this_scheme_block(r: Result<Option<usize>>) -> Result<Option<OpenResult>> {
    r.map(|o| {
        o.map(|number| OpenResult::ThisScheme {
            number,
            flags: NewFdFlags::empty(),
        })
    })
}
pub(crate) fn convert_in_scheme_handle_block(
    _: &Packet,
    result: Result<Option<OpenResult>>,
) -> Result<Option<usize>> {
    match result {
        Ok(Some(OpenResult::ThisScheme { number, .. })) => Ok(Some(number)),
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
        Ok(OpenResult::ThisScheme { number, .. }) => Ok(number),
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
            //KSMSG_MUNMAP => RequestKind::MunmapMsg,
            KSMSG_MMAP => RequestKind::MmapMsg,

            _ => RequestKind::Call(CallRequest {
                inner: Request { sqe: packet },
            }),
        }
    }
    fn create_cqe(req: &CallRequest<Self>, status: Result<usize>) -> Packet {
        Packet {
            a: Error::mux(status),
            id: req.inner.sqe.id,
            ..Packet::default()
        }
    }
    fn post_fevent_cqe(fd: usize, flags: usize) -> Packet {
        syscall::Packet {
            a: syscall::SYS_FEVENT,
            b: fd,
            c: flags,
            d: 0,
            ..Default::default()
        }
    }
}
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
            Some(Opcode::Cancel) => {
                RequestKind::Cancellation(CancellationRequest { id: Id(sqe.tag) })
            }
            Some(Opcode::Msync) => RequestKind::MsyncMsg,
            //Some(Opcode::Munmap) => RequestKind::MunmapMsg,
            Some(Opcode::RequestMmap) => RequestKind::MmapMsg,

            _ => RequestKind::Call(CallRequest {
                inner: Request { sqe },
            }),
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
    pub fn handle_scheme_block(
        self,
        scheme: &mut impl SchemeBlock,
    ) -> Result<Response<Legacy>, Self> {
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
impl CallRequest<V2> {
    pub fn handle_scheme_mut(self, scheme: &mut impl SchemeMut) -> Response<V2> {
        let Some(opcode) = Opcode::try_from_raw(self.inner.sqe.opcode) else {
            return Response::new(&self, Err(Error::new(EOPNOTSUPP)));
        };
        let args = self.inner.sqe.args;

        let hack_uid = args[5] as u32;
        let hack_gid = (args[5] >> 32) as u32;
        let ctx = CallerCtx {
            pid: self.inner.sqe.caller as usize,
            uid: hack_uid,
            gid: hack_gid,
        };

        let [a, b, c, _d, _e, _f] = args.map(|a| a as usize);
        let result = unsafe {
            use core::{slice, str};
            match opcode {
                Opcode::Open => match scheme.xopen(
                    str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
                    c,
                    &ctx,
                ) {
                    Ok(OpenResult::ThisScheme { number, flags }) => {
                        return Response(Cqe {
                            tag: self.inner.sqe.tag,
                            extra_raw: [flags.bits(), 0, 0],
                            flags: CqeOpcode::RespondRegular as u8,
                            result: number as u64,
                        })
                    }
                    Err(err) => Err(err),
                    Ok(OpenResult::OtherScheme { fd }) => {
                        return Response(Cqe {
                            tag: self.inner.sqe.tag,
                            extra_raw: [0_u8; 3],
                            flags: CqeOpcode::RespondWithFd as u8,
                            result: fd as u64,
                        })
                    }
                },
                Opcode::Rmdir => scheme.rmdir(
                    str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
                    hack_uid,
                    hack_gid,
                ),
                Opcode::Unlink => scheme.unlink(
                    str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
                    hack_uid,
                    hack_gid,
                ),
                Opcode::Dup => match scheme.xdup(a, slice::from_raw_parts(b as *const u8, c), &ctx)
                {
                    Ok(OpenResult::ThisScheme { number, flags }) => {
                        return Response(Cqe {
                            tag: self.inner.sqe.tag,
                            extra_raw: [flags.bits(), 0, 0],
                            flags: CqeOpcode::RespondRegular as u8,
                            result: number as u64,
                        })
                    }
                    Err(err) => Err(err),
                    Ok(OpenResult::OtherScheme { fd }) => {
                        return Response(Cqe {
                            tag: self.inner.sqe.tag,
                            extra_raw: [0_u8; 3],
                            flags: CqeOpcode::RespondWithFd as u8,
                            result: fd as u64,
                        })
                    }
                },
                Opcode::Read => scheme.read(
                    a,
                    slice::from_raw_parts_mut(b as *mut u8, c),
                    args[3],
                    args[4] as u32,
                ),
                Opcode::Write => scheme.write(
                    a,
                    slice::from_raw_parts(b as *const u8, c),
                    args[3],
                    args[4] as u32,
                ),

                // TODO: 64-bit offset on 32-bit platforms
                Opcode::Fsize => scheme.fsize(a).map(|o| o as usize),
                Opcode::Fchmod => scheme.fchmod(a, b as u16),
                Opcode::Fchown => scheme.fchown(a, b as u32, c as u32),
                Opcode::Fcntl => scheme.fcntl(a, b, c),
                Opcode::Fevent => scheme
                    .fevent(a, EventFlags::from_bits_retain(b))
                    .map(|fl| fl.bits()),
                Opcode::Fpath => scheme.fpath(a, slice::from_raw_parts_mut(b as *mut u8, c)),
                Opcode::Frename => scheme.frename(
                    a,
                    str::from_utf8_unchecked(slice::from_raw_parts(b as *const u8, c)),
                    hack_uid,
                    hack_gid,
                ),
                Opcode::Fstat => {
                    assert!(c >= size_of::<Stat>());
                    scheme.fstat(a, &mut *(b as *mut Stat))
                }
                Opcode::Fstatvfs => {
                    assert!(c >= size_of::<StatVfs>());
                    scheme.fstatvfs(a, &mut *(b as *mut StatVfs))
                }
                Opcode::Fsync => scheme.fsync(a),
                Opcode::Ftruncate => scheme.ftruncate(a, b),
                Opcode::Futimens => {
                    assert!(c <= 2 * core::mem::size_of::<TimeSpec>());
                    scheme.futimens(
                        a,
                        slice::from_raw_parts(
                            b as *const TimeSpec,
                            c / core::mem::size_of::<TimeSpec>(),
                        ),
                    )
                }

                Opcode::Close => scheme.close(a),

                Opcode::MmapPrep => scheme.mmap_prep(a, args[3], b, MapFlags::from_bits_retain(c)),
                Opcode::Munmap => scheme.munmap(a, args[3], b, MunmapFlags::from_bits_retain(c)),

                _ => return Response::new(&self, Err(Error::new(EOPNOTSUPP))),
            }
        };
        Response::<V2>::new(&self, result)
    }
    // TODO: Copy paste is bad, but ./generate.sh is worse
    pub fn handle_scheme_block_mut(self, scheme: &mut impl SchemeBlockMut) -> Option<Response<V2>> {
        let Some(opcode) = Opcode::try_from_raw(self.inner.sqe.opcode) else {
            return Some(Response::new(&self, Err(Error::new(EOPNOTSUPP))));
        };
        let args = self.inner.sqe.args;

        let hack_uid = args[5] as u32;
        let hack_gid = (args[5] >> 32) as u32;
        let ctx = CallerCtx {
            pid: self.inner.sqe.caller as usize,
            uid: hack_uid,
            gid: hack_gid,
        };

        let [a, b, c, _d, _e, _f] = args.map(|a| a as usize);
        let result = unsafe {
            use core::{slice, str};
            match opcode {
                Opcode::Open => match scheme
                    .xopen(
                        str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
                        c,
                        &ctx,
                    )
                    .transpose()?
                {
                    Ok(OpenResult::ThisScheme { number, flags }) => {
                        return Some(Response(Cqe {
                            tag: self.inner.sqe.tag,
                            extra_raw: [flags.bits(), 0, 0],
                            flags: CqeOpcode::RespondRegular as u8,
                            result: number as u64,
                        }))
                    }
                    Err(err) => Err(err),
                    Ok(OpenResult::OtherScheme { fd }) => {
                        return Some(Response(Cqe {
                            tag: self.inner.sqe.tag,
                            extra_raw: [0_u8; 3],
                            flags: CqeOpcode::RespondWithFd as u8,
                            result: fd as u64,
                        }))
                    }
                },
                Opcode::Rmdir => scheme
                    .rmdir(
                        str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
                        hack_uid,
                        hack_gid,
                    )
                    .transpose()?,
                Opcode::Unlink => scheme
                    .unlink(
                        str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
                        hack_uid,
                        hack_gid,
                    )
                    .transpose()?,
                Opcode::Dup => match scheme
                    .xdup(a, slice::from_raw_parts(b as *const u8, c), &ctx)
                    .transpose()?
                {
                    Ok(OpenResult::ThisScheme { number, flags }) => {
                        return Some(Response(Cqe {
                            tag: self.inner.sqe.tag,
                            extra_raw: [flags.bits(), 0, 0],
                            flags: CqeOpcode::RespondRegular as u8,
                            result: number as u64,
                        }))
                    }
                    Err(err) => Err(err),
                    Ok(OpenResult::OtherScheme { fd }) => {
                        return Some(Response(Cqe {
                            tag: self.inner.sqe.tag,
                            extra_raw: [0_u8; 3],
                            flags: CqeOpcode::RespondWithFd as u8,
                            result: fd as u64,
                        }))
                    }
                },
                Opcode::Read => scheme
                    .read(
                        a,
                        slice::from_raw_parts_mut(b as *mut u8, c),
                        args[3],
                        args[4] as u32,
                    )
                    .transpose()?,
                Opcode::Write => scheme
                    .write(
                        a,
                        slice::from_raw_parts(b as *const u8, c),
                        args[3],
                        args[4] as u32,
                    )
                    .transpose()?,

                // TODO: 64-bit offset on 32-bit platforms
                Opcode::Fsize => scheme.fsize(a).transpose()?.map(|o| o as usize),
                Opcode::Fchmod => scheme.fchmod(a, b as u16).transpose()?,
                Opcode::Fchown => scheme.fchown(a, b as u32, c as u32).transpose()?,
                Opcode::Fcntl => scheme.fcntl(a, b, c).transpose()?,
                Opcode::Fevent => scheme
                    .fevent(a, EventFlags::from_bits_retain(b))
                    .transpose()?
                    .map(|fl| fl.bits()),
                Opcode::Fpath => scheme
                    .fpath(a, slice::from_raw_parts_mut(b as *mut u8, c))
                    .transpose()?,
                Opcode::Frename => scheme
                    .frename(
                        a,
                        str::from_utf8_unchecked(slice::from_raw_parts(b as *const u8, c)),
                        hack_uid,
                        hack_gid,
                    )
                    .transpose()?,
                Opcode::Fstat => {
                    assert!(c >= size_of::<Stat>());
                    scheme.fstat(a, &mut *(b as *mut Stat)).transpose()?
                }
                Opcode::Fstatvfs => {
                    assert!(c >= size_of::<StatVfs>());
                    scheme.fstatvfs(a, &mut *(b as *mut StatVfs)).transpose()?
                }
                Opcode::Fsync => scheme.fsync(a).transpose()?,
                Opcode::Ftruncate => scheme.ftruncate(a, b).transpose()?,
                Opcode::Futimens => {
                    assert!(c <= 2 * core::mem::size_of::<TimeSpec>());
                    scheme
                        .futimens(
                            a,
                            slice::from_raw_parts(
                                b as *const TimeSpec,
                                c / core::mem::size_of::<TimeSpec>(),
                            ),
                        )
                        .transpose()?
                }

                Opcode::Close => scheme.close(a).transpose()?,

                Opcode::MmapPrep => scheme
                    .mmap_prep(a, args[3], b, MapFlags::from_bits_retain(c))
                    .transpose()?,
                Opcode::Munmap => scheme
                    .munmap(a, args[3], b, MunmapFlags::from_bits_retain(c))
                    .transpose()?,

                _ => return Some(Response::new(&self, Err(Error::new(EOPNOTSUPP)))),
            }
        };
        Some(Response::<V2>::new(&self, result))
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
        Ok(Self {
            inner: fd,
            _marker: PhantomData,
        })
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
