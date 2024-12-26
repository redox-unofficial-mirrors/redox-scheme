#![no_std]

extern crate alloc;
use alloc::format;
use syscall::dirent::DirentBuf;

use core::str;

use libredox::flag;
use syscall::schemev2::{Cqe, CqeOpcode, NewFdFlags, Opcode, Sqe};
use syscall::{
    Error, EventFlags, FobtainFdFlags, MapFlags, MunmapFlags, Packet, Result, SendFdFlags, Stat,
    StatVfs, TimeSpec, EBADF, EINTR, EINVAL, ENOENT, EOPNOTSUPP,
};

pub use self::scheme_block::SchemeBlock;
pub use self::scheme::Scheme;

mod scheme_block;
mod scheme;

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
#[derive(Clone, Copy, Debug)]
pub struct CallRequest {
    inner: Request,
}

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
}

impl CallRequest {
    #[inline]
    pub fn request(&self) -> Request {
        self.inner
    }
}

impl CallRequest {
    pub fn handle_scheme(self, scheme: &mut impl Scheme) -> Response {
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

        let [a, b, c, d, e, _f] = args.map(|a| a as usize);
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
                Opcode::Getdents => {
                    DirentBuf::new(slice::from_raw_parts_mut(b as *mut u8, c), d as u16)
                        .map_or(Err(Error::new(EINVAL)), |buf| {
                            scheme.getdents(a, buf, e as u64)
                        })
                        .map(|b| b.finalize())
                }

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
        Response::new(&self, result)
    }
    // TODO: Copy paste is bad, but ./generate.sh is worse
    pub fn handle_scheme_block(self, scheme: &mut impl SchemeBlock) -> Option<Response> {
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

        let [a, b, c, d, e, _f] = args.map(|a| a as usize);
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

                Opcode::Getdents => {
                    DirentBuf::new(slice::from_raw_parts_mut(b as *mut u8, c), d as u16)
                        .map_or(Err(Error::new(EINVAL)), |buf| {
                            scheme.getdents(a, buf, e as u64)
                        })
                        .map(|b| b.map(|b| b.finalize()))
                        .transpose()?
                }

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
        Some(Response::new(&self, result))
    }
}

impl SendFdRequest {
    #[inline]
    pub fn request(&self) -> Request {
        self.inner
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
        let mut flags = flag::O_FSYNC;

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
    pub fn new(req: &CallRequest, status: Result<usize>) -> Self {
        Self(Cqe {
            flags: CqeOpcode::RespondRegular as u8,
            extra_raw: [0_u8; 3],
            result: Error::mux(status) as u64,
            tag: req.inner.sqe.tag,
        })
    }

    pub fn for_sendfd(req: &SendFdRequest, status: Result<usize>) -> Self {
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
