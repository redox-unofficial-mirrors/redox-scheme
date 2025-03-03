#![allow(async_fn_in_trait)]

use core::fmt::{self, Debug};
use core::mem::size_of;
use syscall::dirent::DirentBuf;
use syscall::schemev2::{Opcode, Sqe};
use syscall::{error::*, flag::*, Stat, StatVfs, TimeSpec};

use crate::{CallRequest, CallerCtx, Id, OpenResult, Response, SendFdRequest, Tag};

pub struct OpPathLike<Flags> {
    req: Tag,
    path: *const str, // &req
    pub flags: Flags,
}
impl<F> OpPathLike<F> {
    pub fn path(&self) -> &str {
        // SAFETY: borrowed from self.req
        unsafe { &*self.path }
    }
}
impl<Flags: Debug> Debug for OpPathLike<Flags> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpPathLike")
            .field("path", &self.path())
            .field("flags", &self.flags)
            .finish()
    }
}
pub struct OpCall {
    req: Tag,
    pub fd: usize,
    payload: *mut [u8],     // &req
    metadata: *const [u64], // &req
}
impl OpCall {
    pub fn payload_and_metadata(&mut self) -> (&mut [u8], &[u64]) {
        // SAFETY: borrows &self.req
        unsafe { (&mut *self.payload, &*self.metadata) }
    }
    pub fn payload(&mut self) -> &mut [u8] {
        self.payload_and_metadata().0
    }
    pub fn metadata(&self) -> &[u64] {
        // SAFETY: borrows &self.req
        unsafe { &*self.metadata }
    }
}
impl Debug for OpCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpCall")
            .field("fd", &self.fd)
            // TODO: debug first and last few bytes, collapse middle to ...
            .field("payload", &self.payload)
            .field("metadata", &self.metadata())
            .finish()
    }
}
#[derive(Debug)]
pub struct OpQueryRead<T: ?Sized> {
    pub fd: usize,
    req: Tag,
    buf: *mut T,
}
impl<T: ?Sized> OpQueryRead<T> {
    pub fn buf(&mut self) -> &mut T {
        // SAFETY: borrows &mut self.req
        unsafe { &mut *self.buf }
    }
}
#[derive(Debug)]
pub struct OpQueryWrite<T: ?Sized> {
    pub fd: usize,
    req: Tag,
    buf: *const T,
}
impl<T: ?Sized> OpQueryWrite<T> {
    pub fn buf(&self) -> &T {
        // SAFETY: borrows &self.req
        unsafe { &*self.buf }
    }
}
#[derive(Debug)]
pub struct OpGetdents {
    req: Tag,
    pub fd: usize,
    buf: *mut [u8],
    pub header_size: u16,
    pub opaque_offset: u64,
}
impl OpGetdents {
    pub fn raw_buf(&mut self) -> &mut [u8] {
        // SAFETY: borrows
        unsafe { &mut *self.buf }
    }
    pub fn buf(&mut self) -> Option<DirentBuf<&mut [u8]>> {
        let sz = self.header_size;
        DirentBuf::new(self.raw_buf(), sz)
    }
}
#[derive(Debug)]
pub struct OpRead {
    req: Tag,
    pub fd: usize,
    pub offset: u64,
    pub flags: u32,
    buf: *mut [u8],
}
impl OpRead {
    pub fn buf(&mut self) -> &mut [u8] {
        // SAFETY: Borrows &mut self.req
        unsafe { &mut *self.buf }
    }
}
#[derive(Debug)]
pub struct OpWrite {
    req: Tag,
    pub fd: usize,
    pub offset: u64,
    pub flags: u32,
    buf: *const [u8],
}
impl OpWrite {
    pub fn buf(&self) -> &[u8] {
        // SAFETY: Borrows &self.req
        unsafe { &*self.buf }
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum Op {
    Open(OpPathLike<usize>),
    Rmdir(OpPathLike<()>),
    Unlink(OpPathLike<()>),
    Dup(OpQueryWrite<[u8]>),
    Read(OpRead),
    Write(OpWrite),
    Fsize {
        req: Tag,
        fd: usize,
    },
    Fchmod {
        req: Tag,
        fd: usize,
        new_mode: u16,
    },
    Fchown {
        req: Tag,
        fd: usize,
        new_uid: u32,
        new_gid: u32,
    },
    Fcntl {
        req: Tag,
        fd: usize,
        cmd: usize,
        arg: usize,
    },
    Fevent {
        req: Tag,
        fd: usize,
        req_flags: EventFlags,
    },
    Fpath(OpQueryRead<[u8]>),
    Frename(OpQueryWrite<str>),
    Fstat(OpQueryRead<Stat>),
    FstatVfs(OpQueryRead<StatVfs>),
    Fsync {
        req: Tag,
        fd: usize,
    },
    Ftruncate {
        req: Tag,
        fd: usize,
        new_sz: u64,
    },
    Futimens(OpQueryWrite<[TimeSpec]>),

    MmapPrep {
        req: Tag,
        fd: usize,
        offset: u64,
        len: usize,
        flags: MapFlags,
    },
    Munmap {
        req: Tag,
        fd: usize,
        offset: u64,
        len: usize,
        flags: MunmapFlags,
    },

    Call(OpCall),

    Getdents(OpGetdents),
}

impl Op {
    /// Decode the raw SQE into an Op with borrowed buffers passed as slices.
    ///
    /// # Safety
    ///
    /// Any borrowed buffers will be unmapped whenever a response is sent, which unlike the
    /// move-based CallRequest API, needs to be managed manually by the caller.
    pub unsafe fn from_sqe_unchecked(sqe: &Sqe) -> Option<Op> {
        let req = Tag(Id(sqe.tag));
        let opcode = Opcode::try_from_raw(sqe.opcode)?;
        let args = sqe.args;

        let [a, b, c, _d, _e, _f] = args.map(|a| a as usize);
        use core::{slice, str};

        Some(match opcode {
            Opcode::Open => Op::Open(OpPathLike {
                req,
                path: str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
                flags: c,
            }),
            Opcode::Rmdir => Op::Rmdir(OpPathLike {
                req,
                path: str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
                flags: (),
            }),
            Opcode::Unlink => Op::Unlink(OpPathLike {
                req,
                path: str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
                flags: (),
            }),
            Opcode::Dup => Op::Dup(OpQueryWrite {
                req,
                fd: a,
                buf: slice::from_raw_parts(b as *const u8, c),
            }),
            Opcode::Read => Op::Read(OpRead {
                req,
                fd: a,
                buf: slice::from_raw_parts_mut(b as *mut u8, c),
                offset: args[3],
                flags: args[4] as u32,
            }),
            Opcode::Write => Op::Write(OpWrite {
                req,
                fd: a,
                buf: slice::from_raw_parts(b as *const u8, c),
                offset: args[3],
                flags: args[4] as u32,
            }),

            // TODO: 64-bit offset on 32-bit platforms
            Opcode::Fsize => Op::Fsize { req, fd: a },
            Opcode::Fchmod => Op::Fchmod {
                req,
                fd: a,
                new_mode: b as u16,
            },
            Opcode::Fchown => Op::Fchown {
                req,
                fd: a,
                new_uid: b as u32,
                new_gid: c as u32,
            },
            Opcode::Fcntl => Op::Fcntl {
                req,
                fd: a,
                cmd: b,
                arg: c,
            },
            Opcode::Fevent => Op::Fevent {
                req,
                fd: a,
                req_flags: EventFlags::from_bits_retain(b),
            },
            Opcode::Fpath => Op::Fpath(OpQueryRead {
                req,
                fd: a,
                buf: slice::from_raw_parts_mut(b as *mut u8, c),
            }),
            Opcode::Frename => Op::Frename(OpQueryWrite {
                req,
                fd: a,
                buf: str::from_utf8_unchecked(slice::from_raw_parts(b as *const u8, c)),
            }),
            Opcode::Fstat => {
                assert!(c >= size_of::<Stat>());
                Op::Fstat(OpQueryRead {
                    req,
                    fd: a,
                    buf: &mut *(b as *mut Stat),
                })
            }
            Opcode::Fstatvfs => {
                assert!(c >= size_of::<StatVfs>());
                Op::FstatVfs(OpQueryRead {
                    req,
                    fd: a,
                    buf: &mut *(b as *mut StatVfs),
                })
            }
            Opcode::Fsync => Op::Fsync { req, fd: a },
            Opcode::Ftruncate => Op::Ftruncate {
                req,
                fd: a,
                new_sz: args[1],
            },
            Opcode::Futimens => {
                assert!(c <= 2 * size_of::<TimeSpec>());
                Op::Futimens(OpQueryWrite {
                    req,
                    fd: a,
                    buf: slice::from_raw_parts(b as *const TimeSpec, c / size_of::<TimeSpec>()),
                })
            }

            Opcode::Call => Op::Call(OpCall {
                req,
                fd: a,
                payload: slice::from_raw_parts_mut(b as *mut u8, c),
                metadata: &sqe.args[3..],
            }),
            Opcode::Getdents => Op::Getdents(OpGetdents {
                req,
                fd: a,
                buf: slice::from_raw_parts_mut(b as *mut u8, c),
                header_size: sqe.args[3] as u16,
                opaque_offset: sqe.args[4],
            }),

            Opcode::MmapPrep => Op::MmapPrep {
                req,
                fd: a,
                offset: args[3],
                len: b,
                flags: MapFlags::from_bits_retain(c),
            },
            Opcode::Munmap => Op::Munmap {
                req,
                fd: a,
                offset: args[3],
                len: b,
                flags: MunmapFlags::from_bits_retain(c),
            },

            _ => return None,
        })
    }
}
impl CallRequest {
    pub fn caller(&self) -> CallerCtx {
        let sqe = &self.inner.sqe;

        CallerCtx {
            pid: sqe.caller as usize,
            uid: sqe.args[5] as u32,
            gid: (sqe.args[5] >> 32) as u32,
        }
    }
    pub fn op(self) -> Result<Op, Self> {
        match unsafe { Op::from_sqe_unchecked(&self.inner.sqe) } {
            Some(op) => Ok(op),
            None => Err(self),
        }
    }
    pub async fn handle_async(self, s: &mut impl SchemeAsync) -> Response {
        let caller = self.caller();

        let op = match self.op() {
            Ok(op) => op,
            Err(this) => return Response::new(Err(Error::new(ENOSYS)), this),
        };

        let (res, tag) = match op {
            Op::Open(req) => {
                let res = s.open(req.path(), req.flags, &caller).await;
                return Response::open_dup_like(res, req);
            }
            Op::Rmdir(req) => (
                s.rmdir(req.path(), &caller).await.map(|()| 0),
                req.into_tag(),
            ),
            Op::Unlink(req) => (
                s.unlink(req.path(), &caller).await.map(|()| 0),
                req.into_tag(),
            ),

            Op::Dup(req) => {
                let res = s.dup(req.fd, req.buf(), &caller).await;
                return Response::open_dup_like(res, req);
            }
            Op::Read(mut req) => {
                let OpRead {
                    fd, offset, flags, ..
                } = req;
                (
                    s.read(fd, req.buf(), offset, flags, &caller).await,
                    req.into_tag(),
                )
            }
            Op::Write(req) => (
                s.write(req.fd, req.buf(), req.offset, req.flags, &caller)
                    .await,
                req.into_tag(),
            ),

            // TODO: Don't convert to usize
            Op::Fsize { req, fd } => (s.fsize(fd, &caller).await.map(|l| l as usize), req),

            Op::Fchmod { req, fd, new_mode } => {
                (s.fchmod(fd, new_mode, &caller).await.map(|()| 0), req)
            }
            Op::Fchown {
                req,
                fd,
                new_uid,
                new_gid,
            } => (
                s.fchown(fd, new_uid, new_gid, &caller).await.map(|()| 0),
                req,
            ),
            Op::Fcntl { req, fd, cmd, arg } => (s.fcntl(fd, cmd, arg, &caller).await, req),
            Op::Fevent { req, fd, req_flags } => (
                s.fevent(fd, req_flags, &caller).await.map(|f| f.bits()),
                req,
            ),
            Op::Fpath(mut req) => (s.fpath(req.fd, req.buf(), &caller).await, req.into_tag()),
            Op::Frename(req) => (s.frename(req.fd, req.buf(), &caller).await, req.into_tag()),
            Op::Fstat(mut req) => (
                s.fstat(req.fd, req.buf(), &caller).await.map(|()| 0),
                req.into_tag(),
            ),
            Op::FstatVfs(mut req) => (
                s.fstatvfs(req.fd, req.buf(), &caller).await.map(|()| 0),
                req.into_tag(),
            ),
            Op::Fsync { req, fd } => (s.fsync(fd, &caller).await.map(|()| 0), req),
            Op::Ftruncate { req, fd, new_sz } => {
                (s.ftruncate(fd, new_sz, &caller).await.map(|()| 0), req)
            }
            Op::Futimens(req) => (
                s.futimens(req.fd, req.buf(), &caller).await.map(|()| 0),
                req.into_tag(),
            ),

            Op::MmapPrep {
                req,
                fd,
                offset,
                len,
                flags,
            } => (s.mmap_prep(fd, offset, len, flags, &caller).await, req),
            Op::Munmap {
                req,
                fd,
                offset,
                len,
                flags,
            } => (
                s.munmap(fd, offset, len, flags, &caller).await.map(|()| 0),
                req,
            ),

            Op::Call(mut req) => {
                let fd = req.fd;
                let (payload, metadata) = req.payload_and_metadata();
                (s.call(fd, payload, metadata).await, req.into_tag())
            }

            Op::Getdents(mut req) => {
                let OpGetdents {
                    fd, opaque_offset, ..
                } = req;
                let Some(buf) = req.buf() else {
                    return Response::err(EINVAL, req);
                };
                let buf_res = s.getdents(fd, buf, opaque_offset).await;
                (buf_res.map(|b| b.finalize()), req.into_tag())
            }
        };
        Response::new(res, tag)
    }
    // TODO: Fix function coloring, this is just s/.await//g
    pub fn handle_sync(self, s: &mut impl SchemeSync) -> Response {
        let caller = self.caller();

        let op = match self.op() {
            Ok(op) => op,
            Err(this) => return Response::new(Err(Error::new(ENOSYS)), this),
        };

        let (res, tag) = match op {
            Op::Open(req) => {
                let res = s.open(req.path(), req.flags, &caller);
                return Response::open_dup_like(res, req);
            }
            Op::Rmdir(req) => (s.rmdir(req.path(), &caller).map(|()| 0), req.into_tag()),
            Op::Unlink(req) => (s.unlink(req.path(), &caller).map(|()| 0), req.into_tag()),

            Op::Dup(req) => {
                let res = s.dup(req.fd, req.buf(), &caller);
                return Response::open_dup_like(res, req);
            }
            Op::Read(mut req) => {
                let OpRead {
                    fd, offset, flags, ..
                } = req;
                (
                    s.read(fd, req.buf(), offset, flags, &caller),
                    req.into_tag(),
                )
            }
            Op::Write(req) => (
                s.write(req.fd, req.buf(), req.offset, req.flags, &caller),
                req.into_tag(),
            ),

            // TODO: Don't convert to usize
            Op::Fsize { req, fd } => (s.fsize(fd, &caller).map(|l| l as usize), req),

            Op::Fchmod { req, fd, new_mode } => (s.fchmod(fd, new_mode, &caller).map(|()| 0), req),
            Op::Fchown {
                req,
                fd,
                new_uid,
                new_gid,
            } => (s.fchown(fd, new_uid, new_gid, &caller).map(|()| 0), req),
            Op::Fcntl { req, fd, cmd, arg } => (s.fcntl(fd, cmd, arg, &caller), req),
            Op::Fevent { req, fd, req_flags } => {
                (s.fevent(fd, req_flags, &caller).map(|f| f.bits()), req)
            }
            Op::Fpath(mut req) => (s.fpath(req.fd, req.buf(), &caller), req.into_tag()),
            Op::Frename(req) => (s.frename(req.fd, req.buf(), &caller), req.into_tag()),
            Op::Fstat(mut req) => (
                s.fstat(req.fd, req.buf(), &caller).map(|()| 0),
                req.into_tag(),
            ),
            Op::FstatVfs(mut req) => (
                s.fstatvfs(req.fd, req.buf(), &caller).map(|()| 0),
                req.into_tag(),
            ),
            Op::Fsync { req, fd } => (s.fsync(fd, &caller).map(|()| 0), req),
            Op::Ftruncate { req, fd, new_sz } => {
                (s.ftruncate(fd, new_sz, &caller).map(|()| 0), req)
            }
            Op::Futimens(req) => (
                s.futimens(req.fd, req.buf(), &caller).map(|()| 0),
                req.into_tag(),
            ),

            Op::MmapPrep {
                req,
                fd,
                offset,
                len,
                flags,
            } => (s.mmap_prep(fd, offset, len, flags, &caller), req),
            Op::Munmap {
                req,
                fd,
                offset,
                len,
                flags,
            } => (s.munmap(fd, offset, len, flags, &caller).map(|()| 0), req),

            Op::Call(mut req) => {
                let fd = req.fd;
                let (payload, metadata) = req.payload_and_metadata();
                (s.call(fd, payload, metadata), req.into_tag())
            }

            Op::Getdents(mut req) => {
                let OpGetdents {
                    fd, opaque_offset, ..
                } = req;
                let Some(buf) = req.buf() else {
                    return Response::err(EINVAL, req);
                };
                let buf_res = s.getdents(fd, buf, opaque_offset);
                (buf_res.map(|b| b.finalize()), req.into_tag())
            }
        };
        Response::new(res, tag)
    }
}

#[allow(unused_variables)]
pub trait SchemeAsync {
    /* Scheme operations */
    async fn open(&mut self, path: &str, flags: usize, ctx: &CallerCtx) -> Result<OpenResult> {
        Err(Error::new(ENOENT))
    }

    async fn rmdir(&mut self, path: &str, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(ENOENT))
    }

    async fn unlink(&mut self, path: &str, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(ENOENT))
    }

    /* Resource operations */
    async fn dup(&mut self, old_id: usize, buf: &[u8], ctx: &CallerCtx) -> Result<OpenResult> {
        Err(Error::new(EBADF))
    }

    async fn read(
        &mut self,
        id: usize,
        buf: &mut [u8],
        offset: u64,
        fcntl_flags: u32,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    async fn write(
        &mut self,
        id: usize,
        buf: &[u8],
        offset: u64,
        fcntl_flags: u32,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    async fn fsize(&mut self, id: usize, ctx: &CallerCtx) -> Result<u64> {
        Err(Error::new(ESPIPE))
    }

    async fn fchmod(&mut self, id: usize, new_mode: u16, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    async fn fchown(
        &mut self,
        id: usize,
        new_uid: u32,
        new_gid: u32,
        ctx: &CallerCtx,
    ) -> Result<()> {
        Err(Error::new(EBADF))
    }

    async fn fcntl(&mut self, id: usize, cmd: usize, arg: usize, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    async fn fevent(
        &mut self,
        id: usize,
        flags: EventFlags,
        ctx: &CallerCtx,
    ) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }

    async fn fpath(&mut self, id: usize, buf: &mut [u8], ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    async fn frename(&mut self, id: usize, path: &str, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    async fn fstat(&mut self, id: usize, stat: &mut Stat, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    async fn fstatvfs(&mut self, id: usize, stat: &mut StatVfs, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    async fn fsync(&mut self, id: usize, ctx: &CallerCtx) -> Result<()> {
        Ok(())
    }

    async fn ftruncate(&mut self, id: usize, len: u64, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    async fn futimens(&mut self, id: usize, times: &[TimeSpec], ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    async fn call(&mut self, id: usize, payload: &mut [u8], metadata: &[u64]) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn getdents<'buf>(
        &mut self,
        id: usize,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        Err(Error::new(EBADF))
    }

    async fn mmap_prep(
        &mut self,
        id: usize,
        offset: u64,
        size: usize,
        flags: MapFlags,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn munmap(
        &mut self,
        id: usize,
        offset: u64,
        size: usize,
        flags: MunmapFlags,
        ctx: &CallerCtx,
    ) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
    }
}
#[allow(unused_variables)]
pub trait SchemeSync {
    /* Scheme operations */
    fn open(&mut self, path: &str, flags: usize, ctx: &CallerCtx) -> Result<OpenResult> {
        Err(Error::new(ENOENT))
    }

    fn rmdir(&mut self, path: &str, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(ENOENT))
    }

    fn unlink(&mut self, path: &str, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(ENOENT))
    }

    /* Resource operations */

    fn dup(&mut self, old_id: usize, buf: &[u8], ctx: &CallerCtx) -> Result<OpenResult> {
        Err(Error::new(EBADF))
    }

    fn read(
        &mut self,
        id: usize,
        buf: &mut [u8],
        offset: u64,
        fcntl_flags: u32,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn write(
        &mut self,
        id: usize,
        buf: &[u8],
        offset: u64,
        fcntl_flags: u32,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn fsize(&mut self, id: usize, ctx: &CallerCtx) -> Result<u64> {
        Err(Error::new(ESPIPE))
    }

    fn fchmod(&mut self, id: usize, new_mode: u16, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn fchown(&mut self, id: usize, new_uid: u32, new_gid: u32, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn fcntl(&mut self, id: usize, cmd: usize, arg: usize, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn fevent(&mut self, id: usize, flags: EventFlags, ctx: &CallerCtx) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8], ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn frename(&mut self, id: usize, path: &str, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn fstat(&mut self, id: usize, stat: &mut Stat, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn fstatvfs(&mut self, id: usize, stat: &mut StatVfs, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn fsync(&mut self, id: usize, ctx: &CallerCtx) -> Result<()> {
        Ok(())
    }

    fn ftruncate(&mut self, id: usize, len: u64, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn futimens(&mut self, id: usize, times: &[TimeSpec], ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn getdents<'buf>(
        &mut self,
        id: usize,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        Err(Error::new(EBADF))
    }
    fn call(&mut self, id: usize, payload: &mut [u8], metadata: &[u64]) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn mmap_prep(
        &mut self,
        id: usize,
        offset: u64,
        size: usize,
        flags: MapFlags,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn munmap(
        &mut self,
        id: usize,
        offset: u64,
        size: usize,
        flags: MunmapFlags,
        ctx: &CallerCtx,
    ) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
    }
}
pub trait IntoTag {
    fn into_tag(self) -> Tag;
}
impl IntoTag for Tag {
    fn into_tag(self) -> Tag {
        self
    }
}
impl IntoTag for CallRequest {
    fn into_tag(self) -> Tag {
        Tag(self.request_id())
    }
}
impl IntoTag for SendFdRequest {
    fn into_tag(self) -> Tag {
        Tag(self.request_id())
    }
}
macro_rules! trivial_into {
    [$($name:ident,)*] => {
        $(
        impl IntoTag for $name {
            #[inline]
            fn into_tag(self) -> Tag {
                self.req
            }
        }
        )*
    }
}
trivial_into![OpCall, OpRead, OpWrite, OpGetdents,];
impl<T: ?Sized> IntoTag for OpQueryWrite<T> {
    fn into_tag(self) -> Tag {
        self.req
    }
}
impl<T: ?Sized> IntoTag for OpQueryRead<T> {
    fn into_tag(self) -> Tag {
        self.req
    }
}
impl<F> IntoTag for OpPathLike<F> {
    fn into_tag(self) -> Tag {
        self.req
    }
}
impl IntoTag for Op {
    fn into_tag(self) -> Tag {
        use Op::*;
        match self {
            Open(op) => op.into_tag(),
            Rmdir(op) | Self::Unlink(op) => op.into_tag(),
            Dup(op) => op.into_tag(),
            Read(op) => op.into_tag(),
            Write(op) => op.into_tag(),
            Fsize { req, .. }
            | Fchmod { req, .. }
            | Fchown { req, .. }
            | Fcntl { req, .. }
            | Fevent { req, .. }
            | Fsync { req, .. }
            | Ftruncate { req, .. }
            | MmapPrep { req, .. }
            | Munmap { req, .. } => req,
            Fpath(op) => op.into_tag(),
            Frename(op) => op.into_tag(),
            Fstat(op) => op.into_tag(),
            FstatVfs(op) => op.into_tag(),
            Futimens(op) => op.into_tag(),
            Call(op) => op.into_tag(),
            Getdents(op) => op.into_tag(),
        }
    }
}
