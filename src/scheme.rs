#![allow(async_fn_in_trait)]

use core::fmt::{self, Debug};
use core::mem::size_of;
use syscall::dirent::DirentBuf;
use syscall::schemev2::{Opcode, Sqe, SqeFlags};
use syscall::{Stat, StatVfs, StdFsCallMeta, TimeSpec, error::*, flag::*};

use crate::{
    CallRequest, CallerCtx, Id, OpenResult, RecvFdRequest, Response, SendFdRequest, Socket, Tag,
};

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

pub struct OpFdPathLike<Flags> {
    pub fd: usize,
    pub fcntl_flags: u32,
    inner: OpPathLike<Flags>,
}

impl<F> OpFdPathLike<F> {
    pub fn path(&self) -> &str {
        self.inner.path()
    }
    pub fn flags(&self) -> &F {
        &self.inner.flags
    }
}

impl<Flags: Debug> Debug for OpFdPathLike<Flags> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpFdPathLike")
            .field("fd", &self.fd)
            .field("path", &self.path())
            .field("flags", &self.inner.flags)
            .field("fcntl_flags", &self.fcntl_flags)
            .finish()
    }
}

pub struct OpCall {
    req: Tag,
    fds: [usize; 2],
    num_fds: usize,
    payload: *mut [u8], // &req
    metadata: [u64; 3],
}
impl OpCall {
    pub fn fd(&self) -> usize {
        *self.fds().first().expect("There is no target id")
    }
    pub fn fds(&self) -> &[usize] {
        &self.fds[..self.num_fds]
    }
    pub fn fds_and_payload_and_metadata(&mut self) -> (&[usize], &mut [u8], &[u64]) {
        unsafe {
            (
                &self.fds[..self.num_fds],
                &mut *self.payload,
                &self.metadata,
            )
        }
    }
    pub fn payload_and_metadata(&mut self) -> (&mut [u8], &[u64]) {
        // SAFETY: borrows &self.req
        unsafe { (&mut *self.payload, &self.metadata) }
    }
    pub fn payload(&mut self) -> &mut [u8] {
        self.payload_and_metadata().0
    }
    pub fn metadata(&self) -> &[u64] {
        &self.metadata
    }
}
impl Debug for OpCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpCall")
            .field("fd", &self.fds())
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
    OpenAt(OpFdPathLike<usize>),
    UnlinkAt(OpFdPathLike<usize>),
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
    Flink(OpQueryWrite<str>),
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
    StdFsCall(OpCall),

    Getdents(OpGetdents),

    Recvfd(RecvFdRequest),
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

        let [a, b, c, d, e, f] = args.map(|a| a as usize);
        use core::{slice, str};

        Some(match opcode {
            Opcode::OpenAt => Op::OpenAt(OpFdPathLike {
                fd: a,
                fcntl_flags: e as u32,
                inner: OpPathLike {
                    req,
                    path: unsafe {
                        str::from_utf8_unchecked(slice::from_raw_parts(b as *const u8, c))
                    },
                    flags: d,
                },
            }),
            Opcode::UnlinkAt => Op::UnlinkAt(OpFdPathLike {
                fd: a,
                fcntl_flags: 0,
                inner: OpPathLike {
                    req,
                    path: unsafe {
                        str::from_utf8_unchecked(slice::from_raw_parts(b as *const u8, c))
                    },
                    flags: d,
                },
            }),
            Opcode::Dup => Op::Dup(OpQueryWrite {
                req,
                fd: a,
                buf: unsafe { slice::from_raw_parts(b as *const u8, c) },
            }),
            Opcode::Read => Op::Read(OpRead {
                req,
                fd: a,
                buf: unsafe { slice::from_raw_parts_mut(b as *mut u8, c) },
                offset: args[3],
                flags: args[4] as u32,
            }),
            Opcode::Write => Op::Write(OpWrite {
                req,
                fd: a,
                buf: unsafe { slice::from_raw_parts(b as *const u8, c) },
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
            Opcode::Flink => Op::Flink(OpQueryWrite {
                req,
                fd: a,
                buf: unsafe { str::from_utf8_unchecked(slice::from_raw_parts(b as *const u8, c)) },
            }),
            Opcode::Fpath => Op::Fpath(OpQueryRead {
                req,
                fd: a,
                buf: unsafe { slice::from_raw_parts_mut(b as *mut u8, c) },
            }),
            Opcode::Frename => Op::Frename(OpQueryWrite {
                req,
                fd: a,
                buf: unsafe { str::from_utf8_unchecked(slice::from_raw_parts(b as *const u8, c)) },
            }),
            Opcode::Fstat => {
                assert!(c >= size_of::<Stat>());
                Op::Fstat(OpQueryRead {
                    req,
                    fd: a,
                    buf: unsafe { &mut *(b as *mut Stat) },
                })
            }
            Opcode::Fstatvfs => {
                assert!(c >= size_of::<StatVfs>());
                Op::FstatVfs(OpQueryRead {
                    req,
                    fd: a,
                    buf: unsafe { &mut *(b as *mut StatVfs) },
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
                    buf: unsafe {
                        slice::from_raw_parts(b as *const TimeSpec, c / size_of::<TimeSpec>())
                    },
                })
            }

            Opcode::Call => {
                if sqe.sqe_flags.contains(SqeFlags::MULTIPLE_IDS) {
                    Op::Call(OpCall {
                        req,
                        fds: [a, f],
                        num_fds: 2,
                        payload: unsafe { slice::from_raw_parts_mut(b as *mut u8, c) },
                        metadata: [sqe.args[3], sqe.args[4], 0],
                    })
                } else {
                    Op::Call(OpCall {
                        req,
                        fds: [a, 0],
                        num_fds: 1,
                        payload: unsafe { slice::from_raw_parts_mut(b as *mut u8, c) },
                        metadata: [sqe.args[3], sqe.args[4], sqe.args[5]],
                    })
                }
            }
            Opcode::StdFsCall => {
                if sqe.sqe_flags.contains(SqeFlags::MULTIPLE_IDS) {
                    Op::StdFsCall(OpCall {
                        req,
                        fds: [a, f],
                        num_fds: 2,
                        payload: unsafe { slice::from_raw_parts_mut(b as *mut u8, c) },
                        metadata: [sqe.args[3], sqe.args[4], 0],
                    })
                } else {
                    Op::StdFsCall(OpCall {
                        req,
                        fds: [a, 0],
                        num_fds: 1,
                        payload: unsafe { slice::from_raw_parts_mut(b as *mut u8, c) },
                        metadata: [sqe.args[3], sqe.args[4], sqe.args[5]],
                    })
                }
            }
            Opcode::Getdents => Op::Getdents(OpGetdents {
                req,
                fd: a,
                buf: unsafe { slice::from_raw_parts_mut(b as *mut u8, c) },
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
    pub fn is_explicitly_nonblock(&self) -> bool {
        let flags = match self {
            Self::Read(r) => r.flags,
            Self::Write(w) => w.flags,
            Self::OpenAt(o) => o.fcntl_flags,
            _ => 0,
        };
        flags as usize & O_NONBLOCK != 0
    }
    pub fn file_id(&self) -> Option<usize> {
        Some(match self {
            Op::UnlinkAt(op) => op.fd,
            Op::OpenAt(op) => op.fd,
            Op::Dup(op) => op.fd,
            Op::Read(op) => op.fd,
            Op::Write(op) => op.fd,
            Op::Fsize { fd, .. }
            | Op::Fchmod { fd, .. }
            | Op::Fchown { fd, .. }
            | Op::Fcntl { fd, .. }
            | Op::Fevent { fd, .. }
            | Op::Fsync { fd, .. }
            | Op::Ftruncate { fd, .. }
            | Op::MmapPrep { fd, .. }
            | Op::Munmap { fd, .. } => *fd,
            Op::Flink(op) => op.fd,
            Op::Fpath(op) => op.fd,
            Op::Frename(op) => op.fd,
            Op::Fstat(op) => op.fd,
            Op::FstatVfs(op) => op.fd,
            Op::Futimens(op) => op.fd,
            Op::Call(op) => op.fd(),
            Op::StdFsCall(op) => op.fd(),
            Op::Getdents(op) => op.fd,
            Op::Recvfd(req) => req.id(),
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
            id: Id(sqe.tag),
        }
    }
    pub fn op(self) -> Result<Op, Self> {
        match unsafe { Op::from_sqe_unchecked(&self.inner.sqe) } {
            Some(op) => Ok(op),
            None => Err(self),
        }
    }
    pub async fn handle_async(self, s: &mut impl SchemeAsync, state: &mut SchemeState) -> Response {
        let caller = self.caller();

        let op = match self.op() {
            Ok(op) => op,
            Err(this) => return Response::new(Err(Error::new(ENOSYS)), this),
        };

        op.handle_async(caller, s, state).await
    }
    pub fn handle_sync(self, s: &mut impl SchemeSync, state: &mut SchemeState) -> Response {
        let caller = self.caller();

        let op = match self.op() {
            Ok(op) => op,
            Err(this) => return Response::new(Err(Error::new(ENOSYS)), this),
        };
        op.handle_sync(caller, s, state)
    }
}

impl SendFdRequest {
    pub fn caller(&self) -> CallerCtx {
        let sqe = &self.inner.sqe;

        CallerCtx {
            pid: sqe.caller as usize,
            uid: sqe.args[5] as u32,
            gid: (sqe.args[5] >> 32) as u32,
            id: self.request_id(),
        }
    }
}

impl RecvFdRequest {
    pub fn op(self) -> Op {
        Op::Recvfd(self)
    }
    pub fn caller(&self) -> CallerCtx {
        let sqe = &self.inner.sqe;

        CallerCtx {
            pid: sqe.caller as usize,
            uid: sqe.args[5] as u32,
            gid: (sqe.args[5] >> 32) as u32,
            id: self.request_id(),
        }
    }
}

#[derive(Debug)]
pub enum SchemeResponse {
    Regular(Result<usize>),
    RegularAndNotifyOnDetach(Result<usize>),
    Opened(Result<OpenResult>),
}

impl From<Result<usize>> for SchemeResponse {
    fn from(value: Result<usize>) -> Self {
        Self::Regular(value)
    }
}
impl Op {
    pub fn handle_sync(
        mut self,
        caller: CallerCtx,
        s: &mut impl SchemeSync,
        state: &mut SchemeState,
    ) -> Response {
        match self.handle_sync_dont_consume(&caller, s, state) {
            SchemeResponse::Opened(open) => Response::open_dup_like(open, self),
            SchemeResponse::RegularAndNotifyOnDetach(status) => {
                Response::new_notify_on_detach(status, self)
            }
            SchemeResponse::Regular(reg) => Response::new(reg, self),
        }
    }
    pub fn handle_sync_dont_consume(
        &mut self,
        caller: &CallerCtx,
        s: &mut impl SchemeSync,
        state: &mut SchemeState,
    ) -> SchemeResponse {
        match *self {
            Op::OpenAt(ref req) => {
                let res = s.openat(
                    req.fd,
                    req.path(),
                    req.inner.flags,
                    req.fcntl_flags,
                    &caller,
                );
                return SchemeResponse::Opened(res);
            }
            Op::UnlinkAt(ref req) => s
                .unlinkat(req.fd, req.path(), req.inner.flags, &caller)
                .map(|()| 0)
                .into(),
            Op::Dup(ref req) => {
                let res = s.dup(req.fd, req.buf(), &caller);
                return SchemeResponse::Opened(res);
            }
            Op::Read(ref mut req) => {
                let OpRead {
                    fd, offset, flags, ..
                } = *req;
                s.read(fd, req.buf(), offset, flags, &caller).into()
            }
            Op::Write(ref req) => s
                .write(req.fd, req.buf(), req.offset, req.flags, &caller)
                .into(),

            // TODO: Don't convert to usize
            Op::Fsize { fd, .. } => s.fsize(fd, &caller).map(|l| l as usize).into(),

            Op::Fchmod { fd, new_mode, .. } => s.fchmod(fd, new_mode, &caller).map(|()| 0).into(),
            Op::Fchown {
                fd,
                new_uid,
                new_gid,
                ..
            } => s.fchown(fd, new_uid, new_gid, &caller).map(|()| 0).into(),
            Op::Fcntl { fd, cmd, arg, .. } => s.fcntl(fd, cmd, arg, &caller).into(),
            Op::Fevent { fd, req_flags, .. } => {
                s.fevent(fd, req_flags, &caller).map(|f| f.bits()).into()
            }
            Op::Flink(ref req) => s.flink(req.fd, req.buf(), &caller).into(),
            Op::Fpath(ref mut req) => s.fpath(req.fd, req.buf(), &caller).into(),
            Op::Frename(ref req) => s.frename(req.fd, req.buf(), &caller).into(),
            Op::Fstat(ref mut req) => s.fstat(req.fd, req.buf(), &caller).map(|()| 0).into(),
            Op::FstatVfs(ref mut req) => s.fstatvfs(req.fd, req.buf(), &caller).map(|()| 0).into(),
            Op::Fsync { fd, .. } => s.fsync(fd, &caller).map(|()| 0).into(),
            Op::Ftruncate { fd, new_sz, .. } => s.ftruncate(fd, new_sz, &caller).map(|()| 0).into(),
            Op::Futimens(ref req) => s.futimens(req.fd, req.buf(), &caller).map(|()| 0).into(),

            Op::MmapPrep {
                fd,
                offset,
                len,
                flags,
                ..
            } => s.mmap_prep(fd, offset, len, flags, &caller).into(),
            Op::Munmap {
                fd,
                offset,
                len,
                flags,
                ..
            } => s.munmap(fd, offset, len, flags, &caller).map(|()| 0).into(),

            Op::Call(ref mut req) => {
                let (fds, payload, metadata) = req.fds_and_payload_and_metadata();
                if fds.len() >= 2 {
                    s.call_multiple_ids(fds, payload, metadata, &caller).into()
                } else {
                    s.call(fds[0], payload, metadata, &caller).into()
                }
            }

            Op::StdFsCall(ref mut req) => {
                let fd = req.fd();
                let (fds, payload, metadata) = req.fds_and_payload_and_metadata();
                let Some(kind) = StdFsCallKind::try_from_raw(metadata[0] as u8) else {
                    return Err(Error::new(EOPNOTSUPP)).into();
                };
                let std_fs_call_meta = StdFsCallMeta::new(kind, metadata[1], metadata[2]);
                if let Some(resp) = state.std_fs_call(
                    fd,
                    kind,
                    s.inode(fd).ok(),
                    std_fs_call_meta,
                    payload,
                    &caller,
                ) {
                    return resp;
                } else {
                    s.translate_std_fs_call(fds, kind, payload, std_fs_call_meta, &caller)
                        .into()
                }
            }

            Op::Getdents(ref mut req) => {
                let OpGetdents {
                    fd, opaque_offset, ..
                } = *req;
                let Some(buf) = req.buf() else {
                    return Err(Error::new(EINVAL)).into();
                };
                let buf_res = s.getdents(fd, buf, opaque_offset);
                buf_res.map(|b| b.finalize()).into()
            }
            Op::Recvfd(ref req) => {
                let res = s.on_recvfd(req);
                return SchemeResponse::Opened(res);
            }
        }
    }
    // XXX: Although this has not yet been benchmarked, it likely makes sense for the
    // readiness-based (or non-blockable) and completion-based APIs to diverge, as it is imperative
    // that futures stay small.
    pub async fn handle_async(
        self,
        caller: CallerCtx,
        s: &mut impl SchemeAsync,
        state: &mut SchemeState,
    ) -> Response {
        let (res, tag) = match self {
            Op::OpenAt(req) => {
                let res = s
                    .openat(
                        req.fd,
                        req.path(),
                        req.inner.flags,
                        req.fcntl_flags,
                        &caller,
                    )
                    .await;
                return Response::open_dup_like(res, req);
            }
            Op::UnlinkAt(req) => (
                s.unlinkat(req.fd, req.path(), req.inner.flags, &caller)
                    .await
                    .map(|()| 0)
                    .into(),
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
            Op::Flink(req) => (s.flink(req.fd, req.buf(), &caller).await, req.into_tag()),
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
                let (fds, payload, metadata) = req.fds_and_payload_and_metadata();
                let res = if fds.len() >= 2 {
                    s.call_multiple_ids(fds, payload, metadata, &caller).await
                } else {
                    s.call(fds[0], payload, metadata, &caller).await
                };

                (res, req.into_tag())
            }

            Op::StdFsCall(mut req) => {
                let fd = req.fd();
                let (fds, payload, metadata) = req.fds_and_payload_and_metadata();
                let Some(kind) = StdFsCallKind::try_from_raw(metadata[0] as u8) else {
                    return Response::err(EOPNOTSUPP, req);
                };
                let std_fs_call_meta = StdFsCallMeta::new(kind, metadata[1], metadata[2]);
                if let Some(resp) = state.std_fs_call(
                    fd,
                    kind,
                    s.inode(fd).await.ok(),
                    std_fs_call_meta,
                    payload,
                    &caller,
                ) {
                    match resp {
                        SchemeResponse::Regular(status) => return Response::new(status, req),
                        SchemeResponse::RegularAndNotifyOnDetach(status) => {
                            return Response::new_notify_on_detach(status, req);
                        }
                        _ => unreachable!(),
                    }
                } else {
                    (
                        s.translate_std_fs_call(fds, kind, payload, std_fs_call_meta, &caller)
                            .await,
                        req.into_tag(),
                    )
                }
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
            Op::Recvfd(req) => {
                let res = s.on_recvfd(&req).await;
                return Response::open_dup_like(res, req);
            }
        };
        Response::new(res, tag)
    }
}

#[allow(unused_variables)]
pub trait SchemeAsync {
    /* Scheme operations */
    fn scheme_root(&mut self) -> Result<usize> {
        Err(Error::new(ENOSYS))
    }

    async fn openat(
        &mut self,
        fd: usize,
        path: &str,
        flags: usize,
        fcntl_flags: u32,
        ctx: &CallerCtx,
    ) -> Result<OpenResult> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn inode(&self, id: usize) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn unlinkat(
        &mut self,
        fd: usize,
        path: &str,
        flags: usize,
        ctx: &CallerCtx,
    ) -> Result<()> {
        Err(Error::new(ENOENT))
    }

    /* Resource operations */
    async fn dup(&mut self, old_id: usize, buf: &[u8], ctx: &CallerCtx) -> Result<OpenResult> {
        Err(Error::new(EOPNOTSUPP))
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
        Err(Error::new(EOPNOTSUPP))
    }

    async fn fchown(
        &mut self,
        id: usize,
        new_uid: u32,
        new_gid: u32,
        ctx: &CallerCtx,
    ) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn fcntl(&mut self, id: usize, cmd: usize, arg: usize, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn fevent(
        &mut self,
        id: usize,
        flags: EventFlags,
        ctx: &CallerCtx,
    ) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }

    async fn flink(&mut self, id: usize, path: &str, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn fpath(&mut self, id: usize, buf: &mut [u8], ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn frename(&mut self, id: usize, path: &str, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn fstat(&mut self, id: usize, stat: &mut Stat, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn fstatvfs(&mut self, id: usize, stat: &mut StatVfs, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
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

    async fn relpathat(
        &mut self,
        id: usize,
        dir_id: usize,
        path: &mut [u8],
        ctx: &CallerCtx,
    ) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    async fn call(
        &mut self,
        id: usize,
        payload: &mut [u8],
        metadata: &[u64],
        ctx: &CallerCtx, // Only pid and id are correct here, uid/gid are not used
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn call_multiple_ids(
        &mut self,
        ids: &[usize],
        payload: &mut [u8],
        metadata: &[u64],
        ctx: &CallerCtx, // Only pid and id are correct here, uid/gid are not used
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn std_fs_call(
        &mut self,
        id: usize,
        kind: StdFsCallKind,
        payload: &mut [u8],
        metadata: StdFsCallMeta,
        ctx: &CallerCtx, // Only pid and id are correct here, uid/gid are not used
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn getdents<'buf>(
        &mut self,
        id: usize,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        Err(Error::new(ENOTDIR))
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

    async fn on_recvfd(&mut self, recvfd_request: &RecvFdRequest) -> Result<OpenResult> {
        Err(Error::new(EOPNOTSUPP))
    }

    async fn translate_std_fs_call(
        &mut self,
        ids: &[usize],
        kind: StdFsCallKind,
        payload: &mut [u8],
        metadata: StdFsCallMeta,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        use syscall::flag::StdFsCallKind::*;
        match kind {
            Relpathat => {
                let (Some(target_id), Some(dir_id)) = (ids.first(), ids.get(1)) else {
                    return Err(Error::new(EINVAL));
                };
                self.relpathat(*target_id, *dir_id, payload, ctx).await
            }
            _ => {
                if ids.len() != 1 {
                    return Err(Error::new(EINVAL));
                }
                let id = ids[0];
                match kind {
                    Fchmod => self.fchmod(id, metadata.arg1 as u16, ctx).await.map(|_| 0),
                    // TODO: Handle inside redox-scheme
                    // Since this currently requires get_proc_credentials,
                    // fchown cannot be supported on the redox-scheme side.
                    Fchown => self
                        .std_fs_call(id, kind, payload, metadata, ctx)
                        .await
                        .map(|_| 0),
                    Getdents => {
                        let Some(buf) = DirentBuf::new(payload, metadata.arg2 as u16) else {
                            return Err(Error::new(EINVAL));
                        };
                        self.getdents(id, buf, metadata.arg1)
                            .await
                            .map(|buf_res| buf_res.finalize())
                    }
                    Fstat => {
                        if payload.len() != size_of::<Stat>() {
                            return Err(Error::new(EINVAL));
                        }
                        let stat = payload.as_mut_ptr() as *mut Stat;
                        self.fstat(id, unsafe { &mut *stat }, ctx).await.map(|_| 0)
                    }
                    Fstatvfs => {
                        if payload.len() != size_of::<StatVfs>() {
                            return Err(Error::new(EINVAL));
                        }
                        let stat = payload.as_mut_ptr() as *mut StatVfs;
                        self.fstatvfs(id, unsafe { &mut *stat }, ctx)
                            .await
                            .map(|_| 0)
                    }
                    Fsync => self.fsync(id, ctx).await.map(|_| 0),
                    Ftruncate => self.ftruncate(id, metadata.arg1, ctx).await.map(|_| 0),
                    Futimens => {
                        if payload.len() != 2 * size_of::<TimeSpec>() {
                            return Err(Error::new(EINVAL));
                        }
                        let times = unsafe {
                            core::slice::from_raw_parts(
                                payload.as_ptr() as *const TimeSpec,
                                payload.len() / size_of::<TimeSpec>(),
                            )
                        };
                        self.futimens(id, times, ctx).await.map(|_| 0)
                    }
                    /* TODO: Support Unlinkat using std_fs_call
                    Unlinkat => self.std_fs_call(fd, kind, payload, metadata, &caller).map(|_| 0)
                    */
                    _ => Err(Error::new(EOPNOTSUPP)),
                }
            }
        }
    }
}
#[allow(unused_variables)]
pub trait SchemeSync {
    /* Scheme operations */
    fn scheme_root(&mut self) -> Result<usize> {
        Err(Error::new(ENOSYS))
    }
    fn openat(
        &mut self,
        fd: usize,
        path: &str,
        flags: usize,
        fcntl_flags: u32,
        ctx: &CallerCtx,
    ) -> Result<OpenResult> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn unlinkat(&mut self, fd: usize, path: &str, flags: usize, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(ENOENT))
    }

    fn inode(&self, id: usize) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    /* Resource operations */
    fn dup(&mut self, old_id: usize, buf: &[u8], ctx: &CallerCtx) -> Result<OpenResult> {
        Err(Error::new(EOPNOTSUPP))
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
        Err(Error::new(EOPNOTSUPP))
    }

    fn fchown(&mut self, id: usize, new_uid: u32, new_gid: u32, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn fcntl(&mut self, id: usize, cmd: usize, arg: usize, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn fevent(&mut self, id: usize, flags: EventFlags, ctx: &CallerCtx) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }

    fn flink(&mut self, id: usize, path: &str, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8], ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn frename(&mut self, id: usize, path: &str, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn fstat(&mut self, id: usize, stat: &mut Stat, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn fstatvfs(&mut self, id: usize, stat: &mut StatVfs, ctx: &CallerCtx) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
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

    fn relpathat(
        &mut self,
        id: usize,
        dir_id: usize,
        path: &mut [u8],
        ctx: &CallerCtx,
    ) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn call(
        &mut self,
        id: usize,
        payload: &mut [u8],
        metadata: &[u64],
        ctx: &CallerCtx, // Only pid and id are correct here, uid/gid are not used
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn call_multiple_ids(
        &mut self,
        ids: &[usize],
        payload: &mut [u8],
        metadata: &[u64],
        ctx: &CallerCtx, // Only pid and id are correct here, uid/gid are not used
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn std_fs_call(
        &mut self,
        id: usize,
        kind: StdFsCallKind,
        payload: &mut [u8],
        metadata: StdFsCallMeta,
        ctx: &CallerCtx, // Only pid and id are correct here, uid/gid are not used
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn getdents<'buf>(
        &mut self,
        id: usize,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        Err(Error::new(ENOTDIR))
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

    fn on_close(&mut self, id: usize) {}

    fn on_sendfd(&mut self, sendfd_request: &SendFdRequest) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn on_recvfd(&mut self, recvfd_request: &RecvFdRequest) -> Result<OpenResult> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn translate_std_fs_call(
        &mut self,
        ids: &[usize],
        kind: StdFsCallKind,
        payload: &mut [u8],
        metadata: StdFsCallMeta,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        use syscall::flag::StdFsCallKind::*;
        match kind {
            Relpathat => {
                if ids.len() != 2 {
                    return Err(Error::new(EINVAL));
                }
                self.relpathat(ids[0], ids[1], payload, ctx)
            }
            _ => {
                if ids.len() != 1 {
                    return Err(Error::new(EINVAL));
                }
                let id = ids[0];
                match kind {
                    Fchmod => self.fchmod(id, metadata.arg1 as u16, ctx).map(|_| 0),
                    // TODO: Handle inside redox-scheme
                    // Since this currently requires get_proc_credentials,
                    // fchown cannot be supported on the redox-scheme side.
                    Fchown => self
                        .std_fs_call(id, kind, payload, metadata, ctx)
                        .map(|_| 0),
                    Getdents => {
                        let Some(buf) = DirentBuf::new(payload, metadata.arg2 as u16) else {
                            return Err(Error::new(EINVAL));
                        };
                        self.getdents(id, buf, metadata.arg1)
                            .map(|buf_res| buf_res.finalize())
                    }
                    Fstat => {
                        if payload.len() != size_of::<Stat>() {
                            return Err(Error::new(EINVAL));
                        }
                        let stat = payload.as_mut_ptr() as *mut Stat;
                        self.fstat(id, unsafe { &mut *stat }, ctx).map(|_| 0)
                    }
                    Fstatvfs => {
                        if payload.len() != size_of::<StatVfs>() {
                            return Err(Error::new(EINVAL));
                        }
                        let stat = payload.as_mut_ptr() as *mut StatVfs;
                        self.fstatvfs(id, unsafe { &mut *stat }, ctx).map(|_| 0)
                    }
                    Fsync => self.fsync(id, ctx).map(|_| 0),
                    Ftruncate => self.ftruncate(id, metadata.arg1, ctx).map(|_| 0),
                    Futimens => {
                        if payload.len() != 2 * size_of::<TimeSpec>() {
                            return Err(Error::new(EINVAL));
                        }
                        let times = unsafe {
                            core::slice::from_raw_parts(
                                payload.as_ptr() as *const TimeSpec,
                                payload.len() / size_of::<TimeSpec>(),
                            )
                        };
                        self.futimens(id, times, ctx).map(|_| 0)
                    }
                    /* TODO: Support Unlinkat using std_fs_call
                    Unlinkat => self.std_fs_call(fd, kind, payload, metadata, &caller).map(|_| 0)
                    */
                    _ => Err(Error::new(EOPNOTSUPP)),
                }
            }
        }
    }
}

pub fn register_sync_scheme<S: SchemeSync>(
    socket: &Socket,
    name: &str,
    scheme: &mut S,
) -> Result<()> {
    let cap_id = scheme.scheme_root()?;
    register_scheme_inner(socket, name, cap_id)
}

pub fn register_async_scheme<S: SchemeAsync>(
    socket: &Socket,
    name: &str,
    scheme: &mut S,
) -> Result<()> {
    let cap_id = scheme.scheme_root()?;
    register_scheme_inner(socket, name, cap_id)
}

pub fn register_scheme_inner(socket: &Socket, name: &str, cap_id: usize) -> Result<()> {
    let cap_fd = socket.create_this_scheme_fd(0, cap_id, 0, 0)?;
    let current_namespace_fd = libredox::call::getns()?;
    Ok(libredox::call::register_scheme_to_ns(
        current_namespace_fd,
        name,
        cap_fd,
    )?)
}

pub trait IntoTag {
    fn into_tag(self) -> Tag;
    fn req_id(&self) -> Id;
}
impl IntoTag for Tag {
    fn into_tag(self) -> Tag {
        self
    }
    fn req_id(&self) -> Id {
        self.0
    }
}
impl IntoTag for CallRequest {
    fn into_tag(self) -> Tag {
        Tag(self.request_id())
    }
    fn req_id(&self) -> Id {
        self.request_id()
    }
}
impl IntoTag for SendFdRequest {
    fn into_tag(self) -> Tag {
        Tag(self.request_id())
    }
    fn req_id(&self) -> Id {
        self.request_id()
    }
}
impl IntoTag for RecvFdRequest {
    fn into_tag(self) -> Tag {
        Tag(self.request_id())
    }
    fn req_id(&self) -> Id {
        self.request_id()
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
            #[inline]
            fn req_id(&self) -> Id {
                self.req.req_id()
            }
        }
        )*
    }
}
trivial_into![OpCall, OpRead, OpWrite, OpGetdents,];

macro_rules! trivial_unsafe_impl_send_sync {
    ($($t:ident),* $(,)?) => {
        $(
            unsafe impl Send for $t {}
            unsafe impl Sync for $t {}
        )*
    };
}
// # Safety
//
// Op instances are only valid while processing syscall requests.
trivial_unsafe_impl_send_sync![OpCall, OpRead, OpWrite, OpGetdents,];
unsafe impl<T: ?Sized> Send for OpQueryWrite<T> {}
unsafe impl<T: ?Sized> Sync for OpQueryWrite<T> {}

unsafe impl<T: ?Sized> Send for OpQueryRead<T> {}
unsafe impl<T: ?Sized> Sync for OpQueryRead<T> {}

unsafe impl<Flags> Send for OpFdPathLike<Flags> {}
unsafe impl<Flags> Sync for OpFdPathLike<Flags> {}

unsafe impl<Flags> Send for OpPathLike<Flags> {}
unsafe impl<Flags> Sync for OpPathLike<Flags> {}

impl<T: ?Sized> IntoTag for OpQueryWrite<T> {
    fn into_tag(self) -> Tag {
        self.req
    }
    fn req_id(&self) -> Id {
        self.req.0
    }
}
impl<T: ?Sized> IntoTag for OpQueryRead<T> {
    fn into_tag(self) -> Tag {
        self.req
    }
    fn req_id(&self) -> Id {
        self.req.0
    }
}
impl<F> IntoTag for OpPathLike<F> {
    fn into_tag(self) -> Tag {
        self.req
    }
    fn req_id(&self) -> Id {
        self.req.0
    }
}
impl<F> IntoTag for OpFdPathLike<F> {
    fn into_tag(self) -> Tag {
        self.inner.req
    }
    fn req_id(&self) -> Id {
        self.inner.req.0
    }
}
impl IntoTag for Op {
    fn into_tag(self) -> Tag {
        use Op::*;
        match self {
            OpenAt(op) => op.into_tag(),
            UnlinkAt(op) => op.into_tag(),
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
            Flink(op) => op.into_tag(),
            Fpath(op) => op.into_tag(),
            Frename(op) => op.into_tag(),
            Fstat(op) => op.into_tag(),
            FstatVfs(op) => op.into_tag(),
            Futimens(op) => op.into_tag(),
            Call(op) => op.into_tag(),
            StdFsCall(op) => op.into_tag(),
            Getdents(op) => op.into_tag(),
            Recvfd(req) => req.into_tag(),
        }
    }
    fn req_id(&self) -> Id {
        use Op::*;
        match self {
            OpenAt(op) => op.req_id(),
            UnlinkAt(op) => op.req_id(),
            Dup(op) => op.req_id(),
            Read(op) => op.req_id(),
            Write(op) => op.req_id(),
            Fsize { req, .. }
            | Fchmod { req, .. }
            | Fchown { req, .. }
            | Fcntl { req, .. }
            | Fevent { req, .. }
            | Fsync { req, .. }
            | Ftruncate { req, .. }
            | MmapPrep { req, .. }
            | Munmap { req, .. } => req.req_id(),
            Flink(op) => op.req_id(),
            Fpath(op) => op.req_id(),
            Frename(op) => op.req_id(),
            Fstat(op) => op.req_id(),
            FstatVfs(op) => op.req_id(),
            Futimens(op) => op.req_id(),
            Call(op) => op.req_id(),
            StdFsCall(op) => op.req_id(),
            Getdents(op) => op.req_id(),
            Recvfd(req) => req.req_id(),
        }
    }
}

#[cfg(not(feature = "std"))]
pub struct SchemeState {}
#[cfg(not(feature = "std"))]
impl SchemeState {
    pub fn new() -> Self {
        Self {}
    }
    fn std_fs_call(
        &mut self,
        id: usize,
        kind: StdFsCallKind,
        inode: Option<usize>,
        metadata: StdFsCallMeta,
        payload: &mut [u8],
        ctx: &CallerCtx,
    ) -> Option<SchemeResponse> {
        None
    }
    pub fn on_close(&mut self, id: usize) {}

    pub fn on_detach(&mut self, _id: usize, _inode: usize, _pid: usize) {}
}

#[cfg(feature = "std")]
use crate::advisory_flock::{LockError, LockKind, LockOwner, LockTarget, MountLockSet};
#[cfg(feature = "std")]
pub struct SchemeState {
    flocks: MountLockSet,
}
#[cfg(feature = "std")]
impl SchemeState {
    pub fn new() -> Self {
        Self {
            flocks: MountLockSet::new(),
        }
    }

    fn std_fs_call(
        &mut self,
        id: usize,
        kind: StdFsCallKind,
        inode: Option<usize>,
        metadata: StdFsCallMeta,
        payload: &mut [u8],
        ctx: &CallerCtx,
    ) -> Option<SchemeResponse> {
        match kind {
            StdFsCallKind::Lock => Some({
                let inode = inode?;
                let (owner, target, start, len, kind) = (
                    if metadata.arg1 & (1 << 63) == (1 << 63) {
                        LockOwner::Resource { fd: id }
                    } else {
                        LockOwner::Process { pid: ctx.pid }
                    },
                    LockTarget::Inode { inode: inode },
                    (metadata.arg1 & !(1 << 63)),
                    (metadata.arg2 & !(1 << 63)),
                    if metadata.arg2 & (1 << 63) == (1 << 63) {
                        LockKind::Exclusive
                    } else {
                        LockKind::Shared
                    },
                );

                match self.flocks.lock(kind, owner, target, start, len) {
                    Ok(()) if owner.is_process() => SchemeResponse::RegularAndNotifyOnDetach(Ok(0)),
                    Ok(()) if !owner.is_process() => SchemeResponse::Regular(Ok(0)),
                    Err(LockError::Conflict) => {
                        SchemeResponse::Regular(Err(Error::new(EWOULDBLOCK)))
                    }
                    _ => unreachable!(),
                }
            }),

            StdFsCallKind::Unlock => Some({
                let inode = inode?;
                let (owner, target, start, len) = (
                    if metadata.arg1 & (1 << 63) == (1 << 63) {
                        LockOwner::Resource { fd: id }
                    } else {
                        LockOwner::Process { pid: ctx.pid }
                    },
                    LockTarget::Inode { inode: inode },
                    (metadata.arg1 & !(1 << 63)),
                    metadata[2],
                );

                match self.flocks.unlock(owner, target, start, len) {
                    Ok(()) => SchemeResponse::Regular(Ok(0)),
                    _ => unreachable!(),
                }
            }),

            StdFsCallKind::GetLock => Some({
                let inode = inode?;
                let (owner, target, start, len, kind) = (
                    if metadata.arg1 & (1 << 63) == (1 << 63) {
                        LockOwner::Resource { fd: id }
                    } else {
                        LockOwner::Process { pid: ctx.pid }
                    },
                    LockTarget::Inode { inode: inode },
                    (metadata.arg1 & !(1 << 63)),
                    (metadata.arg2 & !(1 << 63)),
                    if metadata.arg2 & (1 << 63) == (1 << 63) {
                        LockKind::Exclusive
                    } else {
                        LockKind::Shared
                    },
                );
                match self.flocks.get_lock(kind, owner, target, start, len) {
                    Some(lck) => {
                        assert!(payload.len() == size_of::<u64>() * 2);

                        match lck.owner {
                            LockOwner::Process { pid } if pid == ctx.pid => {
                                return Some(SchemeResponse::Regular(Err(Error::new(ESRCH))));
                            }
                            LockOwner::Resource { fd } if fd == id => {
                                return Some(SchemeResponse::Regular(Err(Error::new(ESRCH))));
                            }
                            _ => {}
                        }

                        let payload = unsafe { &mut *(payload.as_mut_ptr() as *mut [u64; 2]) };
                        payload[0] = lck.start as u64;
                        payload[1] =
                            lck.len() as u64 | if lck.kind.is_exclusive() { 1 << 63 } else { 0 };

                        match lck.owner {
                            LockOwner::Resource { .. } => SchemeResponse::Regular(Ok(0)),
                            LockOwner::Process { pid, .. } => SchemeResponse::Regular(Ok(pid)),
                        }
                    }
                    None => SchemeResponse::Regular(Err(Error::new(ESRCH))),
                }
            }),

            _ => None,
        }
    }

    pub fn on_close(&mut self, _id: usize) {}

    pub fn on_detach(&mut self, id: usize, inode: usize, pid: usize) {
        // Remove both F_SETLK locks for the pid and F_ORD_SETLK locks
        // for the file descriptor, as we have no way of knowing which
        // might have been used.
        self.flocks
            .unlock_all(LockOwner::Resource { fd: id }, LockTarget::Inode { inode });
        self.flocks
            .unlock_all(LockOwner::Process { pid }, LockTarget::Inode { inode });
    }
}
