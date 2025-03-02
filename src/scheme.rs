#![allow(async_fn_in_trait)]

use core::mem::size_of;
use syscall::dirent::DirentBuf;
use syscall::schemev2::{Opcode, Sqe};
use syscall::{error::*, flag::*, Stat, StatVfs, TimeSpec};

use crate::{CallRequest, CallerCtx, OpenResult, Response};

#[non_exhaustive]
#[derive(Debug)]
pub enum Op<'a> {
    Open {
        path: &'a str,
        flags: usize,
    },
    Rmdir {
        path: &'a str,
    },
    Unlink {
        path: &'a str,
    },
    Dup {
        old_fd: usize,
        buf: &'a [u8],
    },
    Read {
        fd: usize,
        buf: &'a mut [u8],
        offset: u64,
        flags: u32,
    },
    Write {
        fd: usize,
        buf: &'a [u8],
        offset: u64,
        flags: u32,
    },
    Fsize {
        fd: usize,
    },
    Fchmod {
        fd: usize,
        new_mode: u16,
    },
    Fchown {
        fd: usize,
        new_uid: u32,
        new_gid: u32,
    },
    Fcntl {
        fd: usize,
        cmd: usize,
        arg: usize,
    },
    Fevent {
        fd: usize,
        req_flags: EventFlags,
    },
    Fpath {
        fd: usize,
        buf: &'a mut [u8],
    },
    Frename {
        fd: usize,
        new_path: &'a str,
    },
    Fstat {
        fd: usize,
        stat: &'a mut Stat,
    },
    FstatVfs {
        fd: usize,
        stat: &'a mut StatVfs,
    },
    Fsync {
        fd: usize,
    },
    Ftruncate {
        fd: usize,
        new_sz: u64,
    },
    Futimens {
        fd: usize,
        times: &'a [TimeSpec],
    },

    MmapPrep {
        fd: usize,
        offset: u64,
        len: usize,
        flags: MapFlags,
    },
    Munmap {
        fd: usize,
        offset: u64,
        len: usize,
        flags: MunmapFlags,
    },

    Call {
        fd: usize,
        payload: &'a mut [u8],
        metadata: &'a [u64],
    },

    Getdents {
        fd: usize,
        buf: DirentBuf<&'a mut [u8]>,
        opaque_offset: u64,
    },
}

impl<'a> Op<'a> {
    /// Decode the raw SQE into an Op with borrowed buffers passed as slices.
    ///
    /// # Safety
    ///
    /// Any borrowed buffers will be unmapped whenever a response is sent, which unlike the
    /// move-based CallRequest API, needs to be managed manually by the caller.
    pub unsafe fn from_sqe_unchecked(sqe: &'a Sqe) -> Option<Op<'a>> {
        let opcode = Opcode::try_from_raw(sqe.opcode)?;
        let args = sqe.args;

        let [a, b, c, _d, _e, _f] = args.map(|a| a as usize);
        use core::{slice, str};

        Some(match opcode {
            Opcode::Open => Op::Open {
                path: str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
                flags: c,
            },
            Opcode::Rmdir => Op::Rmdir {
                path: str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
            },
            Opcode::Unlink => Op::Unlink {
                path: str::from_utf8_unchecked(slice::from_raw_parts(a as *const u8, b)),
            },
            Opcode::Dup => Op::Dup {
                old_fd: a,
                buf: slice::from_raw_parts(b as *const u8, c),
            },
            Opcode::Read => Op::Read {
                fd: a,
                buf: slice::from_raw_parts_mut(b as *mut u8, c),
                offset: args[3],
                flags: args[4] as u32,
            },
            Opcode::Write => Op::Write {
                fd: a,
                buf: slice::from_raw_parts(b as *const u8, c),
                offset: args[3],
                flags: args[4] as u32,
            },

            // TODO: 64-bit offset on 32-bit platforms
            Opcode::Fsize => Op::Fsize { fd: a },
            Opcode::Fchmod => Op::Fchmod {
                fd: a,
                new_mode: b as u16,
            },
            Opcode::Fchown => Op::Fchown {
                fd: a,
                new_uid: b as u32,
                new_gid: c as u32,
            },
            Opcode::Fcntl => Op::Fcntl {
                fd: a,
                cmd: b,
                arg: c,
            },
            Opcode::Fevent => Op::Fevent {
                fd: a,
                req_flags: EventFlags::from_bits_retain(b),
            },
            Opcode::Fpath => Op::Fpath {
                fd: a,
                buf: slice::from_raw_parts_mut(b as *mut u8, c),
            },
            Opcode::Frename => Op::Frename {
                fd: a,
                new_path: str::from_utf8_unchecked(slice::from_raw_parts(b as *const u8, c)),
            },
            Opcode::Fstat => {
                assert!(c >= size_of::<Stat>());
                Op::Fstat {
                    fd: a,
                    stat: &mut *(b as *mut Stat),
                }
            }
            Opcode::Fstatvfs => {
                assert!(c >= size_of::<StatVfs>());
                Op::FstatVfs {
                    fd: a,
                    stat: &mut *(b as *mut StatVfs),
                }
            }
            Opcode::Fsync => Op::Fsync { fd: a },
            Opcode::Ftruncate => Op::Ftruncate {
                fd: a,
                new_sz: args[1],
            },
            Opcode::Futimens => {
                assert!(c <= 2 * size_of::<TimeSpec>());
                Op::Futimens {
                    fd: a,
                    times: slice::from_raw_parts(b as *const TimeSpec, c / size_of::<TimeSpec>()),
                }
            }

            Opcode::Call => Op::Call {
                fd: a,
                payload: slice::from_raw_parts_mut(b as *mut u8, c),
                metadata: &sqe.args[3..],
            },
            Opcode::Getdents => Op::Getdents {
                fd: a,
                buf: DirentBuf::new(
                    slice::from_raw_parts_mut(b as *mut u8, c),
                    sqe.args[3] as u16,
                )?,
                opaque_offset: sqe.args[4],
            },

            Opcode::MmapPrep => Op::MmapPrep {
                fd: a,
                offset: args[3],
                len: b,
                flags: MapFlags::from_bits_retain(c),
            },
            Opcode::Munmap => Op::Munmap {
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
    pub fn op(&self) -> Option<Op<'_>> {
        unsafe { Op::from_sqe_unchecked(&self.inner.sqe) }
    }
    pub async fn handle_async(self, s: &mut impl SchemeAsync) -> Result<Response> {
        let caller = self.caller();

        let Some(op) = self.op() else {
            return Ok(Response::new(self, Err(Error::new(ENOSYS))));
        };

        let res = match op {
            Op::Open { path, flags } => {
                let res = s.open(path, flags, &caller).await;
                return Ok(Response::open_dup_like(self, res));
            }
            Op::Rmdir { path } => s.rmdir(path, &caller).await.map(|()| 0),
            Op::Unlink { path } => s.unlink(path, &caller).await.map(|()| 0),

            Op::Dup { old_fd, buf } => {
                let res = s.dup(old_fd, buf, &caller).await;
                return Ok(Response::open_dup_like(self, res));
            }
            Op::Read {
                fd,
                buf,
                offset,
                flags,
            } => s.read(fd, buf, offset, flags, &caller).await,
            Op::Write {
                fd,
                buf,
                offset,
                flags,
            } => s.write(fd, buf, offset, flags, &caller).await,

            // TODO: Don't convert to usize
            Op::Fsize { fd } => s.fsize(fd, &caller).await.map(|l| l as usize),

            Op::Fchmod { fd, new_mode } => s.fchmod(fd, new_mode, &caller).await.map(|()| 0),
            Op::Fchown {
                fd,
                new_uid,
                new_gid,
            } => s.fchown(fd, new_uid, new_gid, &caller).await.map(|()| 0),
            Op::Fcntl { fd, cmd, arg } => s.fcntl(fd, cmd, arg, &caller).await,
            Op::Fevent { fd, req_flags } => {
                s.fevent(fd, req_flags, &caller).await.map(|f| f.bits())
            }
            Op::Fpath { fd, buf } => s.fpath(fd, buf, &caller).await,
            Op::Frename { fd, new_path } => s.frename(fd, new_path, &caller).await,
            Op::Fstat { fd, stat } => s.fstat(fd, stat, &caller).await.map(|()| 0),
            Op::FstatVfs { fd, stat } => s.fstatvfs(fd, stat, &caller).await.map(|()| 0),
            Op::Fsync { fd } => s.fsync(fd, &caller).await.map(|()| 0),
            Op::Ftruncate { fd, new_sz } => s.ftruncate(fd, new_sz, &caller).await.map(|()| 0),
            Op::Futimens { fd, times } => s.futimens(fd, times, &caller).await.map(|()| 0),

            Op::MmapPrep {
                fd,
                offset,
                len,
                flags,
            } => s.mmap_prep(fd, offset, len, flags, &caller).await,
            Op::Munmap {
                fd,
                offset,
                len,
                flags,
            } => s.munmap(fd, offset, len, flags, &caller).await.map(|()| 0),

            Op::Call {
                fd,
                payload,
                metadata,
            } => s.call(fd, payload, metadata).await,

            Op::Getdents {
                fd,
                buf,
                opaque_offset,
            } => {
                let buf = s.getdents(fd, buf, opaque_offset).await?;
                Ok(buf.finalize())
            }
        };
        Ok(Response::new(self, res))
    }
    // TODO: Fix function coloring
    pub fn handle_sync(self, s: &mut impl SchemeSync) -> Result<Response> {
        let caller = self.caller();
        let Some(op) = self.op() else {
            return Ok(Response::new(self, Err(Error::new(ENOSYS))));
        };

        let res = match op {
            Op::Open { path, flags } => {
                let res = s.open(path, flags, &caller);
                return Ok(Response::open_dup_like(self, res));
            }
            Op::Rmdir { path } => s.rmdir(path, &caller).map(|()| 0),
            Op::Unlink { path } => s.unlink(path, &caller).map(|()| 0),

            Op::Dup { old_fd, buf } => {
                let res = s.dup(old_fd, buf, &caller);
                return Ok(Response::open_dup_like(self, res));
            }
            Op::Read {
                fd,
                buf,
                offset,
                flags,
            } => s.read(fd, buf, offset, flags, &caller),
            Op::Write {
                fd,
                buf,
                offset,
                flags,
            } => s.write(fd, buf, offset, flags, &caller),

            // TODO: Don't convert to usize
            Op::Fsize { fd } => s.fsize(fd, &caller).map(|l| l as usize),

            Op::Fchmod { fd, new_mode } => s.fchmod(fd, new_mode, &caller).map(|()| 0),
            Op::Fchown {
                fd,
                new_uid,
                new_gid,
            } => s.fchown(fd, new_uid, new_gid, &caller).map(|()| 0),
            Op::Fcntl { fd, cmd, arg } => s.fcntl(fd, cmd, arg, &caller),
            Op::Fevent { fd, req_flags } => s.fevent(fd, req_flags, &caller).map(|f| f.bits()),
            Op::Fpath { fd, buf } => s.fpath(fd, buf, &caller),
            Op::Frename { fd, new_path } => s.frename(fd, new_path, &caller),
            Op::Fstat { fd, stat } => s.fstat(fd, stat, &caller).map(|()| 0),
            Op::FstatVfs { fd, stat } => s.fstatvfs(fd, stat, &caller).map(|()| 0),
            Op::Fsync { fd } => s.fsync(fd, &caller).map(|()| 0),
            Op::Ftruncate { fd, new_sz } => s.ftruncate(fd, new_sz, &caller).map(|()| 0),
            Op::Futimens { fd, times } => s.futimens(fd, times, &caller).map(|()| 0),

            Op::MmapPrep {
                fd,
                offset,
                len,
                flags,
            } => s.mmap_prep(fd, offset, len, flags, &caller),
            Op::Munmap {
                fd,
                offset,
                len,
                flags,
            } => s.munmap(fd, offset, len, flags, &caller).map(|()| 0),
            Op::Call {
                fd,
                payload,
                metadata,
            } => s.call(fd, payload, metadata),

            Op::Getdents {
                fd,
                buf,
                opaque_offset,
            } => {
                let buf = s.getdents(fd, buf, opaque_offset)?;
                Ok(buf.finalize())
            }
        };
        Ok(Response::new(self, res))
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
