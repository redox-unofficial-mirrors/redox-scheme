use core::mem;

use crate::*;
use syscall::data::*;
use syscall::error::*;
use syscall::flag::*;
use syscall::number::*;

pub struct LazyCallerCtx {
    pub context_id: usize,
}
impl LazyCallerCtx {
    pub fn from_packet(p: &Packet) -> Self {
        Self {
            context_id: p.pid,
        }
    }
}

#[non_exhaustive]
pub enum Op<'a> {
    Open { path: &'a str, flags: usize, caller: CallerCtx },
    Rmdir { path: &'a str, caller: CallerCtx },
    Unlink { path: &'a str, caller: CallerCtx },
    Dup { old_fd: usize, buf: &'a [u8], caller: CallerCtx },
    Read { fd: usize, buf: &'a mut [u8], caller: LazyCallerCtx },
    Write { fd: usize, buf: &'a [u8], caller: LazyCallerCtx },
    Lseek { fd: usize, pos: isize, whence: usize, caller: CallerCtx },
    Fchmod { fd: usize, new_mode: u16, caller: CallerCtx },
    Fchown { fd: usize, new_uid: u32, new_gid: u32, caller: CallerCtx },
    Fcntl { fd: usize, cmd: usize, arg: usize, caller: CallerCtx },
    Fevent { fd: usize, req_flags: EventFlags, caller: CallerCtx },
    Fpath { fd: usize, buf: &'a mut [u8], caller: CallerCtx },
    Frename { fd: usize, new_path: &'a str, caller: CallerCtx },
    Fstat { fd: usize, stat: &'a mut Stat, caller: CallerCtx },
    FstatVfs { fd: usize, stat: &'a mut StatVfs, caller: CallerCtx },
    Fsync { fd: usize, caller: CallerCtx },
    Ftruncate { fd: usize, new_sz: usize, caller: CallerCtx },
    Futimens { fd: usize, times: &'a [TimeSpec], caller: CallerCtx },
    Close { fd: usize },

    MmapPrep { fd: usize, offset: u64, len: usize, flags: MapFlags, caller: LazyCallerCtx },
    Munmap { fd: usize, offset: u64, len: usize, flags: MunmapFlags, caller: LazyCallerCtx },
}

pub enum Response {
    Regular(usize),
    ForwardFd(usize),
}
impl From<OpenResult> for Response {
    fn from(value: OpenResult) -> Self {
        match value {
            OpenResult::ThisScheme { number } => Self::Regular(number),
            OpenResult::OtherScheme { fd } => Self::ForwardFd(fd),
        }
    }
}

impl<'a> Op<'a> {
    pub unsafe fn from_packet_unchecked(packet: Packet) -> Option<Op<'a>> {
        Some(match packet.a {
            SYS_OPEN => {
                let path = str_from_raw_parts(packet.b as *const u8, packet.c).expect("kernel did not provide correct UTF-8 path for SYS_OPEN");
                Op::Open { path, flags: packet.d, caller: CallerCtx::from_packet(&packet) }
            }
            SYS_RMDIR => {
                let path = str_from_raw_parts(packet.b as *const u8, packet.c).expect("kernel did not provide correct UTF-8 path for SYS_RMDIR");
                Op::Rmdir { path, caller: CallerCtx::from_packet(&packet) }
            }
            SYS_UNLINK => {
                let path = str_from_raw_parts(packet.b as *const u8, packet.c).expect("kernel did not provide correct UTF-8 path for SYS_UNLINK");
                Op::Unlink { path, caller: CallerCtx::from_packet(&packet) }
            }

            SYS_DUP => Op::Dup { old_fd: packet.b, buf: slice::from_raw_parts(packet.c as *const u8, packet.d), caller: CallerCtx::from_packet(&packet) },
            SYS_READ => Op::Read { fd: packet.b, buf: slice::from_raw_parts_mut(packet.c as *mut u8, packet.d), caller: LazyCallerCtx::from_packet(&packet) },
            SYS_WRITE => Op::Write { fd: packet.b, buf: slice::from_raw_parts(packet.c as *const u8, packet.d), caller: LazyCallerCtx::from_packet(&packet) },
            SYS_LSEEK => Op::Lseek { fd: packet.b, pos: packet.c as isize, whence: packet.d, caller: CallerCtx::from_packet(&packet) },
            SYS_FCHMOD => Op::Fchmod { fd: packet.b, new_mode: packet.c as u16, caller: CallerCtx::from_packet(&packet) },
            SYS_FCHOWN => Op::Fchown { fd: packet.b, new_uid: packet.c as u32, new_gid: packet.d as u32, caller: CallerCtx::from_packet(&packet) },
            SYS_FCNTL => Op::Fcntl { fd: packet.b, cmd: packet.c, arg: packet.d, caller: CallerCtx::from_packet(&packet) },
            SYS_FEVENT => Op::Fevent { fd: packet.b, req_flags: EventFlags::from_bits_truncate(packet.c), caller: CallerCtx::from_packet(&packet) },
            SYS_FPATH => Op::Fpath { fd: packet.b, buf: slice::from_raw_parts_mut(packet.c as *mut u8, packet.d), caller: CallerCtx::from_packet(&packet) },
            SYS_FRENAME => {
                let new_path = str_from_raw_parts(packet.c as *const u8, packet.d).expect("kernel did not provide correct UTF-8 path for SYS_FRENAME");
                Op::Frename { fd: packet.b, new_path, caller: CallerCtx::from_packet(&packet) }
            }
            SYS_FSTAT => {
                assert!(packet.d < mem::size_of::<Stat>(), "too small Stat from kernel");
                Op::Fstat { fd: packet.b, stat: &mut *(packet.c as *mut Stat), caller: CallerCtx::from_packet(&packet) }
            }
            SYS_FSTATVFS => {
                assert!(packet.d < mem::size_of::<StatVfs>(), "too small StatVfs from kernel");
                Op::FstatVfs { fd: packet.b, stat: &mut *(packet.c as *mut StatVfs), caller: CallerCtx::from_packet(&packet) }
            }
            SYS_FSYNC => Op::Fsync { fd: packet.b, caller: CallerCtx::from_packet(&packet) },
            SYS_FTRUNCATE => Op::Ftruncate { fd: packet.b, new_sz: packet.c, caller: CallerCtx::from_packet(&packet) },
            SYS_FUTIMENS => {
                assert!(packet.d < mem::size_of::<TimeSpec>(), "too small TimeSpec from kernel");
                Op::Futimens { fd: packet.b, times: {
                    slice::from_raw_parts(
                        packet.c as *const TimeSpec,
                        packet.d / mem::size_of::<TimeSpec>(),
                    )
                }, caller: CallerCtx::from_packet(&packet) }
            }
            SYS_CLOSE => Op::Close { fd: packet.b },

            KSMSG_MMAP_PREP => Op::MmapPrep {
                fd: packet.b,
                offset: u64::from(packet.uid) | (u64::from(packet.gid) << 32),
                len: packet.c,
                flags: MapFlags::from_bits_truncate(packet.d),
                caller: LazyCallerCtx::from_packet(&packet),
            },
            KSMSG_MUNMAP => Op::Munmap {
                fd: packet.b,
                offset: u64::from(packet.uid) | (u64::from(packet.gid) << 32),
                len: packet.c,
                flags: MunmapFlags::from_bits_truncate(packet.d),
                caller: LazyCallerCtx::from_packet(&packet),
            },

            _ => return None,
        })
    }
    pub async fn handle(self, s: &mut impl Scheme) -> Response {
        match self.handle_inner(s).await {
            Ok(resp) => resp,
            Err(error) => Response::Regular(Error::mux(Err(error))),
        }
    }
    async fn handle_inner(self, s: &mut impl Scheme) -> Result<Response> {
        Ok(Response::Regular(match self {
            Self::Open { path, flags, caller } => return Ok(s.open(path, flags, &caller).await?.into()),
            Self::Rmdir { path, caller } => s.rmdir(path, &caller).await?,
            Self::Unlink { path, caller } => s.unlink(path, &caller).await?,

            Self::Dup { old_fd, buf, caller } => return Ok(s.dup(old_fd, buf, &caller).await?.into()),
            Self::Read { fd, buf, caller } => s.read(fd, buf, &caller).await?,
            Self::Write { fd, buf, caller } => s.write(fd, buf, &caller).await?,
            Self::Lseek { fd, pos, whence, caller } => s.seek(fd, pos, whence, &caller).await?,
            Self::Fchmod { fd, new_mode, caller } => s.fchmod(fd, new_mode, &caller).await?,
            Self::Fchown { fd, new_uid, new_gid, caller } => s.fchown(fd, new_uid, new_gid, &caller).await?,
            Self::Fcntl { fd, cmd, arg, caller } => s.fcntl(fd, cmd, arg, &caller).await?,
            Self::Fevent { fd, req_flags, caller } => s.fevent(fd, req_flags, &caller).await.map(|f| f.bits())?,
            Self::Fpath { fd, buf, caller } => s.fpath(fd, buf, &caller).await?,
            Self::Frename { fd, new_path, caller } => s.frename(fd, new_path, &caller).await?,
            Self::Fstat { fd, stat, caller } => s.fstat(fd, stat, &caller).await?,
            Self::FstatVfs { fd, stat, caller } => s.fstatvfs(fd, stat, &caller).await?,
            Self::Fsync { fd, caller } => s.fsync(fd, &caller).await?,
            Self::Ftruncate { fd, new_sz, caller } => s.ftruncate(fd, new_sz, &caller).await?,
            Self::Futimens { fd, times, caller } => s.futimens(fd, times, &caller).await?,

            Self::Close { fd } => {
                s.close(fd).await?;
                0
            }
            Self::MmapPrep { fd, offset, len, flags, caller } => s.mmap_prep(fd, offset, len, flags, &caller).await?,
            Self::Munmap { fd, offset, len, flags, caller } => s.munmap(fd, offset, len, flags, &caller).await?,
        }))
    }
}

pub trait Scheme {
    /* Scheme operations */
    #[allow(unused_variables)]
    async fn open(&mut self, path: &str, flags: usize, ctx: &CallerCtx) -> Result<OpenResult> {
        Err(Error::new(ENOENT))
    }

    #[allow(unused_variables)]
    async fn rmdir(&mut self, path: &str, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(ENOENT))
    }

    #[allow(unused_variables)]
    async fn unlink(&mut self, path: &str, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(ENOENT))
    }

    /* Resource operations */
    #[allow(unused_variables)]
    async fn dup(&mut self, old_id: usize, buf: &[u8], ctx: &CallerCtx) -> Result<OpenResult> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn read(&mut self, id: usize, buf: &mut [u8], ctx: &LazyCallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn write(&mut self, id: usize, buf: &[u8], ctx: &LazyCallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn seek(&mut self, id: usize, pos: isize, whence: usize, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn fchmod(&mut self, id: usize, new_mode: u16, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn fchown(&mut self, id: usize, new_uid: u32, new_gid: u32, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn fcntl(&mut self, id: usize, cmd: usize, arg: usize, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn fevent(&mut self, id: usize, flags: EventFlags, ctx: &CallerCtx) -> Result<EventFlags> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn fpath(&mut self, id: usize, buf: &mut [u8], ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn frename(&mut self, id: usize, path: &str, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn fstat(&mut self, id: usize, stat: &mut Stat, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn fstatvfs(&mut self, id: usize, stat: &mut StatVfs, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn fsync(&mut self, id: usize, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn ftruncate(&mut self, id: usize, len: usize, ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn futimens(&mut self, id: usize, times: &[TimeSpec], ctx: &CallerCtx) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn close(&mut self, id: usize) -> Result<()> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    async fn mmap_prep(&mut self, id: usize, offset: u64, size: usize, flags: MapFlags, ctx: &LazyCallerCtx) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    #[allow(unused_variables)]
    async fn munmap(&mut self, id: usize, offset: u64, size: usize, flags: MunmapFlags, ctx: &LazyCallerCtx) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }
}
