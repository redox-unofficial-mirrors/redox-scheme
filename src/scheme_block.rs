use crate::*;
use syscall::dirent::DirentBuf;
use syscall::error::*;

pub trait SchemeBlock {
    #[allow(unused_variables)]
    fn open(&self, path: &str, flags: usize, uid: u32, gid: u32) -> Result<Option<usize>> {
        Err(Error::new(ENOENT))
    }
    #[allow(unused_variables)]
    fn xopen(&self, path: &str, flags: usize, ctx: &CallerCtx) -> Result<Option<OpenResult>> {
        convert_to_this_scheme_block(self.open(path, flags, ctx.uid, ctx.gid))
    }

    #[allow(unused_variables)]
    fn rmdir(&self, path: &str, uid: u32, gid: u32) -> Result<Option<usize>> {
        Err(Error::new(ENOENT))
    }

    #[allow(unused_variables)]
    fn unlink(&self, path: &str, uid: u32, gid: u32) -> Result<Option<usize>> {
        Err(Error::new(ENOENT))
    }

    /* Resource operations */
    #[allow(unused_variables)]
    fn dup(&self, old_id: usize, buf: &[u8]) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn xdup(&self, old_id: usize, buf: &[u8], ctx: &CallerCtx) -> Result<Option<OpenResult>> {
        convert_to_this_scheme_block(self.dup(old_id, buf))
    }

    #[allow(unused_variables)]
    fn read_old(&self, id: usize, buf: &mut [u8]) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }
    #[allow(unused_variables)]
    fn read(&self, id: usize, buf: &mut [u8], offset: u64, fcntl_flags: u32) -> Result<Option<usize>> {
        self.read_old(id, buf)
    }

    #[allow(unused_variables)]
    fn write_old(&self, id: usize, buf: &[u8]) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }
    #[allow(unused_variables)]
    fn write(&self, id: usize, buf: &[u8], offset: u64, fcntl_flags: u32) -> Result<Option<usize>> {
        self.write_old(id, buf)
    }

    #[allow(unused_variables)]
    fn getdents<'buf>(
        &self,
        id: usize,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<Option<DirentBuf<&'buf mut [u8]>>> {
        Err(Error::new(EOPNOTSUPP))
    }

    #[allow(unused_variables)]
    fn fsize(&self, id: usize) -> Result<Option<u64>> {
        Err(Error::new(ESPIPE))
    }

    #[allow(unused_variables)]
    fn fchmod(&self, id: usize, mode: u16) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fchown(&self, id: usize, uid: u32, gid: u32) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fevent(&self, id: usize, flags: EventFlags) -> Result<Option<EventFlags>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn frename(&self, id: usize, path: &str, uid: u32, gid: u32) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fstatvfs(&self, id: usize, stat: &mut StatVfs) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fsync(&self, id: usize) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn ftruncate(&self, id: usize, len: usize) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn futimens(&self, id: usize, times: &[TimeSpec]) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn close(&self, id: usize) -> Result<Option<usize>> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn mmap_prep(&self, id: usize, offset: u64, size: usize, flags: MapFlags) -> Result<Option<usize>> {
        Err(Error::new(EOPNOTSUPP))
    }

    #[allow(unused_variables)]
    fn munmap(&self, id: usize, offset: u64, size: usize, flags: MunmapFlags) -> Result<Option<usize>> {
        Err(Error::new(EOPNOTSUPP))
    }
}
