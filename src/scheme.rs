use crate::*;
use syscall::dirent::DirentBuf;
use syscall::error::*;

pub trait Scheme {
    #[allow(unused_variables)]
    fn open(&self, path: &str, flags: usize, uid: u32, gid: u32) -> Result<usize> {
        Err(Error::new(ENOENT))
    }
    #[allow(unused_variables)]
    fn xopen(&self, path: &str, flags: usize, ctx: &CallerCtx) -> Result<OpenResult> {
        convert_to_this_scheme(self.open(path, flags, ctx.uid, ctx.gid))
    }

    #[allow(unused_variables)]
    fn rmdir(&self, path: &str, uid: u32, gid: u32) -> Result<usize> {
        Err(Error::new(ENOENT))
    }

    #[allow(unused_variables)]
    fn unlink(&self, path: &str, uid: u32, gid: u32) -> Result<usize> {
        Err(Error::new(ENOENT))
    }

    /* Resource operations */
    #[allow(unused_variables)]
    fn dup(&self, old_id: usize, buf: &[u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn xdup(&self, old_id: usize, buf: &[u8], ctx: &CallerCtx) -> Result<OpenResult> {
        convert_to_this_scheme(self.dup(old_id, buf))
    }

    #[allow(unused_variables)]
    fn read_old(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    #[allow(unused_variables)]
    fn read(&self, id: usize, buf: &mut [u8], offset: u64, fcntl_flags: u32) -> Result<usize> {
        self.read_old(id, buf)
    }

    #[allow(unused_variables)]
    fn write_old(&self, id: usize, buf: &[u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    #[allow(unused_variables)]
    fn write(&self, id: usize, buf: &[u8], offset: u64, fcntl_flags: u32) -> Result<usize> {
        self.write_old(id, buf)
    }

    #[allow(unused_variables)]
    fn getdents<'buf>(
        &self,
        id: usize,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        Err(Error::new(EOPNOTSUPP))
    }

    #[allow(unused_variables)]
    fn fsize(&self, id: usize) -> Result<u64> {
        Err(Error::new(ESPIPE))
    }

    #[allow(unused_variables)]
    fn fchmod(&self, id: usize, mode: u16) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fchown(&self, id: usize, uid: u32, gid: u32) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fevent(&self, id: usize, flags: EventFlags) -> Result<EventFlags> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn frename(&self, id: usize, path: &str, uid: u32, gid: u32) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fstatvfs(&self, id: usize, stat: &mut StatVfs) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fsync(&self, id: usize) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn ftruncate(&self, id: usize, len: usize) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn futimens(&self, id: usize, times: &[TimeSpec]) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn close(&self, id: usize) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn mmap_prep(&self, id: usize, offset: u64, size: usize, flags: MapFlags) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    #[allow(unused_variables)]
    fn munmap(&self, id: usize, offset: u64, size: usize, flags: MunmapFlags) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }
}
