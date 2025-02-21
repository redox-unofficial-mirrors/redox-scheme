use crate::*;
use syscall::dirent::DirentBuf;
use syscall::error::*;

pub trait Scheme {
    #[allow(unused_variables)]
    fn open(&mut self, path: &str, flags: usize, uid: u32, gid: u32) -> Result<usize> {
        Err(Error::new(ENOENT))
    }
    #[allow(unused_variables)]
    fn xopen(&mut self, path: &str, flags: usize, ctx: &CallerCtx) -> Result<OpenResult> {
        convert_to_this_scheme(self.open(path, flags, ctx.uid, ctx.gid))
    }

    #[allow(unused_variables)]
    fn rmdir(&mut self, path: &str, uid: u32, gid: u32) -> Result<usize> {
        Err(Error::new(ENOENT))
    }

    #[allow(unused_variables)]
    fn unlink(&mut self, path: &str, uid: u32, gid: u32) -> Result<usize> {
        Err(Error::new(ENOENT))
    }

    /* Resource operations */
    #[allow(unused_variables)]
    fn dup(&mut self, old_id: usize, buf: &[u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn xdup(&mut self, old_id: usize, buf: &[u8], ctx: &CallerCtx) -> Result<OpenResult> {
        convert_to_this_scheme(self.dup(old_id, buf))
    }

    #[allow(unused_variables)]
    fn read_old(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    #[allow(unused_variables)]
    fn read(&mut self, id: usize, buf: &mut [u8], offset: u64, fcntl_flags: u32) -> Result<usize> {
        self.read_old(id, buf)
    }

    #[allow(unused_variables)]
    fn write_old(&mut self, id: usize, buf: &[u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    #[allow(unused_variables)]
    fn write(&mut self, id: usize, buf: &[u8], offset: u64, fcntl_flags: u32) -> Result<usize> {
        self.write_old(id, buf)
    }

    #[allow(unused_variables)]
    fn getdents<'buf>(
        &mut self,
        id: usize,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        Err(Error::new(EOPNOTSUPP))
    }

    #[allow(unused_variables)]
    fn fsize(&mut self, id: usize) -> Result<u64> {
        Err(Error::new(ESPIPE))
    }

    #[allow(unused_variables)]
    fn fchmod(&mut self, id: usize, mode: u16) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fchown(&mut self, id: usize, uid: u32, gid: u32) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fcntl(&mut self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fevent(&mut self, id: usize, flags: EventFlags) -> Result<EventFlags> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fpath(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn frename(&mut self, id: usize, path: &str, uid: u32, gid: u32) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fstat(&mut self, id: usize, stat: &mut Stat) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fstatvfs(&mut self, id: usize, stat: &mut StatVfs) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn fsync(&mut self, id: usize) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn ftruncate(&mut self, id: usize, len: usize) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn futimens(&mut self, id: usize, times: &[TimeSpec]) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    #[allow(unused_variables)]
    fn mmap_prep(&mut self, id: usize, offset: u64, size: usize, flags: MapFlags) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    #[allow(unused_variables)]
    fn munmap(&mut self, id: usize, offset: u64, size: usize, flags: MunmapFlags) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }
}
