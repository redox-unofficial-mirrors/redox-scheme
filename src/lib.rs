use core::{slice, str};

use libredox::flag;
use syscall::{Error, Packet, Result, EOPNOTSUPP, ESKMSG, SKMSG_FRETURNFD};

pub use self::scheme::Scheme;
pub use self::scheme_block::SchemeBlock;
pub use self::scheme_block_mut::SchemeBlockMut;
pub use self::scheme_mut::SchemeMut;
pub use self::seek::*;

unsafe fn str_from_raw_parts(ptr: *const u8, len: usize) -> Option<&'static str> {
    let slice = slice::from_raw_parts(ptr, len);
    str::from_utf8(slice).ok()
}

mod scheme;
mod scheme_block;
mod scheme_block_mut;
mod scheme_mut;
mod seek;

pub struct CallerCtx {
    pub pid: usize,
    pub uid: u32,
    pub gid: u32,
}

pub enum OpenResult {
    ThisScheme { number: usize },
    OtherScheme { fd: usize },
}

// TODO: Find a better solution than generate.sh
pub(crate) fn convert_to_this_scheme(r: Result<usize>) -> Result<OpenResult> {
    r.map(|number| OpenResult::ThisScheme { number })
}
pub(crate) fn convert_to_this_scheme_block(r: Result<Option<usize>>) -> Result<Option<OpenResult>> {
    r.map(|o| o.map(|number| OpenResult::ThisScheme { number }))
}
pub(crate) fn convert_in_scheme_handle_block(
    _: &Packet,
    result: Result<Option<OpenResult>>,
) -> Result<Option<usize>> {
    match result {
        Ok(Some(OpenResult::ThisScheme { number })) => Ok(Some(number)),
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
        Ok(OpenResult::ThisScheme { number }) => Ok(number),
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
#[derive(Clone, Copy, Default)]
pub struct Request(Packet);

impl Request {
    pub fn context_id(&self) -> usize {
        self.0.pid
    }
    pub fn handle_scheme(mut self, scheme: &impl Scheme) -> Response {
        unsafe {
            scheme.handle(&mut self.0);
        }
        Response(self.0)
    }
    pub fn handle_scheme_mut(mut self, scheme: &mut impl SchemeMut) -> Response {
        unsafe {
            scheme.handle(&mut self.0);
        }
        Response(self.0)
    }
    pub fn handle_scheme_block(
        mut self,
        scheme: &mut impl SchemeBlock,
    ) -> Result<Response, Request> {
        match unsafe { scheme.handle(&mut self.0) } {
            Some(code) => Ok(Response(Packet { a: code, ..self.0 })),
            None => Err(self),
        }
    }
    pub fn handle_scheme_block_mut(
        mut self,
        scheme: &mut impl SchemeBlockMut,
    ) -> Result<Response, Request> {
        match unsafe { scheme.handle(&mut self.0) } {
            Some(code) => Ok(Response(Packet { a: code, ..self.0 })),
            None => Err(self),
        }
    }
}

pub struct Socket(libredox::Fd);

impl Socket {
    pub fn create(name: impl AsRef<str>) -> Result<Self> {
        let name = name.as_ref();
        let fd = libredox::Fd::open(&format!(":{name}"), flag::O_CLOEXEC | flag::O_CREAT, 0)?;
        Ok(Self(fd))
    }
    pub fn read_requests(&self, buf: &mut [Request], behavior: SignalBehavior) -> Result<usize> {
        read_requests(self.0.raw(), buf, behavior)
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
        write_responses(self.0.raw(), buf, behavior)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Default)]
pub struct Response(Packet);

impl Response {
    pub fn new(req: &Request, status: Result<usize>) -> Self {
        Self(Packet {
            a: Error::mux(status),
            ..req.0
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
            error @ Err(Error {
                errno: libredox::errno::EINTR,
            }) => match behavior {
                SignalBehavior::Restart => continue,
                SignalBehavior::Interrupt => return error,
            },
            Err(err) => return Err(err),
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
            error @ Err(Error {
                errno: libredox::errno::EINTR,
            }) => match behavior {
                SignalBehavior::Restart => continue,
                SignalBehavior::Interrupt => return error,
            },
            Err(err) => return Err(err),
        }
    };
    debug_assert_eq!(bytes_written % size_of::<Response>(), 0);
    Ok(bytes_written / size_of::<Response>())
}
