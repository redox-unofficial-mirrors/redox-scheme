use core::ops::{Deref, DerefMut};
use std::collections::{HashMap, VecDeque};
use std::ops::ControlFlow;
use std::sync::{Mutex, MutexGuard};

use libredox::errno::{self, ECANCELED, EINTR, EOPNOTSUPP};
use libredox::error::Error as LError;
use syscall::Error;

use crate::scheme::{SchemeResponse, SchemeSync};
use crate::{Request, RequestKind, Response, SignalBehavior, Socket};

pub trait Hooks {
    type Scheme: SchemeSync;
    type Guard<'b>: Deref<Target = Self::Scheme> + DerefMut
        where Self::Scheme: 'b, Self: 'b;
    type E;
    type Ret;

    fn queue_size(&mut self) -> usize;
    fn acquire_scheme<'b>(&'b mut self) -> Result<Self::Guard<'b>, Self::E>;
    fn hook(&mut self, reqs: &[Request]) -> Result<ControlFlow<Self::Ret>, Self::E>;
}

pub struct SimpleHooks<'a, Scheme: SchemeSync> {
    pub queue_size: usize,
    pub scheme: &'a mut Scheme,
}
pub struct LockedHooks<'a, Scheme: SchemeSync> {
    pub queue_size: usize,
    pub scheme: &'a Mutex<Scheme>,
}
impl<'a, Scheme: SchemeSync> Hooks for LockedHooks<'a, Scheme> {
    type Scheme = Scheme;
    type E = LError;
    type Ret = ();
    type Guard<'b> = MutexGuard<'b, Self::Scheme>
        where Self::Scheme: 'b, Self: 'b;

    fn queue_size(&mut self) -> usize {
        self.queue_size
    }
    fn acquire_scheme(&mut self) -> Result<Self::Guard<'_>, Self::E> {
        Ok(self.scheme.lock().unwrap())
    }
    fn hook(&mut self, _reqs: &[Request]) -> Result<ControlFlow<Self::Ret>, Self::E> {
        Ok(ControlFlow::Continue(()))
    }
}

impl Socket {
    /// Wrapper for readiness-based schemes, meaning all requests are "poll-based" without internal
    /// state.
    pub fn run_readiness_based<E, H: Hooks>(
        &self,
        mut hooks: H,
    ) -> Result<Option<H::Ret>, E>
    where
        E: From<H::E> + From<LError>,
    {
        let queue_size = hooks.queue_size();
        let mut requests_read = Vec::with_capacity(queue_size);
        let mut responses_to_write = VecDeque::with_capacity(queue_size);
        let mut states = HashMap::new();

        loop {
            match self.read_requests(&mut requests_read, SignalBehavior::Interrupt) {
                Ok(()) if requests_read.is_empty() => return Ok(None), // EOF
                Ok(()) => (),
                Err(err) if err.errno == EINTR => (),
                Err(err) => return Err(LError::from(err).into()),
            };
            match hooks.hook(&requests_read)? {
                ControlFlow::Break(t) => return Ok(Some(t)),
                ControlFlow::Continue(()) => (),
            }
            for request in requests_read.drain(..) {
                let req = match request.kind() {
                    RequestKind::Call(c) => c,
                    RequestKind::Cancellation(req) => {
                        if let Some((_caller, op)) = states.remove(&req.id) {
                            responses_to_write.push_back(Response::err(ECANCELED, op));
                        }
                        continue;
                    }
                    RequestKind::OnClose { id } => {
                        hooks.acquire_scheme()?.on_close(id);
                        continue;
                    }
                    _ => continue,
                };
                let caller = req.caller();
                let mut op = match req.op() {
                    Ok(op) => op,
                    Err(req) => {
                        responses_to_write.push_back(Response::err(EOPNOTSUPP, req));
                        continue;
                    }
                };
                let resp = match op.handle_sync_dont_consume(&caller, &mut *hooks.acquire_scheme()?) {
                    SchemeResponse::Opened(Err(Error {
                        errno: errno::EWOULDBLOCK,
                    }))
                    | SchemeResponse::Regular(Err(Error {
                        errno: errno::EWOULDBLOCK,
                    })) => {
                        states.insert(caller.id, (caller, op));
                        continue;
                    }
                    SchemeResponse::Regular(r) => Response::new(r, op),
                    SchemeResponse::Opened(o) => Response::open_dup_like(o, op),
                };
                responses_to_write.push_back(resp);
            }
            match self.write_responses(&mut responses_to_write, SignalBehavior::Restart) {
                Ok(()) if responses_to_write.is_empty() => return Ok(None), // EOF
                Ok(()) => (),
                Err(err) if err.errno == EINTR => (),
                Err(err) => return Err(LError::from(err).into()),
            }
        }
    }
}
