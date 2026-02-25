// Missing: F_SETLKW, F_OFD_SETLKW, and deadlock-detection

use std::collections::LinkedList;

const OFFSET_MAX: u64 = i64::MAX as u64;

fn span_end(start: u64, len: u64) -> Result<u64, LockError> {
    if len == 0 {
        Ok(OFFSET_MAX)
    } else {
        if len - 1 > OFFSET_MAX - start {
            return Err(LockError::Overflow);
        }
        Ok(start + (len - 1))
    }
}

#[derive(Debug)]
pub struct LockSet {
    list: LinkedList<Lock>,
}

impl LockSet {
    pub fn new() -> Self {
        Self {
            list: LinkedList::new(),
        }
    }

    /// # Note
    ///
    /// According to POSIX Issue 8:
    /// * Request for a *shared* lock shall fail if the file descriptor is not
    /// open for *reading*.
    ///
    /// * Request for an *exclusive* lock shall fail if the file descriptor is
    /// not open for *writing*.
    ///
    /// The caller **must** ensure that the above conditions are met before
    /// calling this method.
    pub fn lock(
        &mut self,
        kind: LockKind,
        owner: LockOwner,
        start: u64,
        len: u64,
    ) -> Result<(), LockError> {
        let new = Lock::new(kind, owner, start, span_end(start, len)?);
        if let Some(_conflict) = self.list.iter().find(|lck| lck.conflicts_with(&new)) {
            return Err(LockError::Conflict);
        }

        // Locks are grouped by owner. Find the first lock in the lock set with
        // the same owner as the new lock.
        let mut cursor = self.list.cursor_front_mut();
        while let Some(curr) = cursor.current()
            && curr.owner != new.owner
        {
            cursor.move_next();
        }

        if cursor.current().is_none() {
            // No lock with the same owner, insert at the end.
            cursor.insert_before(new);
            return Ok(());
        }

        while let Some(curr) = cursor.current()
            && curr.owner == new.owner
        {
            if new.start > curr.end + 1 {
                // The `new` lock comes after `curr` lock.
                cursor.move_next();
                continue;
            } else if new.end + 1 < curr.start {
                // The `new` lock comes before `curr` lock. Break and insert it
                // *before* `curr` lock.
                break;
            }

            // Now `new` and `curr` overlap or adjacent
            if curr.kind == new.kind {
                // Merge
                curr.start = new.start.min(curr.start);
                curr.end = new.end.max(curr.end);
                return Ok(());
            } else {
                if new.start <= curr.start && new.end >= curr.end {
                    *curr = new;
                    return Ok(());
                } else if start > curr.start && new.end < curr.end {
                    let right = Lock::new(curr.kind, curr.owner, new.end + 1, curr.end);
                    curr.end = new.start - 1;
                    cursor.insert_after(new);
                    cursor.move_next();
                    cursor.insert_after(right);
                    return Ok(());
                } else if start > curr.start {
                    curr.end = start - 1;
                    cursor.insert_after(new);
                    return Ok(());
                } else if new.end < curr.end {
                    curr.start = new.end + 1;
                    break;
                }
            }
        }

        cursor.insert_before(new);
        Ok(())
    }

    // TODO: take out common logic from lock and unlock
    pub fn unlock(&mut self, owner: LockOwner, start: u64, len: u64) -> Result<(), LockError> {
        let end = span_end(start, len)?;
        let mut cursor = self.list.cursor_front_mut();
        while let Some(curr) = cursor.current()
            && curr.owner != owner
        {
            cursor.move_next();
        }

        if cursor.current().is_none() {
            return Err(LockError::NotPresent);
        }

        let mut success = false;
        while let Some(curr) = cursor.current()
            && curr.owner == owner
        {
            if start > curr.end + 1 {
                // The `new` lock comes after `curr` lock.
                cursor.move_next();
                continue;
            } else if end + 1 < curr.start {
                // The `new` lock comes before `curr` lock. Break and insert it
                // *before* `curr` lock.
                break;
            }

            success = true;
            if start <= curr.start && end >= curr.end {
                // Unlock range covers the entire lock. Cursor is moved to point
                // to the next element by `remove_cursor`
                cursor.remove_current();
                continue;
            } else if start > curr.start && end < curr.end {
                // Unlock range is strictly inside the lock.
                let right = Lock::new(curr.kind, curr.owner, end, curr.end);
                curr.end = start - 1;
                cursor.insert_after(right);
                return Ok(());
            } else if start > curr.start {
                // Unlock covers the tail of this lock. Shrink from right.
                curr.end = start - 1;
            } else if end < curr.end {
                // Unlock covers the head of this lock. Shrink from left.
                curr.start = end + 1;
            }

            cursor.move_next();
        }

        if success {
            Ok(())
        } else {
            Err(LockError::NotPresent)
        }
    }

    pub fn get_lock(
        &mut self,
        kind: LockKind,
        owner: LockOwner,
        start: u64,
        len: u64,
    ) -> Option<&Lock> {
        let query = Lock::new(kind, owner, start, start + (len - 1));
        self.list.iter().find(|lck| lck.overlaps_with(&query))
    }

    /// `info` should be `None` for OFD-owned locks.
    pub fn on_close(&mut self, owner: LockOwner) -> Result<(), LockError> {
        let mut cursor = self.list.cursor_front_mut();
        while let Some(curr) = cursor.current() {
            // Closing any file descriptor drops all POSIX locks that the process holds on that
            // file, even if the lock was originally acquired using a different file
            // descriptor.
            let should_remove = owner == curr.owner;

            if should_remove {
                cursor.remove_current();
                return Ok(());
            } else {
                cursor.move_next();
            }
        }

        Err(LockError::NotPresent)
    }
}

#[derive(Debug, PartialEq)]
pub enum LockError {
    Conflict,
    NotPresent,
    Overflow,
}

#[derive(Debug)]
pub struct Lock {
    pub kind: LockKind,
    pub owner: LockOwner,
    // [start, end)
    pub start: u64,
    pub end: u64,
}

impl Lock {
    pub fn new(kind: LockKind, owner: LockOwner, start: u64, end: u64) -> Self {
        Self {
            kind,
            owner,
            start,
            end,
        }
    }

    #[inline]
    pub fn conflicts_with(&self, other: &Lock) -> bool {
        self.owner != other.owner
            && self.overlaps_with(other)
            // Each byte in the file can be either locked with one or more
            // shared locks or with a single exclusive lock.
            && (self.kind.is_exclusive() || other.kind.is_exclusive())
    }

    #[inline]
    pub fn overlaps_with(&self, other: &Lock) -> bool {
        self.start < other.end && self.end > other.start
    }

    #[inline]
    // FIXME: would this work for whole file locks with start=0 and end=0
    pub fn len(&self) -> u64 {
        self.end - self.start
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum LockOwner {
    Process { pid: usize, inode: usize },
    Resource { fd: usize },
}

impl LockOwner {
    pub fn is_process(&self) -> bool {
        matches!(self, Self::Process { .. })
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum LockKind {
    Shared,
    Exclusive,
}

impl LockKind {
    #[inline]
    pub fn is_exclusive(&self) -> bool {
        matches!(self, Self::Exclusive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_owners() {
        let mut set = LockSet::new();
        assert!(
            set.lock(
                LockKind::Exclusive,
                LockOwner::Process { pid: 1, inode: 1 },
                0,
                2
            )
            .is_ok()
        );
        // According to POSIX Issue 8, an **exclusive** process or OFD-owned
        // lock prevents any **other** process or OFD-owned lock from being
        // placed on any overlapping byte range.
        assert!(
            !set.lock(LockKind::Shared, LockOwner::Resource { fd: 1 }, 0, 2)
                .is_ok()
        );
        assert!(
            !set.lock(LockKind::Exclusive, LockOwner::Resource { fd: 1 }, 0, 2)
                .is_ok()
        );

        assert!(
            !set.lock(
                LockKind::Shared,
                LockOwner::Process { pid: 2, inode: 2 },
                0,
                2
            )
            .is_ok()
        );
        assert!(
            !set.lock(
                LockKind::Exclusive,
                LockOwner::Process { pid: 2, inode: 2 },
                0,
                2
            )
            .is_ok()
        );
        // Similarly, a **shared** process or OFD-owned lock prevents any
        // **other exclusive** process or OFD-owned lock from being placed on
        // any overlapping byte range.
        assert!(
            set.lock(
                LockKind::Shared,
                LockOwner::Process { pid: 1, inode: 1 },
                2,
                2
            )
            .is_ok()
        );
        assert!(
            !set.lock(
                LockKind::Exclusive,
                LockOwner::Process { pid: 2, inode: 2 },
                2,
                2
            )
            .is_ok()
        );
        assert!(
            !set.lock(LockKind::Exclusive, LockOwner::Resource { fd: 1 }, 2, 2)
                .is_ok()
        );
        // A **shared** process or OFD-owned lock does **not** prevent any
        // **other shared** process or OFD-owned lock from being placed on any
        // overlapping byte range.
        assert!(
            set.lock(
                LockKind::Shared,
                LockOwner::Process { pid: 2, inode: 2 },
                2,
                2
            )
            .is_ok()
        );
        assert!(
            set.lock(LockKind::Shared, LockOwner::Resource { fd: 1 }, 2, 2)
                .is_ok()
        );
    }

    #[test]
    fn same_owner() {
        let mut set = LockSet::new();
        assert!(
            set.lock(
                LockKind::Exclusive,
                LockOwner::Process { pid: 1, inode: 1 },
                0,
                8
            )
            .is_ok()
        );
        // Requests from the **same** owner as the existing lock are allowed.
        assert!(
            set.lock(
                LockKind::Shared,
                LockOwner::Process { pid: 1, inode: 1 },
                4,
                4
            )
            .is_ok()
        );
        assert!(
            set.unlock(LockOwner::Process { pid: 1, inode: 1 }, 4, 8)
                .is_ok()
        );
        assert!(
            set.unlock(LockOwner::Process { pid: 1, inode: 1 }, 0, 8)
                .is_ok()
        );
    }

    #[test]
    fn test_on_close() {
        let mut set = LockSet::new();
        assert!(
            set.lock(
                LockKind::Exclusive,
                LockOwner::Process { pid: 1, inode: 1 },
                0,
                10
            )
            .is_ok()
        );
        assert!(
            set.on_close(LockOwner::Process { pid: 1, inode: 1 })
                .is_ok()
        );
        assert!(
            set.on_close(LockOwner::Process { pid: 1, inode: 1 }) == Err(LockError::NotPresent)
        );
    }
}
