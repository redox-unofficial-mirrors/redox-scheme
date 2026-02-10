// Missing: F_SETLKW, F_OFD_SETLKW, and deadlock-detection

#![feature(linked_list_cursors)]

use std::collections::LinkedList;

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
        start: usize,
        len: usize,
    ) -> LockResult {
        let new = Lock::new(kind, owner, start, start + (len - 1));
        if let Some(_conflict) = self.list.iter().find(|lck| lck.conflicts_with(&new)) {
            return LockResult::Conflict;
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
            cursor.insert_after(new);
            return LockResult::Ok;
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
                return LockResult::Ok;
            } else {
                if new.start <= curr.start && new.end >= curr.end {
                    *curr = new;
                    return LockResult::Ok;
                } else if start > curr.start && new.end < curr.end {
                    let right = Lock::new(curr.kind, curr.owner, new.end + 1, curr.end);
                    curr.end = new.start - 1;
                    cursor.insert_after(new);
                    cursor.move_next();
                    cursor.insert_after(right);
                    return LockResult::Ok;
                } else if start > curr.start {
                    curr.end = start - 1;
                    cursor.insert_after(new);
                    return LockResult::Ok;
                } else if new.end < curr.end {
                    curr.start = new.end + 1;
                    break;
                }
            }
        }

        cursor.insert_before(new);
        LockResult::Ok
    }

    // TODO: take out common logic from lock and unlock
    pub fn unlock(&mut self, owner: LockOwner, start: usize, len: usize) -> LockResult {
        let end = start + (len - 1);
        let mut cursor = self.list.cursor_front_mut();
        while let Some(curr) = cursor.current()
            && curr.owner != owner
        {
            cursor.move_next();
        }

        if cursor.current().is_none() {
            return LockResult::NotPresent;
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
                return LockResult::Ok;
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
            LockResult::Ok
        } else {
            LockResult::NotPresent
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum LockResult {
    Ok,
    Conflict,
    NotPresent,
}

impl LockResult {
    #[inline]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

#[derive(Debug)]
struct Lock {
    kind: LockKind,
    owner: LockOwner,
    // [start, end)
    start: usize,
    end: usize,
}

impl Lock {
    pub fn new(kind: LockKind, owner: LockOwner, start: usize, end: usize) -> Self {
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
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum LockOwner {
    Process { pid: usize },
    Resource { fd: usize },
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

    #[inline]
    pub fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_owners() {
        let mut set = LockSet::new();
        assert!(
            set.lock(LockKind::Exclusive, LockOwner::Process { pid: 1 }, 0, 2)
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
            !set.lock(LockKind::Shared, LockOwner::Process { pid: 2 }, 0, 2)
                .is_ok()
        );
        assert!(
            !set.lock(LockKind::Exclusive, LockOwner::Process { pid: 2 }, 0, 2)
                .is_ok()
        );
        // Similarly, a **shared** process or OFD-owned lock prevents any
        // **other exclusive** process or OFD-owned lock from being placed on
        // any overlapping byte range.
        assert!(
            set.lock(LockKind::Shared, LockOwner::Process { pid: 1 }, 2, 2)
                .is_ok()
        );
        assert!(
            !set.lock(LockKind::Exclusive, LockOwner::Process { pid: 2 }, 2, 2)
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
            set.lock(LockKind::Shared, LockOwner::Process { pid: 2 }, 2, 2)
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
            set.lock(LockKind::Exclusive, LockOwner::Process { pid: 1 }, 0, 8)
                .is_ok()
        );
        // Requests from the **same** owner as the existing lock are allowed.
        assert!(
            set.lock(LockKind::Shared, LockOwner::Process { pid: 1 }, 4, 4)
                .is_ok()
        );
        assert!(set.unlock(LockOwner::Process { pid: 1 }, 4, 8).is_ok());
        assert!(set.unlock(LockOwner::Process { pid: 1 }, 0, 8).is_ok());
    }
}
