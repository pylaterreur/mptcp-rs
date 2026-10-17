//! The endpoint's connections, which of them `poll_transmit` visits, and their deadlines
//! (issue #12).
//!
//! A connection is ready while it may have something to send, and parked otherwise. Every
//! endpoint call that reaches a connection makes it ready: a packet for it, a path call,
//! `Endpoint::connection` (which hands out `&mut Connection`), a `handle_timeout` pass. So does
//! its timer: a parked connection wakes when its wake time passes (`wake_at`: its deadline or a
//! pacing release), which is when the passing of time alone can give it a segment to send. A
//! turn that sends nothing and leaves nothing for the next one (`Visit::Idle`) parks it. The
//! turns skipped meanwhile would change nothing, so `poll_transmit` sends what the full scan
//! sent, in the same order (`diff_tests`).
//!
//! Each connection also caches its deadline (`Slot::timer`, what `next_deadline` computes),
//! and a min-heap orders the cached deadlines, so that `poll_timeout` reads the earliest one
//! and `handle_timeout` finds the due connections without looking at the others. A deadline
//! only changes with the connection's state, so the same calls mark it, and so do the
//! endpoint's own turns (`touch`, `park`). A marked connection's deadline is computed again at
//! the next `refresh`, and by `next_timer` until then; `handle_timeout` processes a touched one
//! once even if it is not due, as it did every connection.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::ops::{Bound, Index};

use crate::Instant;
use crate::connection::Connection;

use super::{ConnectionHandle, next_deadline};

/// The endpoint's bookkeeping of one connection.
#[derive(Default)]
pub(crate) struct Slot {
    /// Its cached deadline (`next_deadline`), which `Conns::timers` holds.
    timer: Option<Instant>,
    /// Marked since the last `refresh` (listed in `Conns::stale`): `timer` may be outdated.
    stale: bool,
    /// Touched since `handle_timeout` last processed it (listed in `Conns::pending`).
    pending: bool,
    /// Its wake time while parked, which `Conns::wakes` holds.
    parked: Option<Instant>,
}

/// Every connection by handle, with the ready set `poll_transmit` visits and the deadlines
/// `poll_timeout` and `handle_timeout` use.
#[derive(Default)]
pub(crate) struct Conns {
    map: BTreeMap<ConnectionHandle, Connection>,
    /// The connections `poll_transmit` visits, in handle order.
    ready: BTreeSet<ConnectionHandle>,
    /// Each parked connection with a wake time, at `Slot::parked`; entries that no longer
    /// match it are skipped.
    wakes: BinaryHeap<Reverse<(Instant, ConnectionHandle)>>,
    /// Cached deadlines, earliest first. An entry is dropped once it reaches the top if its
    /// connection is gone, marked or caches another deadline (`settle`): the top one is
    /// current.
    timers: BinaryHeap<Reverse<(Instant, ConnectionHandle)>>,
    stale: Vec<ConnectionHandle>,
    pending: Vec<ConnectionHandle>,
    /// The connections `Endpoint::connection` handed out since `aborting`.
    lent: Vec<ConnectionHandle>,
}

impl Conns {
    pub fn insert(&mut self, h: ConnectionHandle, c: Connection) {
        self.map.insert(h, c);
        self.touch(h);
    }

    pub fn remove(&mut self, h: &ConnectionHandle) -> Option<Connection> {
        self.ready.remove(h);
        let c = self.map.remove(h);
        self.settle();
        c
    }

    pub fn get(&self, h: &ConnectionHandle) -> Option<&Connection> {
        self.map.get(h)
    }

    /// Marks the connection changed (`touch`).
    pub fn get_mut(&mut self, h: &ConnectionHandle) -> Option<&mut Connection> {
        if !self.map.contains_key(h) {
            return None;
        }
        self.touch(*h);
        self.map.get_mut(h)
    }

    /// For the application (`Endpoint::connection`): touched as by `get_mut`, and listed for
    /// `aborting`.
    pub fn lend(&mut self, h: &ConnectionHandle) -> Option<&mut Connection> {
        if !self.map.contains_key(h) {
            return None;
        }
        self.touch(*h);
        self.lent.push(*h);
        self.map.get_mut(h)
    }

    /// Without marking it: the caller does (`touch`, `passed`, `park`) if it changes it.
    pub fn untracked_mut(&mut self, h: &ConnectionHandle) -> Option<&mut Connection> {
        self.map.get_mut(h)
    }

    #[cfg(test)]
    pub fn contains_key(&self, h: &ConnectionHandle) -> bool {
        self.map.contains_key(h)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ConnectionHandle, &Connection)> {
        self.map.iter()
    }

    /// Every connection, without marking any.
    pub fn iter_untracked_mut(
        &mut self,
    ) -> impl Iterator<Item = (&ConnectionHandle, &mut Connection)> {
        self.map.iter_mut()
    }

    /// `h` may have changed: it is ready, its deadline is computed again, and `handle_timeout`
    /// processes it once.
    pub fn touch(&mut self, h: ConnectionHandle) {
        let Some(c) = self.map.get_mut(&h) else {
            return;
        };
        self.ready.insert(h);
        c.slot.parked = None;
        if !std::mem::replace(&mut c.slot.pending, true) {
            self.pending.push(h);
        }
        self.retime(h);
    }

    /// `handle_timeout` passed over `h`: it is ready, and its deadline is computed again.
    pub fn passed(&mut self, h: ConnectionHandle) {
        if let Some(c) = self.map.get_mut(&h) {
            self.ready.insert(h);
            c.slot.parked = None;
        }
        self.retime(h);
    }

    /// `h`'s deadline may have changed, but nothing a turn or `handle_timeout` would act on.
    fn retime(&mut self, h: ConnectionHandle) {
        let Some(c) = self.map.get_mut(&h) else {
            return;
        };
        if !std::mem::replace(&mut c.slot.stale, true) {
            self.stale.push(h);
            // The top entry must stay current.
            if self.timers.peek().map(|e| e.0.1) == Some(h) {
                self.settle();
            }
        }
    }

    /// The connections `abort` was called on since the last look, in handle order.
    pub fn aborting(&mut self) -> Vec<ConnectionHandle> {
        let mut lent = std::mem::take(&mut self.lent);
        lent.retain(|h| self.map.get(h).is_some_and(|c| c.aborting));
        lent.sort_unstable();
        lent.dedup();
        lent
    }

    /// The first ready connection in `range`.
    pub fn next_ready(
        &self,
        range: (Bound<ConnectionHandle>, Bound<ConnectionHandle>),
    ) -> Option<ConnectionHandle> {
        self.ready.range(range).next().copied()
    }

    /// `h`'s turn found nothing to do: it waits for a change or for its wake time, from its
    /// `deadline` (`next_deadline`, cached here too).
    pub fn park(&mut self, h: ConnectionHandle, deadline: Option<Instant>) {
        self.ready.remove(&h);
        let c = self.map.get_mut(&h).unwrap();
        let wake = super::wake_at(c, deadline);
        c.slot.parked = wake;
        if let Some(at) = wake {
            self.wakes.push(Reverse((at, h)));
        }
        c.slot.stale = false;
        if c.slot.timer != deadline {
            c.slot.timer = deadline;
            if let Some(at) = deadline {
                self.timers.push(Reverse((at, h)));
            }
            self.settle();
        }
        // Each park adds at most one entry: rebuilding once stale ones outnumber the
        // connections keeps the heap within twice their number, at O(1) amortized per park.
        if self.wakes.len() > 2 * self.map.len() + 64 {
            let live = (self.map.iter()).filter_map(|(&h, c)| Some(Reverse((c.slot.parked?, h))));
            self.wakes = live.collect();
        }
    }

    /// Makes ready every parked connection whose wake time is at or before `now`.
    pub fn wake(&mut self, now: Instant) {
        while let Some(&Reverse((at, h))) = self.wakes.peek() {
            if at > now {
                break;
            }
            self.wakes.pop();
            if let Some(c) = self.map.get_mut(&h).filter(|c| c.slot.parked == Some(at)) {
                c.slot.parked = None;
                self.ready.insert(h);
            }
        }
    }

    /// Caches the deadline of every connection marked since the last refresh.
    pub fn refresh(&mut self) {
        let mut stale = std::mem::take(&mut self.stale);
        for h in stale.drain(..) {
            let Some(c) = self.map.get_mut(&h).filter(|c| c.slot.stale) else {
                continue;
            };
            c.slot.stale = false;
            let timer = next_deadline(c);
            if c.slot.timer != timer {
                c.slot.timer = timer;
                if let Some(at) = timer {
                    self.timers.push(Reverse((at, h)));
                }
            }
        }
        self.stale = stale;
        self.settle();
        // As for `wakes`: no connection is marked now.
        if self.timers.len() > 2 * self.map.len() + 64 {
            let live = (self.map.iter()).filter_map(|(&h, c)| Some(Reverse((c.slot.timer?, h))));
            self.timers = live.collect();
        }
    }

    /// `refresh` if many connections are marked, which `next_timer` computes on each call
    /// until then: draining `poll_transmit` (the driver contract) refreshes anyway.
    pub fn refresh_if_many(&mut self) {
        if self.stale.len() > 64 {
            self.refresh();
        }
    }

    /// Drops the entries at the top of the deadline heap until its top one is current.
    fn settle(&mut self) {
        while let Some(&Reverse((at, h))) = self.timers.peek() {
            if let Some(c) = self.map.get_mut(&h).filter(|c| c.slot.timer == Some(at)) {
                if !c.slot.stale {
                    return;
                }
                // Queued again at the next `refresh`.
                c.slot.timer = None;
            }
            self.timers.pop();
        }
    }

    /// The connections whose deadline is at or before `now`, and those touched since the last
    /// call, in handle order. The caller marks each again as it processes it.
    pub fn due(&mut self, now: Instant) -> Vec<ConnectionHandle> {
        let mut due = std::mem::take(&mut self.pending);
        // Freed connections stay listed until here.
        due.retain(|h| {
            let c = self.map.get_mut(h);
            c.map(|c| c.slot.pending = false).is_some()
        });
        while let Some(&Reverse((at, h))) = self.timers.peek() {
            if at > now {
                break;
            }
            self.timers.pop();
            if let Some(c) = self.map.get_mut(&h).filter(|c| c.slot.timer == Some(at)) {
                c.slot.timer = None;
                if !std::mem::replace(&mut c.slot.stale, true) {
                    self.stale.push(h);
                }
                due.push(h);
            }
        }
        self.settle();
        due.sort_unstable();
        due.dedup();
        due
    }

    /// The earliest deadline: the cached ones, and those of the marked connections computed
    /// now.
    pub fn next_timer(&self) -> Option<Instant> {
        let marked = (self.stale.iter()).filter_map(|h| self.map.get(h).filter(|c| c.slot.stale));
        let cached = self.timers.peek().map(|&Reverse((at, _))| at);
        marked.filter_map(next_deadline).chain(cached).min()
    }

    /// Frees each connection of `hs` that `f` does not keep (`BTreeMap::retain` over `hs`).
    pub fn retain_some(
        &mut self,
        hs: &[ConnectionHandle],
        mut f: impl FnMut(&ConnectionHandle, &mut Connection) -> bool,
    ) {
        for h in hs {
            let Some(c) = self.map.get_mut(h) else {
                continue;
            };
            if !f(h, c) {
                self.map.remove(h);
                self.ready.remove(h);
            }
        }
        self.settle();
    }
}

impl Index<&ConnectionHandle> for Conns {
    type Output = Connection;

    fn index(&self, h: &ConnectionHandle) -> &Connection {
        &self.map[h]
    }
}
