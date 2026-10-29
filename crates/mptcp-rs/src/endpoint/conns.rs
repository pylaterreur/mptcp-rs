//! The endpoint's connections and their deadlines (issue #12). Each connection caches its
//! deadline (`Slot::timer`, what `next_deadline` computes), and a min-heap orders the cached
//! deadlines, so that `poll_timeout` reads the earliest one and `handle_timeout` finds the due
//! connections without looking at the others.
//!
//! A deadline only changes with the connection's state, so every endpoint call that reaches a
//! connection marks it: `get_mut` and `insert` (packets, path calls), `lend`
//! (`Endpoint::connection`, which hands out `&mut Connection`), `poll_transmit`'s turns
//! (`scan`) and `handle_timeout`'s passes (`passed`). A marked connection's deadline is
//! computed again at the next `refresh`, and by `next_timer` until then; `handle_timeout`
//! processes a touched one once even if it is not due, as it did every connection. A turn that
//! finds nothing to do leaves the connection idle until its wake time (`wake_at`): the turns
//! until then change nothing, so they mark nothing.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::ops::{Bound, ControlFlow, Index};

use crate::Instant;
use crate::connection::Connection;

use super::{ConnectionHandle, next_deadline};

/// The endpoint's bookkeeping of one connection.
#[derive(Default)]
pub(crate) struct Slot {
    /// Its cached deadline (`next_deadline`), which the heap holds.
    timer: Option<Instant>,
    /// Marked since the last `refresh` (listed in `Conns::stale`): `timer` may be outdated.
    stale: bool,
    /// Touched since `handle_timeout` last processed it (listed in `Conns::pending`).
    pending: bool,
    /// Its last turn in `poll_transmit` found nothing to send and changed nothing a later turn
    /// would act on: turns change nothing until `wake` passes or something changes it.
    pub idle: bool,
    pub wake: Option<Instant>,
}

/// Every connection by handle, with the deadlines `poll_timeout` and `handle_timeout` use.
#[derive(Default)]
pub(crate) struct Conns {
    map: BTreeMap<ConnectionHandle, Connection>,
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
        let c = self.map.remove(h);
        // Half-opens can be removed before any timer fires, so `due` may never drain these.
        if self.pending.len() > 2 * self.map.len() + 64 {
            self.pending.retain(|h| self.map.contains_key(h));
        }
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

    /// Without marking it: the caller does (`touch`, `passed`) if it changes it.
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

    /// `f` takes a turn of every connection in `range`, in handle order, until it breaks, and
    /// returns `None` if the turn may have changed the connection, `Some(false)` if it found
    /// nothing to do, and `Some(true)` if the connection was idle already; the bookkeeping of
    /// the turn follows without looking the connection up again.
    pub fn scan<B>(
        &mut self,
        range: (Bound<ConnectionHandle>, Bound<ConnectionHandle>),
        mut f: impl FnMut(ConnectionHandle, &mut Connection) -> ControlFlow<B, Option<bool>>,
    ) -> ControlFlow<B> {
        let mut settle = false;
        let mut flow = ControlFlow::Continue(());
        for (&h, c) in self.map.range_mut(range) {
            let idle = match f(h, c) {
                ControlFlow::Continue(idle) => idle,
                ControlFlow::Break(b) => {
                    flow = ControlFlow::Break(b);
                    None
                }
            };
            match idle {
                Some(true) => continue,
                // Its deadline as of now: cached at once, and its wake time.
                Some(false) => {
                    let timer = next_deadline(c);
                    (c.slot.idle, c.slot.wake) = (true, super::wake_at(c, timer));
                    c.slot.stale = false;
                    if c.slot.timer != timer {
                        c.slot.timer = timer;
                        settle = true;
                        if let Some(at) = timer {
                            self.timers.push(Reverse((at, h)));
                        }
                    }
                }
                None => {
                    c.slot.idle = false;
                    if !std::mem::replace(&mut c.slot.pending, true) {
                        self.pending.push(h);
                    }
                    if !std::mem::replace(&mut c.slot.stale, true) {
                        self.stale.push(h);
                        settle |= self.timers.peek().map(|e| e.0.1) == Some(h);
                    }
                }
            }
            if flow.is_break() {
                break;
            }
        }
        if settle {
            self.settle();
        }
        flow
    }

    /// `h` may have changed: its deadline is computed again, and `handle_timeout` processes it
    /// once.
    pub fn touch(&mut self, h: ConnectionHandle) {
        let Some(c) = self.map.get_mut(&h) else {
            return;
        };
        c.slot.idle = false;
        if !std::mem::replace(&mut c.slot.pending, true) {
            self.pending.push(h);
        }
        self.retime(h);
    }

    /// `handle_timeout` passed over `h`: its next turn and its deadline are looked at again.
    pub fn passed(&mut self, h: ConnectionHandle) {
        if let Some(c) = self.map.get_mut(&h) {
            c.slot.idle = false;
        }
        self.retime(h);
    }

    /// `h`'s deadline may have changed, but nothing `handle_timeout` would act on.
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
        // Each refresh adds at most one entry per connection: rebuilding once stale ones
        // outnumber the connections keeps the heap within twice their number, at O(1)
        // amortized per entry. No connection is marked now.
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

    /// Drops the entries at the top of the heap until its top one is current.
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
        // Freed connections may stay listed until here.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seq::SeqNum;
    use crate::wire::packet::{self, Segment, TcpFlags};
    use crate::{Endpoint, ListenConfig};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn cancelled_half_opens_bound_pending_without_timeouts() {
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
        let dst = "10.0.0.2:80".parse().unwrap();
        ep.listen(
            dst,
            ListenConfig {
                max_half_open: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let syn = Segment {
            src: "10.0.0.1:40000".parse().unwrap(),
            dst,
            seq: SeqNum(1000),
            ack: SeqNum(0),
            flags: TcpFlags::SYN,
            wnd: 65535,
            options: &[],
            payload: &[],
        };
        let mut buf = [0u8; 1500];
        for i in 0..10_000 {
            let now = Instant::from_nanos(i * 10_000_000);
            let n = packet::build(&syn, 0, &mut buf).unwrap();
            ep.handle_packet(now, &buf[..n]);
            assert!(ep.poll_transmit(now, &mut buf).is_some());
            assert!(ep.poll_transmit(now, &mut buf).is_none());
            let rst = Segment {
                seq: SeqNum(1001),
                flags: TcpFlags::RST,
                ..syn
            };
            let n = packet::build(&rst, 0, &mut buf).unwrap();
            let now = Instant::from_nanos(i * 10_000_000 + 1_000_000);
            ep.handle_packet(now, &buf[..n]);
            assert!(ep.poll_transmit(now, &mut buf).is_none());
            assert!(ep.conns.is_empty());
            assert_eq!(ep.poll_timeout(), None);
        }
        assert!(
            ep.conns.pending.len() <= 64,
            "{} pending handles with no connections or timers",
            ep.conns.pending.len()
        );
    }
}
