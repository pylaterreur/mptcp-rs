//! The sans-I/O entry point: owns every connection, demultiplexes packets and builds output
//! (spec §1, §3.1).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand_core::CryptoRng;

use crate::Instant;
use crate::SeqNum;
use crate::connection::{Connection, ConnectionHooks, QueuedJoin};
use crate::crypto::IsnGenerator;
use crate::mptcp::{
    Join, JoinRole, Negotiation, SUBFLOW_CAP, State, Subflow, SubflowHooks, SubflowId, SubflowMp,
    SubflowState, SynCapable, fastclose, syn_capable, syn_scale, tcprst,
};
use crate::tcp::{CloseReason, ConnectConfig, Reaction, SegmentWriter, Tcb, TcpState};
use crate::wire::mptcp::{self, MpJoin, MptcpOption, is_join};
use crate::wire::packet::{self, Segment, TcpFlags};
use crate::wire::tcp_options::{TcpOpt, walk};
use conns::Conns;
pub(crate) use conns::Slot;

mod aborted;
mod conns;

/// Queued RSTs for segments without a TCB; beyond this they are dropped.
const MAX_PENDING_RST: usize = 64;
const EPHEMERAL_FIRST: u16 = 49152;
const EPHEMERAL_COUNT: u32 = 65536 - EPHEMERAL_FIRST as u32;

/// Opaque, never reused within one `Endpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionHandle(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    Connected {
        mptcp: bool,
    },
    /// A listener's connection completed its handshake: the first event on its handle, and
    /// `Endpoint::connection` finds it only from now on. Passive opens get this instead of
    /// `Connected`; a handshake that fails before it leaves no trace.
    Accepted {
        mptcp: bool,
    },
    /// The connection continues as plain TCP on one subflow; every other one was reset (no
    /// `SubflowDown` for them). It ends the per-subflow events: a Stale survivor becomes
    /// Active again without `SubflowRecovered`, and a survivor whose join completed on the
    /// same segment without `SubflowUp`.
    FellBack,
    /// The connection ended. After `Normal`, unread data stays readable (`Connection::close`).
    /// - `Normal`: the close completed. With MPTCP: both DATA_FINs acknowledged and every
    ///   subflow closed, so it waits until every subflow has left TIME-WAIT (up to 2·MSL =
    ///   120 s, also for one retired earlier by `close_subflow`). Plain TCP: the FIN exchange.
    /// - `Reset`: a RST without MPTCP in use (plain TCP, after a fallback), or MP_FASTCLOSE.
    /// - `Timeout`: retransmissions gave up without MPTCP in use, or the no-subflow wait ended.
    /// - `FallbackDataLoss`: see `CloseReason::FallbackDataLoss`.
    /// - `Aborted`: `Connection::abort`.
    Closed {
        reason: CloseReason,
    },
    /// A joined subflow completed its MP_JOIN handshake and can carry data. For a join the
    /// peer opened through a listener (on any connection, whatever its role) this is the first
    /// event naming it; one that fails before it is never reported.
    SubflowUp {
        subflow: SubflowId,
    },
    /// A subflow ended (`Reset`: refused or reset, also a queued join that can no longer
    /// start, or reset by us at close because it held only DATA_ACKed data; `Timeout`: R2;
    /// `Normal`: FIN exchange, reported on entering TIME-WAIT). Data the subflow had in flight
    /// is resent on the others. If no other subflow is open (TIME-WAIT does not count), the
    /// connection ends: after both DATA_FINs in `Closed { Normal }`, otherwise the no-subflow
    /// wait starts and ends in `Closed { Timeout }` unless `add_subflow` starts a join first.
    /// Not emitted for the subflows a fallback or MP_FASTCLOSE resets, nor for the initial
    /// subflow ending after both DATA_FINs. `rst`: the MP_TCPRST of the peer's RST that ended
    /// it, if it carried one.
    SubflowDown {
        subflow: SubflowId,
        reason: CloseReason,
        rst: Option<MpTcpRst>,
    },
    /// A subflow's retransmission timer expired R1 = 3 times in a row: it gets no new data,
    /// and data it had in flight is resent on the other subflows.
    SubflowStale {
        subflow: SubflowId,
    },
    /// A Stale subflow's data was acknowledged again: it carries data again.
    SubflowRecovered {
        subflow: SubflowId,
    },
    /// The peer announced an address (ADD_ADDR) as `id`; `addr` carries the port to join.
    /// Emitted again when the peer repeats the announcement, which also lifts `AddressFailed`.
    /// An announcement that arrives before the connection is confirmed is reported once it is.
    /// Never for an unspecified, multicast or loopback address.
    AddressAnnounced {
        id: u8,
        addr: SocketAddr,
    },
    /// The peer withdrew its address `id` (REMOVE_ADDR): one it announced, or one a subflow's
    /// handshake carried (0 for the initial subflow). Each subflow to it is probed and kept if
    /// it answers, else reset (`SubflowDown { Reset }`).
    AddressRemoved {
        id: u8,
    },
    /// The peer asked us to treat `subflow` as backup or not (MP_PRIO).
    PeerPriority {
        subflow: SubflowId,
        backup: bool,
    },
}

/// The MP_TCPRST option of a peer's RST (RFC 8684 §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MpTcpRst {
    pub reason: u8,
    /// The T flag: the condition is temporary, a new join may succeed.
    pub transient: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddSubflowError {
    NoConnection,
    /// Plain TCP, or the connection fell back to it.
    NotMptcp,
    /// The peer's MP_CAPABLE set C=1, and `remote` is the connection's initial remote address
    /// and port.
    PeerForbidsJoin,
    /// `remote` is an address the peer announced, and a join to it failed; joins to it are
    /// refused until the peer announces it again.
    AddressFailed,
    /// `local` and `remote` are of different IP families.
    FamilyMismatch,
    /// IPv4 needs an MTU of at least 68, IPv6 at least 1280.
    InvalidMtu,
    /// The application closed the connection, or it is closed.
    Closed,
    /// All ephemeral ports from `local` to the remote are in use.
    NoPort,
    /// The connection has 8 open subflows (not ended: TIME-WAIT does not count), queued joins
    /// and joins a listener is answering included.
    TooManySubflows,
    /// The connection has bound 256 local IPs, each to its own address ID, and `local` is
    /// another one.
    TooManyAddresses,
    /// The connection has used up its subflow IDs.
    SubflowIdsExhausted,
}

/// Why a call on one subflow failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubflowError {
    NoConnection,
    /// The connection never issued this ID, or its subflow has ended.
    NoSubflow,
    /// Plain TCP, or the connection fell back to it.
    NotMptcp,
    /// The application closed the connection, or it is closed.
    Closed,
    /// `close_subflow`: no other Active subflow can take over its data.
    LastSubflow,
}

/// Why `remove_address` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressError {
    NoConnection,
    /// Plain TCP, or the connection fell back to it.
    NotMptcp,
    /// The connection never bound this local IP to an address ID.
    UnknownAddress,
    /// The application closed the connection, or it is closed.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectError {
    /// All ephemeral ports to this remote are in use.
    NoPort,
    /// IPv4 needs an MTU of at least 68, IPv6 at least 1280.
    InvalidMtu,
    /// `send_buffer` and `recv_buffer` must be within 1 and 2^30.
    InvalidBuffer,
    /// `local` and `remote` are of different IP families.
    FamilyMismatch,
}

/// What `Endpoint::listen` accepts connections with. Build it from `ListenConfig::default()`
/// and assign the fields to change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListenConfig {
    /// The configuration of each accepted connection.
    pub connection: ConnectConfig,
    /// Offer MPTCP to clients that ask for it.
    pub mptcp: bool,
    /// Connections still in their handshake at most; SYNs beyond it are dropped silently.
    pub max_half_open: usize,
}

impl Default for ListenConfig {
    fn default() -> Self {
        ListenConfig {
            connection: ConnectConfig::default(),
            mptcp: true,
            max_half_open: 256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenError {
    /// This address and port already has a listener.
    InUse,
    PortZero,
    /// IPv4 needs an MTU of at least 68, IPv6 at least 1280.
    InvalidMtu,
    /// `send_buffer` and `recv_buffer` must be within 1 and 2^30.
    InvalidBuffer,
    /// `max_half_open` must be at least 1.
    InvalidHalfOpen,
}

struct Listener {
    cfg: ListenConfig,
    /// Its passive subflows not yet up (`Subflow::pending_via`).
    half_open: usize,
}

struct PendingRst {
    src: SocketAddr,
    dst: SocketAddr,
    seq: SeqNum,
    ack: SeqNum,
    flags: TcpFlags,
    /// MP_FASTCLOSE, on the RSTs of an aborted subflow (M3 spec §3.5), or MP_TCPRST on a
    /// refused join; empty for none.
    option: Vec<u8>,
}

pub struct Endpoint<R: CryptoRng> {
    rng: R,
    isn: IsnGenerator,
    conns: Conns,
    /// (local, remote) → (handle, subflow) (a BTreeMap: no OS-seeded hasher in the core). Closed and TIME-WAIT TCBs stay until `handle_timeout`.
    demux: BTreeMap<(SocketAddr, SocketAddr), (ConnectionHandle, SubflowId)>,
    next_handle: u64,
    /// Round-robin cursor for `poll_transmit`.
    cursor: u64,
    ip_id: u16,
    events: VecDeque<(ConnectionHandle, Event)>,
    pending_rst: VecDeque<PendingRst>,
    /// The 4-tuples `Connection::abort` reset with MP_FASTCLOSE.
    aborted: aborted::Aborted,
    scratch: SegmentWriter,
    /// Connections with queued joins (`Connection::queued_joins`).
    pending_joins: BTreeSet<ConnectionHandle>,
    /// Keyed by local address and port; an unspecified IP matches every local address.
    listeners: BTreeMap<SocketAddr, Listener>,
    /// Live connections by local token; unique across both roles (RFC 8684 L791–796).
    tokens: BTreeMap<u32, ConnectionHandle>,
    /// Test-only keys, popped before the RNG by `new_negotiation`.
    #[cfg(test)]
    pub(crate) keys: VecDeque<u64>,
    /// Test-only MP_JOIN nonces, popped before the RNG by `nonce`.
    #[cfg(test)]
    pub(crate) nonces: VecDeque<u32>,
    /// Congestion controller for new connections; `None` is the default (CUBIC).
    #[cfg(test)]
    pub(crate) cc: Option<fn() -> Box<dyn crate::tcp::cc::CongestionControl>>,
    /// Connections `poll_transmit` has visited.
    #[cfg(test)]
    pub(crate) visits: u64,
    /// Connections `handle_timeout` has processed.
    #[cfg(test)]
    pub(crate) timeouts: u64,
    /// Test-only oracle: `poll_transmit` takes a turn of every connection, and `poll_timeout`
    /// and `handle_timeout` look at every connection, as before the ready set and the deadline
    /// heap (`diff_tests`).
    #[cfg(test)]
    pub(crate) full_scan: bool,
}

impl<R: CryptoRng> Endpoint<R> {
    pub fn new(mut rng: R) -> Self {
        let mut secret = [0u8; 16];
        rng.fill_bytes(&mut secret);
        Self {
            rng,
            isn: IsnGenerator::new(secret),
            conns: Conns::default(),
            demux: BTreeMap::new(),
            next_handle: 0,
            cursor: 0,
            ip_id: 0,
            events: VecDeque::new(),
            pending_rst: VecDeque::new(),
            aborted: Default::default(),
            scratch: SegmentWriter::default(),
            pending_joins: BTreeSet::new(),
            listeners: BTreeMap::new(),
            tokens: BTreeMap::new(),
            #[cfg(test)]
            keys: VecDeque::new(),
            #[cfg(test)]
            nonces: VecDeque::new(),
            #[cfg(test)]
            cc: None,
            #[cfg(test)]
            visits: 0,
            #[cfg(test)]
            timeouts: 0,
            #[cfg(test)]
            full_scan: false,
        }
    }

    /// Draws a key whose token no live connection uses and reserves the token for `h`
    /// (RFC 8684 L791–796); `make` builds the role's negotiation from it. The entry lives
    /// until `free`, through TIME-WAIT and fallback.
    pub(crate) fn new_negotiation(
        &mut self,
        h: ConnectionHandle,
        make: fn(u64, bool) -> Negotiation,
    ) -> Negotiation {
        let checksums = self.conns[&h].cfg.checksums;
        loop {
            #[cfg(test)]
            let key = self.keys.pop_front().unwrap_or_else(|| self.rng.next_u64());
            #[cfg(not(test))]
            let key = self.rng.next_u64();
            let n = make(key, checksums);
            if let std::collections::btree_map::Entry::Vacant(e) = self.tokens.entry(n.token) {
                e.insert(h);
                return n;
            }
        }
    }

    /// A fresh MP_JOIN nonce (RFC 8684 L2691–2692).
    fn nonce(&mut self) -> u32 {
        #[cfg(test)]
        if let Some(n) = self.nonces.pop_front() {
            return n;
        }
        self.rng.next_u32()
    }

    pub fn connect(
        &mut self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
        cfg: ConnectConfig,
    ) -> Result<ConnectionHandle, ConnectError> {
        // The wire carries only IP and port: drop IPv6 flow info and scope so demux keys match
        // what `packet::parse` builds.
        let remote = SocketAddr::new(remote.ip(), remote.port());
        let min_mtu = min_mtu(local, remote.ip()).ok_or(ConnectError::FamilyMismatch)?;
        if cfg.mtu < min_mtu {
            return Err(ConnectError::InvalidMtu);
        }
        if !buffers_ok(&cfg) {
            return Err(ConnectError::InvalidBuffer);
        }
        let local = (self.free_port(now, local, remote)).ok_or(ConnectError::NoPort)?;
        let isn = self.isn.isn(now, local, remote);
        let tcb = self.new_tcb(&cfg, local, remote, isn, now);
        Ok(self.insert(cfg, tcb, local, remote, None))
    }

    /// Adds a connection whose initial subflow is `tcb`, with its demux entry; `pending_via`:
    /// the listener that accepted it, which keeps it half-open until `Accepted`.
    fn insert(
        &mut self,
        cfg: ConnectConfig,
        tcb: Tcb,
        local: SocketAddr,
        remote: SocketAddr,
        pending_via: Option<SocketAddr>,
    ) -> ConnectionHandle {
        let h = ConnectionHandle(self.next_handle);
        self.next_handle += 1;
        self.demux.insert((local, remote), (h, SubflowId(0)));
        let sf = Subflow {
            id: SubflowId(0),
            tcb,
            local,
            remote,
            state: SubflowState::Active,
            mp: SubflowMp::new(),
            pending_via,
        };
        let mut c = Connection::new(cfg, sf);
        c.half_open = pending_via.is_some();
        self.conns.insert(h, c);
        h
    }

    /// Accepts connections to `local` (an unspecified IP: to every local address) on port
    /// `local.port()` until `unlisten`. Each completed handshake is an `Event::Accepted` on
    /// the new connection's handle; a half-open connection has no handle the application
    /// can use (spec G10).
    pub fn listen(&mut self, local: SocketAddr, cfg: ListenConfig) -> Result<(), ListenError> {
        use ListenError as E;
        // Only IP and port reach the wire (`connect`).
        let local = SocketAddr::new(local.ip(), local.port());
        if self.listeners.contains_key(&local) {
            return Err(E::InUse);
        }
        if local.port() == 0 {
            return Err(E::PortZero);
        }
        if cfg.connection.mtu < min_mtu(local.ip(), local.ip()).unwrap() {
            return Err(E::InvalidMtu);
        }
        if !buffers_ok(&cfg.connection) {
            return Err(E::InvalidBuffer);
        }
        if cfg.max_half_open == 0 {
            return Err(E::InvalidHalfOpen);
        }
        let half_open = 0;
        self.listeners.insert(local, Listener { cfg, half_open });
        Ok(())
    }

    /// Stops accepting on `local`; `false` if it had no listener. Its half-open connections
    /// are dropped silently, and joins it answered that are not up yet are reset; established
    /// connections and subflows carry on.
    pub fn unlisten(&mut self, local: SocketAddr) -> bool {
        let key = SocketAddr::new(local.ip(), local.port());
        if self.listeners.remove(&key).is_none() {
            return false;
        }
        // Its pending joins are reset at the next `handle_timeout`, which `poll_timeout` makes
        // due at once (as `Connection::abort`), or by their next segment. A join holds its
        // listener's slot only while it is open (`free_ended`), so only these can.
        let mut changed = Vec::new();
        for (&h, c) in self.conns.iter_untracked_mut() {
            for sf in &mut c.subflows {
                if sf.mp.join.is_some() && sf.pending_via == Some(key) {
                    sf.pending_via = None;
                    sf.mp.reset = true;
                    sf.mp.reset_option = Some(tcprst(0x01, false).to_vec());
                    changed.push(h);
                }
            }
        }
        for h in changed {
            self.conns.touch(h);
        }
        let pending = |(_, c): &(&ConnectionHandle, &Connection)| {
            c.half_open && c.subflows[0].pending_via == Some(key)
        };
        let gone: Vec<_> = self.conns.iter().filter(pending).map(|(&h, _)| h).collect();
        for h in gone {
            self.free(h);
        }
        true
    }

    /// The listener for a segment to `dst`: the exact key, else the wildcard of its family.
    fn listener_for(&self, dst: SocketAddr) -> Option<SocketAddr> {
        let any: IpAddr = match dst {
            SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        [dst, SocketAddr::new(any, dst.port())]
            .into_iter()
            .find(|k| self.listeners.contains_key(k))
    }

    /// A SYN to listener `key` opens a half-open connection (RFC 9293 §3.10.7.2), or is
    /// dropped silently while the listener is at its cap (spec G9). With MPTCP on and a valid
    /// MP_CAPABLE (`syn_capable`) its key is drawn now, before the SYN/ACK carries it; else it
    /// is plain TCP, with no MPTCP option in the SYN/ACK (RFC 8684 L992–993).
    fn accept(&mut self, now: Instant, key: SocketAddr, syn: &Segment) {
        let l = self.listeners.get_mut(&key).unwrap();
        if l.half_open >= l.cfg.max_half_open {
            return;
        }
        l.half_open += 1;
        let mptcp = l.cfg.mptcp;
        let cfg = l.cfg.connection.clone();
        let (local, remote) = (syn.dst, syn.src);
        let (tcb, _) = self.passive_tcb(&cfg, syn, now);
        let h = self.insert(cfg, tcb, local, remote, Some(key));
        if let (true, SynCapable::V1 { peer_c, peer_a }) = (mptcp, syn_capable(syn)) {
            let mut n = self.new_negotiation(h, Negotiation::new_passive);
            n.peer_c = peer_c;
            // A client that requires checksums is honoured (RFC 8684 L958–967).
            n.csum |= peer_a;
            let c = self.conns.get_mut(&h).unwrap();
            c.hooks.negotiation = Some(n);
            c.subflows[0].mp.peer_scale = syn_scale(syn);
        }
    }

    /// A SYN-RECEIVED `Tcb` answering `syn`, and its ISS.
    fn passive_tcb(&mut self, cfg: &ConnectConfig, syn: &Segment, now: Instant) -> (Tcb, SeqNum) {
        let isn = self.isn.isn(now, syn.dst, syn.src);
        let seed = self.rng.next_u64();
        #[cfg(test)]
        if let Some(cc) = self.cc {
            return (Tcb::passive_with_cc(cfg, syn.dst, syn, isn, now, cc()), isn);
        }
        (Tcb::new_passive(cfg, syn.dst, syn, isn, now, seed), isn)
    }

    /// An MP_JOIN SYN to listener `key` (RFC 8684 §3.2; spec G3, G3b, G4, G4a). Its token
    /// alone picks the connection, whatever its role and wherever the SYN comes from. An
    /// unknown token, a connection not Confirmed (or reset or closed; one the application has
    /// closed still takes joins while its data drains), a listener without MPTCP or at
    /// its half-open cap draws a RST with MP_TCPRST "Unspecified MPTCP error"; a connection at
    /// its subflow cap, "Lack of resources" (L1114–1119, L1222–1231, L2254). Neither leaves
    /// state. Otherwise a Joining subflow answers with the SYN/ACK, holding a half-open slot
    /// of the listener until it is up or ends (`release_pending`).
    fn answer_join(&mut self, now: Instant, key: SocketAddr, syn: &Segment) {
        let parsed = walk(syn.options).find_map(|o| match o {
            Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                Ok(MptcpOption::Join(MpJoin::Syn {
                    backup,
                    addr_id,
                    token,
                    nonce,
                })) => Some((backup, addr_id, token, nonce)),
                _ => None,
            },
            _ => None,
        });
        let l = &self.listeners[&key];
        let listener_ok = l.cfg.mptcp && l.half_open < l.cfg.max_half_open;
        // Not while `Waiting` for an MP_FAIL answer (M4b spec G12).
        let confirmed = |c: &&Connection| {
            let m = c.hooks.negotiation.as_ref();
            !c.half_open
                && m.is_some_and(|m| m.state == State::Confirmed)
                && !(c.reset || c.detached || closed(c) || c.hooks.frozen())
        };
        let found = parsed.filter(|_| listener_ok).and_then(|(.., token, _)| {
            let h = *self.tokens.get(&token)?;
            self.conns.get(&h).filter(confirmed).map(|_| h)
        });
        let (Some((backup, peer_addr_id, _, peer_nonce)), Some(h)) = (parsed, found) else {
            return self.queue_rst_with(syn, now, tcprst(0x01, false).to_vec());
        };
        let c = self.conns.get_mut(&h).unwrap();
        let id = SubflowId(c.next_subflow);
        let next = c.next_subflow.checked_add(1);
        let slot = c.subflow_slots() < SUBFLOW_CAP;
        // The local IP's address ID, as for our own joins; the initial one's is 0.
        let addr_id = next
            .filter(|_| slot)
            .and_then(|_| c.local_addrs.bind(syn.dst.ip()));
        let Some(addr_id) = addr_id else {
            return self.queue_rst_with(syn, now, tcprst(0x02, true).to_vec());
        };
        let cfg = c.cfg.clone();
        let (mut tcb, isn) = self.passive_tcb(&cfg, syn, now);
        let nonce = self.nonce();
        self.listeners.get_mut(&key).unwrap().half_open += 1;
        let c = self.conns.get_mut(&h).unwrap();
        tcb.set_nodelay(c.nodelay);
        // As `start_join`, plus what the initiator learns from the SYN/ACK: the peer's
        // window scale and its backup request, here from the SYN (spec G3c, L1101–1109).
        let mut mp = SubflowMp::new();
        mp.local_isn = isn;
        mp.tcp_acked_dsn = c.hooks.data.as_ref().map_or(0, |d| d.send.una);
        mp.peer_scale = syn_scale(syn);
        mp.peer_backup = backup;
        mp.join = Some(Join::responder(
            nonce,
            addr_id,
            peer_nonce,
            peer_addr_id,
            false,
        ));
        c.hooks.cancel_no_subflow_wait();
        c.hooks.signals.cancel_remove(addr_id);
        c.next_subflow = next.unwrap();
        self.demux.insert((syn.dst, syn.src), (h, id));
        c.subflows.push(Subflow {
            id,
            tcb,
            local: syn.dst,
            remote: syn.src,
            state: SubflowState::Joining,
            mp,
            pending_via: Some(key),
        });
    }

    /// Removes connection `h` and its demux entries at once.
    fn free(&mut self, h: ConnectionHandle) {
        let mut c = self.conns.remove(&h).unwrap();
        for sf in &mut c.subflows {
            release_pending(&mut self.listeners, sf);
        }
        if let Some(n) = &c.hooks.negotiation {
            self.tokens.remove(&n.token);
        }
        for sf in &c.subflows {
            let key = (sf.local, sf.remote);
            if self.demux.get(&key) == Some(&(h, sf.id)) {
                self.demux.remove(&key);
            }
        }
    }

    /// A free ephemeral port from `local` to `remote`, searched from a random start. A retained
    /// aborted 4-tuple is in use.
    fn free_port(&mut self, now: Instant, local: IpAddr, remote: SocketAddr) -> Option<SocketAddr> {
        let start = self.rng.next_u32() % EPHEMERAL_COUNT;
        (0..EPHEMERAL_COUNT)
            .map(|i| EPHEMERAL_FIRST + ((start + i) % EPHEMERAL_COUNT) as u16)
            .map(|port| SocketAddr::new(local, port))
            .find(|&l| {
                !self.demux.contains_key(&(l, remote))
                    && self.aborted.key((l, remote), now).is_none()
            })
    }

    fn new_tcb(
        &mut self,
        cfg: &ConnectConfig,
        local: SocketAddr,
        remote: SocketAddr,
        isn: SeqNum,
        now: Instant,
    ) -> Tcb {
        let seed = self.rng.next_u64();
        #[cfg(test)]
        if let Some(cc) = self.cc {
            return Tcb::with_cc(cfg, local, remote, isn, now, cc());
        }
        Tcb::new_active(cfg, local, remote, isn, now, seed)
    }

    /// Opens an MP_JOIN subflow from `local`, whose path MTU is `mtu`, to `remote`: the
    /// connection's remote address, or another endpoint of the peer such as one it announced
    /// (`Event::AddressAnnounced`). Its `Tcb` uses the connection's `ConnectConfig` with this
    /// MTU. `backup` is the preference the join advertises, the MP_JOIN SYN's B bit: whether
    /// the peer should send on it only as a backup (`set_backup` changes it later; our own use
    /// of the subflow is `set_local_backup`).
    /// Until a DSS from the peer has arrived (on an accepted connection, too) the join is
    /// queued and starts at the first `poll_transmit` after that (RFC 8684 L884–887); a queued
    /// join that can no longer start (fallback, C=1) ends with `SubflowDown { Reset }`.
    /// `SubflowUp` follows the peer's acknowledgement of the third ACK; data goes only to
    /// subflows that are up.
    pub fn add_subflow(
        &mut self,
        now: Instant,
        h: ConnectionHandle,
        local: IpAddr,
        remote: SocketAddr,
        mtu: u16,
        backup: bool,
    ) -> Result<SubflowId, AddSubflowError> {
        use AddSubflowError as E;
        // Only IP and port reach the wire (`connect`).
        let remote = SocketAddr::new(remote.ip(), remote.port());
        let c = self.open_mptcp(h, [E::NoConnection, E::NotMptcp, E::Closed])?;
        let m = c.hooks.negotiation.as_ref().unwrap();
        if m.peer_c && remote == c.subflows[0].remote {
            return Err(E::PeerForbidsJoin);
        }
        if c.peer_addrs.failed(remote) {
            return Err(E::AddressFailed);
        }
        let min = min_mtu(local, remote.ip()).ok_or(E::FamilyMismatch)?;
        if mtu < min {
            return Err(E::InvalidMtu);
        }
        if c.subflow_slots() >= SUBFLOW_CAP {
            return Err(E::TooManySubflows);
        }
        let id = SubflowId(c.next_subflow);
        let next = c
            .next_subflow
            .checked_add(1)
            .ok_or(E::SubflowIdsExhausted)?;
        let addr_id = c.local_addrs.bind(local).ok_or(E::TooManyAddresses)?;
        let join = QueuedJoin {
            id,
            local,
            remote,
            mtu,
            addr_id,
            backup,
            local_backup: false,
        };
        if m.state == State::Confirmed && m.peer_dss_seen && !c.hooks.frozen() {
            self.start_join(now, h, join)?;
        } else {
            c.queued_joins.push(join);
            self.pending_joins.insert(h);
        }
        let c = self.conns.get_mut(&h).unwrap();
        c.next_subflow = next;
        c.hooks.signals.cancel_remove(addr_id);
        Ok(id)
    }

    /// `h` as an open MPTCP connection, else the caller's error for: no such connection, not
    /// MPTCP (plain TCP or fallen back), closed.
    fn open_mptcp<E>(
        &mut self,
        h: ConnectionHandle,
        [none, not_mptcp, closed_err]: [E; 3],
    ) -> Result<&mut Connection, E> {
        let c = (self.conns.get_mut(&h).filter(|c| !c.half_open)).ok_or(none)?;
        if !(c.hooks.negotiation.as_ref()).is_some_and(|m| m.state != State::FellBack) {
            return Err(not_mptcp);
        }
        if c.closed_by_app || c.reset || c.detached || closed(c) {
            return Err(closed_err);
        }
        Ok(c)
    }

    /// The connection of a call on subflow `s`, which must be issued and not ended (a queued
    /// join counts). TIME-WAIT is ended: entering it reported `SubflowDown`.
    fn subflow_conn(
        &mut self,
        h: ConnectionHandle,
        s: SubflowId,
    ) -> Result<&mut Connection, SubflowError> {
        use SubflowError as E;
        let c = self.open_mptcp(h, [E::NoConnection, E::NotMptcp, E::Closed])?;
        let open = |sf: &Subflow| sf.id == s && !sf.ended();
        if !(c.subflows.iter().any(open) || c.queued_joins.iter().any(|q| q.id == s)) {
            return Err(E::NoSubflow);
        }
        Ok(c)
    }

    /// Advertises whether the peer should send on subflow `s` only as a backup: an MP_PRIO on
    /// `s` (RFC 8684 §3.3.8), sent once on an ACK when `s` is up and the connection Confirmed.
    /// MP_PRIO is not acknowledged, so it may be lost; call again to repeat it. Each call
    /// leaves one MP_PRIO due with the latest value. Our own use of `s` is unchanged
    /// (`set_local_backup`); the peer's requests arrive as `Event::PeerPriority`.
    pub fn set_backup(
        &mut self,
        _now: Instant,
        h: ConnectionHandle,
        s: SubflowId,
        backup: bool,
    ) -> Result<(), SubflowError> {
        let c = self.subflow_conn(h, s)?;
        c.hooks.signals.prio(s, backup);
        Ok(())
    }

    /// Sends on subflow `s` only as a backup, or not; no wire effect. A subflow is a backup if
    /// this says so or the peer asked for it (MP_JOIN B bit, MP_PRIO): new data, reinjections
    /// and copies go to a backup subflow only while no other subflow is usable, Active with a
    /// nonzero peer window. A busy (cwnd- or pacing-limited) subflow is still usable. May be
    /// called as soon as `add_subflow` returns.
    pub fn set_local_backup(
        &mut self,
        h: ConnectionHandle,
        s: SubflowId,
        backup: bool,
    ) -> Result<(), SubflowError> {
        let c = self.subflow_conn(h, s)?;
        match c.subflows.iter_mut().find(|sf| sf.id == s) {
            Some(sf) => sf.mp.local_backup = backup,
            None => {
                let q = c.queued_joins.iter_mut().find(|q| q.id == s).unwrap();
                q.local_backup = backup;
            }
        }
        Ok(())
    }

    /// Retires subflow `s`, which still works, by FIN exchange (RFC 8684 L2114–2116): it gets
    /// no new data, its TCP retransmissions go on, and once it ends (`SubflowDown`) the data it
    /// held that is not DATA_ACKed is resent on the others. A queued join, or one still in
    /// SYN-SENT, is dropped (`SubflowDown { Reset }`). Only while another subflow can take over: one that is Active
    /// (not Joining, Stale or retiring), not under the peer's REMOVE_ADDR keepalive, and has an
    /// established TCB; a closed window or busy cwnd does not matter. Otherwise `LastSubflow`
    /// and nothing changes: closing every subflow is `Connection::close`.
    pub fn close_subflow(
        &mut self,
        now: Instant,
        h: ConnectionHandle,
        s: SubflowId,
    ) -> Result<(), SubflowError> {
        let c = self.subflow_conn(h, s)?;
        if !(c.subflows.iter()).any(|o| o.id != s && o.can_replace()) {
            return Err(SubflowError::LastSubflow);
        }
        let dropped = match c.subflows.iter_mut().find(|sf| sf.id == s) {
            // RFC 9293 §3.10.4: CLOSE in SYN-SENT deletes the TCB, sending nothing.
            Some(sf) if sf.tcb.state() == TcpState::SynSent => {
                sf.tcb.delete(now);
                true
            }
            Some(sf) => {
                sf.state = SubflowState::Closing;
                sf.tcb.close();
                false
            }
            None => {
                c.queued_joins.retain(|q| q.id != s);
                true
            }
        };
        if dropped {
            (self.events).push_back((h, down(s, CloseReason::Reset, None)));
        }
        Ok(())
    }

    /// Withdraws the local IP `local`, which is no longer valid (its interface is gone; RFC
    /// 8684 §3.4.2). Every subflow using it is reset with MP_TCPRST 0x00 T=0 (a join still in
    /// SYN-SENT is deleted, sending nothing), and joins queued from it are dropped, each with
    /// `SubflowDown { Reset }`; with no subflow left the no-subflow wait starts. If the peer has
    /// learned `local`'s address ID (the initial IP's is 0), a REMOVE_ADDR for it goes once on
    /// another Active subflow, when one exists. A later `add_subflow` from `local` keeps the ID
    /// and drops that REMOVE_ADDR if it has not gone out yet. To retire a working path,
    /// `close_subflow` it first (make-before-break).
    pub fn remove_address(
        &mut self,
        now: Instant,
        h: ConnectionHandle,
        local: IpAddr,
    ) -> Result<(), AddressError> {
        use AddressError as E;
        let c = self.open_mptcp(h, [E::NoConnection, E::NotMptcp, E::Closed])?;
        let id = c.local_addrs.id(local).ok_or(E::UnknownAddress)?;
        if c.local_addrs.on_wire(id) {
            c.hooks.signals.remove(id);
        }
        let c = self.conns.get_mut(&h).unwrap();
        for i in 0..c.subflows.len() {
            let sf = &c.subflows[i];
            if sf.local.ip() != local || sf.ended() {
                continue;
            }
            let last = !others_open(&c.subflows, i);
            let tcb = &mut c.subflows[i].tcb;
            let r = if tcb.state() == TcpState::SynSent {
                // RFC 9293 §3.10.5: ABORT in SYN-SENT sends nothing (ruling R20a).
                tcb.delete(now);
                Reaction::Closed(CloseReason::Reset)
            } else {
                tcb.abort_with(CloseReason::Reset, Some(tcprst(0x00, false).to_vec()), now)
            };
            Self::report(&mut self.events, h, c, i, r, last, now);
        }
        for q in std::mem::take(&mut c.queued_joins) {
            if q.local == local {
                (self.events).push_back((h, down(q.id, CloseReason::Reset, None)));
            } else {
                c.queued_joins.push(q);
            }
        }
        Ok(())
    }

    /// Materializes a join: port, ISN, nonce, demux entry and a Joining subflow whose `Tcb`
    /// sends the MP_JOIN SYN at the next `poll_transmit`.
    fn start_join(
        &mut self,
        now: Instant,
        h: ConnectionHandle,
        q: QueuedJoin,
    ) -> Result<(), AddSubflowError> {
        let c = &self.conns[&h];
        let remote = q.remote;
        let cfg = ConnectConfig {
            mtu: q.mtu,
            ..c.cfg.clone()
        };
        let local = (self.free_port(now, q.local, remote)).ok_or(AddSubflowError::NoPort)?;
        let isn = self.isn.isn(now, local, remote);
        let mut tcb = self.new_tcb(&cfg, local, remote, isn, now);
        let nonce = self.nonce();
        let c = self.conns.get_mut(&h).unwrap();
        tcb.set_nodelay(c.nodelay);
        // SubflowMp fields the MP_CAPABLE path would set: this subflow's own ISN, and nothing
        // TCP-acknowledged on it yet. `peer_scale` comes with its SYN/ACK (`join_segment`).
        let mut mp = SubflowMp::new();
        mp.local_isn = isn;
        mp.tcp_acked_dsn = c.hooks.data.as_ref().map_or(0, |d| d.send.una);
        mp.join = Some(Join::new(nonce, q.addr_id, q.backup));
        mp.local_backup = q.local_backup;
        c.hooks.cancel_no_subflow_wait();
        self.demux.insert((local, remote), (h, q.id));
        c.subflows.push(Subflow {
            id: q.id,
            tcb,
            local,
            remote,
            state: SubflowState::Joining,
            mp,
            pending_via: None,
        });
        Ok(())
    }

    /// Starts the queued joins of connections that became Confirmed; drops those that can no
    /// longer start (fallback, C=1 for the initial remote, connection closed).
    fn start_queued_joins(&mut self, now: Instant) {
        for h in std::mem::take(&mut self.pending_joins) {
            let Some(c) = self.conns.get_mut(&h) else {
                continue;
            };
            let m = c.hooks.negotiation.as_ref().unwrap();
            let open = !c.reset && !c.detached && !closed(c);
            let (state, peer_c, initial) = (m.state, m.peer_c, c.subflows[0].remote);
            // Our joins wait for a DSS from the peer (RFC 8684 L884–887), and while we are
            // `Waiting` for an MP_FAIL answer (M4b spec G12).
            let ready = state == State::Confirmed && m.peer_dss_seen && !c.hooks.frozen();
            let waiting = open && !ready && state != State::FellBack;
            let mut kept = Vec::new();
            for q in std::mem::take(&mut c.queued_joins) {
                let subflow = q.id;
                let allowed = open && !(peer_c && q.remote == initial);
                if allowed && waiting {
                    kept.push(q);
                } else if !(allowed && ready && self.start_join(now, h, q).is_ok()) {
                    (self.events).push_back((h, down(subflow, CloseReason::Reset, None)));
                }
            }
            if !kept.is_empty() {
                self.conns.get_mut(&h).unwrap().queued_joins = kept;
                self.pending_joins.insert(h);
            }
        }
    }

    /// Opens an MPTCP v1 connection, falling back to TCP if the peer does not support it.
    pub fn connect_mptcp(
        &mut self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
        cfg: ConnectConfig,
    ) -> Result<ConnectionHandle, ConnectError> {
        let h = self.connect(now, local, remote, cfg)?;
        let negotiation = self.new_negotiation(h, Negotiation::new);
        self.conns.get_mut(&h).unwrap().hooks.negotiation = Some(negotiation);
        Ok(h)
    }

    /// `None` once the connection is freed, and before `Accepted`. A closed (not reset)
    /// connection with unread data stays reachable, without its port, until the data is read
    /// and `handle_timeout` runs.
    pub fn connection(&mut self, h: ConnectionHandle) -> Option<&mut Connection> {
        self.conns.lend(&h).filter(|c| !c.half_open)
    }

    pub fn poll_event(&mut self) -> Option<(ConnectionHandle, Event)> {
        self.events.pop_front()
    }

    /// Feeds one received IP packet. Unparseable packets are dropped silently. Never frees a
    /// TCB (`handle_timeout` does), so buffered data and `Err(Reset)` stay readable.
    pub fn handle_packet(&mut self, now: Instant, ip_packet: &[u8]) {
        let Ok(seg) = packet::parse(ip_packet) else {
            return;
        };
        self.apply_aborts(now);
        let Some(&(h, id)) = self.demux.get(&(seg.dst, seg.src)) else {
            let f = seg.flags;
            let (syn, ack) = (f.contains(TcpFlags::SYN), f.contains(TcpFlags::ACK));
            let ctl = syn || ack || f.contains(TcpFlags::RST);
            // A SYN with an MP_JOIN asks to join a connection, whatever its role (spec G4a).
            let join = walk(seg.options).any(|o| matches!(o, Ok(TcpOpt::Mptcp(m)) if is_join(m)));
            match self.listener_for(seg.dst) {
                // LISTEN (RFC 9293 §3.10.7.2): a RST is ignored and an ACK draws a RST
                // (`queue_rst`); without SYN, ACK or RST the segment is dropped (L3340–3346).
                Some(_) if !ctl => {}
                Some(key) if syn && !ack && !f.contains(TcpFlags::RST) => {
                    if join {
                        self.answer_join(now, key, &seg);
                    } else {
                        self.accept(now, key, &seg);
                    }
                }
                _ => self.queue_rst(&seg, now),
            }
            return;
        };
        let Some(c) = self.conns.get_mut(&h) else {
            return;
        };
        let mark = self.events.len();
        let Some(mut i) = c.subflows.iter().position(|sf| sf.id == id) else {
            return;
        };
        // A Closed TCB kept for its connection (`subflows[0]`, or until `handle_timeout`)
        // answers as CLOSED (§3.10.7.1); a RST still due for it is the answer already.
        let tcb = &c.subflows[i].tcb;
        if tcb.state() == TcpState::Closed {
            if !tcb.reset_pending() {
                self.queue_rst(&seg, now);
            }
            return;
        }
        let last = !others_open(&c.subflows, i);
        let sf = &mut c.subflows[i];
        let mut hk = SubflowHooks {
            conn: &mut c.hooks,
            sf: &mut sf.mp,
        };
        let m = |c: &ConnectionHooks| c.negotiation.as_ref().map(|m| m.state);
        // An input that begins PreConfirmed stages ADD_ADDR and REMOVE_ADDR for its whole
        // length (M3 spec §3.3 rev3 S2a).
        let staged = m(hk.conn) == Some(State::PreConfirmed);
        let r = sf.tcb.on_segment(&seg, now, &mut hk);
        let port = sf.remote.port();
        if let Some(backup) = sf.mp.peer_prio.take() {
            let subflow = sf.id;
            (self.events).push_back((h, Event::PeerPriority { subflow, backup }));
        }
        // New offers leave out the octets every hold buffer keeps (M4b spec G7, memory); with
        // no checksums nothing is ever held, so nothing is summed (G9, A1).
        let csum = c.hooks.negotiation.as_ref().is_some_and(|m| m.csum);
        if let Some(d) = c.hooks.data.as_mut().filter(|_| csum) {
            d.recv
                .set_held(c.subflows.iter().map(|s| s.mp.hold.held()).sum());
        }
        // Waiting for an MP_FAIL answer: joins not yet complete are reset (M4b spec G12).
        if c.mp_fail_input(i, now) {
            for subflow in c.cancel_joins(now) {
                (self.events).push_back((h, down(subflow, CloseReason::Reset, None)));
            }
        }
        c.note_join_failure(i);
        // MP_FASTCLOSE tears down every subflow (RFC 8684 L2168–2172).
        if c.hooks.fast_closed {
            c.abort_all(now, Some(i), None);
        }
        let mut fell_back = std::mem::take(&mut c.hooks.fallback_event);
        if fell_back {
            if c.on_fallback(i, now) {
                fell_back = false;
                c.reset = true;
                let reason = CloseReason::FallbackDataLoss;
                self.events.push_back((h, Event::Closed { reason }));
            }
            i = 0;
        }
        for id in std::mem::take(&mut c.hooks.peer_removed) {
            if !c.hooks.active() {
                continue;
            }
            if staged {
                for q in c.staged_removed(id) {
                    (self.events).push_back((h, down(q, CloseReason::Reset, None)));
                }
            } else if c.peer_removed(id) {
                self.events.push_back((h, Event::AddressRemoved { id }));
            }
        }
        for e in std::mem::take(&mut c.hooks.peer_announced) {
            let addr = (c.hooks.active()).then(|| c.peer_announced(e, port));
            if let Some(addr) = addr.flatten().filter(|_| !staged) {
                (self.events).push_back((h, Event::AddressAnnounced { id: e.id, addr }));
            }
        }
        // The input that confirms publishes the staged table, after its own signals and
        // fallback detection, before any queued join starts (S3).
        if staged && c.hooks.active() && m(&c.hooks) == Some(State::Confirmed) {
            for (&id, a) in &c.peer_addrs.0 {
                if let Some((ip, port)) = a.advertised {
                    let addr = SocketAddr::new(ip, port);
                    (self.events).push_back((h, Event::AddressAnnounced { id, addr }));
                }
            }
        }
        // Events first: a join this segment completed is Active before `update_health`, so a
        // bare FIN on the same segment retires it (`SubflowUp`, then the Closing path).
        let sf = &mut c.subflows[i];
        if i != 0 {
            let view = (sf.id, &mut sf.state, &sf.tcb, &sf.mp);
            Self::subflow_event(&mut self.events, &c.hooks, h, view, r);
        } else if r != Reaction::None {
            let rst = sf.mp.rst;
            Self::push_event(&mut self.events, &c.hooks, &mut c.reset, h, r, !last, rst);
        }
        if let Some(e) = c.update_health(i) {
            self.events.push_back((h, e));
        }
        let time_wait = time_wait(c);
        let sf = &mut c.subflows[i];
        let mut hk = SubflowHooks {
            conn: &mut c.hooks,
            sf: &mut sf.mp,
        };
        Self::update_close(
            &mut self.events,
            &mut hk,
            &sf.tcb,
            &mut c.reset,
            h,
            now,
            last,
            time_wait,
        );
        c.update_recovery(now);
        if fell_back {
            self.events.push_back((h, Event::FellBack));
        }
        let mut free = false;
        if c.half_open {
            // Nothing about a half-open connection reaches the application (spec G10); its
            // `Connected` becomes `Accepted`.
            self.events.truncate(mark);
            let sf = &mut c.subflows[0];
            if r == Reaction::Established {
                c.half_open = false;
                release_pending(&mut self.listeners, sf);
                let mptcp = c.hooks.active();
                self.events.push_back((h, Event::Accepted { mptcp }));
            } else if sf.tcb.state() == TcpState::Closed {
                // A RST, or the peer's SYN in the window, returns a passive open to LISTEN
                // (RFC 9293 L3580–3592, L3652–3658): freed now, unless a RST is still due.
                release_pending(&mut self.listeners, sf);
                free = !sf.tcb.reset_pending();
            }
        }
        Self::free_ended(&mut self.demux, &mut self.listeners, h, c);
        if free {
            self.free(h);
        }
    }

    /// Frees the ended subflows (TCB Closed, no RST left to send) other than `subflows[0]`,
    /// with their demux entries and ports, as soon as they end. A subflow in TIME-WAIT is not
    /// Closed, so it keeps its 4-tuple until 2·MSL. A join we answered gives its listener's
    /// half-open slot back once it is up or Closed.
    fn free_ended(
        demux: &mut BTreeMap<(SocketAddr, SocketAddr), (ConnectionHandle, SubflowId)>,
        listeners: &mut BTreeMap<SocketAddr, Listener>,
        h: ConnectionHandle,
        c: &mut Connection,
    ) {
        for sf in &mut c.subflows {
            if sf.mp.join.is_some() && (!sf.mp.joining() || sf.tcb.state() == TcpState::Closed) {
                release_pending(listeners, sf);
            }
        }
        let mut first = true;
        let freed = &mut c.hooks.freed_dsn_end;
        let signals = &mut c.hooks.signals;
        c.subflows.retain(|sf| {
            let keep = std::mem::take(&mut first)
                || sf.tcb.state() != TcpState::Closed
                || sf.tcb.reset_pending();
            if !keep {
                signals.forget(sf.id);
                if let Some(end) = sf.mp.dsn_end {
                    *freed = crate::mptcp::later(*freed, end);
                }
                if demux.get(&(sf.local, sf.remote)) == Some(&(h, sf.id)) {
                    demux.remove(&(sf.local, sf.remote));
                }
            }
            keep
        });
    }

    /// After reaction `r` of subflow `i` to a timeout or a local call (`last`: no other subflow
    /// was open before it): its health, its event and the connection's close.
    fn report(
        events: &mut VecDeque<(ConnectionHandle, Event)>,
        h: ConnectionHandle,
        c: &mut Connection,
        i: usize,
        r: Reaction,
        last: bool,
        now: Instant,
    ) {
        c.note_join_failure(i);
        if let Some(e) = c.update_health(i) {
            events.push_back((h, e));
        }
        let time_wait = time_wait(c);
        let sf = &mut c.subflows[i];
        let mut hk = SubflowHooks {
            conn: &mut c.hooks,
            sf: &mut sf.mp,
        };
        if i != 0 {
            let view = (sf.id, &mut sf.state, &sf.tcb, &*hk.sf);
            Self::subflow_event(events, hk.conn, h, view, r);
        } else {
            let rst = hk.sf.rst;
            Self::push_event(events, hk.conn, &mut c.reset, h, r, !last, rst);
        }
        Self::update_close(
            events,
            &mut hk,
            &sf.tcb,
            &mut c.reset,
            h,
            now,
            last,
            time_wait,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn update_close(
        events: &mut VecDeque<(ConnectionHandle, Event)>,
        hk: &mut SubflowHooks<'_>,
        tcb: &Tcb,
        reset: &mut bool,
        h: ConnectionHandle,
        now: Instant,
        last: bool,
        time_wait: bool,
    ) {
        if let Some(reason) = hk.update_close(tcb, now, last, time_wait) {
            *reset |= reason != CloseReason::Normal;
            events.push_back((h, Event::Closed { reason }));
        }
    }

    /// The events of a subflow other than `subflows[0]`: `SubflowDown` when its TCB ends
    /// (not for an MP_FASTCLOSE reset, nor for a join we answered that never came up: the
    /// application never saw it), else `SubflowUp` once its join completes (`joining` false),
    /// which also makes it Active.
    fn subflow_event(
        events: &mut VecDeque<(ConnectionHandle, Event)>,
        hooks: &ConnectionHooks,
        h: ConnectionHandle,
        (subflow, state, tcb, mp): (SubflowId, &mut SubflowState, &Tcb, &SubflowMp),
        r: Reaction,
    ) {
        let (joining, rst) = (mp.joining(), mp.rst);
        let answered = (mp.join.as_ref()).is_some_and(|j| j.role == JoinRole::Responder);
        let reason = match r {
            Reaction::Closed(reason) => Some(reason),
            // A SYN/ACK the join rejects resets the TCB inside its `Established` processing.
            Reaction::Established if tcb.state() == TcpState::Closed => Some(CloseReason::Reset),
            _ => None,
        };
        if let Some(reason) = reason {
            if !hooks.fast_closed && !(answered && *state == SubflowState::Joining) {
                events.push_back((h, down(subflow, reason, rst)));
            }
        } else if *state == SubflowState::Joining && !joining {
            *state = SubflowState::Active;
            events.push_back((h, Event::SubflowUp { subflow }));
        }
    }

    /// The events of `subflows[0]`. With MPTCP active its end is `SubflowDown` while the
    /// connection carries on (not on MP_FASTCLOSE): another subflow is open (`others_open`),
    /// or, as the last one, its end starts the no-subflow wait, whose end is `Closed`.
    fn push_event(
        events: &mut VecDeque<(ConnectionHandle, Event)>,
        hooks: &ConnectionHooks,
        reset: &mut bool,
        h: ConnectionHandle,
        r: Reaction,
        others_open: bool,
        rst: Option<MpTcpRst>,
    ) {
        match r {
            Reaction::None => {}
            Reaction::Established => {
                if hooks.negotiation.is_some() {
                    return;
                }
                events.push_back((h, Event::Connected { mptcp: false }));
            }
            Reaction::Closed(reason) => {
                if hooks.active() {
                    let carries_on = others_open || !hooks.data_closed();
                    if carries_on && hooks.retained() && !hooks.fast_closed {
                        events.push_back((h, down(SubflowId::INITIAL, reason, rst)));
                    }
                    return;
                }
                *reset |= reason == CloseReason::Reset;
                events.push_back((h, Event::Closed { reason }));
            }
        }
    }

    /// Carries out `Connection::abort` (M3 spec §3.5) where it was called: every TCB is
    /// deleted, each synchronized one (TIME-WAIT included) with a RST at SND.MAX, with
    /// MP_FASTCLOSE and a retained 4-tuple when MPTCP is in use.
    fn apply_aborts(&mut self, now: Instant) {
        // Only the application's `abort` sets `aborting`, through `connection`.
        for h in self.conns.aborting() {
            let c = self.conns.untracked_mut(&h).unwrap();
            if !std::mem::take(&mut c.aborting) || ended(c) {
                continue;
            }
            let key = c.hooks.abort();
            // Dropped silently: nothing follows `Closed { Aborted }`.
            c.queued_joins.clear();
            for sf in &mut c.subflows {
                let state = sf.tcb.state();
                if state == TcpState::Closed {
                    continue;
                }
                let rto = sf.tcb.retransmission_timeout();
                let seq = sf.tcb.delete(now);
                if state == TcpState::SynSent {
                    continue;
                }
                let (src, dst) = (sf.local, sf.remote);
                let (ack, flags) = (SeqNum(0), TcpFlags::RST);
                let option = key.map_or(Vec::new(), |k| fastclose(k).to_vec());
                // Not bounded by MAX_PENDING_RST: at most one per subflow, once per connection.
                (self.pending_rst).push_back(PendingRst {
                    src,
                    dst,
                    seq,
                    ack,
                    flags,
                    option,
                });
                if let Some(key) = key {
                    self.aborted.insert((src, dst), key, now + 3 * rto);
                }
            }
            c.reset = true;
            let reason = CloseReason::Aborted;
            self.events.push_back((h, Event::Closed { reason }));
        }
    }

    /// RFC 9293 §3.10.7.1: segment arrives in CLOSED. Never in reply to a RST. On a retained
    /// aborted 4-tuple the RST carries MP_FASTCLOSE (M3 spec §3.5).
    fn queue_rst(&mut self, seg: &Segment, now: Instant) {
        self.queue_rst_with(seg, now, Vec::new());
    }

    /// `queue_rst` whose RST carries `option` (a refused join's MP_TCPRST) unless it carries
    /// MP_FASTCLOSE.
    fn queue_rst_with(&mut self, seg: &Segment, now: Instant, option: Vec<u8>) {
        if seg.flags.contains(TcpFlags::RST) || self.pending_rst.len() >= MAX_PENDING_RST {
            return;
        }
        let (seq, ack, flags) = if seg.flags.contains(TcpFlags::ACK) {
            (seg.ack, SeqNum(0), TcpFlags::RST)
        } else {
            let len = seg.payload.len() as u32
                + seg.flags.contains(TcpFlags::SYN) as u32
                + seg.flags.contains(TcpFlags::FIN) as u32;
            (
                SeqNum(0),
                seg.seq.wrapping_add(len),
                TcpFlags::RST | TcpFlags::ACK,
            )
        };
        let key = self.aborted.key((seg.dst, seg.src), now);
        let option = key.map_or(option, |k| fastclose(k).to_vec());
        self.pending_rst.push_back(PendingRst {
            src: seg.dst,
            dst: seg.src,
            seq,
            ack,
            flags,
            option,
        });
    }

    /// Writes one complete IP packet into `buf` and returns its length, or `None` if nothing is
    /// to be sent. `buf` must hold the largest MTU of any subflow of any connection: a subflow
    /// whose MTU exceeds `buf.len()` is skipped (nothing is built for it, so no sequence,
    /// mapping, pacing or timer state is consumed) until a large enough `buf` is passed.
    /// Driver contract: call this after every `read`, `write`, `close`, `abort`, `add_subflow`
    /// and `handle_packet` until it returns `None`: those calls can make a packet (window update,
    /// data, FIN, MP_JOIN SYN) due without any timer being armed.
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut [u8]) -> Option<usize> {
        self.apply_aborts(now);
        while let Some(r) = self.pending_rst.pop_front() {
            let seg = Segment {
                src: r.src,
                dst: r.dst,
                seq: r.seq,
                ack: r.ack,
                flags: r.flags,
                wnd: 0,
                options: &r.option,
                payload: &[],
            };
            if let Some(n) = Self::build(&mut self.ip_id, &seg, buf) {
                return Some(n);
            }
        }
        if !self.pending_joins.is_empty() {
            self.start_queued_joins(now);
        }
        #[cfg(test)]
        if self.full_scan {
            return self.poll_transmit_full_scan(now, buf);
        }
        self.conns.wake(now);
        use std::ops::Bound::{Excluded, Included, Unbounded};
        let cursor = ConnectionHandle(self.cursor);
        // Round robin from the cursor, then wrap around, over the ready connections: a parked
        // one would send nothing (`conns`).
        for (mut from, to) in [(Included(cursor), Unbounded), (Unbounded, Excluded(cursor))] {
            while let Some(h) = self.conns.next_ready((from, to)) {
                from = Excluded(h);
                match self.visit(h, now, buf) {
                    Visit::Sent(n) => {
                        self.conns.touch(h);
                        self.cursor = h.0 + 1;
                        if n.is_some() {
                            self.conns.refresh_if_many();
                            return n;
                        }
                    }
                    Visit::Idle => {
                        let deadline = next_deadline(&self.conns[&h]);
                        self.conns.park(h, deadline);
                    }
                    Visit::Busy => self.conns.touch(h),
                }
            }
        }
        self.conns.refresh();
        None
    }

    /// `poll_transmit`'s round robin as it was before the ready set: a turn of every connection
    /// from the cursor, then wrapping around, until one sends.
    #[cfg(test)]
    fn poll_transmit_full_scan(&mut self, now: Instant, buf: &mut [u8]) -> Option<usize> {
        let cursor = ConnectionHandle(self.cursor);
        let all: Vec<ConnectionHandle> = self.conns.iter().map(|(&h, _)| h).collect();
        let (before, after): (Vec<_>, Vec<_>) = all.into_iter().partition(|&h| h < cursor);
        for h in after.into_iter().chain(before) {
            if let Visit::Sent(n) = self.visit(h, now, buf) {
                self.cursor = h.0 + 1;
                if n.is_some() {
                    return n;
                }
            }
        }
        None
    }

    /// One connection's turn in `poll_transmit`.
    fn visit(&mut self, h: ConnectionHandle, now: Instant, buf: &mut [u8]) -> Visit {
        #[cfg(test)]
        {
            self.visits += 1;
        }
        let c = self.conns.untracked_mut(&h).unwrap();
        let states = tcb_states(c);
        c.update_recovery(now);
        c.select_control();
        // Step 1 (spec §3.1): each subflow's own traffic — ACKs, TCP retransmissions,
        // assigned data, control items — never through the scheduler.
        let mut sent = None;
        let mut busy = false;
        for (i, sf) in c.subflows.iter_mut().enumerate() {
            let mut hk = SubflowHooks {
                conn: &mut c.hooks,
                sf: &mut sf.mp,
            };
            // Whatever is due (a third ACK, data) stays due until `buf` can hold it.
            if buf.len() < sf.tcb.mtu() {
                busy = true;
                continue;
            }
            hk.prepare_send(&mut sf.tcb, now, sf.id);
            if c.closed_by_app && !hk.conn.close() {
                sf.tcb.close();
            }
            if sf.tcb.poll_send(now, &mut hk, &mut self.scratch).is_some() {
                sent = Some(i);
                break;
            }
        }
        // Steps 2–3: plan one mapping, install it, send it on its subflow.
        if sent.is_none() {
            // A step that trims the reinjection head or moves the repair state leaves the next
            // turn something else to do (its roles and demand differ), as does a mapping the
            // `Tcb` holds back (SWS).
            let before = scheduled(c);
            if let Some(i) = c.schedule(now, buf.len()) {
                busy = true;
                let sf = &mut c.subflows[i];
                let mut hk = SubflowHooks {
                    conn: &mut c.hooks,
                    sf: &mut sf.mp,
                };
                if sf.tcb.poll_send(now, &mut hk, &mut self.scratch).is_some() {
                    sent = Some(i);
                }
            } else {
                busy |= scheduled(c) != before;
            }
        }
        let Some(i) = sent else {
            // A subflow closed without a segment (a join in SYN-SENT once our DATA_FIN is
            // acknowledged) changes what the next turn's recovery update does.
            busy |= tcb_states(c) != states;
            return if busy { Visit::Busy } else { Visit::Idle };
        };
        let sf = &mut c.subflows[i];
        let mut hk = SubflowHooks {
            conn: &mut c.hooks,
            sf: &mut sf.mp,
        };
        let w = &self.scratch;
        let seg = Segment {
            src: sf.local,
            dst: sf.remote,
            seq: w.seq,
            ack: w.ack,
            flags: w.flags,
            wnd: w.wnd,
            options: w.options(),
            payload: &w.payload,
        };
        let Some(n) = Self::build(&mut self.ip_id, &seg, buf) else {
            return Visit::Sent(None);
        };
        let rto = sf.tcb.retransmission_timeout();
        hk.on_transmitted(&seg, now, rto);
        hk.sf.keepalive_sent(sf.tcb.keepalive_pending(), now, rto);
        if let Some(j) = hk
            .sf
            .join
            .as_ref()
            .filter(|_| w.flags.contains(TcpFlags::SYN))
        {
            c.local_addrs.sent(j.addr_id);
        }
        if let Some(mptcp) = hk
            .conn
            .negotiation
            .as_mut()
            .and_then(|m| m.on_transmitted(w.flags))
        {
            self.events.push_back((h, Event::Connected { mptcp }));
        }
        if w.flags.contains(TcpFlags::RST) {
            Self::free_ended(&mut self.demux, &mut self.listeners, h, c);
        }
        Visit::Sent(Some(n))
    }

    fn build(ip_id: &mut u16, seg: &Segment, buf: &mut [u8]) -> Option<usize> {
        let id = *ip_id;
        *ip_id = id.wrapping_add(1);
        packet::build(seg, id, buf).ok()
    }

    /// Earliest `poll_send_at` over all connections. Driver contract: after any `read`,
    /// `write` or `close` call `poll_transmit` (they can make a packet due), then re-read this.
    pub fn poll_timeout(&self) -> Option<Instant> {
        #[cfg(test)]
        if self.full_scan {
            let all = self.conns.iter().filter_map(|(_, c)| next_deadline(c));
            return all.chain(self.aborted.next_expiry()).min();
        }
        (self.conns.next_timer().into_iter())
            .chain(self.aborted.next_expiry())
            .min()
    }

    /// Runs `Tcb::on_timeout` on every due TCB (Closed ones included: a SYN-SENT close reports
    /// its `Closed(Normal)` there) and the MP_JOIN third-ACK items, then frees the TCBs that
    /// are `Closed`: ended joined subflows with their ports, and connections.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.apply_aborts(now);
        self.aborted.expire(now);
        self.conns.refresh();
        // The connections with a deadline at or before `now`, and those changed since their
        // last pass here: any other would change nothing.
        let due = self.conns.due(now);
        #[cfg(test)]
        let due = match self.full_scan {
            true => self.conns.iter().map(|(&h, _)| h).collect(),
            false => due,
        };
        for &h in &due {
            let c = self.conns.untracked_mut(&h).unwrap();
            if c.detached {
                continue;
            }
            #[cfg(test)]
            {
                self.timeouts += 1;
            }
            let mark = self.events.len();
            c.update_recovery(now);
            let mp_fail_expired = c.mp_fail_timeout(now);
            for i in 0..c.subflows.len() {
                let last = !others_open(&c.subflows, i);
                let sf = &mut c.subflows[i];
                let mut hk = SubflowHooks {
                    conn: &mut c.hooks,
                    sf: &mut sf.mp,
                };
                let mut r = Reaction::None;
                let syn_sent = sf.tcb.state() == TcpState::SynSent;
                if Some(sf.id) == mp_fail_expired {
                    // No answer to our MP_FAIL in 120 s (M4b spec G16); held octets go too.
                    hk.sf.hold.clear();
                }
                if Some(sf.id) == mp_fail_expired && sf.tcb.state() != TcpState::Closed {
                    let rst = Some(tcprst(0x06, false).to_vec());
                    r = sf.tcb.abort_with(CloseReason::Reset, rst, now);
                } else if sf.tcb.state() == TcpState::SynReceived && hk.sf.reset {
                    // A join whose listener was removed (`unlisten`): RFC 9293 §3.10.5 ABORT.
                    r = sf
                        .tcb
                        .abort_with(CloseReason::Reset, hk.sf.reset_option.clone(), now);
                } else if hk.sf.strand_at.is_some_and(|t| t <= now)
                    && sf.tcb.state() != TcpState::Closed
                {
                    // Like a FIN exchange's end, a joined subflow reports `SubflowDown`.
                    r = sf.tcb.abort_with(
                        CloseReason::Reset,
                        Some(tcprst(0x04, true).to_vec()),
                        now,
                    );
                } else if sf.tcb.state() != TcpState::Closed && hk.sf.keepalive_failed(now) {
                    // The REMOVE_ADDR keepalive went unanswered (M3 spec §3.3, §3.4).
                    r = sf.tcb.abort_with(
                        CloseReason::Reset,
                        Some(tcprst(0x00, false).to_vec()),
                        now,
                    );
                } else if sf.tcb.poll_send_at().is_some_and(|t| t <= now) {
                    r = sf.tcb.on_timeout(now, &mut hk);
                }
                if let Some(j) = &mut hk.sf.join {
                    if r == Reaction::None && sf.tcb.state() != TcpState::Closed {
                        r = j.on_timeout(&mut sf.tcb, now, c.cfg.r2_data);
                    }
                }
                // A join that timed out (SYN R2, third-ACK give-up) failed (M3 spec §3.3).
                if r == Reaction::Closed(CloseReason::Timeout) && hk.sf.joining() {
                    hk.sf.join_failed = Some(None);
                }
                // Once a join was started, a synchronized subflow ended at R2 is reset, so that
                // the peer frees it too and schedules nothing more on it; one in SYN-SENT sends
                // nothing (RFC 9293 §3.10.5, ruling R20a); before any join, the initial subflow
                // keeps the M0/M1 behaviour.
                if (hk.sf.join.is_some() || hk.conn.joined_ever)
                    && r == Reaction::Closed(CloseReason::Timeout)
                    && !syn_sent
                    && !sf.tcb.reset_pending()
                {
                    sf.tcb
                        .abort_with(CloseReason::Timeout, Some(tcprst(0x00, true).to_vec()), now);
                }
                Self::report(&mut self.events, h, c, i, r, last, now);
            }
            if let Some(d) = c.hooks.data.as_mut().filter(|_| mp_fail_expired.is_some()) {
                d.recv
                    .set_held(c.subflows.iter().map(|s| s.mp.hold.held()).sum());
            }
            // A subflow this timeout ended may have been the one `Waiting` was on.
            c.end_orphaned_wait();
            // A half-open connection ends silently, at R2 (spec G10).
            if c.half_open {
                self.events.truncate(mark);
            }
            Self::free_ended(&mut self.demux, &mut self.listeners, h, c);
            self.conns.passed(h);
        }
        let (demux, events) = (&mut self.demux, &mut self.events);
        let (listeners, tokens) = (&mut self.listeners, &mut self.tokens);
        self.conns.retain_some(&due, |&h, c| {
            // A half-open connection is never retained nor detached: no application holds it
            // (spec G10), and keeping it would bypass `max_half_open` (spec G9).
            let retained = !c.half_open && c.hooks.retained();
            if retained || c.subflows.iter().any(|sf| sf.tcb.reset_pending()) {
                return true;
            }
            if c.subflows
                .iter()
                .any(|sf| sf.tcb.state() != TcpState::Closed)
            {
                return true;
            }
            for sf in &mut c.subflows {
                release_pending(listeners, sf);
                let key = (sf.local, sf.remote);
                if demux.get(&key) == Some(&(h, sf.id)) {
                    demux.remove(&key);
                }
            }
            for q in c.queued_joins.drain(..) {
                events.push_back((h, down(q.id, CloseReason::Reset, None)));
            }
            // A reset connection's data is not readable; otherwise keep it until drained.
            c.detached = !c.reset && !c.half_open && c.hooks.has_unread();
            if let (false, Some(n)) = (c.detached, &c.hooks.negotiation) {
                tokens.remove(&n.token);
            }
            c.detached
        });
        self.conns.refresh();
    }
}

/// `SubflowDown`; `rst`: the MP_TCPRST of the peer RST that ended the subflow.
fn down(subflow: SubflowId, reason: CloseReason, rst: Option<MpTcpRst>) -> Event {
    Event::SubflowDown {
        subflow,
        reason,
        rst,
    }
}

/// Gives back the half-open slot `sf` holds on its listener, at most once; nothing if that
/// listener was removed.
fn release_pending(listeners: &mut BTreeMap<SocketAddr, Listener>, sf: &mut Subflow) {
    if let Some(l) = sf.pending_via.take().and_then(|k| listeners.get_mut(&k)) {
        l.half_open -= 1;
    }
}

/// `send_buffer` and `recv_buffer` are within 1 and 2^30.
fn buffers_ok(cfg: &ConnectConfig) -> bool {
    [cfg.send_buffer, cfg.recv_buffer]
        .iter()
        .all(|b| (1..=1 << 30).contains(b))
}

/// IPv4 needs an MTU of at least 68, IPv6 at least 1280; `None` for mixed families.
fn min_mtu(local: IpAddr, remote: IpAddr) -> Option<u16> {
    match (local, remote) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Some(68),
        (IpAddr::V6(_), IpAddr::V6(_)) => Some(1280),
        _ => None,
    }
}

/// Some subflow other than `subflows[i]` is open (not `Subflow::ended`).
fn others_open(subflows: &[Subflow], i: usize) -> bool {
    (subflows.iter().enumerate()).any(|(j, s)| j != i && !s.ended())
}

/// What `poll_transmit` made of a connection's turn.
enum Visit {
    /// A segment, and its packet unless `buf` could not hold it.
    Sent(Option<usize>),
    /// Nothing to send, and nothing changed that a later turn would act on: it can wait for
    /// a change or for `wake_at`.
    Idle,
    /// Nothing sent, but the next turn may send or change more: a subflow's MTU exceeds
    /// `buf` (what it has due waits for a larger one), a mapping was installed and held, the
    /// reinjection head or repair state moved, or a subflow's TCP state changed.
    Busy,
}

/// The earliest deadline of `c` (`poll_timeout`); `None` once it is detached.
fn next_deadline(c: &Connection) -> Option<Instant> {
    if c.detached {
        return None;
    }
    // A Closed TCB's deadline frees the connection, which waits for TIME-WAIT.
    let free = !(c.hooks.retained() || time_wait(c));
    c.subflows
        .iter()
        .flat_map(|sf| {
            let open = sf.tcb.state() != TcpState::Closed;
            let tcb = sf.tcb.poll_send_at().filter(|_| free || open);
            let join =
                (sf.mp.join.as_ref().filter(|_| open)).and_then(|j| j.deadline(c.cfg.r2_data));
            let strand = sf.mp.strand_at.filter(|_| open);
            let keepalive = sf.mp.keepalive.and_then(|k| k.deadline);
            let keepalive = keepalive.filter(|_| open);
            let unlisten = (sf.tcb.state() == TcpState::SynReceived && sf.mp.reset)
                .then_some(Instant::from_nanos(0));
            let tcb = tcb.into_iter().chain(join).chain(strand).chain(keepalive);
            tcb.chain(unlisten)
        })
        .chain(c.hooks.recovery_deadline())
        .chain(c.mp_fail_deadline())
        .chain(c.opp_deadline())
        .chain(c.hooks.signals.next_wake())
        .chain(c.aborting.then_some(Instant::from_nanos(0)))
        .min()
}

/// The state a scheduling step may change for the next one: the reinjection head and repair.
fn scheduled(c: &Connection) -> (Option<(u64, u64)>, crate::mptcp::Repair) {
    (
        c.hooks.data.as_ref().and_then(|d| d.reinject.first()),
        c.repair,
    )
}

/// The TCP states of `c`'s subflows, packed: changes when one changes or one is freed.
fn tcb_states(c: &Connection) -> u64 {
    (c.subflows.iter()).fold(c.subflows.len() as u64, |k, sf| {
        k << 4 | sf.tcb.state() as u64
    })
}

/// When the passing of time alone may give `c` something to send: its deadline (`deadline`,
/// from `next_deadline`), or a pacing release, which the deadline leaves out when nothing it
/// knows of waits for it.
fn wake_at(c: &Connection, deadline: Option<Instant>) -> Option<Instant> {
    let release = (c.subflows.iter())
        .filter_map(|sf| sf.tcb.release_at())
        .min();
    deadline.into_iter().chain(release).min()
}

/// Some subflow of `c` is in TIME-WAIT.
fn time_wait(c: &Connection) -> bool {
    (c.subflows.iter()).any(|sf| sf.tcb.state() == TcpState::TimeWait)
}

/// `Closed` was reported, or (a `close` in SYN-SENT) is due without further input.
pub(crate) fn ended(c: &Connection) -> bool {
    let initial = c.subflows[0].tcb.state();
    c.detached
        || if c.hooks.active() {
            !c.hooks.retained()
        } else {
            matches!(initial, TcpState::Closed | TcpState::TimeWait)
        }
}

/// The connection's data level has closed (MPTCP; no data state yet counts as open).
fn closed(c: &Connection) -> bool {
    c.hooks.data.is_some() && !c.hooks.retained()
}

#[cfg(test)]
mod diff_tests;
#[cfg(test)]
mod mptcp_tests;
#[cfg(test)]
mod scale_tests;
#[cfg(test)]
mod server_tests;
