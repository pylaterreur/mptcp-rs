//! Pure TCP state machine (RFC 9293), driven by segments, time and hooks (spec §3, §3.1).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::time::Duration;

use rangemap::RangeSet;

use super::cc::bbr::Bbr;
use super::cc::cubic::Cubic;
use super::cc::rate::{RateSampler, SampleCtx};
use super::cc::{
    AckSample, AppLimited, CongestionControl, CongestionEvent, RecoveryAck, RecoveryKind,
    RecoveryStart, Start, Transmit,
};
use super::hooks::{AckPurpose, Hooks};
use super::recovery::{DupAck, NewAck, NewReno};
use super::rtt::{INITIAL_RTO, RttEstimator};
use super::sack::{DupAck as SackDupAck, Sack};
use crate::seq::SeqNum;
use crate::time::Instant;
use crate::wire::packet::{Segment, TcpFlags};
use crate::wire::tcp_options::{self, TcpOpt};

/// RFC 9293 MUST-23: R2 for a SYN is at least 3 minutes.
const MIN_R2_SYN: Duration = Duration::from_secs(180);
const MAX_WS_SHIFT: u8 = 14;
/// Persist interval cap (RFC 9293 SHLD-30 leaves it open; same as the RTO cap).
const MAX_PERSIST: Duration = Duration::from_secs(60);
/// Sender SWS override timeout (RFC 9293 §3.8.6.2.1 rule 4).
const SWS_OVERRIDE: Duration = Duration::from_millis(500);
/// Delayed ACK bound (RFC 9293 MUST-40: less than 0.5 s).
const DELAYED_ACK: Duration = Duration::from_millis(200);
/// Out-of-order receipt ranges kept at most; a segment that would add one more is dropped.
const MAX_OOO_RANGES: usize = 64;
/// Maximum segment lifetime: 60 s, below RFC 9293's "arbitrarily 2 minutes" as common stacks
/// do; TIME-WAIT lasts 2·MSL (MUST-13).
const MSL: Duration = Duration::from_secs(60);

/// Per-connection settings (spec §3; R2 is settable per connection, RFC 9293 MUST-21).
/// Build it from `ConnectConfig::default()` and assign the fields to change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectConfig {
    pub mtu: u16,
    /// Octets received in order and not yet read, which bounds the window offered. Memory
    /// can exceed it: MPTCP also holds octets above that point up to the advertised edge
    /// (below 2·`recv_buffer` + 2^scale, `RecvAssembler`), and the in-order buffer (a
    /// `VecDeque`, plain TCP and MPTCP alike) keeps its peak capacity until freed.
    pub recv_buffer: u32,
    /// Octets written and not yet acknowledged (MPTCP: DATA_ACKed). Memory exceeds it: MPTCP
    /// keeps every `write` call as its own allocation plus bookkeeping, and each `write`
    /// costs O(live writes), so many small writes into a large buffer cost memory and CPU
    /// far beyond the octet count (coalescing them is M3); plain TCP's `VecDeque` keeps its
    /// peak capacity until freed.
    pub send_buffer: u32,
    pub r2_data: Duration,
    /// Used as at least 180 s (RFC 9293 MUST-23).
    pub r2_syn: Duration,
    /// The congestion controller of every subflow of the connection.
    pub congestion_control: CongestionControlKind,
    /// Require DSS checksums (A=1). A peer that requires them is honoured either way. Plain
    /// TCP ignores it. The default is `true`.
    pub checksums: bool,
}

/// A congestion controller to run (`ConnectConfig::congestion_control`). MPTCP subflows are
/// uncoupled: each runs its own, so two subflows through one bottleneck take about two flows'
/// share.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CongestionControlKind {
    /// CUBIC (RFC 9438) with HyStart++ and pacing.
    #[default]
    Cubic,
    /// BBRv3 (draft-ietf-ccwg-bbr-06, experimental).
    BbrV3,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            // 16 MiB (scale 9): two-path s2c needs about 7 MB of span plus held data (rate
            // 350 Mbit/s x max path RTT incl. queueing, Task 9b); 4 and 8 MiB bound it.
            recv_buffer: 16 << 20,
            // 16 MiB: the store keeps every octet until DATA_ACK, which follows the slowest
            // path, so it needs about total rate x max path RTT incl. queueing: two-path c2s
            // 44.6 MB/s x 0.145-0.18 s = 6.5-8 MB (Task 9c); 4 MiB bound it, 8 MiB leaves no
            // margin for loss episodes. Octets, not memory: see the field.
            send_buffer: 16 << 20,
            r2_data: Duration::from_secs(100),
            r2_syn: Duration::from_secs(180),
            congestion_control: CongestionControlKind::Cubic,
            checksums: true,
        }
    }
}

/// RFC 9293 connection states. LISTEN belongs to the endpoint's listener, not to a TCB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TcpState {
    Closed,
    SynSent,
    /// A passive open answered the peer's SYN. Simultaneous open (SYN-SENT → SYN-RECEIVED,
    /// RFC 9293 §3.5) would also lead here; it is a later addition.
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    Normal,
    Reset,
    Timeout,
    /// The peer fell back to TCP (infinite mapping) while another subflow held data not yet
    /// acknowledged at connection level: that data can no longer be delivered.
    FallbackDataLoss,
    /// The application aborted the connection (`Connection::abort`).
    Aborted,
}

/// What the caller must report after an input. Every `Closed(_)` is returned exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    None,
    Established,
    Closed(CloseReason),
}

/// Exact new-mapping shapes permitted by the TCP sender at this instant.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SendBudget {
    pub seg_payload: usize,
    pub full_segments: usize,
    pub partial: usize,
}
impl SendBudget {
    /// A mapping consists of full segments, or one permitted partial segment.
    pub fn bytes(self) -> usize {
        if self.seg_payload == 0 {
            return 0;
        }
        let full = self.full_segments * self.seg_payload;
        if full > 0 { full } else { self.partial }
    }
}

/// The segment `poll_send` just wrote into the `SegmentWriter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentMeta {
    pub seq: SeqNum,
    pub len: u32,
    pub flags: TcpFlags,
}

/// TCP header fields and payload of one outgoing segment; the Endpoint adds the addresses and
/// builds the IP packet with `wire::packet::build`.
#[derive(Debug)]
pub struct SegmentWriter {
    pub seq: SeqNum,
    pub ack: SeqNum,
    pub flags: TcpFlags,
    pub wnd: u16,
    pub options: [u8; 40],
    pub options_len: usize,
    /// Reused across segments.
    pub payload: Vec<u8>,
}

impl Default for SegmentWriter {
    fn default() -> Self {
        Self {
            seq: SeqNum(0),
            ack: SeqNum(0),
            flags: TcpFlags::default(),
            wnd: 0,
            options: [0; 40],
            options_len: 0,
            payload: Vec::new(),
        }
    }
}

impl SegmentWriter {
    pub fn options(&self) -> &[u8] {
        &self.options[..self.options_len]
    }

    /// Starts a segment with no options and no payload.
    fn start(&mut self, seq: SeqNum, ack: SeqNum, flags: TcpFlags, wnd: u16) -> SentMeta {
        self.seq = seq;
        self.ack = ack;
        self.flags = flags;
        self.wnd = wnd;
        self.options_len = 0;
        self.payload.clear();
        SentMeta { seq, len: 0, flags }
    }
}

/// One transmitted data segment still outstanding (draft-ietf-ccwg-bbr-06 §4.1.2.1.2,
/// per-packet state).
#[derive(Debug, Clone, Copy)]
struct SentRecord {
    /// One past its last sequence number, FIN included.
    end: SeqNum,
    /// Transmission order, new and resent segments alike: the ACK's sample is taken from
    /// the covered record sent last (§4.1.2.3 IsNewestPacket), not the highest in sequence.
    tx_order: u64,
    /// Sent inside an app-limited interval (P.is_app_limited).
    app_limited: bool,
    sent_at: Instant,
    /// A retransmission: no RTT sample from it (Karn).
    resent: bool,
    /// Wholly inside a SACK block (RFC 2018): delivered when that ACK arrived.
    sacked: bool,
}

/// The loss-recovery lifecycle BBR sees (spec §1.7); CUBIC's recovery state is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LossRecovery {
    None,
    /// From the fast-retransmit entry (SACK or NewReno) to its exit or an RTO.
    Fast,
    /// Until SND.UNA reaches `point`, the absolute offset of SND.MAX at the latest RTO.
    Rto {
        point: u64,
    },
}

#[derive(Debug)]
pub struct Tcb {
    cfg: ConnectConfig,
    v6: bool,
    state: TcpState,
    /// Opened from a listener (RFC 9293 L3580–3592 treats a RST in SYN-RECEIVED by it).
    passive: bool,
    nodelay: bool,

    // Send sequence space (RFC 9293 §3.3.1).
    iss: SeqNum,
    snd_una: SeqNum,
    /// Next sequence number to send; pulled back to SND.UNA by an RTO (go-back).
    snd_nxt: SeqNum,
    /// One past the highest sequence number sent (SND.MAX). ACKs up to it are acceptable and
    /// SND.MAX − SND.UNA is what is outstanding (FlightSize).
    snd_max: SeqNum,
    /// Peer's window in octets, already scaled.
    snd_wnd: u32,
    /// Shift applied to the peer's window fields (RFC 7323 Snd.Wind.Shift).
    snd_shift: u8,
    /// SEG.SEQ / SEG.ACK of the segment that last updated `snd_wnd`.
    snd_wl1: SeqNum,
    snd_wl2: SeqNum,
    /// Max(SND.WND), the sender SWS estimate of the peer's buffer (RFC 9293 §3.8.6.2.1).
    max_snd_wnd: u32,
    /// Effective send MSS (spec §3); final once ESTABLISHED.
    eff_mss: u16,
    /// Relative SSN of our FIN: the end of the data queued at the first `poll_send` after
    /// `close`. Nothing queued later is sent.
    fin_rel: Option<u32>,

    // Receive sequence space.
    rcv_nxt: SeqNum,
    /// Relative SSN of RCV.NXT, not wrapped (IRS + 1 is 1); keys `rcv_ooo`.
    rcv_ssn: u64,
    /// Shift applied to our window fields (RFC 7323 Rcv.Wind.Shift). Holds our offer until the
    /// SYN/ACK; 0 if the peer did not offer.
    rcv_shift: u8,
    /// Largest right window edge ever advertised (never moves left, RFC 9293 SHLD-14).
    rcv_right_edge: SeqNum,
    /// The edge the receiver SWS rule last set; every window is rounded up from it. It never
    /// passes the memory's edge (RCV.NXT + free + held out of order), which only moves right.
    rcv_sws_edge: SeqNum,
    /// Out-of-order receipt ranges (headers only, spec §2 step 4), in unwrapped relative SSN.
    /// Exactly the octets the hooks hold out of order.
    rcv_ooo: RangeSet<u64>,
    /// Peer offered SACK-Permitted in its SYN (ours always does): SACK blocks on our ACKs
    /// and SACK-based loss recovery (RFC 6675) for our data.
    sack_permitted: bool,
    /// Points in the most recently received out-of-order blocks, newest first.
    sack_recent: Vec<u64>,
    /// Duplicate data from the latest input, reported once (RFC 2883).
    dsack: Option<(SeqNum, SeqNum)>,
    /// In-order data segments received since our last ACK.
    rcv_unacked: u8,
    /// The peer's FIN is received (RCV.NXT is past it).
    fin_received: bool,

    cc: Box<dyn CongestionControl>,
    /// Loss recovery without SACK.
    recovery: NewReno,
    /// Loss recovery with SACK (RFC 6675): used instead of `recovery` once both SYNs carried
    /// SACK-Permitted (`sack_permitted`).
    sack: Sack,
    /// Delivery-rate and loss accounting for the CC hooks (spec §1.1).
    rate: RateSampler,
    loss_recovery: LossRecovery,

    // Timers.
    rtt: RttEstimator,
    /// Consecutive data RTO expirations since SND.UNA last advanced.
    rto_streak: u32,
    /// Retransmission timer (SYN, then data at SND.UNA).
    rto_at: Option<Instant>,
    /// End of the last retransmission at SND.UNA and its earliest permitted RTO expiry
    /// (RFC 6298 §5). Cleared once all of that segment, including any FIN, is acknowledged.
    rto_not_before: Option<(SeqNum, Instant)>,
    /// The one timed segment (Karn): its end and send time; cleared by any RTO.
    rtt_timed: Option<(SeqNum, Instant)>,
    /// Every data segment outstanding, in sequence order; a retransmission replaces the
    /// records it covers. Gives the CC one RTT sample per ACK (RFC 9406 §4.3 recommends
    /// N_RTT_SAMPLE per round) and the app-limited flag; the RTO estimator keeps the one
    /// timed segment.
    sent: VecDeque<SentRecord>,
    /// Data segments transmitted so far, new and resent (`SentRecord::tx_order`).
    tx_count: u64,
    /// Cumulative octets acknowledged (draft-ietf-ccwg-bbr-06 §4.1.2.1.1 C.delivered).
    delivered: u64,
    /// The app-limited interval (C.app_limited): data sent while it is set is marked, and the
    /// ACK that makes `delivered` pass it clears it (§4.1.2.3 GenerateRateSample), and so does
    /// an RTO (`on_timeout_data`).
    app_limited_until: Option<u64>,
    /// Why the interval was last (re)started; cleared with it, or once new data goes out.
    app_limited: Option<AppLimited>,
    /// SND.MAX after the latest data transmission that left less than one SMSS of cwnd unused
    /// (the flow was cwnd-limited, RFC 7661 §3); an ACK up to it is `AckSample::cwnd_limited`.
    /// Cleared by an ACK beyond it.
    cwnd_full_at: Option<SeqNum>,
    /// A send since the last rate sample left less than one SMSS of cwnd room (spec §1.8);
    /// each sample takes it.
    cwnd_filled: bool,
    /// Pacing release time: no data segment goes out before it, beyond the burst opened at
    /// the previous release. Reaching it consumes it.
    next_send_at: Option<Instant>,
    /// Octets the burst opened at the last release may still send before `next_send_at`.
    burst_left: u32,
    /// Assigned data or a FIN was unsent at the last `poll_send`.
    unsent: bool,
    /// Unassigned connection data or a queued reinjection at the last `pending_send`.
    conn_pending: bool,
    /// When data octets last went out (RFC 5681 §4.1 idle detection).
    last_data_sent: Option<Instant>,
    /// R2 base for data: first transmission of the segment at SND.UNA, restarted when SND.UNA
    /// advances; or the first unanswered zero-window probe. `None` when nothing is pending.
    r2_since: Option<Instant>,
    /// Persist timer and its current interval (first = RTO, ×2 per probe, cap 60 s).
    persist_at: Option<Instant>,
    probe_demand: bool,
    persist_ivl: Duration,
    /// Sender SWS override timer (RFC 9293 §3.8.6.2.1 rule 4).
    sws_at: Option<Instant>,
    /// Delayed-ACK deadline.
    ack_at: Option<Instant>,
    /// First SYN transmission; R2 for the SYN counts from here.
    first_syn_at: Option<Instant>,
    /// End of TIME-WAIT.
    time_wait_at: Option<Instant>,
    /// `None` in `Closed` only after a `close` in SYN-SENT that `on_timeout` has not reported.
    closed_at: Option<Instant>,

    // Segments due at the next `poll_send`.
    syn_due: bool,
    ack_due: bool,
    /// An ACK only to carry a protocol signal (`request_signal_ack`).
    signal_ack_due: bool,
    /// RST answering an unacceptable ACK, `<SEQ=SEG.ACK><CTL=RST>`, or ending this TCB, with
    /// the protocol options it carries.
    rst_due: Option<(SeqNum, Option<Vec<u8>>)>,
    /// Resend one segment at SND.UNA (RTO, fast retransmit, partial ACK).
    retransmit_due: bool,
    probe_due: bool,
    /// Resend the highest-sequence outstanding segment once (`probe_tail`).
    tail_probe_due: bool,
    /// `send_keepalive_probe`.
    keepalive_due: bool,
    /// SWS override timer expired: send what the window allows.
    sws_override: bool,
}

impl Tcb {
    /// `seed` seeds BBR's PRNG (BBRv3 spec §3.4); CUBIC does not use it. The argument is new
    /// in 0.2.0.
    pub fn new_active(
        cfg: &ConnectConfig,
        local: SocketAddr,
        remote: SocketAddr,
        isn: SeqNum,
        now: Instant,
        seed: u64,
    ) -> Tcb {
        Self::with_cc(cfg, local, remote, isn, now, new_cc(cfg, seed))
    }

    /// SYN-RECEIVED from the peer's `syn` (a passive open): the SYN/ACK is due. `seed` as in
    /// `new_active`.
    pub fn new_passive(
        cfg: &ConnectConfig,
        local: SocketAddr,
        syn: &Segment,
        isn: SeqNum,
        now: Instant,
        seed: u64,
    ) -> Tcb {
        Self::passive_with_cc(cfg, local, syn, isn, now, new_cc(cfg, seed))
    }

    pub(crate) fn passive_with_cc(
        cfg: &ConnectConfig,
        local: SocketAddr,
        syn: &Segment,
        isn: SeqNum,
        now: Instant,
        cc: Box<dyn CongestionControl>,
    ) -> Tcb {
        let mut tcb = Self::with_cc(cfg, local, syn.src, isn, now, cc);
        tcb.state = TcpState::SynReceived;
        tcb.passive = true;
        tcb.take_peer_syn(syn);
        tcb
    }

    pub(crate) fn with_cc(
        cfg: &ConnectConfig,
        _local: SocketAddr,
        remote: SocketAddr,
        isn: SeqNum,
        now: Instant,
        cc: Box<dyn CongestionControl>,
    ) -> Tcb {
        let mut tcb = Tcb {
            cfg: cfg.clone(),
            v6: remote.is_ipv6(),
            state: TcpState::SynSent,
            passive: false,
            nodelay: false,
            iss: isn,
            snd_una: isn,
            // Becomes ISS + 1 when the SYN is sent; until then no ACK is acceptable.
            snd_nxt: isn,
            snd_max: isn,
            snd_wnd: 0,
            snd_shift: 0,
            snd_wl1: SeqNum(0),
            snd_wl2: SeqNum(0),
            max_snd_wnd: 0,
            eff_mss: 0,
            fin_rel: None,
            rcv_nxt: SeqNum(0),
            rcv_ssn: 0,
            rcv_shift: ws_shift(cfg.recv_buffer),
            rcv_right_edge: SeqNum(0),
            rcv_sws_edge: SeqNum(0),
            rcv_ooo: RangeSet::new(),
            sack_permitted: false,
            sack_recent: Vec::new(),
            dsack: None,
            rcv_unacked: 0,
            fin_received: false,
            cc,
            recovery: NewReno::new(isn),
            sack: Sack::default(),
            // Replaced at ESTABLISHED, once SACK is negotiated.
            rate: RateSampler::new(now, false),
            loss_recovery: LossRecovery::None,
            rtt: RttEstimator::new(),
            rto_streak: 0,
            rto_at: None,
            rto_not_before: None,
            rtt_timed: None,
            sent: VecDeque::new(),
            tx_count: 0,
            delivered: 0,
            app_limited_until: None,
            app_limited: None,
            cwnd_full_at: None,
            cwnd_filled: false,
            next_send_at: None,
            burst_left: 0,
            unsent: false,
            conn_pending: false,
            last_data_sent: None,
            r2_since: None,
            persist_at: None,
            probe_demand: false,
            persist_ivl: Duration::ZERO,
            sws_at: None,
            ack_at: None,
            first_syn_at: None,
            time_wait_at: None,
            closed_at: None,
            syn_due: true,
            ack_due: false,
            signal_ack_due: false,
            rst_due: None,
            retransmit_due: false,
            probe_due: false,
            tail_probe_due: false,
            keepalive_due: false,
            sws_override: false,
        };
        tcb.eff_mss = tcb.eff_mss_for(None);
        tcb
    }

    /// ESTABLISHED as if our SYN had been answered by a SYN/ACK carrying `peer_mss` and
    /// `peer_ws` (window 65535) at `now`; the handshake ACK is due. `cc::Reno`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_established(
        cfg: &ConnectConfig,
        local: SocketAddr,
        remote: SocketAddr,
        isn: SeqNum,
        peer_isn: SeqNum,
        peer_mss: Option<u16>,
        peer_ws: Option<u8>,
        now: Instant,
    ) -> Tcb {
        let reno = Box::new(super::cc::Reno::new());
        let mut tcb = Self::with_cc(cfg, local, remote, isn, now, reno);
        tcb.syn_due = false;
        tcb.snd_nxt = isn.wrapping_add(1);
        tcb.snd_max = tcb.snd_nxt;
        let mut opts = [0u8; 8];
        let mut n = 0;
        if let Some(m) = peer_mss {
            n += tcp_options::write_mss(&mut opts[n..], m);
        }
        if let Some(s) = peer_ws {
            n += tcp_options::write_ws(&mut opts[n..], s);
        }
        let synack = Segment {
            src: remote,
            dst: local,
            seq: peer_isn,
            ack: tcb.snd_nxt,
            flags: TcpFlags::SYN | TcpFlags::ACK,
            wnd: 65535,
            options: &opts[..n],
            payload: &[],
        };
        let h = &mut super::PlainHooks::new(cfg);
        assert_eq!(
            tcb.on_segment_syn_sent(&synack, now, h),
            Reaction::Established
        );
        tcb
    }

    pub fn state(&self) -> TcpState {
        self.state
    }

    /// Opened passively, from a listener (spec G11).
    pub(crate) fn passive(&self) -> bool {
        self.passive
    }

    /// RFC 9293 §3.10.4 CLOSE; idempotent. ESTABLISHED → FIN-WAIT-1 and CLOSE-WAIT →
    /// LAST-ACK at once; the FIN follows the data queued at the next `poll_send`, and nothing
    /// queued after that is sent (the Connection rejects writes after `close` before they
    /// reach the hooks).
    ///
    /// SYN-SENT: the TCB is deleted. `state()` is `Closed` at once and nothing more is sent or
    /// accepted; `poll_send_at` reports a deadline that is already due, and the next
    /// `on_timeout` returns `Closed(Normal)`, once, and sets `closed_at`.
    ///
    /// SYN-RECEIVED is left unchanged on purpose: FIN-WAIT-1 (RFC 9293 L3143–3148) would skip
    /// an MP_JOIN responder's HMAC check of the third ACK.
    pub fn close(&mut self) {
        self.state = match self.state {
            TcpState::SynSent => TcpState::Closed,
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            s => s,
        };
    }

    pub(crate) fn mtu(&self) -> usize {
        usize::from(self.cfg.mtu)
    }

    /// The peer's FIN has been received. Every data octet before it was handed to the hooks
    /// first, so once they hold no more data the application's read is at EOF.
    pub fn fin_received(&self) -> bool {
        self.fin_received
    }

    /// Switches Nagle off (`true`) or on (`false`, the default).
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    pub fn on_segment(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> Reaction {
        match self.state {
            TcpState::Closed => Reaction::None,
            TcpState::SynSent => {
                let r = self.on_segment_syn_sent(seg, now, h);
                if r == Reaction::Established {
                    h.on_valid_segment(seg);
                    // §3.10.7.3: text and FIN on the SYN/ACK are processed once ESTABLISHED,
                    // from the sequence number after the SYN. The FIN's CLOSE-WAIT move
                    // emits no `Closed`, so the reaction stays `Established`.
                    let text = Segment {
                        seq: seg.seq.wrapping_add(1),
                        ..seg.clone()
                    };
                    self.on_text_and_fin(&text, now, h);
                }
                r
            }
            TcpState::SynReceived => {
                let r = self.on_segment_syn_received(seg, now, h);
                if r == Reaction::Established {
                    h.on_valid_segment(seg);
                    // Text and FIN on the final ACK, from RCV.NXT, once ESTABLISHED. A reset
                    // the hooks request there (a join's bad HMAC) ends it before it is reported.
                    let closed = self.on_text_and_fin(seg, now, h);
                    if matches!(closed, Reaction::Closed(_)) {
                        return closed;
                    }
                }
                r
            }
            _ => self.on_segment_sync(seg, now, h),
        }
    }

    /// Processes every timer expiry due at `now` (spec §3.1).
    pub fn on_timeout(&mut self, now: Instant, h: &mut impl Hooks) -> Reaction {
        match self.state {
            TcpState::SynSent | TcpState::SynReceived => self.on_timeout_syn_sent(now),
            // A `close` in SYN-SENT, reported once.
            TcpState::Closed if self.closed_at.is_none() => {
                self.closed_at = Some(now);
                Reaction::Closed(CloseReason::Normal)
            }
            TcpState::Closed => Reaction::None,
            TcpState::TimeWait => {
                if self.time_wait_at.is_some_and(|t| now >= t) {
                    // `Closed(Normal)` was returned on entering TIME-WAIT.
                    self.terminate(CloseReason::Normal, now);
                }
                Reaction::None
            }
            _ => self.on_timeout_data(now, h),
        }
    }

    /// Additional assigned octets sendable now for a concrete candidate. `bytes` is all
    /// pending data (after connection credit); `contiguous` bounds this mapping (16-bit
    /// length, a reinjection's uncovered run). Keeping both prevents a mapping boundary from
    /// bypassing sender SWS.
    /// Reinjections bypass Nagle/SWS but still respect cwnd and the subflow window.
    /// Calls do not mutate CC, sequence numbers, options or timers.
    pub fn send_budget(
        &self,
        now: Instant,
        bytes: usize,
        contiguous: usize,
        reinject: bool,
        option_len: usize,
        h: &impl Hooks,
    ) -> SendBudget {
        // Pacing is part of the budget: nothing before the release time.
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait)
            || self.retransmit_due
            || self.snd_nxt != self.snd_max
            || (self.burst_left == 0 && self.next_send_at.is_some_and(|t| t > now))
        {
            return SendBudget::default();
        }
        let mss = self.seg_payload(option_len);
        if mss == 0 {
            return SendBudget::default();
        }
        let cwnd = self.send_cwnd(now);
        let assigned =
            self.data_len(self.snd_nxt, self.iss.wrapping_add(h.assigned_end())) as usize;
        let usable = self.window_room(cwnd, self.snd_una.distance(self.snd_nxt) as u32) as usize;
        let room = usable.saturating_sub(assigned);
        let len = bytes.min(room).min(contiguous);
        let partial = len.min(mss - 1);
        let nagle_ok = (self.in_flight() == 0 && assigned == 0) || self.nodelay;
        let override_due = self.sws_override || self.sws_at.is_some_and(|t| now >= t);
        let partial = if reinject
            || override_due
            || (nagle_ok && (bytes <= room || partial >= self.max_snd_wnd as usize / 2))
        {
            partial
        } else {
            0
        };
        // ponytail: one quantum per release (Linux tcp_tso_autosize), or the CC's own.
        let full_segments = match self.cc.pacing_rate() {
            Some(rate) => {
                let allowance = if self.next_send_at.is_some_and(|t| t > now) {
                    self.burst_left as usize
                } else {
                    self.burst(rate, mss)
                };
                len.min(allowance) / mss
            }
            None => len / mss,
        };
        SendBudget {
            seg_payload: mss,
            full_segments,
            partial,
        }
    }

    /// Payload of one segment that carries `option_len` octets of protocol options (and the
    /// SACK blocks due with them).
    fn seg_payload(&self, option_len: usize) -> usize {
        usize::from(self.eff_mss).saturating_sub(option_len + self.sack_len(option_len))
    }

    /// cwnd for a send at `now`: the restart window after an idle period (RFC 5681 §4.1).
    fn send_cwnd(&self, now: Instant) -> u32 {
        if self.in_flight() == 0
            && self
                .last_data_sent
                .is_some_and(|t| now > t + self.rtt.rto())
        {
            self.cc.restart_cwnd()
        } else {
            self.cc.cwnd()
        }
    }

    /// Octets new data may add beyond the `sent` octets above SND.UNA: min(cwnd, SND.WND)
    /// less what is outstanding (RFC 5681 §2); in SACK loss recovery, the peer's window and
    /// cwnd − pipe once that is at least one SMSS (RFC 6675 §5 (C)).
    fn window_room(&self, cwnd: u32, sent: u32) -> u32 {
        if !self.sack.in_recovery() {
            return self.snd_wnd.min(cwnd).saturating_sub(sent);
        }
        let room = cwnd.saturating_sub(self.pipe_to(self.snd_max));
        let room = if room < u32::from(self.eff_mss) {
            0
        } else {
            room
        };
        self.snd_wnd.saturating_sub(sent).min(room)
    }

    /// cwnd less the send gate's admission measure (spec §1.8): pipe in SACK loss recovery,
    /// else `sent_below_nxt` (FlightSize outside a go-back). Taken before the peer's window,
    /// pacing and the multipath layer limit the send.
    pub(crate) fn cwnd_room(&self) -> u32 {
        let measure = if self.sack.in_recovery() {
            self.pipe_to(self.snd_max)
        } else {
            self.sent_below_nxt()
        };
        self.cc.cwnd().saturating_sub(measure)
    }

    /// SND.NXT − SND.UNA; after a go-back, less what the receiver has SACKed below SND.NXT,
    /// which has left the network.
    fn sent_below_nxt(&self) -> u32 {
        let sent = self.snd_una.distance(self.snd_nxt) as u32;
        if self.snd_nxt.lt(self.snd_max) && self.sack_permitted {
            let nxt = self.abs(self.snd_nxt);
            return sent - self.sack.sacked_in(self.delivered, nxt) as u32;
        }
        sent
    }

    /// CheckIfApplicationLimited (spec §1.6), independent of the legacy marker: nothing
    /// assigned is unsent, no application data waits beyond it (or this sender was just
    /// `offered_no_data`), and at least one SMSS of cwnd room.
    pub(crate) fn check_app_limited(&mut self, h: &impl Hooks, offered_no_data: bool) {
        // A due resend is a loss not yet resent (draft: lost_out > retrans_out); NewReno
        // declares it lost only at the send (spec §1.4).
        let unsent = self.data_len(self.snd_nxt, self.iss.wrapping_add(h.assigned_end())) > 0
            || (self.fin_rel.is_some() && !self.fin_sent())
            || self.retransmit_due;
        let no_unsent = !unsent && (offered_no_data || !h.more_app_data());
        let room = self.cwnd_room() >= u32::from(self.eff_mss);
        self.rate.check_app_limited(no_unsent, room);
    }

    /// The CC's MarkConnectionAppLimited request, taken after `on_rate_sample` and
    /// `on_transmit` (spec §2).
    fn app_limited_request(&mut self) {
        if self.cc.take_app_limited_request() {
            self.rate.force_app_limited();
        }
    }

    /// Octets one pacing release may send: the CC's send quantum, else `pacing_quantum`
    /// (spec §3.3).
    fn burst(&self, rate: u64, seg: usize) -> usize {
        self.cc
            .send_quantum()
            .map_or_else(|| pacing_quantum(rate, seg), |q| q as usize)
    }

    /// pipe (RFC 6675 SetPipe) with SND.MAX at `max`.
    fn pipe_to(&self, max: SeqNum) -> u32 {
        self.sack.pipe(self.delivered, self.abs(max)) as u32
    }

    /// The scoreboard's absolute offset of `seq` (ISS + 1 is 0): `delivered` is that of
    /// SND.UNA.
    fn abs(&self, seq: SeqNum) -> u64 {
        self.delivered
            .wrapping_add_signed(i64::from(self.snd_una.distance(seq)))
    }

    fn seq_at(&self, abs: u64) -> SeqNum {
        self.snd_una
            .wrapping_add(abs.wrapping_sub(self.delivered) as u32)
    }

    /// NextSeg() (RFC 6675 §4) in SACK loss recovery while cwnd − pipe ≥ SMSS (§5 (C)): the
    /// range [start, end) to retransmit and whether it is the rescue (rule 4), unless rule (2)
    /// (new data, which the normal send path takes) or nothing applies.
    fn next_rxt(&self, h: &impl Hooks) -> Option<(SeqNum, SeqNum, bool)> {
        if !self.sack.in_recovery() {
            return None;
        }
        let max = self.abs(self.snd_max);
        let pipe = self.sack.pipe(self.delivered, max);
        if u64::from(self.cc.cwnd()) < pipe + u64::from(self.eff_mss) {
            return None;
        }
        let queued = self.data_len(self.snd_nxt, self.iss.wrapping_add(h.assigned_end()));
        let fin_pending = self.fin_rel.is_some() && !self.fin_sent();
        let window = self.snd_wnd > self.snd_una.distance(self.snd_nxt) as u32;
        let new_data = (queued > 0 || fin_pending || self.conn_pending) && window;
        let r = self
            .sack
            .next_seg(self.delivered, max, u32::from(self.eff_mss), new_data)?;
        Some((self.seq_at(r.start), self.seq_at(r.end), r.rescue))
    }

    /// Update() (RFC 6675 §4) with the ACK's SACK blocks clipped to (SEG.ACK, SND.MAX] (a
    /// D-SACK block below SEG.ACK, RFC 2883, is nothing new); marks the records wholly inside
    /// newly SACKed ranges. Returns the newly SACKed octets and, of the records they
    /// delivered, the one sent last. Runs before SND.UNA advances to SEG.ACK.
    fn sack_update(&mut self, seg: &Segment, now: Instant) -> (u64, Option<SentRecord>) {
        let (una, max, base) = (self.snd_una, self.snd_max, self.delivered);
        let floor = seg.ack;
        let abs = |s: SeqNum| base.wrapping_add_signed(i64::from(una.distance(s)));
        let blocks = tcp_options::walk(seg.options)
            .map_while(Result::ok)
            .filter_map(|o| match o {
                TcpOpt::Sack(raw) => Some(raw),
                _ => None,
            })
            .flat_map(|raw| raw.chunks_exact(8))
            .filter_map(|b| {
                let l = SeqNum(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                let r = SeqNum(u32::from_be_bytes([b[4], b[5], b[6], b[7]]));
                let l = if l.lt(floor) { floor } else { l };
                (r.gt(floor) && r.le(max) && l.lt(r)).then(|| abs(l)..abs(r))
            });
        let (sent, rate) = (&mut self.sent, &mut self.rate);
        let mut newest: Option<SentRecord> = None;
        let new = self
            .sack
            .update(base, u32::from(self.eff_mss), blocks, |g| {
                rate.on_delivered(g.clone(), now);
                let at = |a: u64| una.wrapping_add((a - base) as u32);
                let (s0, s1) = (at(g.start), at(g.end));
                let mut i = sent.partition_point(|r| r.end.le(s0));
                while let Some(r) = sent.get(i).copied().filter(|r| r.end.le(s1)) {
                    let start = if i == 0 { una } else { sent[i - 1].end };
                    if !start.lt(s0) && !r.sacked {
                        sent[i].sacked = true;
                        if newest.is_none_or(|n| r.tx_order > n.tx_order) {
                            newest = Some(r);
                        }
                    }
                    i += 1;
                }
            });
        (new, newest)
    }

    /// Arm sender SWS for data awaiting assignment; budget queries remain read-only.
    /// `bytes` (unassigned data) or `reinject` (a queued reinjection) is demand that the
    /// pacing release time must wake for.
    pub fn pending_send(
        &mut self,
        now: Instant,
        bytes: usize,
        contiguous: usize,
        option_len: usize,
        reinject: bool,
        h: &impl Hooks,
    ) {
        self.conn_pending = bytes > 0 || reinject;
        if bytes > 0 && self.in_flight() == 0 && self.snd_wnd > 0 && !self.probe_demand {
            let budget = self.send_budget(now, bytes, contiguous, false, option_len, h);
            if budget.seg_payload > 0 && budget.bytes() == 0 {
                self.sws_at.get_or_insert(now + SWS_OVERRIDE);
            }
        }
    }

    /// Connection-level zero-window demand shares TCP's existing persist timer.
    pub fn set_probe_demand(&mut self, demand: bool) {
        self.probe_demand = demand;
    }
    pub(crate) fn ack_pending(&self) -> bool {
        self.ack_due
    }
    pub(crate) fn reset_pending(&self) -> bool {
        self.rst_due.is_some()
    }
    /// RFC 9293 §3.10.5 ABORT: a RST `<SEQ=SND.MAX>` carrying `rst_option` is due and the TCB
    /// is Closed.
    pub(crate) fn abort_with(
        &mut self,
        reason: CloseReason,
        rst_option: Option<Vec<u8>>,
        now: Instant,
    ) -> Reaction {
        self.rst_due = Some((self.snd_max, rst_option));
        self.terminate(reason, now)
    }
    /// RFC 9293 §3.10.5 ABORT whose RST, if any, the caller sends: the TCB is Closed with
    /// `Aborted`. Returns SND.MAX, that RST's sequence number.
    pub(crate) fn delete(&mut self, now: Instant) -> SeqNum {
        self.terminate(CloseReason::Aborted, now);
        self.snd_max
    }
    pub(crate) fn request_ack(&mut self) {
        self.ack_due = true;
    }
    /// Makes one keepalive probe due: the zero-window probe's shape, zero-length at
    /// SND.UNA − 1 with no options, which the peer answers with an ACK. It goes out at the next `poll_send`
    /// while synchronized and not in TIME-WAIT, before anything but a RST.
    pub(crate) fn send_keepalive_probe(&mut self) {
        self.keepalive_due = true;
    }
    /// A keepalive probe is due and has not gone out.
    pub(crate) fn keepalive_pending(&self) -> bool {
        self.keepalive_due
    }
    /// An ACK-only segment is due only to carry a protocol signal (`AckPurpose::SignalOnly`
    /// unless an ACK is due anyway). It goes out only if the hooks add a signal to it.
    pub(crate) fn request_signal_ack(&mut self) {
        self.signal_ack_due = true;
    }
    pub(crate) fn retransmission_timeout(&self) -> Duration {
        self.rtt.rto()
    }
    /// RTO from SRTT and RTTVAR alone (RFC 6298 §2), ignoring any backoff; `None` before the
    /// first RTT sample.
    pub(crate) fn base_rto(&self) -> Option<Duration> {
        self.rtt.base_rto()
    }
    /// Smoothed RTT; `None` before the first sample.
    pub(crate) fn srtt(&self) -> Option<Duration> {
        self.rtt.srtt()
    }
    /// Consecutive RTO expirations since SND.UNA last advanced (0 after an advance).
    pub(crate) fn rto_streak(&self) -> u32 {
        self.rto_streak
    }
    /// The tail loss probe time for the data up to relative SSN `end` (M3 spec §2.3, after
    /// RFC 8985 §7.2): once all of it is sent, nothing else waits to be sent, it is not all
    /// acknowledged and no loss recovery or RTO runs, the last data transmission plus
    /// PTO = 2·SRTT (the initial RTO before a sample), at most the RTO.
    pub(crate) fn tail_probe_at(&self, end: u32) -> Option<Instant> {
        let end = self.iss.wrapping_add(end);
        let pto = self
            .rtt
            .srtt()
            .map_or(INITIAL_RTO, |s| s * 2)
            .min(self.rtt.rto());
        (end.le(self.snd_max)
            && self.snd_una.lt(end)
            && self.snd_nxt == self.snd_max
            && !self.unsent
            && !self.retransmit_due
            && self.rto_streak == 0
            && !self.sack.in_recovery()
            && !self.recovery.in_recovery())
        .then_some(self.last_data_sent? + pto)
    }
    /// SND.UNA has reached relative SSN `end`.
    pub(crate) fn acked_to(&self, end: u32) -> bool {
        self.iss.wrapping_add(end).le(self.snd_una)
    }
    /// The later of the last SND.UNA advance and the start of the current flight (the R2 base);
    /// `None` with nothing outstanding.
    pub(crate) fn silence_since(&self) -> Option<Instant> {
        self.r2_since
    }
    /// Makes one tail loss probe due (RFC 8985 §7.3, no new data to send): the
    /// highest-sequence outstanding segment again, regardless of cwnd, without changing cwnd,
    /// ssthresh or recovery state. Dropped if a retransmission or recovery starts first.
    pub(crate) fn probe_tail(&mut self) {
        self.tail_probe_due = true;
    }
    /// Start of the tail probe's segment, while one is due and still applies.
    fn tail_probe_seq(&self) -> Option<SeqNum> {
        if !self.tail_probe_due
            || self.retransmit_due
            || self.snd_nxt != self.snd_max
            || self.sack.in_recovery()
            || self.recovery.in_recovery()
        {
            return None;
        }
        let start = (self.sent.len().checked_sub(2)).map_or(self.snd_una, |i| self.sent[i].end);
        let start = if start.lt(self.snd_una) {
            self.snd_una
        } else {
            start
        };
        (self.data_len(start, self.snd_max) > 0).then_some(start)
    }
    /// A multipath penalty (M3 spec §2.5): `CongestionEvent::Penalized` with FlightSize, unless
    /// loss recovery or an RTO backoff (an RTO since SND.UNA last advanced) already decreased
    /// cwnd. Returns whether it applied.
    pub(crate) fn penalize(&mut self, now: Instant) -> bool {
        if self.rto_streak > 0 || self.sack.in_recovery() || self.recovery.in_recovery() {
            return false;
        }
        self.cc
            .on_congestion(CongestionEvent::Penalized, self.in_flight(), now);
        true
    }
    #[cfg(test)]
    pub(crate) fn set_r2_data(&mut self, r2: Duration) {
        self.cfg.r2_data = r2;
    }
    #[cfg(test)]
    pub(crate) fn cwnd(&self) -> u32 {
        self.cc.cwnd()
    }
    #[cfg(test)]
    pub(crate) fn cc(&self) -> &dyn CongestionControl {
        &*self.cc
    }
    #[cfg(test)]
    pub(crate) fn sampler(&self) -> &RateSampler {
        &self.rate
    }
    /// This sender had a sending opportunity and nothing to send (draft-ietf-ccwg-bbr-06
    /// §4.1.2.4 MarkConnectionAppLimited): data sent until `delivered` passes the data now in
    /// flight is marked app-limited. Refreshed on every call that qualifies. A no-op unless
    /// ESTABLISHED or CLOSE-WAIT, nothing assigned is unsent, nothing is due for resending
    /// and min(cwnd, SND.WND) − in-flight holds a full segment. A pending pacing release does
    /// not prevent it: it leaves the sender with nothing to send all the same. The sampler's own
    /// check (spec §1.6) runs first, whatever this guard decides.
    pub(crate) fn mark_unused_opportunity(
        &mut self,
        now: Instant,
        reason: AppLimited,
        h: &impl Hooks,
    ) {
        self.check_app_limited(h, reason == AppLimited::NotScheduled);
        let seg = self.seg_payload(h.data_option_len());
        let room = self.window_room(self.send_cwnd(now), self.in_flight());
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait)
            || self.retransmit_due
            || self.snd_nxt != self.snd_max
            || self.data_len(self.snd_nxt, self.iss.wrapping_add(h.assigned_end())) > 0
            || seg == 0
            || (room as usize) < seg
        {
            return;
        }
        let mark = self.delivered + u64::from(self.in_flight());
        self.app_limited_until = Some(self.app_limited_until.map_or(mark, |m| m.max(mark)));
        self.app_limited = Some(reason);
    }
    /// Why the current app-limited interval started, if one is open.
    pub(crate) fn app_limited(&self) -> Option<AppLimited> {
        self.app_limited
    }
    pub fn peer_window_closed(&self) -> bool {
        self.snd_wnd == 0
    }
    /// Sequence space sent and not yet acknowledged (SND.MAX > SND.UNA).
    pub(crate) fn has_unacked(&self) -> bool {
        self.in_flight() > 0
    }
    /// Data octets (not the FIN) between SND.UNA and SND.MAX.
    pub(crate) fn unacked_data(&self) -> bool {
        self.data_len(self.snd_una, self.snd_max) > 0
    }
    /// Effective send MSS (RFC 9293 MUST-14/15/16), before protocol options.
    pub(crate) fn eff_mss(&self) -> u16 {
        self.eff_mss
    }

    fn sack_len(&self, protocol: usize) -> usize {
        if protocol >= 40 {
            return 0;
        }
        let mut options = [0; 40];
        let end = usize::from(self.eff_mss.saturating_sub(1))
            .min(40)
            .max(protocol);
        self.write_sacks(&mut options[protocol..end])
    }

    pub fn poll_send(
        &mut self,
        now: Instant,
        h: &mut impl Hooks,
        out: &mut SegmentWriter,
    ) -> Option<SentMeta> {
        if let Some((seq, option)) = self.rst_due.take() {
            let meta = out.start(seq, SeqNum(0), TcpFlags::RST, 0);
            if let Some(o) = option {
                debug_assert!(o.len() % 4 == 0 && o.len() <= 16);
                out.options[..o.len()].copy_from_slice(&o);
                out.options_len = o.len();
            }
            return Some(meta);
        }
        if self.state == TcpState::Closed {
            return None;
        }
        if self.syn_due {
            self.syn_due = false;
            self.first_syn_at.get_or_insert(now);
            self.rto_at = Some(now + self.rtt.rto());
            self.snd_nxt = self.iss.wrapping_add(1);
            self.snd_max = self.snd_nxt;
            // RFC 7323 §2.2: the window field of a SYN is never scaled.
            let wnd = self.cfg.recv_buffer.min(65535) as u16;
            let passive = self.passive();
            let (flags, ack) = if passive {
                (TcpFlags::SYN | TcpFlags::ACK, self.rcv_nxt)
            } else {
                (TcpFlags::SYN, SeqNum(0))
            };
            let meta = out.start(self.iss, ack, flags, wnd);
            let mut n = h.options_for(flags, &mut out.options);
            n += tcp_options::write_mss(&mut out.options[n..], self.mss_option());
            // A SYN/ACK carries WS only if the SYN did (RFC 7323 §2.2), which left a shift
            // here; with both shifts 0, leaving it out changes nothing.
            if !passive || self.rcv_shift > 0 || self.snd_shift > 0 {
                n += tcp_options::write_ws(&mut out.options[n..], self.rcv_shift);
            }
            if !passive || self.sack_permitted {
                n += tcp_options::write_sack_permitted(&mut out.options[n..]);
            }
            out.options_len = n;
            return Some(meta);
        }
        if !matches!(
            self.state,
            TcpState::SynSent | TcpState::SynReceived | TcpState::TimeWait
        ) {
            if std::mem::take(&mut self.keepalive_due) {
                // The peer drops it unprocessed (below its window) and answers with an ACK, so
                // it carries no options and answers nothing: a due ACK stays due.
                let wnd = self.wnd_field(h);
                let seq = self.snd_una.wrapping_add(u32::MAX);
                return Some(out.start(seq, self.rcv_nxt, TcpFlags::ACK, wnd));
            }
            let fin_unsent = matches!(
                self.state,
                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
            );
            if fin_unsent && self.fin_rel.is_none() {
                self.fin_rel = Some(h.assigned_end());
            }
            // RFC 6675 §5.1 "filling in" after an RTO: the go-back skips what the receiver has
            // SACKed since, which has left the network. Before the options are chosen for the
            // segment's SSN.
            if self.sack_permitted && self.snd_nxt.lt(self.snd_max) {
                let skip = self.sack.skip(self.abs(self.snd_nxt));
                self.snd_nxt = self.seq_at(skip.min(self.abs(self.snd_max)));
            }
            let mut options = [0u8; 40];
            let rxt = if self.retransmit_due {
                None
            } else {
                self.next_rxt(h)
            };
            let seq = if self.retransmit_due {
                self.snd_una
            } else {
                (self.tail_probe_seq()).unwrap_or_else(|| rxt.map_or(self.snd_nxt, |r| r.0))
            };
            let ssn = self.rel(seq);
            let has_data =
                h.segment_limit(ssn) > 0 && h.peek_with(ssn, 1, |b| !b.is_empty()).unwrap_or(false);
            let n = if has_data {
                h.data_options_for(ssn, &mut options)
            } else {
                h.options_for(TcpFlags::ACK, &mut options)
            };
            let reserved = if has_data {
                n.max(h.data_option_len())
            } else {
                n
            };
            let sack_len = self.sack_len(reserved);
            self.write_sacks(&mut options[n..n + sack_len]);
            if let Some(meta) = self.poll_data(now, h, out, (reserved + sack_len) as u16, rxt) {
                // A persist probe is payload-free even when assigned data exists.
                let n = if meta.len == 0 {
                    let n = h.options_for(TcpFlags::ACK, &mut options);
                    n + self.write_sacks(&mut options[n..40])
                } else {
                    n + sack_len
                };
                out.options[..n].copy_from_slice(&options[..n]);
                out.options_len = n;
                self.ack_sent();
                return Some(meta);
            }
            // No data segment now: the burst opened at the last release is over.
            self.burst_left = 0;
            // A read that let the window edge move is announced (RFC 9293 §3.8.6.2.2), while
            // data can still arrive.
            if !self.ack_due && !self.fin_received && self.window_update_due(h) {
                self.ack_due = true;
            }
        }
        if self.ack_due || self.signal_ack_due {
            let purpose = if self.ack_due {
                AckPurpose::Ordinary
            } else {
                AckPurpose::SignalOnly
            };
            self.signal_ack_due = false;
            // Protocol options, then signals, then SACK blocks in what is left (M3 spec §3.2).
            let limit = usize::from(self.mss_option()).min(out.options.len());
            let n = h.options_for(TcpFlags::ACK, &mut out.options);
            let room = limit.saturating_sub(n);
            let k = h.ack_signals(purpose, room, &mut out.options[n..limit.max(n)]);
            if purpose == AckPurpose::SignalOnly && k == 0 {
                return None;
            }
            let n = n + k;
            let wnd = self.wnd_field(h);
            // SND.MAX, not a pulled-back SND.NXT: a SEQ below the peer's RCV.NXT would make
            // the ACK unacceptable to it (RFC 9293 Table 6).
            let meta = out.start(self.snd_max, self.rcv_nxt, TcpFlags::ACK, wnd);
            out.options_len = n + self.write_sacks(&mut out.options[n..limit.max(n)]);
            h.ack_emitted();
            self.ack_sent();
            return Some(meta);
        }
        None
    }

    /// The next timer deadline; `closed_at` once `Closed`. Segments made due by an input are
    /// not reported here: the driver calls `poll_send` after every input.
    pub fn poll_send_at(&self) -> Option<Instant> {
        match self.state {
            // Due at once after a `close` in SYN-SENT.
            TcpState::Closed => Some(self.closed_at.unwrap_or(Instant::from_nanos(0))),
            TcpState::SynSent | TcpState::SynReceived => {
                let r2 = self.first_syn_at.map(|t| t + self.r2_syn());
                [self.rto_at, r2].into_iter().flatten().min()
            }
            TcpState::TimeWait => self.time_wait_at,
            _ => {
                let r2 = self.r2_since.map(|t| t + self.cfg.r2_data);
                // The pacing release, while something waits for it.
                let release = self
                    .next_send_at
                    .filter(|_| self.unsent || self.retransmit_due || self.conn_pending);
                [
                    self.rto_deadline(),
                    r2,
                    self.persist_at,
                    self.sws_at,
                    self.ack_at,
                    release,
                ]
                .into_iter()
                .flatten()
                .min()
            }
        }
    }

    /// The pacing release, if one is set: data and FINs held back for it may go once it
    /// passes, also those `poll_send_at` leaves it out for (a go-back's lone FIN).
    pub(crate) fn release_at(&self) -> Option<Instant> {
        // Closed and TIME-WAIT TCBs never consume a pacing release.
        if matches!(self.state, TcpState::Closed | TcpState::TimeWait) {
            return None;
        }
        self.next_send_at
    }

    /// Preserve NewReno's nominal timer (only the first partial ACK restarts it), while
    /// preventing a timer-based retry less than one RTO after the last retransmission.
    fn rto_deadline(&self) -> Option<Instant> {
        self.rto_at.map(|at| {
            self.rto_not_before
                .map_or(at, |(_, earliest)| at.max(earliest))
        })
    }

    /// RFC 9293 §3.10.7.3. A segment without ACK is dropped: a RST without ACK by the RFC's
    /// rule, a bare SYN because simultaneous open (to SYN-RECEIVED) is a later addition.
    fn on_segment_syn_sent(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> Reaction {
        let rst = seg.flags.contains(TcpFlags::RST);
        if !seg.flags.contains(TcpFlags::ACK) {
            return Reaction::None;
        }
        // Acceptable iff SND.UNA (= ISS here) < SEG.ACK =< SND.NXT.
        if seg.ack.le(self.iss) || seg.ack.gt(self.snd_nxt) {
            if !rst {
                self.rst_due = Some((seg.ack, None));
            }
            return Reaction::None;
        }
        if rst {
            h.on_reset(seg);
            return self.terminate(CloseReason::Reset, now);
        }
        if !seg.flags.contains(TcpFlags::SYN) {
            return Reaction::None;
        }
        self.take_peer_syn(seg);
        self.snd_una = seg.ack;
        self.snd_wnd = u32::from(seg.wnd);
        self.max_snd_wnd = self.snd_wnd;
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        self.recovery.last_wnd = self.snd_wnd;
        self.establish(now);
        self.ack_due = true;
        Reaction::Established
    }

    /// The peer's SYN, either role: its MSS, WS and SACK-Permitted, RCV.NXT and the first
    /// receive edges.
    fn take_peer_syn(&mut self, seg: &Segment) {
        let (mut mss, mut ws) = (None, None);
        for opt in tcp_options::walk(seg.options).map_while(Result::ok) {
            match opt {
                TcpOpt::Mss(m) => mss = Some(m),
                TcpOpt::WindowScale(s) => ws = Some(s),
                TcpOpt::SackPermitted => self.sack_permitted = true,
                _ => {}
            }
        }
        self.eff_mss = self.eff_mss_for(mss);
        // RFC 7323 §2.3: scaling only if both SYNs carry WS; a shift above 14 is used as 14.
        match ws {
            Some(s) => self.snd_shift = s.min(MAX_WS_SHIFT),
            None => self.rcv_shift = 0,
        }
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.rcv_ssn = 1;
        // The window field of our SYN or SYN/ACK (unscaled) is the first edge advertised.
        self.rcv_right_edge = self.rcv_nxt.wrapping_add(self.cfg.recv_buffer.min(65535));
        self.rcv_sws_edge = self.rcv_right_edge;
    }

    /// ESTABLISHED, either role, once the send-side variables are set from the segment.
    fn establish(&mut self, now: Instant) {
        // RFC 6298 §5.7: the timer expired awaiting the SYN's ACK (only then is RTO above 1 s).
        let syn_lost = self.rtt.rto() > INITIAL_RTO;
        if syn_lost {
            self.rtt.reinit_after_syn_retransmission();
        }
        let smss = u32::from(self.eff_mss);
        self.cc.init(smss, syn_lost);
        self.cc.on_start(&Start {
            smss,
            syn_lost,
            srtt: self.rtt.srtt(),
            sack: self.sack_permitted,
            now,
        });
        self.rate = RateSampler::new(now, self.sack_permitted);
        // A SYN retransmission made due by an RTO that fired just before is now moot.
        self.syn_due = false;
        self.rto_at = None;
        self.state = TcpState::Established;
    }

    /// RFC 9293 §3.10.7.4 in SYN-RECEIVED (only reached by a passive open so far).
    fn on_segment_syn_received(
        &mut self,
        seg: &Segment,
        now: Instant,
        h: &mut impl Hooks,
    ) -> Reaction {
        // Second step as in the synchronized states (RFC 5961 §3, L3551). A RST at RCV.NXT
        // closes with `Reset`; the endpoint frees a passive TCB silently (L3580–3592).
        if seg.flags.contains(TcpFlags::RST) {
            return self.on_segment_sync(seg, now, h);
        }
        let syn = seg.flags.contains(TcpFlags::SYN);
        // The peer's SYN again: our SYN/ACK was lost, so it is the answer due (the ACK
        // L3527–3530 asks for, in this state).
        if syn && seg.seq.wrapping_add(1) == self.rcv_nxt {
            self.syn_due = true;
            return Reaction::None;
        }
        // First step (L3491–3530).
        if !self.acceptable(seg) {
            self.ack_due = true;
            return Reaction::None;
        }
        // Fourth step (L3652–3658): a passive open returns to LISTEN, which the endpoint does
        // by freeing the TCB silently. Simultaneous open (later) takes the synchronized states'
        // challenge ACK here instead.
        if syn {
            return self.terminate(CloseReason::Reset, now);
        }
        if !seg.flags.contains(TcpFlags::ACK) {
            return Reaction::None;
        }
        // Fifth step (L3729–3746): SND.UNA < SEG.ACK =< SND.NXT, else <SEQ=SEG.ACK><CTL=RST>.
        if !(self.snd_una.lt(seg.ack) && seg.ack.le(self.snd_nxt)) {
            self.rst_due = Some((seg.ack, None));
            return Reaction::None;
        }
        self.snd_una = seg.ack;
        // Not a SYN: the window field is scaled (RFC 7323 §2.2).
        self.snd_wnd = u32::from(seg.wnd) << self.snd_shift;
        self.max_snd_wnd = self.snd_wnd;
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        self.recovery.last_wnd = self.snd_wnd;
        self.establish(now);
        Reaction::Established
    }

    fn on_timeout_syn_sent(&mut self, now: Instant) -> Reaction {
        if self.first_syn_at.is_some_and(|t| now >= t + self.r2_syn()) {
            return self.terminate(CloseReason::Timeout, now);
        }
        if self.rto_at.is_some_and(|t| now >= t) {
            self.rto_at = None;
            self.rtt.backoff();
            self.syn_due = true;
        }
        Reaction::None
    }

    /// RFC 9293 §3.10.7.4 in the synchronized states.
    fn on_segment_sync(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> Reaction {
        let fin = seg.flags.contains(TcpFlags::FIN);
        // Second step, on SEG.SEQ alone (RFC 5961 §3 as RFC 9293 gives it): RCV.NXT exactly
        // resets, elsewhere in the window draws a challenge ACK, outside it the RST is dropped
        // silently. This also covers the first step for RSTs and, with the window empty, the
        // "special allowance" for them (a RST with text at RCV.NXT still resets). No RFC 5961
        // challenge-ACK rate limit.
        if seg.flags.contains(TcpFlags::RST) {
            let off = self.rcv_nxt.distance(seg.seq);
            if off == 0 {
                // Even when the hooks ask for a reset (MP_FASTCLOSE on it): a RST is never
                // answered (RFC 9293 §3.10.7).
                h.on_valid_segment(seg);
                h.on_reset(seg);
                return self.on_reset(now);
            }
            self.ack_due |= off > 0 && (off as u32) < self.rcv_wnd();
            return Reaction::None;
        }
        // TIME-WAIT: a retransmitted FIN ends at RCV.NXT, below the window, so it is ACKed and
        // restarts 2·MSL here rather than in the fifth and eighth steps it cannot reach.
        let seg_end = seg.seq.wrapping_add(seg.payload.len() as u32);
        if self.state == TcpState::TimeWait && fin && seg_end.wrapping_add(1) == self.rcv_nxt {
            if seg.flags.contains(TcpFlags::ACK) && !seg.ack.gt(self.snd_max) {
                h.on_valid_segment(seg);
                if h.reset_requested() {
                    return self.abort_with(CloseReason::Reset, h.reset_option(), now);
                }
            }
            self.time_wait_at = Some(now + 2 * MSL);
            self.ack_due = true;
            return Reaction::None;
        }
        // First: an unacceptable segment draws an ACK and is dropped.
        let delegated = h.delegates_data()
            && !seg.payload.is_empty()
            && !seg.flags.contains(TcpFlags::SYN)
            && !h.requires_tcp_sequence_check(seg);
        if !delegated && !self.acceptable(seg) {
            self.ack_due = true;
            if seg.flags.contains(TcpFlags::ACK)
                && !seg.flags.contains(TcpFlags::SYN)
                && !seg.ack.gt(self.snd_max)
            {
                self.record_dsack(seg);
            }
            // "If the RCV.WND is zero, ... special allowance should be made to accept valid
            // ACKs": with our window closed, the ACK field of a segment from RCV.NXT up to one
            // past the largest edge is still processed; its text is not. One past: a one-octet
            // probe into the closed window (RFC 9293 §3.8.6.1) moves the peer's SND.NXT there.
            let ack_only = seg.flags.contains(TcpFlags::ACK) && !seg.flags.contains(TcpFlags::SYN);
            let edge = self.rcv_right_edge.wrapping_add(1);
            if ack_only
                && !h.requires_tcp_sequence_check(seg)
                && self.rcv_nxt.le(seg.seq)
                && seg.seq.le(edge)
                && self.window_offer(h).0 == 0
            {
                if let ControlFlow::Break(r) = self.on_ack(seg, now, h) {
                    return r;
                }
            }
            return Reaction::None;
        }
        // Fourth: a SYN (e.g. a retransmitted SYN/ACK) draws a challenge ACK (RFC 5961 §4).
        if seg.flags.contains(TcpFlags::SYN) {
            self.ack_due = true;
            return Reaction::None;
        }
        // Fifth.
        if !seg.flags.contains(TcpFlags::ACK) {
            return Reaction::None;
        }
        if let ControlFlow::Break(r) = self.on_ack(seg, now, h) {
            return r;
        }
        self.on_text_and_fin(seg, now, h)
    }

    /// Seventh and eighth steps. Seventh, until the peer's FIN (URG is not processed: urgent
    /// data is delivered inline, RFC 6093); text after the FIN is ignored. Eighth: a FIN right
    /// after all the text before it.
    fn on_text_and_fin(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> Reaction {
        if !h.reset_requested() && !self.fin_received {
            self.on_text(seg, now, h);
        }
        if h.reset_requested() {
            return self.abort_with(CloseReason::Reset, h.reset_option(), now);
        }
        let seg_end = seg.seq.wrapping_add(seg.payload.len() as u32);
        // Trim sequence-space controls to the receive window too (RFC 9293 §3.10.7.4).
        // Text may consume the whole window, leaving the following FIN outside it.
        if seg.flags.contains(TcpFlags::FIN) {
            if !seg_end.lt(self.rcv_right_edge) {
                self.ack_due = true;
            } else if seg_end == self.rcv_nxt {
                return self.on_fin(now);
            }
        }
        Reaction::None
    }

    /// Eighth step for a FIN at RCV.NXT: ACK it at once, CLOSE-WAIT / CLOSING / TIME-WAIT.
    fn on_fin(&mut self, now: Instant) -> Reaction {
        self.ack_due = true;
        if self.fin_received {
            // A second FIN where the first one ended: only ACKed.
            return Reaction::None;
        }
        self.fin_received = true;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        match self.state {
            TcpState::Established => self.state = TcpState::CloseWait,
            // Our FIN is not ACKed yet: `on_ack` moves FIN-WAIT-1 to FIN-WAIT-2 when it is.
            TcpState::FinWait1 => self.state = TcpState::Closing,
            TcpState::FinWait2 => return self.enter_time_wait(now),
            _ => {}
        }
        Reaction::None
    }

    /// The only entry into TIME-WAIT: start 2·MSL, stop the other timers, `Closed(Normal)`.
    fn enter_time_wait(&mut self, now: Instant) -> Reaction {
        self.state = TcpState::TimeWait;
        self.time_wait_at = Some(now + 2 * MSL);
        self.rto_at = None;
        self.rto_not_before = None;
        self.r2_since = None;
        self.persist_at = None;
        self.sws_at = None;
        self.ack_at = None;
        Reaction::Closed(CloseReason::Normal)
    }

    /// An acceptable RST (second step): CLOSED. In TIME-WAIT, `Closed(Normal)` was already
    /// returned, so nothing more is.
    fn on_reset(&mut self, now: Instant) -> Reaction {
        if self.state == TcpState::TimeWait {
            self.terminate(CloseReason::Normal, now);
            return Reaction::None;
        }
        self.terminate(CloseReason::Reset, now)
    }

    /// RFC 9293 Table 6, against the largest window advertised (RFC 7323 §2.4 rule 1).
    fn acceptable(&self, seg: &Segment) -> bool {
        let wnd = i64::from(self.rcv_wnd());
        let len = seg.payload.len() as i64
            + i64::from(seg.flags.contains(TcpFlags::SYN))
            + i64::from(seg.flags.contains(TcpFlags::FIN));
        let off = i64::from(self.rcv_nxt.distance(seg.seq));
        let in_wnd = |o: i64| 0 <= o && o < wnd;
        match (len, wnd) {
            (0, 0) => off == 0,
            (0, _) => in_wnd(off),
            (_, 0) => false,
            _ => in_wnd(off) || in_wnd(off + len - 1),
        }
    }

    /// Seventh step for an acceptable segment: hands the octets that are new, inside the window
    /// and fit the memory to the hooks once each, in order of SSN, and decides when to ACK
    /// (RFC 5681 §4.2, RFC 9293 §3.8.6.3). Octets cut off are neither recorded nor ACKed.
    fn on_text(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) {
        if seg.payload.is_empty() {
            return;
        }
        self.record_dsack(seg);
        if h.delegates_data() {
            self.on_delegated_text(seg, h);
            return;
        }
        let off = i64::from(self.rcv_nxt.distance(seg.seq));
        let end = off + seg.payload.len() as i64;
        // Free memory counts from RCV.NXT with the held out-of-order octets inside it, so the
        // octets at RCV.NXT always fit.
        let held: u64 = self.rcv_ooo.iter().map(|r| r.end - r.start).sum();
        let room = u64::from(self.rcv_wnd()).min(u64::from(h.recv_window()) + held);
        let (lo, hi) = (off.max(0), end.min(room as i64));
        let was_ooo = !self.rcv_ooo.is_empty();
        if lo < hi {
            let (s, e) = (self.rcv_ssn + lo as u64, self.rcv_ssn + hi as u64);
            let new_range = lo > 0 && !self.rcv_ooo.overlaps(&(s - 1..e + 1));
            if new_range && self.rcv_ooo.len() >= MAX_OOO_RANGES {
                return;
            }
            for gap in self.rcv_ooo.gaps(&(s..e)) {
                let at = |ssn: u64| ((ssn - self.rcv_ssn) as i64 - off) as usize;
                h.accept_payload(gap.start as u32, &seg.payload[at(gap.start)..at(gap.end)]);
            }
            self.rcv_ooo.insert(s..e);
            if self.sack_permitted && lo > 0 {
                // Retain only points in other held blocks; insertion may have coalesced them.
                self.sack_recent.retain(|point| {
                    self.rcv_ooo
                        .get(point)
                        .is_some_and(|r| !r.contains(&(e - 1)))
                });
                self.sack_recent.insert(0, e - 1);
                self.sack_recent.truncate(4);
            }
            if let Some(r) = self
                .rcv_ooo
                .first()
                .cloned()
                .filter(|r| r.start == self.rcv_ssn)
            {
                self.rcv_nxt = self.rcv_nxt.wrapping_add((r.end - r.start) as u32);
                self.rcv_ssn = r.end;
                self.rcv_ooo.remove(r);
            }
        }
        // Out of order, filling a gap, or cut short by the window or the memory: ACK now.
        if was_ooo || !self.rcv_ooo.is_empty() || hi < end {
            self.ack_due = true;
        } else {
            // Every second segment, else within DELAYED_ACK (RFC 5681 §4.2: "at least every
            // second segment, regardless of size").
            self.rcv_unacked = self.rcv_unacked.saturating_add(1);
            if self.rcv_unacked >= 2 {
                self.ack_due = true;
            } else {
                self.ack_at.get_or_insert(now + DELAYED_ACK);
            }
        }
    }

    /// MPTCP receipts are headers only, independent of DSN retention and eviction.
    fn on_delegated_text(&mut self, seg: &Segment, h: &mut impl Hooks) {
        let off = i64::from(self.rcv_nxt.distance(seg.seq));
        let ssn = (self.rcv_ssn as u32).wrapping_add_signed(off as i32);
        for range in h.receive_data(ssn, self.rcv_ssn as u32, seg.payload) {
            let lo = (off + range.start as i64).max(0);
            let hi = off + range.end as i64;
            if lo >= hi {
                continue;
            }
            let (s, e) = (self.rcv_ssn + lo as u64, self.rcv_ssn + hi as u64);
            if lo > 0
                && !self.rcv_ooo.overlaps(&(s - 1..e + 1))
                && self.rcv_ooo.len() >= MAX_OOO_RANGES
            {
                continue;
            }
            self.rcv_ooo.insert(s..e);
            if self.sack_permitted && lo > 0 {
                self.sack_recent.retain(|point| {
                    self.rcv_ooo
                        .get(point)
                        .is_some_and(|r| !r.contains(&(e - 1)))
                });
                self.sack_recent.insert(0, e - 1);
                self.sack_recent.truncate(4);
            }
        }
        if let Some(r) = self
            .rcv_ooo
            .first()
            .cloned()
            .filter(|r| r.start == self.rcv_ssn)
        {
            self.rcv_nxt = self.rcv_nxt.wrapping_add((r.end - r.start) as u32);
            self.rcv_ssn = r.end;
            self.rcv_ooo.remove(r);
        }
        h.receipt_advanced(self.rcv_ssn as u32);
        self.ack_due = true;
    }

    /// RFC 9293 §3.10.7.4 fifth step, send side: SND.UNA, the send buffer, RTT, loss recovery,
    /// CC and SND.WND. `Break` means drop the segment and return.
    fn on_ack(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> ControlFlow<Reaction> {
        if seg.ack.lt(self.snd_una) {
            // An old duplicate ACK: ignored, the segment is processed further.
            h.on_valid_segment(seg);
            return ControlFlow::Continue(());
        }
        if seg.ack.gt(self.snd_max) {
            self.ack_due = true;
            return ControlFlow::Break(Reaction::None);
        }
        h.on_valid_segment(seg);
        if h.reset_requested() {
            let r = self.abort_with(CloseReason::Reset, h.reset_option(), now);
            return ControlFlow::Break(r);
        }
        // Spec §1.6: before any transition.
        self.check_app_limited(h, false);
        self.rate.begin_ack();
        let lost_end = self.sack.lost_end();
        // Recovery this ACK enters, and whether it ends one (spec §1.7).
        let mut entered = None;
        let mut exit = false;
        // RFC 6675 §5: the scoreboard first (Update), from SND.UNA before this ACK.
        let (sacked_new, sack_newest) = if self.sack_permitted {
            self.sack_update(seg, now)
        } else {
            (0, None)
        };
        // Duplicate ACK (RFC 5681 §2), judged before this segment updates SND.WND.
        let wnd = u32::from(seg.wnd) << self.snd_shift;
        let abcd = self.in_flight() > 0
            && seg.payload.is_empty()
            && !seg.flags.contains(TcpFlags::SYN)
            && !seg.flags.contains(TcpFlags::FIN)
            && seg.ack == self.snd_una
            && h.duplicate_ack_allowed(seg);
        if !self.sack_permitted && self.recovery.is_duplicate(abcd, wnd) {
            match self.recovery.on_dup_ack(seg.ack, self.snd_max) {
                DupAck::Ignore => {}
                DupAck::FastRetransmit => {
                    let flight = self.in_flight();
                    self.cc
                        .on_congestion(CongestionEvent::FastRetransmit, flight, now);
                    self.retransmit_due = true;
                    entered = Some(RecoveryKind::Fast);
                }
                DupAck::Inflate => self.cc.on_recovery_ack(RecoveryAck::Duplicate),
            }
        }
        if seg.ack.gt(self.snd_una) {
            let acked = self.snd_una.distance(seg.ack) as u32;
            let old = self.delivered;
            self.snd_una = seg.ack;
            self.delivered += u64::from(acked);
            if self.sack_permitted {
                self.sack.ack(old, self.delivered, u32::from(self.eff_mss));
            }
            self.rate.on_delivered(old..self.delivered, now);
            self.rate.drop_below(self.delivered);
            if let LossRecovery::Rto { point } = self.loss_recovery {
                exit |= self.delivered >= point;
            }
            self.rto_streak = 0;
            if self.rto_not_before.is_some_and(|(end, _)| end.le(seg.ack)) {
                self.rto_not_before = None;
            }
            // An ACK past a pulled-back SND.NXT: those octets need no resend.
            if self.snd_nxt.lt(self.snd_una) {
                self.snd_nxt = self.snd_una;
            }
            // The FIN is not in the send buffer.
            let data_una = self.fin_seq().filter(|f| f.lt(seg.ack)).unwrap_or(seg.ack);
            h.mark_acked(self.rel(data_una));
            if let Some((_, sent)) = self.rtt_timed.filter(|(end, _)| end.le(seg.ack)) {
                self.rtt_timed = None;
                self.rtt.sample(now - sent);
            }
            // The most recently sent segment this ACK newly delivers, cumulatively or by SACK
            // (draft-ietf-ccwg-bbr-06 §4.1.2.3), gives the RTT sample, unless it was resent
            // (Karn), and the app-limited flag. A record SACKed by an earlier ACK was
            // delivered then.
            let mut newest = sack_newest;
            while let Some(&r) = self.sent.front().filter(|r| r.end.le(seg.ack)) {
                self.sent.pop_front();
                if !r.sacked && newest.is_none_or(|n| r.tx_order > n.tx_order) {
                    newest = Some(r);
                }
            }
            let rtt = newest.filter(|r| !r.resent).map(|r| now - r.sent_at);
            let app_limited = newest.is_some_and(|r| r.app_limited);
            let cwnd_limited = self.cwnd_full_at.is_some_and(|m| seg.ack.le(m));
            if !cwnd_limited {
                self.cwnd_full_at = None;
            }
            // The app-limited bubble is acknowledged and gone (GenerateRateSample).
            if self.app_limited_until.is_some_and(|m| self.delivered > m) {
                self.app_limited_until = None;
                self.app_limited = None;
            }
            let in_flight = self.in_flight();
            // RFC 6298 §5.2 / §5.3, except that only the first partial ACK of a fast recovery
            // restarts the timer (RFC 6582 §3.2 step 3); R2 restarts with SND.UNA (ruling R8).
            let mut restart_rto = true;
            let sample = AckSample {
                acked,
                rtt,
                in_flight,
                now,
                delivered: self.delivered,
                app_limited,
                cwnd_limited,
            };
            let classic = if self.sack_permitted {
                // RFC 6675: cwnd stays ssthresh through recovery (sending is by pipe) and
                // after the ACK covering RecoveryPoint that ends it (§5 (A)); the RTO timer
                // restarts on every advance (RFC 6298 §5.3, RFC 6675 §6).
                if !self.sack.in_recovery() {
                    self.cc.on_ack(&sample);
                }
                exit |= self.sack.exit_if_covered(self.delivered);
                None
            } else {
                Some(self.recovery.on_new_ack(seg.ack))
            };
            match classic {
                None => {}
                Some(NewAck::Normal) => self.cc.on_ack(&sample),
                Some(NewAck::Partial { first }) => {
                    self.cc.on_recovery_ack(RecoveryAck::Partial { acked });
                    self.retransmit_due = true;
                    restart_rto = first;
                }
                Some(NewAck::Full) => {
                    self.cc.on_recovery_ack(RecoveryAck::Full { in_flight });
                    exit = true;
                }
            }
            let restart = (in_flight > 0).then_some(now);
            if restart_rto {
                self.rto_at = restart.map(|t| t + self.rtt.rto());
            }
            self.r2_since = restart;
        }
        // IsLost's point rose: the never-resent `Pending` octets below it are lost (spec §1.4).
        // Below SND.UNA everything is delivered, so the range starts there at the lowest.
        let new_lost_end = self.sack.lost_end();
        if new_lost_end > lost_end {
            self.rate
                .declare_lost(lost_end.max(self.delivered)..new_lost_end, now, true);
        }
        // RFC 6675 §5: a newly SACKing ACK is a duplicate ACK; DupThresh of them, or
        // IsLost(HighACK + 1), starts loss recovery. As for RFC 5681 duplicates, one carrying
        // non-DSS MPTCP signaling does not count (spec §3).
        if sacked_new > 0 {
            let counts = h.duplicate_ack_allowed(seg);
            if self.sack.on_dup_ack(sacked_new, counts, self.delivered) == SackDupAck::Enter {
                let flight = self.in_flight();
                self.cc
                    .on_congestion(CongestionEvent::FastRetransmit, flight, now);
                // (4.2) cwnd = ssthresh: the RFC 5681 §3.2 step 6 deflation, at once
                // (FlightSize ≥ ssthresh), and no inflation after it.
                self.cc
                    .on_recovery_ack(RecoveryAck::Full { in_flight: flight });
                self.sack.enter(self.delivered, self.abs(self.snd_max));
                // (4.3): HighACK + 1 first, regardless of pipe.
                self.retransmit_due = true;
                entered = Some(RecoveryKind::Fast);
            }
        }
        if exit {
            self.loss_recovery = LossRecovery::None;
        }
        if entered.is_some() {
            self.loss_recovery = LossRecovery::Fast;
        }
        self.recovery_hooks(entered, now);
        let ctx = SampleCtx {
            in_recovery: self.loss_recovery != LossRecovery::None,
            recovery_exit: exit,
            cwnd_filled: std::mem::take(&mut self.cwnd_filled),
        };
        let rs = self.rate.sample(now, ctx);
        self.cc.on_rate_sample(&rs);
        self.app_limited_request();
        self.check_app_limited(h, false);
        if self.snd_wl1.lt(seg.seq) || (self.snd_wl1 == seg.seq && self.snd_wl2.le(seg.ack)) {
            self.snd_wnd = wnd;
            self.max_snd_wnd = self.max_snd_wnd.max(self.snd_wnd);
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
        }
        // An acceptable ACK with nothing outstanding or a zero window answers the probe (the
        // zero-length one, or the retransmission that probes while data is unacknowledged):
        // answered probes do not count toward R2 (MUST-37).
        if self.in_flight() == 0 || self.snd_wnd == 0 {
            self.r2_since = (self.in_flight() > 0).then_some(now);
        }
        if self.fin_seq().is_some_and(|f| f.lt(self.snd_una)) {
            // Our FIN is acknowledged.
            match self.state {
                TcpState::FinWait1 => self.state = TcpState::FinWait2,
                TcpState::Closing => return ControlFlow::Break(self.enter_time_wait(now)),
                TcpState::LastAck => {
                    return ControlFlow::Break(self.terminate(CloseReason::Normal, now));
                }
                _ => {}
            }
        }
        ControlFlow::Continue(())
    }

    fn on_timeout_data(&mut self, now: Instant, h: &impl Hooks) -> Reaction {
        // Reaching the release time consumes it, whether or not anything can go out then.
        if self.next_send_at.is_some_and(|t| now >= t) {
            self.next_send_at = None;
        }
        if self.r2_since.is_some_and(|t| now >= t + self.cfg.r2_data) {
            return self.terminate(CloseReason::Timeout, now);
        }
        if self.rto_deadline().is_some_and(|t| now >= t) {
            // Spec §1.6: before any transition.
            self.check_app_limited(h, false);
            // RFC 6298 §5.4–5.6: the retransmission restarts the timer when it is sent.
            self.rto_at = None;
            self.rto_not_before = None;
            self.rtt.backoff();
            self.rto_streak = self.rto_streak.saturating_add(1);
            // Karn: nothing in flight now is timed.
            self.rtt_timed = None;
            self.cc
                .on_congestion(CongestionEvent::Rto, self.in_flight(), now);
            self.recovery.on_rto(self.snd_max);
            // The RTO ends the app-limited interval. Its end, `delivered` + in-flight when it was
            // marked, assumed that flight would be delivered at the rate it was sent at. Now all of
            // it is presumed lost and resent from cwnd = 1 SMSS (CheckIfApplicationLimited,
            // draft-ietf-ccwg-bbr-06 §4.1.2.4, would not mark: lost_out > retrans_out). Kept, it
            // marks every go-back resend, and RFC 9438 §5.8 then holds cwnd at 1 SMSS until the
            // whole pre-RTO flight is ACKed, one segment per RTT. The draft clears C.app_limited
            // only by delivery; that freeze only happens with a CC that gates growth on the flag.
            // SACK and fast recovery keep the mark: there cwnd stays at ssthresh, so the interval
            // drains at the recovery's rate. Records sent before the RTO keep their flag. A resend
            // replaces its record (on_data_sent), and an ACK samples the newest record it covers,
            // so only an ACK that delivers no post-RTO resend is still marked.
            self.app_limited_until = None;
            self.app_limited = None;
            self.rate.on_rto(now);
            if self.sack_permitted {
                self.sack.rto(self.abs(self.snd_max));
                for r in &mut self.sent {
                    r.sacked = false;
                }
            }
            // Go back (RFC 5681 §3.1, RFC 6298 §5.4): SND.UNA's segment now, the rest of the
            // window under slow start as ACKs return.
            self.snd_nxt = self.snd_una;
            self.retransmit_due = true;
            self.loss_recovery = LossRecovery::Rto {
                point: self.abs(self.snd_max),
            };
            self.recovery_hooks(Some(RecoveryKind::Rto), now);
        }
        if self.persist_at.is_some_and(|t| now >= t) {
            self.probe_due = true;
            self.persist_ivl = (self.persist_ivl * 2).min(MAX_PERSIST);
            self.persist_at = Some(now + self.persist_ivl);
        }
        if self.sws_at.is_some_and(|t| now >= t) {
            self.sws_at = None;
            self.sws_override = true;
        }
        if self.ack_at.is_some_and(|t| now >= t) {
            self.ack_at = None;
            self.ack_due = true;
        }
        Reaction::None
    }

    /// The retransmission, zero-window probe or new data segment due now, if any; also arms
    /// and disarms the persist and SWS override timers.
    fn poll_data(
        &mut self,
        now: Instant,
        h: &mut impl Hooks,
        out: &mut SegmentWriter,
        options_len: u16,
        rxt: Option<(SeqNum, SeqNum, bool)>,
    ) -> Option<SentMeta> {
        // Reaching the release time consumes it, whether or not anything can go out now.
        if self.next_send_at.is_some_and(|t| now >= t) {
            self.next_send_at = None;
        }
        let paced = self.next_send_at.is_some() && self.burst_left == 0;
        let mss = u32::from(self.eff_mss.saturating_sub(options_len));
        let in_flight = self.in_flight();
        let queued = self.data_len(self.snd_nxt, self.iss.wrapping_add(h.assigned_end()));
        let fin_pending = self.fin_rel.is_some() && !self.fin_sent();
        self.unsent = queued > 0 || fin_pending || rxt.is_some();
        if !paced && std::mem::take(&mut self.retransmit_due) && in_flight > 0 {
            // The segment at SND.UNA (RTO, fast retransmit, partial ACK): sent regardless of
            // cwnd, Nagle and SWS, even into a zero window, where it is the probe (spec §3).
            // Karn: the RTO estimator times nothing now in flight.
            self.rtt_timed = None;
            let mut len = self.data_len(self.snd_una, self.snd_max).min(mss);
            if self.sack.in_recovery() {
                let sacked = self.sack.next_start(self.delivered) - self.delivered;
                len = len.min(sacked.min(u64::from(u32::MAX)) as u32);
            }
            let fin = self.fin_sent();
            let meta = self.write_data(self.snd_una, len, fin, now, h, out)?;
            let end = self.snd_una.wrapping_add(seq_len(&meta));
            // The (4.3), fast-retransmit and partial-ACK resends declare exactly what they
            // resend lost (spec §1.4), outside any ACK; after an RTO nothing here is Pending.
            self.rate
                .declare_lost(self.delivered..self.abs(end), now, false);
            self.report_losses();
            self.sack
                .on_retransmit(self.delivered, self.abs(end), false);
            self.on_data_sent(self.snd_una, &meta, now, true);
            self.rto_not_before = Some((end, now + self.rtt.rto()));
            if end.gt(self.snd_nxt) {
                self.snd_nxt = end;
            }
            return Some(meta);
        }
        if let Some(seq) = self.tail_probe_seq() {
            self.tail_probe_due = false;
            let len = self.data_len(seq, self.snd_max).min(mss);
            let meta = self.write_data(seq, len, false, now, h, out)?;
            self.rtt_timed = None;
            self.on_data_sent(seq, &meta, now, true);
            return Some(meta);
        }
        self.tail_probe_due = false;
        let idle = in_flight == 0;

        // RFC 9293 §3.8.6.1 (a FIN waits for the window like data); never armed while data is
        // unacknowledged.
        // Assigned bytes already own connection credit. Drain them (or a pending FIN)
        // through an open subflow before probing for credit for unassigned data.
        let connection_probe =
            self.probe_demand && (self.snd_wnd == 0 || (queued == 0 && !fin_pending));
        if idle && (((queued > 0 || fin_pending) && self.snd_wnd == 0) || connection_probe) {
            // Persist replaces the SWS override for this zero-window episode.
            self.sws_at = None;
            self.sws_override = false;
            if self.persist_at.is_none() {
                self.persist_ivl = self.rtt.rto();
                self.persist_at = Some(now + self.persist_ivl);
            }
            if !std::mem::take(&mut self.probe_due) {
                return None;
            }
            // Zero-length at SND.UNA − 1 (spec §3, I3). Unanswered probes count toward R2.
            self.r2_since.get_or_insert(now);
            let wnd = self.wnd_field(h);
            let seq = self.snd_una.wrapping_add(u32::MAX);
            return Some(out.start(seq, self.rcv_nxt, TcpFlags::ACK, wnd));
        }
        self.persist_at = None;
        self.probe_due = false;
        // Data (new, resent or reinjected) waits for the release; ACKs and probes do not.
        if paced {
            return None;
        }

        // RFC 5681 §4.1: "a TCP SHOULD set cwnd to no more than RW before beginning
        // transmission if the TCP has not sent data in an interval exceeding the
        // retransmission timeout" (the SHOULD, not the receive-side wording of the prose
        // above it). Idempotent, so a send held back by Nagle may repeat it.
        if idle
            && queued > 0
            && self
                .last_data_sent
                .is_some_and(|t| now > t + self.rtt.rto())
        {
            self.cc.on_idle_restart();
        }

        // SACK loss recovery: NextSeg()'s retransmission (RFC 6675 §5 (C)).
        if let Some((seq, end, rescue)) = rxt {
            let len = self.data_len(seq, end).min(mss);
            let meta = self.write_data(seq, len, self.fin_sent(), now, h, out)?;
            let e = seq.wrapping_add(seq_len(&meta));
            self.sack.on_retransmit(self.abs(seq), self.abs(e), rescue);
            self.rtt_timed = None;
            self.on_data_sent(seq, &meta, now, true);
            self.cwnd_filled |= self.cwnd_room() < u32::from(self.eff_mss);
            return Some(meta);
        }

        // RFC 5681 §2: nothing beyond SND.UNA + min(cwnd, rwnd); after a go-back the octets
        // between SND.NXT and SND.MAX count as lost, and those SACKed since the RTO as gone.
        let sent = self.sent_below_nxt();
        let resend = self.snd_nxt.distance(self.snd_max) as u32;
        let mut sacked_ahead = u32::MAX;
        if resend > 0 && self.sack_permitted {
            let nxt = self.abs(self.snd_nxt);
            sacked_ahead = (self.sack.next_start(nxt) - nxt).min(u64::from(u32::MAX)) as u32;
        }
        let usable = self.window_room(self.cc.cwnd(), sent);
        if resend > 0 {
            // Go-back: resends stop at SND.MAX (and at SACKed data) and skip Nagle and SWS;
            // they are not timed. The FIN goes again if the window has room behind the data.
            let len = self
                .data_len(self.snd_nxt, self.snd_max)
                .min(usable)
                .min(mss)
                .min(sacked_ahead);
            let fin = self.fin_sent() && usable > len;
            let meta = self.write_data(self.snd_nxt, len, fin, now, h, out)?;
            self.on_data_sent(self.snd_nxt, &meta, now, true);
            self.snd_nxt = self.snd_nxt.wrapping_add(seq_len(&meta));
            self.cwnd_filled |= self.cwnd_room() < u32::from(self.eff_mss);
            return Some(meta);
        }
        let sws_override = self.sws_override;
        let len = queued.min(usable).min(mss);
        // The FIN takes one sequence number of the window, behind the last data octet.
        let fin = fin_pending && usable > len;
        if len == 0 && !fin {
            return None;
        }
        // RFC 9293 §3.8.6.2.1 rules (1)–(4), Fs = 1/2; the bracketed SND.NXT = SND.UNA is
        // Nagle's (§3.7.4) and dropped by `set_nodelay(true)`. Every write counts as pushed.
        // A FIN alone is sent at once.
        let nagle_ok = idle || self.nodelay;
        let send = len == 0
            || len == mss
            || (nagle_ok && u64::from(queued) + h.unassigned_len() as u64 <= u64::from(usable))
            || (nagle_ok && len >= self.max_snd_wnd / 2)
            || sws_override
            || h.is_reinjection(self.rel(self.snd_nxt));
        if !send {
            // Only an idle sender can stall here; otherwise the next ACK re-evaluates.
            if idle {
                self.sws_at.get_or_insert(now + SWS_OVERRIDE);
            } else {
                self.sws_at = None;
            }
            return None;
        }
        let meta = self.write_data(self.snd_nxt, len, fin, now, h, out)?;
        self.on_data_sent(self.snd_nxt, &meta, now, false);
        if meta.len > 0 {
            self.app_limited = None;
        }
        self.sws_at = None;
        self.sws_override = false;
        self.snd_nxt = self.snd_nxt.wrapping_add(seq_len(&meta));
        self.snd_max = self.snd_nxt;
        self.cwnd_filled |= self.cwnd_room() < u32::from(self.eff_mss);
        // New data only (SEQ = SND.MAX): resends never get here (Karn).
        self.rtt_timed.get_or_insert((self.snd_nxt, now));
        Some(meta)
    }

    /// Logs the data segment `meta` just written from `seq` (draft-ietf-ccwg-bbr-06
    /// §4.1.2.2 OnPacketSent) and, if the CC paces, moves the release time past it. A resend
    /// replaces the records it covers.
    fn on_data_sent(&mut self, seq: SeqNum, meta: &SentMeta, now: Instant, resent: bool) {
        // Draft OnTransmit (spec §3.2), before the sampler charges this send.
        if self.rate.inflight() == 0 {
            self.cc.on_transmit(&Transmit {
                inflight: 0,
                app_limited: self.rate.is_app_limited(),
                now,
            });
            self.app_limited_request();
        }
        self.tx_count += 1;
        let rec = SentRecord {
            end: seq.wrapping_add(seq_len(meta)),
            tx_order: self.tx_count,
            app_limited: self.app_limited_until.is_some(),
            sent_at: now,
            resent,
            sacked: false,
        };
        if !resent {
            self.sent.push_back(rec);
        } else {
            // Records ending above `seq`, up to the one `rec` ends in, which it splits.
            let mut i = self.sent.partition_point(|r| r.end.le(seq));
            while let Some(end) = self.sent.get(i).map(|r| r.end) {
                if end.le(rec.end) {
                    self.sent[i] = SentRecord { end, ..rec };
                    i += 1;
                    continue;
                }
                if i == 0 || self.sent[i - 1].end.lt(rec.end) {
                    self.sent.insert(i, rec);
                }
                break;
            }
        }
        let start = self.abs(seq);
        self.rate
            .on_send(start..start + u64::from(seq_len(meta)), now, resent);
        // The flow filled cwnd: what is outstanding now was sent cwnd-limited.
        let max = if rec.end.gt(self.snd_max) {
            rec.end
        } else {
            self.snd_max
        };
        // In SACK recovery the window holds pipe, not FlightSize (RFC 6675 §5 (C)).
        let flight = if self.sack.in_recovery() {
            self.pipe_to(max)
        } else {
            self.snd_una.distance(max) as u32
        };
        if self.cc.cwnd().saturating_sub(flight) < u32::from(self.eff_mss) {
            self.cwnd_full_at = Some(max);
        }
        if let Some(rate) = self.cc.pacing_rate().filter(|_| meta.len > 0) {
            if !self.next_send_at.is_some_and(|t| t > now) {
                // At a release: a new burst of one quantum.
                self.burst_left = self.burst(rate, usize::from(self.eff_mss)) as u32;
            }
            // A remainder smaller than this segment closes the burst.
            self.burst_left = self
                .burst_left
                .checked_sub(meta.len)
                .filter(|&left| left >= meta.len)
                .unwrap_or(0);
            let gap = Duration::from_nanos(u64::from(meta.len) * 1_000_000_000 / rate.max(1));
            self.next_send_at = Some(self.next_send_at.map_or(now, |t| t.max(now)) + gap);
        }
    }

    /// Writes up to `len` data octets from SEQ `seq`, PSH if they end at the last queued octet,
    /// and the FIN if `fin` and they end where it sits; `None` if neither data nor FIN goes.
    /// Starts the RTO and R2 clocks if they are not running (RFC 6298 §5.1).
    fn write_data(
        &mut self,
        seq: SeqNum,
        len: u32,
        fin: bool,
        now: Instant,
        h: &mut impl Hooks,
        out: &mut SegmentWriter,
    ) -> Option<SentMeta> {
        let (wnd, edge, sws_edge) = self.window_offer(h);
        let mut meta = out.start(seq, self.rcv_nxt, TcpFlags::ACK, wnd);
        let start = self.rel(seq);
        let len = len.min(h.segment_limit(start).min(u32::MAX as usize) as u32);
        let mut got = 0u32;
        // A run may end early at a buffer boundary; an empty run is not progress.
        while got < len {
            let run = h.peek_with(start.wrapping_add(got), (len - got) as usize, |d| {
                out.payload.extend_from_slice(d);
                d.len() as u32
            });
            match run {
                Some(n) if n > 0 => got += n,
                _ => break,
            }
        }
        let end = start.wrapping_add(got);
        let fin = fin && self.fin_rel == Some(end);
        if got == 0 && !fin {
            return None;
        }
        if got > 0 && end == self.fin_rel.unwrap_or(h.assigned_end()) {
            out.flags = out.flags | TcpFlags::PSH;
        }
        if fin {
            out.flags = out.flags | TcpFlags::FIN;
        }
        meta.flags = out.flags;
        meta.len = got;
        self.record_offer(edge, sws_edge);
        h.window_sent(wnd, self.rcv_shift);
        if got > 0 {
            self.last_data_sent = Some(now);
        }
        self.rto_at.get_or_insert(now + self.rtt.rto());
        self.r2_since.get_or_insert(now);
        Some(meta)
    }

    /// Octets outstanding: SND.MAX − SND.UNA (FlightSize).
    fn in_flight(&self) -> u32 {
        self.snd_una.distance(self.snd_max) as u32
    }

    /// SEQ of our FIN, once fixed.
    fn fin_seq(&self) -> Option<SeqNum> {
        self.fin_rel.map(|r| self.iss.wrapping_add(r))
    }

    fn fin_sent(&self) -> bool {
        self.fin_seq().is_some_and(|f| f.lt(self.snd_max))
    }

    /// Data octets from `seq` to `end`, stopping at the FIN; 0 if `seq` is past either.
    fn data_len(&self, seq: SeqNum, end: SeqNum) -> u32 {
        let end = self.fin_seq().filter(|f| f.lt(end)).unwrap_or(end);
        seq.distance(end).max(0) as u32
    }

    /// The end of an ACK's or RTO's processing, after its legacy callbacks (spec §1.7):
    /// `on_recovery_start` if it `entered` recovery, then `on_loss` for its events.
    fn recovery_hooks(&mut self, entered: Option<RecoveryKind>, now: Instant) {
        if let Some(kind) = entered {
            let inflight = self.rate.inflight();
            self.cc.on_recovery_start(&RecoveryStart {
                kind,
                inflight,
                now,
            });
        }
        self.report_losses();
    }

    /// `on_loss` for each loss event queued in the sampler, in offset order.
    fn report_losses(&mut self) {
        for e in self.rate.take_loss_events() {
            self.cc.on_loss(&e);
        }
    }

    /// Relative SSN of `seq`: ISS + 1 is SSN 1 (spec §5.3).
    fn rel(&self, seq: SeqNum) -> u32 {
        seq.0.wrapping_sub(self.iss.0)
    }

    /// Window field of a non-SYN segment. Records the SWS edge, and the advertised edge if it
    /// is the largest so far (acceptability keeps the largest).
    fn wnd_field(&mut self, h: &mut impl Hooks) -> u16 {
        let (field, edge, sws_edge) = self.window_offer(h);
        self.record_offer(edge, sws_edge);
        h.window_sent(field, self.rcv_shift);
        field
    }

    /// Records an advertised window. Only for a segment that is really going out.
    fn record_offer(&mut self, edge: SeqNum, sws_edge: SeqNum) {
        self.rcv_sws_edge = sws_edge;
        if edge.gt(self.rcv_right_edge) {
            self.rcv_right_edge = edge;
        }
    }

    /// The window field to send now, the edge it advertises and the SWS edge behind it
    /// (spec §5.4 applied to plain TCP, ruling R16).
    ///
    /// The SWS edge moves to the scale-aligned RCV.NXT + free memory only when the receiver
    /// SWS rule allows (RFC 9293 §3.8.6.2.2) and never moves left; the field is the SWS edge
    /// rounded up to the scale unit, so it rounds only when the edge is re-advertised from an
    /// older RCV.NXT.
    ///
    /// Invariant: the SWS edge never passes the memory's edge, so the advertised edge is less
    /// than 2^scale beyond it, and no advertisement retracts the largest edge by 2^scale or
    /// more (RFC 7323 §2.4). With no free memory nothing is held out of order (a hole below it
    /// would be free), the SWS edge is at or before RCV.NXT and the field is 0 (ruling R14).
    fn window_offer(&self, h: &impl Hooks) -> (u16, SeqNum, SeqNum) {
        if let Some(field) = h.window_offer(self.rcv_shift, self.eff_mss) {
            let edge = self
                .rcv_nxt
                .wrapping_add(u32::from(field) << self.rcv_shift);
            return (field, edge, edge);
        }
        let free = h.recv_window();
        let mut sws_edge = self.rcv_sws_edge;
        if self.sws_moves(free) {
            let aligned = (free >> self.rcv_shift).min(65535) << self.rcv_shift;
            let edge = self.rcv_nxt.wrapping_add(aligned);
            if edge.gt(sws_edge) {
                sws_edge = edge;
            }
        }
        // At most 65535: the SWS edge was set by a field of at most 65535 from an RCV.NXT at
        // or before the current one.
        let wnd = self.rcv_nxt.distance(sws_edge).max(0) as u32;
        let field = wnd.div_ceil(1 << self.rcv_shift).min(65535);
        debug_assert!(free > 0 || field == 0, "a window without memory");
        let edge = self.rcv_nxt.wrapping_add(field << self.rcv_shift);
        (field as u16, edge, sws_edge)
    }

    /// Receiver SWS (RFC 9293 §3.8.6.2.2): `buffer_edge − sws_edge >= min(buffer/2, eff_mss)`.
    fn sws_moves(&self, free: u32) -> bool {
        let sws = (self.cfg.recv_buffer / 2).min(u32::from(self.eff_mss));
        let buffer_edge = self.rcv_nxt.wrapping_add(free);
        i64::from(self.rcv_sws_edge.distance(buffer_edge)) >= i64::from(sws)
    }

    /// After a read, an update is sent only if the SWS rule moves the edge by at least the
    /// window the peer still has (ruling R15): a closed window reopens at once, while reads
    /// during a transfer ride on the ACKs the data draws anyway, and a field capped at 65535
    /// draws no extra ACK per segment.
    fn window_update_due(&self, h: &impl Hooks) -> bool {
        if h.delegates_data() {
            return h.window_update_due(self.rcv_shift, self.eff_mss);
        }
        let (_, edge, sws_edge) = self.window_offer(h);
        let grow = self.rcv_right_edge.distance(edge);
        sws_edge != self.rcv_sws_edge && grow > 0 && grow as u32 >= self.rcv_wnd()
    }

    /// RCV.WND: from RCV.NXT to the largest edge advertised.
    fn rcv_wnd(&self) -> u32 {
        self.rcv_nxt.distance(self.rcv_right_edge).max(0) as u32
    }

    /// Our ACK is going out: the delayed ACK is done.
    fn ack_sent(&mut self) {
        self.ack_due = false;
        self.ack_at = None;
        self.rcv_unacked = 0;
        self.dsack = None;
    }

    /// Reports only bytes actually received, including a prefix below the cumulative ACK.
    fn record_dsack(&mut self, seg: &Segment) {
        self.dsack = None;
        if !self.sack_permitted || seg.payload.is_empty() {
            return;
        }
        let next = self
            .rcv_nxt
            .wrapping_add(0u32.wrapping_sub(u32::from(self.fin_received)));
        let off = i64::from(next.distance(seg.seq));
        let end = off + seg.payload.len() as i64;
        let lo = off.max(1 - self.rcv_ssn as i64);
        let hi = end.min(0);
        if lo < hi {
            self.dsack = Some((next.wrapping_add(lo as u32), next.wrapping_add(hi as u32)));
        } else if end > 0 {
            let start = self.rcv_ssn + off.max(0) as u64;
            let end = self.rcv_ssn + end as u64;
            if let Some(r) = self.rcv_ooo.iter().find(|r| r.start < end && r.end > start) {
                let left = r.start.max(start);
                let right = r.end.min(end);
                self.dsack = Some((
                    next.wrapping_add((left - self.rcv_ssn) as u32),
                    next.wrapping_add((right - self.rcv_ssn) as u32),
                ));
            }
        }
    }

    /// DSACK first, its containing block second, then held blocks in reception order.
    fn write_sacks(&self, out: &mut [u8]) -> usize {
        if !self.sack_permitted {
            return 0;
        }
        let mut blocks = [(0, 0); 4];
        let mut count = 0;
        let duplicate = self
            .dsack
            .filter(|(left, _)| !left.lt(self.rcv_nxt))
            .map(|(left, _)| self.rcv_ssn + self.rcv_nxt.distance(left) as u64);
        // A DSACK above ACK requires its containing block too (RFC 2883 §4).
        let dsack = self
            .dsack
            .filter(|_| duplicate.is_none() || out.len() >= 20);
        if let Some((left, right)) = dsack {
            blocks[0] = (left.0, right.0);
            count = 1;
        }
        for point in duplicate
            .into_iter()
            .chain(self.sack_recent.iter().copied())
            .chain(self.rcv_ooo.iter().rev().map(|r| r.end - 1))
        {
            if let Some(r) = self.rcv_ooo.get(&point) {
                let block = (
                    self.rcv_nxt.wrapping_add((r.start - self.rcv_ssn) as u32).0,
                    self.rcv_nxt.wrapping_add((r.end - self.rcv_ssn) as u32).0,
                );
                // A full duplicate above ACK needs the same block again to identify DSACK.
                let first = usize::from(dsack.is_some());
                if count < blocks.len() && !blocks[first..count].contains(&block) {
                    blocks[count] = block;
                    count += 1;
                }
            }
        }
        tcp_options::write_sack(out, &blocks[..count])
    }

    fn terminate(&mut self, reason: CloseReason, now: Instant) -> Reaction {
        self.state = TcpState::Closed;
        // Closing ends recovery silently (spec §1.7).
        self.loss_recovery = LossRecovery::None;
        self.closed_at = Some(now);
        Reaction::Closed(reason)
    }

    fn r2_syn(&self) -> Duration {
        self.cfg.r2_syn.max(MIN_R2_SYN)
    }

    /// Our SYN's MSS option: MTU minus the IP and TCP headers (RFC 9293 §3.7.1).
    fn mss_option(&self) -> u16 {
        self.cfg.mtu.saturating_sub(if self.v6 { 60 } else { 40 })
    }

    /// Spec §3: min(peer's MSS option, or 536 / 1220 when absent; our MTU-derived MSS). TCP
    /// option bytes are subtracted by `poll_data` when SACK accompanies data.
    fn eff_mss_for(&self, peer: Option<u16>) -> u16 {
        let peer = peer.unwrap_or(if self.v6 { 1220 } else { 536 });
        // ponytail: a peer MSS of 0 would stall the send path; used as 1.
        peer.min(self.mss_option()).max(1)
    }
}

/// Sequence numbers a segment we sent occupies: its data and the FIN.
/// Octets one pacing release may send (Linux tcp_tso_autosize): `rate` × 1 ms, at least two
/// `seg` segments, at most 64 KiB (the cap wins).
fn pacing_quantum(rate: u64, seg: usize) -> usize {
    usize::try_from(rate / 1000)
        .unwrap_or(usize::MAX)
        .max(2 * seg)
        .min(64 << 10)
}

fn seq_len(m: &SentMeta) -> u32 {
    m.len + u32::from(m.flags.contains(TcpFlags::FIN))
}

fn new_cc(cfg: &ConnectConfig, seed: u64) -> Box<dyn CongestionControl> {
    match cfg.congestion_control {
        CongestionControlKind::Cubic => Box::new(Cubic::new()),
        CongestionControlKind::BbrV3 => Box::new(Bbr::new(seed)),
    }
}

/// Smallest shift `s` with `buffer >> s <= 65535`, at most 14 (RFC 7323 §2.3).
fn ws_shift(buffer: u32) -> u8 {
    (0..MAX_WS_SHIFT)
        .find(|&s| buffer >> s <= 65535)
        .unwrap_or(MAX_WS_SHIFT)
}

#[cfg(test)]
mod tests;
