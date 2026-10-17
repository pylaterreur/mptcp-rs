//! Many idle connections next to one busy one (issue #12): the work per packet must not grow
//! with the number of connections.
use super::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::time::Duration;

const SERVER: &str = "10.0.0.2:80";
/// One-way delay of the in-memory link.
const DELAY: Duration = Duration::from_millis(5);

/// A client and a server endpoint joined by a lossless link with `DELAY` each way.
struct Pair {
    a: Endpoint<ChaCha20Rng>,
    b: Endpoint<ChaCha20Rng>,
    now: Instant,
    /// (delivery time, sequence) → (to `b`, packet).
    wire: BTreeMap<(Instant, u64), (bool, Vec<u8>)>,
    n: u64,
    packets: u64,
    /// `handle_timeout` calls.
    timeouts: u64,
    accepted: Vec<ConnectionHandle>,
}

impl Pair {
    fn new(max_half_open: usize) -> Self {
        let mut b = Endpoint::new(ChaCha20Rng::seed_from_u64(2));
        let cfg = ListenConfig {
            max_half_open,
            ..ListenConfig::default()
        };
        b.listen(SERVER.parse().unwrap(), cfg).unwrap();
        Pair {
            a: Endpoint::new(ChaCha20Rng::seed_from_u64(1)),
            b,
            now: Instant::from_nanos(0),
            wire: BTreeMap::new(),
            n: 0,
            packets: 0,
            timeouts: 0,
            accepted: Vec::new(),
        }
    }

    fn connect(&mut self) -> ConnectionHandle {
        let local = "10.0.9.2".parse().unwrap();
        let cfg = ConnectConfig::default();
        (self
            .a
            .connect_mptcp(self.now, local, SERVER.parse().unwrap(), cfg))
        .unwrap()
    }

    /// Sends everything both endpoints have due.
    fn pump(&mut self) {
        let mut buf = [0u8; 1500];
        for to_b in [true, false] {
            let ep = if to_b { &mut self.a } else { &mut self.b };
            while let Some(len) = ep.poll_transmit(self.now, &mut buf) {
                self.n += 1;
                self.packets += 1;
                let at = self.now + DELAY;
                self.wire.insert((at, self.n), (to_b, buf[..len].to_vec()));
            }
        }
        while let Some((h, e)) = self.b.poll_event() {
            if matches!(e, Event::Accepted { .. }) {
                self.accepted.push(h);
            }
        }
        while self.a.poll_event().is_some() {}
    }

    /// Handles the next delivery or timeout; `false` once nothing is pending before `until`.
    fn step(&mut self, until: Instant) -> bool {
        self.pump();
        let next = [
            self.wire.first_key_value().map(|(k, _)| k.0),
            self.a.poll_timeout(),
            self.b.poll_timeout(),
        ];
        let Some(next) = next.into_iter().flatten().min().filter(|&t| t <= until) else {
            return false;
        };
        self.now = self.now.max(next);
        while let Some(e) = self.wire.first_entry().filter(|e| e.key().0 <= self.now) {
            let (to_b, p) = e.remove();
            let ep = if to_b { &mut self.b } else { &mut self.a };
            ep.handle_packet(self.now, &p);
        }
        for ep in [&mut self.a, &mut self.b] {
            if ep.poll_timeout().is_some_and(|t| t <= self.now) {
                ep.handle_timeout(self.now);
                self.timeouts += 1;
            }
        }
        true
    }

    fn run_for(&mut self, d: Duration) {
        let until = self.now + d;
        while self.step(until) {}
        self.now = until;
    }
}

/// `n` idle MPTCP connections, then one transfer of `len` octets from the client: returns the
/// connections `handle_timeout` processed per call during the transfer.
fn timeouts_per_call(n: usize, len: usize) -> f64 {
    let mut p = Pair::new(n + 1);
    for _ in 0..n {
        p.connect();
    }
    p.run_for(Duration::from_secs(1));
    assert_eq!(p.accepted.len(), n, "every idle connection is accepted");
    let h = p.connect();
    p.run_for(Duration::from_millis(100));
    // A changed connection gets one pass even if not due: the first call after the
    // handshakes takes them all, once.
    for ep in [&mut p.a, &mut p.b] {
        ep.handle_timeout(p.now);
    }
    let server_h = *p.accepted.last().unwrap();
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let (processed, calls) = (p.a.timeouts + p.b.timeouts, p.timeouts);
    let (mut written, mut received) = (0, Vec::new());
    let mut buf = vec![0u8; 65536];
    while received.len() < len {
        if written < len {
            written += p.a.connection(h).unwrap().write(&data[written..]).unwrap();
        }
        let until = p.now + Duration::from_secs(10);
        assert!(p.step(until), "the transfer stalled");
        while let Ok(k) = p.b.connection(server_h).unwrap().read(&mut buf) {
            received.extend_from_slice(&buf[..k]);
        }
    }
    assert!(received == data);
    let processed = p.a.timeouts + p.b.timeouts - processed;
    processed as f64 / (p.timeouts - calls) as f64
}

#[test]
fn idle_connections_do_not_slow_timeouts() {
    // Processing every connection made this the number of connections per call (issue #12);
    // with the deadline heap it is the due and changed ones only.
    let few = timeouts_per_call(1, 300_000);
    let many = timeouts_per_call(2000, 300_000);
    assert!(
        many < 3.0,
        "{many} connections per call with 2000 idle connections"
    );
    assert!(many < few + 0.5, "{many} vs {few} with one idle connection");
}

/// `n` idle MPTCP connections, then one transfer of `len` octets from the client: returns the
/// connections `poll_transmit` visited per packet sent during the transfer.
fn visits_per_packet(n: usize, len: usize) -> f64 {
    let mut p = Pair::new(n + 1);
    for _ in 0..n {
        p.connect();
    }
    p.run_for(Duration::from_secs(1));
    assert_eq!(p.accepted.len(), n, "every idle connection is accepted");
    let h = p.connect();
    p.run_for(Duration::from_millis(100));
    // A connection an endpoint call reached is visited again after its next `handle_timeout`
    // pass: the first call after the handshakes takes them all, once.
    for ep in [&mut p.a, &mut p.b] {
        ep.handle_timeout(p.now);
    }
    p.pump();
    let server_h = *p.accepted.last().unwrap();
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let (visits, packets) = (p.a.visits + p.b.visits, p.packets);
    let (mut written, mut received) = (0, Vec::new());
    let mut buf = vec![0u8; 65536];
    while received.len() < len {
        if written < len {
            written += p.a.connection(h).unwrap().write(&data[written..]).unwrap();
        }
        let until = p.now + Duration::from_secs(10);
        assert!(p.step(until), "the transfer stalled");
        while let Ok(k) = p.b.connection(server_h).unwrap().read(&mut buf) {
            received.extend_from_slice(&buf[..k]);
        }
    }
    assert!(received == data);
    let visits = p.a.visits + p.b.visits - visits;
    visits as f64 / (p.packets - packets) as f64
}

#[test]
fn idle_connections_do_not_slow_transmit() {
    // Visiting every connection until one sends made this about the number of connections
    // per packet (issue #12); with the ready set it is one or two whatever their number.
    let few = visits_per_packet(1, 300_000);
    let many = visits_per_packet(2000, 300_000);
    assert!(
        many < 3.0,
        "{many} visits per packet with 2000 idle connections"
    );
    assert!(many < few + 0.5, "{many} vs {few} with one idle connection");
}
