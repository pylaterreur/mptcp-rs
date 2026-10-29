use super::*;
use crate::tcp::SendBuf;
use crate::wire::tcp_options::{TcpOpt, walk};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::time::Duration;

fn open(ep: &mut Endpoint<ChaCha20Rng>) -> ConnectionHandle {
    ep.connect_mptcp(
        Instant::from_nanos(0),
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        checksums_cfg(false),
    )
    .unwrap()
}

fn transmit(ep: &mut Endpoint<ChaCha20Rng>, now: Instant) -> Vec<u8> {
    let mut out = vec![0; 1500];
    let len = ep.poll_transmit(now, &mut out).expect("packet due");
    out.truncate(len);
    out
}

fn mpc(options: &[u8]) -> Vec<&[u8]> {
    walk(options)
        .filter_map(|o| match o.unwrap() {
            TcpOpt::Mptcp(raw) => Some(raw),
            _ => None,
        })
        .collect()
}

#[test]
fn capable_syn_uses_version_one_and_only_h() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    assert_eq!(mpc(syn.options), vec![&[30, 4, 1, 1][..]]);
    // With MSS, WS and SACK-Permitted (RFC 2018 §2): 16 octets of the 40.
    let kinds: Vec<_> = walk(syn.options).map(Result::unwrap).collect();
    assert!(matches!(
        kinds[..],
        [
            TcpOpt::Mptcp(_),
            TcpOpt::Mss(_),
            TcpOpt::WindowScale(_),
            TcpOpt::SackPermitted
        ]
    ));
    assert_eq!(syn.options.len(), 16);
}

use crate::wire::mptcp::{self, CAP_H, MpCapable, MptcpOption};
const PEER_KEY: u64 = 0x1020304050607080;
fn capable(version: u8, flags: u8) -> Vec<u8> {
    let mut out = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Capable(MpCapable {
            version,
            flags,
            sender_key: Some(PEER_KEY),
            receiver_key: None,
            data_len: None,
            checksum: None,
        }),
        &mut out,
    )
    .unwrap();
    out[..n].to_vec()
}
fn reply(ep: &mut Endpoint<ChaCha20Rng>, syn: &Segment, options: &[u8], ack: SeqNum) {
    let seg = Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(5000),
        ack,
        flags: TcpFlags::SYN | TcpFlags::ACK,
        wnd: 1234,
        options,
        payload: &[],
    };
    let mut out = [0; 1500];
    let n = packet::build(&seg, 0, &mut out).unwrap();
    ep.handle_packet(Instant::from_nanos(1), &out[..n]);
}

#[test]
fn keys_repeat_after_lost_third_ack_and_event_follows_emission() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(2));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    let options = capable(1, CAP_H);
    reply(&mut ep, &syn, &options, syn.seq.wrapping_add(1));
    assert_eq!(ep.poll_event(), None, "third ACK has not been emitted");
    assert!(
        ep.poll_transmit(Instant::from_nanos(1), &mut [0; 20])
            .is_none()
    );
    assert_eq!(
        ep.poll_event(),
        None,
        "small buffer cannot complete handshake"
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(1));
    let ack = packet::parse(&bytes).unwrap();
    let opts = mpc(ack.options);
    assert_eq!(opts.len(), 1);
    assert_eq!(opts[0].len(), 20);
    let MptcpOption::Capable(c) = mptcp::parse(opts[0]).unwrap() else {
        panic!()
    };
    assert!(c.sender_key.is_some());
    assert_eq!(c.receiver_key, Some(PEER_KEY));
    assert_eq!(ep.poll_event(), Some((h, Event::Connected { mptcp: true })));
    // The server missed that ACK and repeats its SYN/ACK. Every response still carries keys.
    for key in [PEER_KEY, PEER_KEY.wrapping_add(1), PEER_KEY] {
        let mut repeated = options.clone();
        repeated[4..12].copy_from_slice(&key.to_be_bytes());
        reply(&mut ep, &syn, &repeated, syn.seq.wrapping_add(1));
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        assert_eq!(mpc(packet::parse(&bytes).unwrap().options), opts);
        assert_eq!(ep.poll_event(), None);
    }
}

#[test]
fn invalid_synack_option_falls_back_permanently() {
    let good = capable(1, CAP_H);
    let mut cases = vec![
        vec![],
        vec![30, 4, 1, CAP_H],
        vec![30, 12, 1, CAP_H],
        [good.clone(), good.clone()].concat(),
        [good.clone(), vec![99, 1]].concat(),
    ];
    for version in [0, 2, 15] {
        cases.push(capable(version, CAP_H));
    }
    // A=1 (0x81) is valid since M4b: the server requires checksums.
    for flags in [0, 0x41, 0x02, 0x03, 0x05, 0x09, 0x11] {
        cases.push(capable(1, flags));
    }
    for options in cases {
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(2));
        let h = open(&mut ep);
        let bytes = transmit(&mut ep, Instant::from_nanos(0));
        let syn = packet::parse(&bytes).unwrap();
        reply(&mut ep, &syn, &options, syn.seq.wrapping_add(1));
        assert_eq!(ep.poll_event(), None);
        let bytes = transmit(&mut ep, Instant::from_nanos(1));
        assert!(mpc(packet::parse(&bytes).unwrap().options).is_empty());
        assert_eq!(
            ep.poll_event(),
            Some((h, Event::Connected { mptcp: false }))
        );
        reply(&mut ep, &syn, &good, syn.seq.wrapping_add(1));
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        assert!(mpc(packet::parse(&bytes).unwrap().options).is_empty());
        assert_eq!(ep.poll_event(), None);
    }
}

#[test]
fn original_plus_two_capable_syn_retries_then_plain() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(3));
    open(&mut ep);
    let mut now = Instant::from_nanos(0);
    for attempt in 0..6 {
        let bytes = transmit(&mut ep, now);
        let syn = packet::parse(&bytes).unwrap();
        assert_eq!(mpc(syn.options).len(), usize::from(attempt < 3));
        now = ep.poll_timeout().unwrap();
        ep.handle_timeout(now);
    }
}

#[test]
fn syn_timeout_fallback_still_reports_connected_once_after_ack() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(7));
    let h = open(&mut ep);
    let mut now = Instant::from_nanos(0);
    let mut bytes = Vec::new();
    for _ in 0..4 {
        bytes = transmit(&mut ep, now);
        now = ep.poll_timeout().unwrap();
        ep.handle_timeout(now);
    }
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    assert_eq!(ep.poll_event(), None);
    let bytes = transmit(&mut ep, now);
    assert!(mpc(packet::parse(&bytes).unwrap().options).is_empty());
    assert_eq!(
        ep.poll_event(),
        Some((h, Event::Connected { mptcp: false }))
    );
    assert_eq!(ep.poll_event(), None);
}

fn input(ep: &mut Endpoint<ChaCha20Rng>, seg: &Segment) {
    let mut out = [0; 1500];
    let n = packet::build(seg, 0, &mut out).unwrap();
    ep.handle_packet(Instant::from_nanos(2), &out[..n]);
}
fn data_ack(ack: u64) -> Vec<u8> {
    let mut out = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(ack)),
            mapping: None,
        }),
        &mut out,
    )
    .unwrap();
    out[..n].to_vec()
}

#[test]
fn confirmation_requires_tcp_acceptable_well_formed_dss() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(8));
    open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(
        &mut ep,
        &syn,
        &capable(1, CAP_H | mptcp::CAP_C),
        syn.seq.wrapping_add(1),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(1));
    let ack = packet::parse(&bytes).unwrap();
    let MptcpOption::Capable(keys) = mptcp::parse(mpc(ack.options)[0]).unwrap() else {
        panic!()
    };
    let data_ack = data_ack(
        crate::crypto::key_token_idsn(keys.sender_key.unwrap())
            .1
            .wrapping_add(1),
    );
    let good = Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(5001),
        ack: syn.seq.wrapping_add(1),
        flags: TcpFlags::ACK,
        wnd: 1234,
        options: &data_ack,
        payload: &[],
    };
    for bad in [
        Segment {
            seq: SeqNum(4999),
            ..good.clone()
        },
        Segment {
            ack: syn.seq.wrapping_add(100),
            ..good.clone()
        },
        Segment {
            flags: TcpFlags::default(),
            ..good.clone()
        },
    ] {
        input(&mut ep, &bad);
        // Force an ACK even when TCP silently drops a non-ACK.
        reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        assert!(matches!(
            mptcp::parse(mpc(packet::parse(&bytes).unwrap().options)[0]),
            Ok(MptcpOption::Capable(_))
        ));
    }
    for opts in [
        vec![30, 12, 0x20, 3],
        [data_ack.clone(), data_ack.clone()].concat(),
        [data_ack.clone(), vec![99, 1]].concat(),
    ] {
        input(
            &mut ep,
            &Segment {
                options: &opts,
                ..good.clone()
            },
        );
        reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        assert!(matches!(
            mptcp::parse(mpc(packet::parse(&bytes).unwrap().options)[0]),
            Ok(MptcpOption::Capable(_))
        ));
    }
    input(&mut ep, &good);
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let options = mpc(packet::parse(&bytes).unwrap().options);
    let MptcpOption::Dss(dss) = mptcp::parse(options[0]).unwrap() else {
        panic!("expected confirmed DSS")
    };
    assert_eq!(
        dss.data_ack,
        Some(mptcp::DataAck::Ack64(
            crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1)
        ))
    );
}

#[test]
fn synack_installs_dsn_origins_and_unscaled_credit_only_after_tcp_accepts() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(9));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    let opts = [capable(1, CAP_H), vec![3, 3, 14, 1]].concat();
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(2));
    let m = ep.conns[&h].hooks.negotiation.as_ref().unwrap();
    assert_eq!(m.peer_idsn, None);
    assert_eq!(m.send_right_edge, None);
    // Drain the RFC 9293 reset response to the impossible ACK.
    let bytes = transmit(&mut ep, Instant::from_nanos(1));
    assert_eq!(packet::parse(&bytes).unwrap().flags, TcpFlags::RST);
    assert_eq!(ep.poll_event(), None);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    let bytes = transmit(&mut ep, Instant::from_nanos(1));
    let ack = packet::parse(&bytes).unwrap();
    let MptcpOption::Capable(c) = mptcp::parse(mpc(ack.options)[0]).unwrap() else {
        panic!()
    };
    let m = ep.conns[&h].hooks.negotiation.as_ref().unwrap();
    let (token, idsn) = crate::crypto::key_token_idsn(c.sender_key.unwrap());
    assert_eq!(m.token, token);
    assert_eq!(m.local_idsn, idsn);
    assert_eq!(m.peer_idsn, Some(crate::crypto::key_token_idsn(PEER_KEY).1));
    assert_eq!(m.send_right_edge, Some(idsn.wrapping_add(1 + 1234)));
}

#[test]
fn dss_before_third_ack_does_not_omit_keys() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(12));
    open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    let dss = data_ack(0);
    input(
        &mut ep,
        &Segment {
            src: syn.dst,
            dst: syn.src,
            seq: SeqNum(5001),
            ack: syn.seq.wrapping_add(1),
            flags: TcpFlags::ACK,
            wnd: 1234,
            options: &dss,
            payload: &[],
        },
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(matches!(
        mptcp::parse(mpc(packet::parse(&bytes).unwrap().options)[0]),
        Ok(MptcpOption::Capable(_))
    ));
}

#[test]
fn token_collision_regenerates_key_and_time_wait_reserves_token() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(13));
    let before_open = ep.rng.clone();
    let a = open(&mut ep);
    let token_a = ep.conns[&a].hooks.negotiation.as_ref().unwrap().token;
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    ep.poll_event();
    let local_fin = ep.conns[&a].hooks.data.as_ref().unwrap().send.end;
    let peer_fin = ep.conns[&a].hooks.data.as_ref().unwrap().recv.next;
    ep.connection(a).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(!packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));
    input(
        &mut ep,
        &peer_data(&syn, 5001, &data_ack(local_fin.wrapping_add(1)), &[]),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));
    let opts = fin_option(peer_fin, 0, 1, Some(local_fin.wrapping_add(1)));
    let seg = Segment {
        ack: syn.seq.wrapping_add(2),
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ..peer_data(&syn, 5001, &opts, &[])
    };
    input(&mut ep, &seg);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(
        dack(&packet::parse(&bytes).unwrap()),
        peer_fin.wrapping_add(1)
    );
    ep.handle_timeout(Instant::from_nanos(2));
    assert_eq!(ep.conns[&a].subflows[0].tcb.state(), TcpState::TimeWait);
    assert_eq!(
        ep.poll_event(),
        None,
        "TCP TIME_WAIT is not connection closure"
    );
    // Lost final DATA_ACK: repeat the FIN below the receive window in TIME_WAIT.
    input(&mut ep, &seg);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(
        dack(&packet::parse(&bytes).unwrap()),
        peer_fin.wrapping_add(1)
    );
    input(
        &mut ep,
        &Segment {
            seq: SeqNum(5002),
            flags: TcpFlags::ACK,
            ..seg.clone()
        },
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(
        dack(&packet::parse(&bytes).unwrap()),
        peer_fin.wrapping_add(1)
    );
    // Rewind injected randomness: port probing then generates the exact same first key.
    ep.rng = before_open.clone();
    let b = open(&mut ep);
    assert_ne!(
        ep.conns[&b].hooks.negotiation.as_ref().unwrap().token,
        token_a
    );
    ep.connection(b).unwrap().close();
    ep.handle_timeout(Instant::from_nanos(2));
    assert!(!ep.conns.contains_key(&b));
    let deadline = ep.poll_timeout().unwrap();
    assert_eq!(deadline, Instant::from_nanos(2) + Duration::from_secs(120));
    ep.handle_timeout(deadline);
    // The other connection was closed during SYN-SENT; drain its Normal first.
    assert_eq!(
        ep.poll_event(),
        Some((
            b,
            Event::Closed {
                reason: CloseReason::Normal
            }
        ))
    );
    assert_eq!(
        ep.poll_event(),
        Some((
            a,
            Event::Closed {
                reason: CloseReason::Normal
            }
        ))
    );
    assert_eq!(ep.poll_event(), None);
    assert!(!ep.conns.contains_key(&a));
    ep.rng = before_open;
    let c = open(&mut ep);
    assert_eq!(
        ep.conns[&c].hooks.negotiation.as_ref().unwrap().token,
        token_a,
        "final teardown releases the token"
    );
}

#[test]
fn capable_has_priority_over_sack_and_dsack_within_forty_bytes() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(14));
    open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    let options = [capable(1, CAP_H), vec![4, 2, 1, 1]].concat();
    reply(&mut ep, &syn, &options, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    // Exercise TCP receipt bookkeeping; interpreting MPTCP payload is Step 2.
    for seq in [5010, 5020, 5030, 5030] {
        input(
            &mut ep,
            &Segment {
                src: syn.dst,
                dst: syn.src,
                seq: SeqNum(seq),
                ack: syn.seq.wrapping_add(1),
                flags: TcpFlags::ACK,
                wnd: 1234,
                options: &[],
                payload: b"x",
            },
        );
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        let ack = packet::parse(&bytes).unwrap();
        let opts: Vec<_> = walk(ack.options).map(Result::unwrap).collect();
        assert!(matches!(opts[0], TcpOpt::Mptcp(raw) if raw.len() == 20));
        let TcpOpt::Sack(blocks) = opts[1] else {
            panic!()
        };
        assert_eq!(&blocks[..4], &seq.to_be_bytes());
        // 40 − 20 octets leave room for exactly two blocks once two ranges are held.
        assert_eq!(blocks.len(), if seq == 5010 { 8 } else { 16 });
        assert!(ack.options.len() <= 40);
        assert_eq!(ack.options.len() % 4, 0);
    }
}

#[test]
fn all_synack_flags_and_option_lengths_are_checked() {
    for flags in 0..=255 {
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(15));
        let h = open(&mut ep);
        let bytes = transmit(&mut ep, Instant::from_nanos(0));
        let syn = packet::parse(&bytes).unwrap();
        reply(&mut ep, &syn, &capable(1, flags), syn.seq.wrapping_add(1));
        let bytes = transmit(&mut ep, Instant::from_nanos(1));
        // C and A are free (A: the server requires checksums, M4b).
        let valid = flags & !(mptcp::CAP_C | mptcp::CAP_A) == CAP_H;
        assert_eq!(
            mpc(packet::parse(&bytes).unwrap().options).len(),
            usize::from(valid)
        );
        assert_eq!(
            ep.poll_event(),
            Some((h, Event::Connected { mptcp: valid }))
        );
    }
    for len in 0..=40 {
        if len == 12 {
            continue;
        }
        let mut opts = vec![0; len.max(2)];
        opts[0] = 30;
        opts[1] = len as u8;
        if len >= 4 {
            opts[2] = 1;
            opts[3] = CAP_H;
        }
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(16));
        let h = open(&mut ep);
        let bytes = transmit(&mut ep, Instant::from_nanos(0));
        let syn = packet::parse(&bytes).unwrap();
        reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
        transmit(&mut ep, Instant::from_nanos(1));
        assert_eq!(
            ep.poll_event(),
            Some((h, Event::Connected { mptcp: false })),
            "length {len}"
        );
    }
}

fn mapping(ssn: u32, dsn: u64, len: u16) -> Vec<u8> {
    let mut out = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: None,
            mapping: Some(mptcp::Mapping {
                ssn,
                dsn: mptcp::Dsn::Dsn64(dsn),
                data_len: len,
                checksum: None,
            }),
        }),
        &mut out,
    )
    .unwrap();
    out[..n].to_vec()
}

#[test]
fn dsn_receive_bypasses_ssn_window_and_acks_only_dsn_window_bytes() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(17));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let dsn = crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1);
    // A fresh SSN outside the last subflow window carries the in-order connection head.
    let opts = mapping(5_000_000, dsn, 3);
    let seg = Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(5_005_000),
        ack: syn.seq.wrapping_add(1),
        flags: TcpFlags::ACK,
        wnd: 1234,
        options: &opts,
        payload: b"abc",
    };
    input(&mut ep, &seg);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let ack = packet::parse(&bytes).unwrap();
    assert_eq!(ack.ack, SeqNum(5001));
    let MptcpOption::Dss(dss) = mptcp::parse(mpc(ack.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(
        dss.data_ack,
        Some(mptcp::DataAck::Ack64(dsn.wrapping_add(3)))
    );
    let mut buf = [0; 3];
    assert_eq!(ep.connection(h).unwrap().read(&mut buf), Ok(3));
    assert_eq!(&buf, b"abc");
    // Out-of-DSN-window data at the TCP head cannot advance TCP ACK.
    let opts = mapping(1, dsn.wrapping_add(10_000_000), 3);
    input(
        &mut ep,
        &Segment {
            seq: SeqNum(5001),
            options: &opts,
            ..seg.clone()
        },
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().ack, SeqNum(5001));
}

#[test]
fn unmapped_data_is_tcp_acked_but_not_delivered() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(18));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let seg = Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(5001),
        ack: syn.seq.wrapping_add(1),
        flags: TcpFlags::ACK,
        wnd: 1234,
        options: &[],
        payload: b"abc",
    };
    input(&mut ep, &seg);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().ack, SeqNum(5004));
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 3]),
        Err(crate::connection::ReadError::WouldBlock)
    );
}

fn connected_with_capacity(cap: u32) -> (Endpoint<ChaCha20Rng>, ConnectionHandle, Vec<u8>, u64) {
    connected_with_capacity_cc(cap, None)
}
fn connected_with_capacity_cc(
    cap: u32,
    cc: Option<fn() -> Box<dyn crate::tcp::cc::CongestionControl>>,
) -> (Endpoint<ChaCha20Rng>, ConnectionHandle, Vec<u8>, u64) {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(19));
    ep.cc = cc;
    let h = ep
        .connect_mptcp(
            Instant::from_nanos(0),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            ConnectConfig {
                recv_buffer: cap,
                ..checksums_cfg(false)
            },
        )
        .unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    ep.poll_event();
    (
        ep,
        h,
        bytes,
        crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1),
    )
}
fn peer_data<'a>(syn: &Segment, seq: u32, options: &'a [u8], payload: &'a [u8]) -> Segment<'a> {
    Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(seq),
        ack: syn.seq.wrapping_add(1),
        flags: TcpFlags::ACK,
        wnd: 1234,
        options,
        payload,
    }
}
fn dack(seg: &Segment) -> u64 {
    let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    let Some(mptcp::DataAck::Ack64(a)) = d.data_ack else {
        panic!()
    };
    a
}

#[test]
fn data_held_beyond_memory_advances_tcp_ack_only() {
    let (mut ep, h, bytes, dsn) = connected_with_capacity(4);
    let syn = packet::parse(&bytes).unwrap();
    ep.conns
        .get_mut(&h)
        .unwrap()
        .hooks
        .data
        .as_mut()
        .unwrap()
        .recv
        .right_edge = dsn.wrapping_add(6);
    input(
        &mut ep,
        &peer_data(&syn, 5001, &mapping(1, dsn, 4), b"abcd"),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().ack, SeqNum(5005));
    input(
        &mut ep,
        &peer_data(&syn, 5005, &mapping(5, dsn.wrapping_add(4), 2), b"ef"),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let ack = packet::parse(&bytes).unwrap();
    assert_eq!(ack.ack, SeqNum(5007));
    assert_eq!(dack(&ack), dsn.wrapping_add(4));
    let mut out = [0; 8];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(4));
    assert_eq!(&out[..4], b"abcd");
    // The held copy was delivered by the read; a reinjection on new SSNs is a duplicate.
    input(
        &mut ep,
        &peer_data(&syn, 5007, &mapping(7, dsn.wrapping_add(4), 2), b"ef"),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(dack(&packet::parse(&bytes).unwrap()), dsn.wrapping_add(6));
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(2));
    assert_eq!(&out[..2], b"ef");
}

#[test]
fn conflicting_mapping_resets_only_after_tcp_validity() {
    let (mut ep, h, bytes, dsn) = connected_with_capacity(64);
    let syn = packet::parse(&bytes).unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &mapping(1, dsn, 4), b"ab"));
    transmit(&mut ep, Instant::from_nanos(2));
    let opts = mapping(1, dsn.wrapping_add(1), 4);
    let mut seg = peer_data(&syn, 5003, &opts, b"cd");
    seg.ack = syn.seq.wrapping_add(2); // ACKs unsent sequence space
    input(&mut ep, &seg);
    transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(ep.poll_event(), None);
    seg.ack = syn.seq.wrapping_add(1);
    input(&mut ep, &seg);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::RST));
    assert_eq!(ep.poll_event(), Some((h, initial_down(CloseReason::Reset))));
    assert_eq!(ep.conns[&h].subflows[0].tcb.state(), TcpState::Closed);
    assert!(ep.conns[&h].hooks.retained());
}

#[test]
fn unmapped_byte_bound_resets_subflow() {
    let (mut ep, h, bytes, _) = connected_with_capacity(4);
    let syn = packet::parse(&bytes).unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &[], b"abcd"));
    transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(ep.poll_event(), None);
    input(&mut ep, &peer_data(&syn, 5005, &[], b"e"));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::RST));
    assert_eq!(ep.poll_event(), Some((h, initial_down(CloseReason::Reset))));
    assert_eq!(ep.conns[&h].subflows[0].tcb.state(), TcpState::Closed);
    assert!(ep.conns[&h].hooks.retained());
}

#[test]
fn initial_mpc_and_equivalent_dss_deliver_once() {
    let (mut ep, h, bytes, dsn) = connected_with_capacity(64);
    let syn = packet::parse(&bytes).unwrap();
    let local_key = {
        reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
        let ack = transmit(&mut ep, Instant::from_nanos(2));
        let packet = packet::parse(&ack).unwrap();
        let MptcpOption::Capable(c) = mptcp::parse(mpc(packet.options)[0]).unwrap() else {
            panic!()
        };
        c.sender_key.unwrap()
    };
    let mut opts = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Capable(MpCapable {
            version: 1,
            flags: CAP_H,
            sender_key: Some(PEER_KEY),
            receiver_key: Some(local_key),
            data_len: Some(4),
            checksum: None,
        }),
        &mut opts,
    )
    .unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &opts[..n], b"ab"));
    transmit(&mut ep, Instant::from_nanos(2));
    input(
        &mut ep,
        &peer_data(&syn, 5001, &mapping(1, dsn, 4), b"abcd"),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(dack(&packet::parse(&bytes).unwrap()), dsn.wrapping_add(4));
    let mut out = [0; 8];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(4));
    assert_eq!(&out[..4], b"abcd");
    assert_eq!(
        ep.connection(h).unwrap().read(&mut out),
        Err(crate::connection::ReadError::WouldBlock)
    );
}

#[test]
fn ack32_promotion_releases_connection_store_only_with_tcp_ack() {
    let (mut ep, h, bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&bytes).unwrap();
    let c = ep.conns.get_mut(&h).unwrap();
    let d = c.hooks.data.as_mut().unwrap();
    // Install a wrapped send origin before any application data.
    d.send = crate::mptcp::data::SendStore::new(u64::MAX - 1, 4);
    assert_eq!(d.send.write(b"abcd"), 4);
    assert!(
        d.send
            .assign(&mut c.subflows[0].mp.tx, u64::MAX - 1, 4, false)
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().payload, b"abcd");
    let mut opts = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack32(2)),
            mapping: None,
        }),
        &mut opts,
    )
    .unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &opts[..n], &[]));
    let d = ep.conns.get_mut(&h).unwrap().hooks.data.as_mut().unwrap();
    assert_eq!(d.send.una, 2);
    assert_eq!(d.send.write(b"e"), 0);
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.ack = syn.seq.wrapping_add(5);
    input(&mut ep, &ack);
    let d = ep.conns.get_mut(&h).unwrap().hooks.data.as_mut().unwrap();
    assert_eq!(d.send.write(b"e"), 1);
}

#[test]
fn queued_handshake_bytes_move_into_connection_store() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(20));
    let h = open(&mut ep);
    assert_eq!(ep.connection(h).unwrap().write(b"abcd"), Ok(4));
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert_eq!(d.send.end.wrapping_sub(d.send.una), 4);
}

#[test]
fn peer_dsn_signed_boundary_preserves_tcp_and_data_ack_rules() {
    for offset in [i64::MAX, i64::MAX - 1, i64::MIN, i64::MIN + 1] {
        let (mut ep, h, bytes, dsn) = connected_with_capacity(64);
        let syn = packet::parse(&bytes).unwrap();
        let opts = mapping(1, dsn.wrapping_add_signed(offset), 2);
        input(&mut ep, &peer_data(&syn, 5001, &opts, b"ab"));
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        let ack = packet::parse(&bytes).unwrap();
        assert_eq!(ack.ack, SeqNum(if offset > 0 { 5001 } else { 5003 }));
        assert_eq!(dack(&ack), dsn);
        assert_eq!(
            ep.connection(h).unwrap().read(&mut [0; 2]),
            Err(crate::connection::ReadError::WouldBlock)
        );
    }
}

#[test]
fn automatic_initial_mapping_reserves_dss_and_retransmits_immutable_mapping() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().write(&vec![7; 1600]).unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.payload.len(), 508); // default peer MSS 536 minus DSS layout 28
    assert_eq!(seg.options.len(), 24);
    let MptcpOption::Capable(c) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(c.data_len, Some(1016)); // two full segments fit initial unscaled 1234 credit
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().payload.len(), 508);
    assert!(
        ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
            .is_none()
    );
    // Partial TCP ACK confirms DSS; retransmission must retain full original coordinates.
    let mut options = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(origin)),
            mapping: None,
        }),
        &mut options,
    )
    .unwrap();
    let mut ack = peer_data(&syn, 5001, &options[..n], &[]);
    ack.ack = syn.seq.wrapping_add(101);
    input(&mut ep, &ack);
    ep.handle_timeout(Instant::from_nanos(2_000_000_000));
    let bytes = transmit(&mut ep, Instant::from_nanos(2_000_000_000));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.seq, syn.seq.wrapping_add(101));
    let MptcpOption::Dss(dss) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    let mapping = dss.mapping.unwrap();
    assert_eq!(mapping.ssn, 1);
    assert_eq!(mapping.dsn, mptcp::Dsn::Dsn64(origin));
    assert_eq!(mapping.data_len, 1016);
    assert_eq!(seg.options.len(), 28);
}

#[test]
fn shared_window_read_reopens_and_peer_window_requires_valid_data_ack() {
    let (mut ep, h, syn_bytes, dsn) = connected_with_capacity(8);
    let syn = packet::parse(&syn_bytes).unwrap();
    input(
        &mut ep,
        &peer_data(&syn, 5001, &mapping(1, dsn, 8), b"abcdefgh"),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().wnd, 0);
    ep.connection(h).unwrap().read(&mut [0; 8]).unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().wnd, 8);
    input(
        &mut ep,
        &peer_data(&syn, 5009, &mapping(9, dsn.wrapping_add(8), 1), b"i"),
    );
    assert_eq!(ep.connection(h).unwrap().read(&mut [0; 1]), Ok(1));
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    for (ack, window, expected) in [
        (origin.wrapping_sub(1), 6000, 1234),
        (origin.wrapping_add(1), 6000, 1234),
        (origin, 5000, 5000),
        (origin, 1, 5000),
    ] {
        let mut options = [0; 40];
        let n = mptcp::encode(
            &MptcpOption::Dss(mptcp::Dss {
                data_fin: false,
                data_ack: Some(mptcp::DataAck::Ack64(ack)),
                mapping: None,
            }),
            &mut options,
        )
        .unwrap();
        let mut seg = peer_data(&syn, 5010, &options[..n], &[]);
        seg.wnd = window;
        input(&mut ep, &seg);
        assert_eq!(
            ep.conns[&h]
                .hooks
                .negotiation
                .as_ref()
                .unwrap()
                .send_right_edge,
            Some(origin.wrapping_add(expected))
        );
    }
}

#[test]
fn connection_window_persists_without_assigned_bytes_and_recovers_lost_update() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().set_nodelay(true);
    ep.connection(h).unwrap().write(&vec![3; 1235]).unwrap();
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    for _ in 0..3 {
        transmit(&mut ep, Instant::from_nanos(2));
    }
    let next = origin.wrapping_add(1234);
    let mut options = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(next)),
            mapping: None,
        }),
        &mut options,
    )
    .unwrap();
    let mut ack = peer_data(&syn, 5001, &options[..n], &[]);
    ack.ack = syn.seq.wrapping_add(1235);
    ack.wnd = 0;
    input(&mut ep, &ack);
    assert!(
        ep.poll_transmit(Instant::from_nanos(3), &mut [0; 1500])
            .is_none()
    );
    // Even repeated answers for longer than R2 must not close the connection.
    for sec in [2, 5, 10, 20, 40, 80, 140, 200] {
        let now = Instant::from_nanos(sec * 1_000_000_000);
        ep.handle_timeout(now);
        let bytes = transmit(&mut ep, now);
        let probe = packet::parse(&bytes).unwrap();
        assert_eq!(probe.seq, syn.seq.wrapping_add(1234));
        assert!(probe.payload.is_empty());
        assert_eq!(ep.conns[&h].hooks.data.as_ref().unwrap().send.next, next);
        let mut wire = [0; 1500];
        let len = packet::build(&ack, 0, &mut wire).unwrap();
        ep.handle_packet(now, &wire[..len]);
        ep.poll_transmit(now, &mut wire);
    }
    // The initial reopening ACK was lost; a response to a later probe supplies the credit.
    ack.wnd = 16;
    let mut wire = [0; 1500];
    let len = packet::build(&ack, 0, &mut wire).unwrap();
    ep.handle_packet(Instant::from_nanos(201_000_000_000), &wire[..len]);
    let bytes = transmit(&mut ep, Instant::from_nanos(201_000_000_000));
    assert_eq!(packet::parse(&bytes).unwrap().payload, &[3]);
}

#[test]
fn write_boundary_does_not_bypass_sender_sws_and_timeout_releases_whole_window() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().write(&[1; 8]).unwrap();
    ep.connection(h).unwrap().write(&[2; 1000]).unwrap();
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.wnd = 100;
    input(&mut ep, &ack);
    assert!(
        ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
            .is_none()
    );
    let deadline = ep
        .poll_timeout()
        .expect("SWS override for unassigned bytes");
    assert!(deadline <= Instant::from_nanos(500_000_002));
    ep.handle_timeout(deadline);
    let bytes = transmit(&mut ep, deadline);
    // One segment fills the window across the write boundary.
    assert_eq!(
        packet::parse(&bytes).unwrap().payload,
        [[1; 8].as_slice(), &[2; 92]].concat()
    );
}

#[test]
fn padded_dss_and_sack_fit_tiny_mss_and_mapping_splits() {
    for mss in [28u16, 29, 40, 64] {
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(21));
        let h = open(&mut ep);
        let bytes = transmit(&mut ep, Instant::from_nanos(0));
        let syn = packet::parse(&bytes).unwrap();
        let mut opts = capable(1, CAP_H);
        let mut tcp = [0; 8];
        let n = crate::wire::tcp_options::write_mss(&mut tcp, mss);
        opts.extend_from_slice(&tcp[..n]);
        let n = crate::wire::tcp_options::write_sack_permitted(&mut tcp);
        opts.extend_from_slice(&tcp[..n]);
        reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
        transmit(&mut ep, Instant::from_nanos(1));
        ep.connection(h).unwrap().set_nodelay(true);
        ep.connection(h).unwrap().write(&[3; 100]).unwrap();
        let dsn = crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1);
        input(
            &mut ep,
            &peer_data(&syn, 5003, &mapping(3, dsn.wrapping_add(2), 2), b"ab"),
        );
        // The ACK first reports the out-of-order receipt, then data coexists with SACK.
        transmit(&mut ep, Instant::from_nanos(2));
        let mut wire = [0; 1500];
        let n = ep.poll_transmit(Instant::from_nanos(2), &mut wire);
        if mss == 28 {
            assert!(n.is_none());
            continue;
        }
        let seg = packet::parse(&wire[..n.unwrap()]).unwrap();
        assert!(seg.options.len() + seg.payload.len() <= usize::from(mss));
        assert_eq!(seg.options.len(), if mss > 40 { 40 } else { 28 });
        if mss > 40 {
            assert!(walk(seg.options).any(|o| matches!(o, Ok(TcpOpt::Sack(_)))));
        }
        let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
            panic!()
        };
        assert!(usize::from(d.mapping.unwrap().data_len) >= seg.payload.len());
    }
}

#[test]
fn shared_window_scaling_rounds_only_to_preserve_edge() {
    let mut recv = crate::mptcp::data::RecvAssembler::new(1000, 10, 4);
    assert_eq!(recv.window_offer(2, 536), 3); // 10-byte promise rounds to 12
    recv.window_sent(3, 2);
    recv.accept(1000, b"abcdefghij");
    assert_eq!(recv.free(), 0);
    assert_eq!(recv.window_offer(2, 536), 1); // preserves promise despite memory pressure
    recv.window_sent(1, 2);
    assert_eq!(recv.right_edge, 1014);
    recv.read(&mut [0; 10]);
    assert_eq!(recv.window_offer(2, 536), 2); // floor(10 / 4), sufficient to move edge
    recv.window_sent(2, 2);
    assert_eq!(recv.right_edge, 1018);
}

/// Data-Level Length of the DSS mapping or MP_CAPABLE data form a segment carries.
fn mapped_len(seg: &Segment) -> u16 {
    match mptcp::parse(mpc(seg.options)[0]).unwrap() {
        MptcpOption::Dss(d) => d.mapping.unwrap().data_len,
        MptcpOption::Capable(c) => c.data_len.unwrap(),
        _ => panic!("no mapping"),
    }
}

#[test]
fn short_write_joins_the_next_write_in_a_full_segment_at_once() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().write(&[1; 8]).unwrap();
    ep.connection(h).unwrap().write(&[2; 2000]).unwrap();
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.wnd = 1000;
    input(&mut ep, &ack);
    // A full segment is sendable (RFC 9293 §3.8.6.2.1 (1)): no SWS override wait.
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.payload, [[1; 8].as_slice(), &[2; 500]].concat());
    assert_eq!(mapped_len(&seg), 508, "one mapping spans both writes");
}

/// Cumulative payload octets sent after each 20 ms round of a bulk transfer written in 64 KiB
/// pieces (as the TUN client does), the peer acknowledging every segment through a 4 MiB
/// window. `mptcp = false` answers the SYN without MP_CAPABLE: the plain-TCP path.
fn bulk_rounds(mptcp: bool, rounds: u64) -> Vec<u64> {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(26));
    let h = open(&mut ep);
    let syn_bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&syn_bytes).unwrap();
    let mut opts = if mptcp { capable(1, CAP_H) } else { Vec::new() };
    let mut o = [0; 4];
    let n = crate::wire::tcp_options::write_mss(&mut o, 1460);
    opts.extend_from_slice(&o[..n]);
    let n = crate::wire::tcp_options::write_ws(&mut o, 7);
    opts.extend_from_slice(&o[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let data_base = ep.conns[&h].hooks.data.as_ref().map(|d| d.send.una);
    assert_eq!(data_base.is_some(), mptcp);
    let chunk = [5; 65536];
    for _ in 0..6 {
        assert_eq!(ep.connection(h).unwrap().write(&chunk), Ok(chunk.len()));
    }
    let (mut sent, mut cumulative) = (0, Vec::new());
    for round in 0..rounds {
        let now = Instant::from_nanos(1 + round * 20_000_000);
        let mut ends = Vec::new();
        let mut out = [0; 1500];
        while let Some(n) = ep.poll_transmit(now, &mut out) {
            let seg = packet::parse(&out[..n]).unwrap();
            sent += seg.payload.len() as u64;
            ends.push(seg.seq.wrapping_add(seg.payload.len() as u32));
        }
        cumulative.push(sent);
        for end in ends {
            let options = data_base.map_or_else(Vec::new, |base| {
                data_ack(base.wrapping_add(u64::from(end.0.wrapping_sub(syn.seq.0) - 1)))
            });
            let ack = Segment {
                ack: end,
                wnd: 32768,
                ..peer_data(&syn, 5001, &options, &[])
            };
            let mut wire = [0; 1500];
            let n = packet::build(&ack, 0, &mut wire).unwrap();
            ep.handle_packet(now, &wire[..n]);
        }
    }
    cumulative
}

#[test]
fn bulk_send_across_write_boundaries_keeps_pace_with_plain_tcp() {
    // A mapping may cover several application writes: the sub-MSS tail of one 64 KiB write is
    // not a short segment while the next write is queued behind it (RFC 9293 §3.8.6.2.1 (1)),
    // so the sender never idles for the SWS override timer, and its window grows like TCP's.
    let plain = bulk_rounds(false, 8);
    let mptcp = bulk_rounds(true, 8);
    for (round, (p, m)) in plain.iter().zip(&mptcp).enumerate() {
        assert!(
            m + 1460 * (round as u64 + 1) >= *p,
            "round {round}: MPTCP {mptcp:?} vs plain {plain:?}"
        );
    }
}

#[test]
fn signaling_acks_do_not_trigger_fast_retransmit_but_dss_duplicates_do() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().write(&[8; 100]).unwrap();
    transmit(&mut ep, Instant::from_nanos(2));
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    for _ in 0..4 {
        input(&mut ep, &peer_data(&syn, 5001, &capable(1, CAP_H), &[]));
        assert!(
            ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
                .is_none()
        );
    }
    let mut options = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(origin)),
            mapping: None,
        }),
        &mut options,
    )
    .unwrap();
    for _ in 0..2 {
        input(&mut ep, &peer_data(&syn, 5001, &options[..n], &[]));
        assert!(
            ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
                .is_none()
        );
    }
    input(&mut ep, &peer_data(&syn, 5001, &options[..n], &[]));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.seq, syn.seq.wrapping_add(1));
    assert_eq!(seg.payload, &[8; 100]);
}

#[test]
fn syn_credit_is_unscaled_then_data_ack_window_uses_negotiated_scale() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(22));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    let mut opts = capable(1, CAP_H);
    let mut ws = [0; 4];
    let n = crate::wire::tcp_options::write_ws(&mut ws, 3);
    opts.extend_from_slice(&ws[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    assert_eq!(
        ep.conns[&h]
            .hooks
            .negotiation
            .as_ref()
            .unwrap()
            .send_right_edge,
        Some(origin.wrapping_add(1234))
    );
    let mut options = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(origin)),
            mapping: None,
        }),
        &mut options,
    )
    .unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &options[..n], &[]));
    assert_eq!(
        ep.conns[&h]
            .hooks
            .negotiation
            .as_ref()
            .unwrap()
            .send_right_edge,
        Some(origin.wrapping_add(1234 << 3))
    );
    // A much larger window without DATA_ACK cannot change the connection edge.
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.wnd = 65535;
    input(&mut ep, &ack);
    assert_eq!(
        ep.conns[&h]
            .hooks
            .negotiation
            .as_ref()
            .unwrap()
            .send_right_edge,
        Some(origin.wrapping_add(1234 << 3))
    );
}

#[test]
fn dsack_coexists_with_covering_mapping_when_remainder_is_split() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(23));
    let h = open(&mut ep);
    let syn_bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&syn_bytes).unwrap();
    let mut opts = capable(1, CAP_H);
    let mut sack = [0; 4];
    let n = crate::wire::tcp_options::write_sack_permitted(&mut sack);
    opts.extend_from_slice(&sack[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let dsn = crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1);
    let map = mapping(1, dsn, 2);
    input(&mut ep, &peer_data(&syn, 5001, &map, b"ab"));
    transmit(&mut ep, Instant::from_nanos(2));
    ep.connection(h).unwrap().write(&[4; 1600]).unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().payload.len(), 508);
    input(&mut ep, &peer_data(&syn, 5001, &map, b"ab"));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.options.len(), 40);
    assert_eq!(seg.payload.len(), 496);
    assert!(walk(seg.options).any(|o| matches!(o, Ok(TcpOpt::Sack(_)))));
    let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    let map = d.mapping.unwrap();
    assert_eq!(map.ssn, 1);
    assert_eq!(map.data_len, 1016);
}

#[test]
fn read_advertises_shared_edge_after_sws_threshold_even_with_open_window() {
    let (mut ep, h, syn_bytes, dsn) = connected_with_capacity(10000);
    let syn = packet::parse(&syn_bytes).unwrap();
    input(
        &mut ep,
        &peer_data(&syn, 5001, &mapping(1, dsn, 1000), &[1; 1000]),
    );
    transmit(&mut ep, Instant::from_nanos(2));
    ep.connection(h).unwrap().read(&mut [0; 1000]).unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().wnd, 10000);
}

#[test]
fn sws_partial_budget_covers_the_run_across_write_boundaries() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(24));
    let h = open(&mut ep);
    let syn_bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&syn_bytes).unwrap();
    let mut opts = capable(1, CAP_H);
    let mut mss = [0; 4];
    let n = crate::wire::tcp_options::write_mss(&mut mss, 1000);
    opts.extend_from_slice(&mss[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    ep.connection(h).unwrap().write(&[1; 8]).unwrap();
    ep.connection(h).unwrap().write(&[2; 2000]).unwrap();
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.next;
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.wnd = 500;
    input(&mut ep, &ack);
    assert!(
        ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
            .is_none()
    );
    assert_eq!(
        ep.conns[&h].hooks.data.as_ref().unwrap().send.next,
        origin,
        "nothing assigned before it can send"
    );
    // Half the largest window (RFC 9293 §3.8.6.2.1 (3)) goes as one segment and one mapping.
    ack.wnd = 800;
    input(&mut ep, &ack);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.payload, [[1; 8].as_slice(), &[2; 792]].concat());
    assert_eq!(mapped_len(&seg), 800);
}

#[test]
fn connection_probe_demand_does_not_block_already_credited_mapping() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(25));
    let h = open(&mut ep);
    let syn_bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&syn_bytes).unwrap();
    let mut opts = capable(1, CAP_H);
    let mut mss = [0; 4];
    let n = crate::wire::tcp_options::write_mss(&mut mss, 645);
    opts.extend_from_slice(&mss[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    ep.connection(h).unwrap().write(&[7; 2000]).unwrap();
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.next;
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().payload.len(), 617);
    assert_eq!(
        ep.conns[&h].hooks.data.as_ref().unwrap().send.next,
        origin.wrapping_add(1234)
    );
    // The first segment is acknowledged before the second is polled. No TCP bytes remain
    // in flight, but the second half of this mapping already owns connection credit.
    let mut opts = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(origin.wrapping_add(617))),
            mapping: None,
        }),
        &mut opts,
    )
    .unwrap();
    let mut ack = peer_data(&syn, 5001, &opts[..n], &[]);
    ack.ack = syn.seq.wrapping_add(618);
    ack.wnd = 617;
    input(&mut ep, &ack);
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.seq, syn.seq.wrapping_add(618));
    assert_eq!(seg.payload, &[7; 617]);
    let MptcpOption::Dss(dss) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(dss.mapping.unwrap().data_len, 1234);
    assert_eq!(
        ep.conns[&h].hooks.data.as_ref().unwrap().send.next,
        origin.wrapping_add(1234)
    );
}

#[test]
fn tcp_acked_without_data_ack_reinjects_with_new_ssn_and_backoff() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"lost").unwrap();
    let first = transmit(&mut ep, Instant::from_nanos(2));
    let first = packet::parse(&first).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let options = data_ack(head); // TCP received it, DSN assembler discarded it.
    let mut ack = peer_data(&syn, 5001, &options, &[]);
    ack.ack = first.seq.wrapping_add(4);
    input(&mut ep, &ack);
    let deadline = ep.poll_timeout().expect("connection recovery timer");
    ep.handle_timeout(deadline);
    let retry = transmit(&mut ep, deadline);
    let retry = packet::parse(&retry).unwrap();
    assert_eq!(retry.seq, first.seq.wrapping_add(4));
    assert_eq!(retry.payload, b"lost");
    let MptcpOption::Dss(d) = mptcp::parse(mpc(retry.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(d.mapping.unwrap().dsn, mptcp::Dsn::Dsn64(head));
    assert!(ep.poll_transmit(deadline, &mut [0; 1500]).is_none());
    ack.ack = retry.seq.wrapping_add(4);
    let mut bytes = [0; 1500];
    let n = packet::build(&ack, 0, &mut bytes).unwrap();
    ep.handle_packet(deadline, &bytes[..n]);
    let second = ep.poll_timeout().unwrap();
    assert!(second - deadline >= std::time::Duration::from_secs(2));
    ep.handle_timeout(second);
    let retry = transmit(&mut ep, second);
    assert_eq!(packet::parse(&retry).unwrap().payload, b"lost");
}

/// `connected_with_capacity`, "first" sent and ACKed without any MPTCP option, so the
/// connection falls back (RFC 8684 L2313–2328). Returns the endpoint, its handle, our SYN and
/// the head DSN.
fn stripped_fallback() -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Segment<'static>,
    u64,
) {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(syn.leak()).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    ep.connection(h).unwrap().write(b"first").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.ack = sent.seq.wrapping_add(5);
    ack.wnd = 65535;
    input(&mut ep, &ack);
    assert_eq!(
        ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
        crate::mptcp::State::FellBack
    );
    (ep, h, syn, head)
}

/// The DSN of `seg`'s first payload octet by the infinite mapping it carries.
fn placed_by_infinite_mapping(seg: &Segment, syn: &Segment) -> u64 {
    let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!("no DSS")
    };
    let m = d.mapping.expect("a mapping");
    assert_eq!((m.data_len, d.data_ack), (0, None), "the infinite mapping");
    let mptcp::Dsn::Dsn64(dsn) = m.dsn else {
        panic!()
    };
    dsn + u64::from(seg.seq.0.wrapping_sub(syn.seq.0).wrapping_sub(m.ssn))
}

/// The ACK-only copy of our infinite mapping and the data segment after it are both lost: the
/// retransmission carries the mapping and places its octets at their DSN. Once the peer
/// acknowledges it, data goes as plain TCP.
#[test]
fn infinite_mapping_rides_on_retransmission() {
    let (mut ep, h, syn, head) = stripped_fallback();
    let now = Instant::from_nanos(3);
    let copy = transmit(&mut ep, now);
    let copy = packet::parse(&copy).unwrap();
    // At SND.MAX, where "second" will start.
    assert!(copy.payload.is_empty());
    assert_eq!(placed_by_infinite_mapping(&copy, &syn), head + 5);
    ep.connection(h).unwrap().write(b"second").unwrap();
    let lost = transmit(&mut ep, now);
    let lost = packet::parse(&lost).unwrap();
    assert_eq!(lost.payload, b"second");
    assert_eq!(placed_by_infinite_mapping(&lost, &syn), head + 5);
    // The RTO resends it.
    let mut buf = [0; 1500];
    let (n, at) = loop {
        let at = ep.poll_timeout().unwrap();
        ep.handle_timeout(at);
        if let Some(n) = ep.poll_transmit(at, &mut buf) {
            break (n, at);
        }
    };
    let retrans = packet::parse(&buf[..n]).unwrap();
    assert_eq!((retrans.seq, retrans.payload), (lost.seq, &b"second"[..]));
    assert_eq!(placed_by_infinite_mapping(&retrans, &syn), head + 5);
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.ack = retrans.seq.wrapping_add(6);
    input(&mut ep, &ack);
    ep.connection(h).unwrap().write(b"third").unwrap();
    let third = transmit(&mut ep, at);
    let third = packet::parse(&third).unwrap();
    assert_eq!(third.payload, b"third");
    assert!(mpc(third.options).is_empty(), "plain TCP once acknowledged");
}

/// Data written after the ACK-only copy carries the mapping itself, so a network that lets it
/// overtake the copy (which then falls below the peer's RCV.NXT) still places every octet.
#[test]
fn data_overtaking_infinite_mapping_copy_carries_it() {
    let (mut ep, h, syn, head) = stripped_fallback();
    let now = Instant::from_nanos(3);
    let copy = transmit(&mut ep, now);
    assert!(packet::parse(&copy).unwrap().payload.is_empty());
    // Four segments: the initial window at this MSS (no Nagle hold on the last).
    let data: Vec<u8> = (0..2000).map(|i| (i % 251) as u8).collect();
    ep.connection(h).unwrap().set_nodelay(true);
    ep.connection(h).unwrap().write(&data).unwrap();
    let mut got = vec![None; data.len()];
    let mut buf = [0; 1500];
    let mut segs = 0;
    while let Some(n) = ep.poll_transmit(now, &mut buf) {
        segs += 1;
        let seg = packet::parse(&buf[..n]).unwrap();
        let at = (placed_by_infinite_mapping(&seg, &syn) - head - 5) as usize;
        for (k, &b) in seg.payload.iter().enumerate() {
            got[at + k] = Some(b);
        }
    }
    assert!(segs > 1, "{segs}");
    let got: Vec<u8> = got.into_iter().map(|b| b.expect("every octet")).collect();
    assert_eq!(got, data);
}

#[test]
fn lost_data_ack_falls_back_once_preserving_both_streams() {
    let (mut ep, h, syn, peer_dsn) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    let opts = mapping(1, peer_dsn, 3);
    input(&mut ep, &peer_data(&syn, 5001, &opts, b"old"));
    transmit(&mut ep, Instant::from_nanos(2));
    ep.connection(h).unwrap().write(b"first").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(3));
    let sent = packet::parse(&sent).unwrap();
    ep.connection(h).unwrap().write(b"queued").unwrap();
    let mut ack = peer_data(&syn, 5004, &[], b"new");
    ack.ack = sent.seq.wrapping_add(5);
    input(&mut ep, &ack);
    assert_eq!(
        ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
        crate::mptcp::State::FellBack
    );
    assert!(
        ep.poll_transmit(Instant::from_nanos(4), &mut [0; 20])
            .is_none()
    );
    let final_dss = transmit(&mut ep, Instant::from_nanos(4));
    let final_dss = packet::parse(&final_dss).unwrap();
    let MptcpOption::Dss(dss) = mptcp::parse(mpc(final_dss.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(dss.mapping.unwrap().data_len, 0);
    assert_eq!(dss.data_ack, None);
    let queued = transmit(&mut ep, Instant::from_nanos(4));
    let queued = packet::parse(&queued).unwrap();
    assert_eq!(queued.seq, sent.seq.wrapping_add(5));
    assert_eq!(queued.payload, b"queued");
    // The infinite mapping rides on the data after it until that data is acknowledged.
    assert_eq!(mpc(queued.options), mpc(final_dss.options));
    let mut out = [0; 20];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(6));
    assert_eq!(&out[..6], b"oldnew");
}

#[test]
fn data_mapping_confirmation_is_distinct_from_receiving_peer_dss() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"first").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let options = data_ack(head + 5);
    let mut ack = peer_data(&syn, 5001, &options, &[]);
    ack.ack = sent.seq.wrapping_add(5);
    input(&mut ep, &ack);
    ep.connection(h).unwrap().write(b"second").unwrap();
    let second = transmit(&mut ep, Instant::from_nanos(3));
    ack.ack = packet::parse(&second).unwrap().seq.wrapping_add(6);
    ack.options = &[];
    input(&mut ep, &ack);
    assert_ne!(
        ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
        crate::mptcp::State::FellBack
    );
}

#[test]
fn fallback_plain_tcp_does_not_ack_discarded_receive_bytes() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(4);
    let syn = packet::parse(&syn).unwrap();
    let inf = mapping(1, dsn, 0);
    input(&mut ep, &peer_data(&syn, 5001, &inf, b"ab"));
    transmit(&mut ep, Instant::from_nanos(2));
    // Earlier rounding can advertise more than the remaining memory.
    ep.conns
        .get_mut(&h)
        .unwrap()
        .hooks
        .data
        .as_mut()
        .unwrap()
        .recv
        .right_edge = dsn + 8;
    input(&mut ep, &peer_data(&syn, 5003, &[], b"cdef"));
    let ack = transmit(&mut ep, Instant::from_nanos(3));
    assert_eq!(packet::parse(&ack).unwrap().ack, SeqNum(5005));
    let mut out = [0; 4];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(4));
    assert_eq!(&out, b"abcd");
    input(&mut ep, &peer_data(&syn, 5005, &[], b"ef"));
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(2));
    assert_eq!(&out[..2], b"ef");
}

#[test]
fn fallback_close_drains_unassigned_bytes_before_fin() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    let inf = mapping(1, dsn, 0);
    input(&mut ep, &peer_data(&syn, 5001, &inf, &[]));
    transmit(&mut ep, Instant::from_nanos(2));
    ep.connection(h).unwrap().write(b"last").unwrap();
    ep.connection(h).unwrap().close();
    let data = transmit(&mut ep, Instant::from_nanos(3));
    let data = packet::parse(&data).unwrap();
    assert_eq!(data.payload, b"last");
    let fin = if data.flags.contains(TcpFlags::FIN) {
        data.seq.wrapping_add(4)
    } else {
        let fin = transmit(&mut ep, Instant::from_nanos(3));
        let fin = packet::parse(&fin).unwrap();
        assert!(fin.flags.contains(TcpFlags::FIN));
        fin.seq
    };
    assert_eq!(fin, syn.seq.wrapping_add(5));
}

#[test]
fn malformed_and_stale_acks_cannot_trigger_or_confirm_fallback() {
    for options in [vec![99, 1], [data_ack(u64::MAX), vec![99, 1]].concat()] {
        let (mut ep, h, syn, _) = connected_with_capacity(64);
        let syn = packet::parse(&syn).unwrap();
        ep.connection(h).unwrap().write(b"abc").unwrap();
        let sent = transmit(&mut ep, Instant::from_nanos(2));
        let sent = packet::parse(&sent).unwrap();
        let mut ack = peer_data(&syn, 5001, &[], &[]);
        ack.ack = sent.seq.wrapping_add(4); // unsent byte
        input(&mut ep, &ack);
        assert_ne!(
            ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
            crate::mptcp::State::FellBack
        );
        ack.ack = sent.seq.wrapping_add(1);
        ack.options = &options;
        input(&mut ep, &ack); // TCP advances, malformed MPTCP cannot mutate state
        assert_ne!(
            ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
            crate::mptcp::State::FellBack
        );
        ack.ack = sent.seq;
        ack.options = &[];
        input(&mut ep, &ack);
        assert_ne!(
            ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
            crate::mptcp::State::FellBack
        );
        ack.ack = sent.seq.wrapping_add(3);
        input(&mut ep, &ack);
        assert_eq!(ep.poll_event(), Some((h, Event::FellBack)));
        let final_dss = transmit(&mut ep, Instant::from_nanos(3));
        assert_eq!(mpc(packet::parse(&final_dss).unwrap().options).len(), 1);
        input(&mut ep, &ack);
        assert_eq!(ep.poll_event(), None);
    }
}

#[test]
fn received_infinite_mapping_is_permanent_and_keeps_inflight_send() {
    let (mut ep, h, syn, peer_dsn) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"outstanding").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let inf = mapping(1, peer_dsn, 0);
    input(&mut ep, &peer_data(&syn, 5001, &inf, b"reply"));
    assert_eq!(ep.poll_event(), Some((h, Event::FellBack)));
    let out = transmit(&mut ep, Instant::from_nanos(3));
    assert_eq!(mpc(packet::parse(&out).unwrap().options).len(), 1);
    input(&mut ep, &peer_data(&syn, 5001, &inf, b"reply"));
    let out = transmit(&mut ep, Instant::from_nanos(3));
    assert!(mpc(packet::parse(&out).unwrap().options).is_empty());
    assert_eq!(ep.poll_event(), None);
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    let retrans = transmit(&mut ep, at);
    let retrans = packet::parse(&retrans).unwrap();
    assert_eq!(retrans.seq, sent.seq);
    assert_eq!(retrans.payload, b"outstanding");
    // Our infinite mapping (SSN 1, retroactive) rides on the retransmission too, until the
    // data it maps is acknowledged.
    let MptcpOption::Dss(d) = mptcp::parse(mpc(retrans.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(d.mapping.map(|m| (m.ssn, m.data_len)), Some((1, 0)));
    let mut ack = peer_data(&syn, 5006, &[], &[]);
    ack.ack = sent.seq.wrapping_add(11);
    input(&mut ep, &ack);
    assert_eq!(
        ep.conns[&h].hooks.data.as_ref().unwrap().send.una,
        ep.conns[&h].hooks.data.as_ref().unwrap().send.next
    );
    assert_eq!(ep.poll_timeout(), None);
    let mut out = [0; 5];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(5));
    assert_eq!(&out, b"reply");
}

#[test]
fn invalid_data_ack_does_not_confirm_mapping() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"abc").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let opts = data_ack(head + 100);
    let mut ack = peer_data(&syn, 5001, &opts, &[]);
    ack.ack = sent.seq.wrapping_add(1);
    input(&mut ep, &ack);
    ack.options = &[];
    ack.ack = sent.seq.wrapping_add(3);
    input(&mut ep, &ack);
    assert_eq!(ep.poll_event(), Some((h, Event::FellBack)));
}

#[test]
fn recovery_reevaluates_head_and_cancels_after_data_ack() {
    let (mut ep, h, syn, _) = connected_with_capacity_cc(64, Some(reno));
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"abcd").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let opts = data_ack(head);
    let mut ack = peer_data(&syn, 5001, &opts, &[]);
    ack.ack = sent.seq.wrapping_add(4);
    input(&mut ep, &ack);
    let old = ep.poll_timeout().unwrap();
    let opts = data_ack(head + 2);
    ack.options = &opts;
    let now = Instant::from_nanos(500_000_000);
    let mut bytes = [0; 1500];
    let n = packet::build(&ack, 0, &mut bytes).unwrap();
    ep.handle_packet(now, &bytes[..n]);
    let new = ep.poll_timeout().unwrap();
    assert!(new > old);
    ep.handle_timeout(old);
    assert!(ep.poll_transmit(old, &mut bytes).is_none());
    ep.handle_timeout(new);
    let retry = transmit(&mut ep, new);
    let retry = packet::parse(&retry).unwrap();
    assert_eq!(retry.payload, b"cd");
    let MptcpOption::Dss(d) = mptcp::parse(mpc(retry.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(d.mapping.unwrap().dsn, mptcp::Dsn::Dsn64(head + 2));
    let opts = data_ack(head + 4);
    ack.options = &opts;
    ack.ack = retry.seq.wrapping_add(2);
    let n = packet::build(&ack, 0, &mut bytes).unwrap();
    ep.handle_packet(new, &bytes[..n]);
    assert_eq!(ep.poll_timeout(), None);
}

#[test]
fn reinjection_respects_zero_tcp_window_and_deduplicates_live_copy() {
    let (mut ep, h, syn, _) = connected_with_capacity_cc(64, Some(reno));
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"data").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let opts = data_ack(head);
    let mut ack = peer_data(&syn, 5001, &opts, &[]);
    ack.ack = sent.seq.wrapping_add(4);
    ack.wnd = 0;
    input(&mut ep, &ack);
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    assert!(ep.poll_transmit(at, &mut [0; 1500]).is_none());
    assert_eq!(ep.conns[&h].subflows[0].mp.tx.assigned_end(), 5);
    ack.wnd = 1234;
    let mut bytes = [0; 1500];
    let n = packet::build(&ack, 0, &mut bytes).unwrap();
    ep.handle_packet(at, &bytes[..n]);
    let retry = transmit(&mut ep, at);
    let retry = packet::parse(&retry).unwrap();
    assert_eq!(retry.seq, sent.seq.wrapping_add(4));
    // Live copy remains the only copy; its own TCP RTO reuses the same SSN.
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    let retrans = transmit(&mut ep, at);
    assert_eq!(packet::parse(&retrans).unwrap().seq, retry.seq);
    assert_eq!(ep.conns[&h].subflows[0].mp.tx.assigned_end(), 9);
}

#[test]
fn infinite_receive_mapping_tracks_ssn_wrap() {
    use crate::tcp::SegmentHooks;
    let (mut ep, h, syn, dsn) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &mapping(1, dsn, 0), &[]));
    let c = ep.conns.get_mut(&h).unwrap();
    let hooks = &mut crate::mptcp::SubflowHooks {
        conn: &mut c.hooks,
        sf: &mut c.subflows[0].mp,
    };
    // Skip stored payload while simulating bounded successive TCP receipt advances.
    for offset in [0x7000_0000u64, 0xe000_0000, 0x1_5000_0000] {
        let next = dsn.wrapping_add(offset);
        let recv = &mut hooks.conn.data.as_mut().unwrap().recv;
        recv.next = next;
        recv.right_edge = next.wrapping_add(64);
        hooks.receipt_advanced((offset as u32).wrapping_add(1));
        let ssn = (offset as u32).wrapping_add(1);
        assert_eq!(hooks.receive_data(ssn, ssn, b"x"), vec![0..1]);
        assert_eq!(hooks.conn.read(&mut [0; 1]), 1);
    }
}

#[test]
fn corrected_data_ack_confirms_already_tcp_acked_mapping() {
    for corrected in [true, false] {
        let (mut ep, h, syn, _) = connected_with_capacity(64);
        let syn = packet::parse(&syn).unwrap();
        ep.connection(h).unwrap().write(b"abc").unwrap();
        let sent = transmit(&mut ep, Instant::from_nanos(2));
        let sent = packet::parse(&sent).unwrap();
        let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
        let invalid = data_ack(head.wrapping_add(100));
        let mut ack = peer_data(&syn, 5001, &invalid, &[]);
        ack.ack = sent.seq.wrapping_add(3);
        input(&mut ep, &ack);
        assert!(ep.conns[&h].subflows[0].mp.tx.mapping(1).is_none());
        let valid = data_ack(head.wrapping_add(3));
        ack.options = &valid;
        if !corrected {
            ack.ack = sent.seq;
        } // Old SYN-only ACK cannot confirm data.
        input(&mut ep, &ack);
        ep.connection(h).unwrap().write(b"def").unwrap();
        let next = transmit(&mut ep, Instant::from_nanos(3));
        ack.ack = packet::parse(&next).unwrap().seq.wrapping_add(3);
        ack.options = &[];
        input(&mut ep, &ack);
        assert_eq!(
            ep.poll_event(),
            if corrected {
                None
            } else {
                Some((h, Event::FellBack))
            }
        );
    }
}

#[test]
fn current_tcp_ack_without_data_ack_falls_back_after_invalid_data_ack() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"abc").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let invalid = data_ack(head.wrapping_add(100));
    let mut ack = peer_data(&syn, 5001, &invalid, &[]);
    ack.ack = sent.seq.wrapping_add(3);
    input(&mut ep, &ack);
    assert_eq!(ep.poll_event(), None);
    assert!(ep.poll_timeout().is_some());
    ack.options = &[];
    for stale in [sent.seq, sent.seq.wrapping_add(2)] {
        ack.ack = stale;
        input(&mut ep, &ack);
        assert_eq!(ep.poll_event(), None);
    }
    ack.ack = sent.seq.wrapping_add(3);
    input(&mut ep, &ack);
    assert_eq!(ep.poll_event(), Some((h, Event::FellBack)));
    assert_eq!(ep.poll_timeout(), None);
    let final_dss = transmit(&mut ep, Instant::from_nanos(3));
    let final_dss = packet::parse(&final_dss).unwrap();
    let MptcpOption::Dss(dss) = mptcp::parse(mpc(final_dss.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(dss.mapping.unwrap().data_len, 0);
    assert!(final_dss.payload.is_empty());
    input(&mut ep, &ack);
    assert_eq!(ep.poll_event(), None);
    assert!(
        ep.poll_transmit(Instant::from_nanos(3), &mut [0; 1500])
            .is_none()
    );
}

fn fin_option(dsn: u64, ssn: u32, len: u16, ack: Option<u64>) -> Vec<u8> {
    let mut out = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: true,
            data_ack: ack.map(mptcp::DataAck::Ack64),
            mapping: Some(mptcp::Mapping {
                dsn: mptcp::Dsn::Dsn64(dsn),
                ssn,
                data_len: len,
                checksum: None,
            }),
        }),
        &mut out,
    )
    .unwrap();
    out[..n].to_vec()
}

#[test]
fn standalone_data_fin_is_immediately_acked_and_half_closes_data_only() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    input(
        &mut ep,
        &peer_data(&syn, 5001, &fin_option(dsn, 0, 1, None), &[]),
    );
    let packet = transmit(&mut ep, Instant::from_nanos(2));
    let ack = packet::parse(&packet).unwrap();
    assert_eq!(ack.ack, SeqNum(5001));
    assert_eq!(dack(&ack), dsn.wrapping_add(1));
    assert_eq!(ep.connection(h).unwrap().read(&mut [0; 1]), Ok(0));
    assert_eq!(ep.connection(h).unwrap().write(b"reply"), Ok(5));
}

#[test]
fn local_data_fin_is_standalone_and_tcp_fin_waits_for_data_ack() {
    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    let fin_dsn = ep
        .connection(h)
        .unwrap()
        .hooks
        .data
        .as_ref()
        .unwrap()
        .send
        .end;
    ep.connection(h).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    let fin = packet::parse(&bytes).unwrap();
    assert!(!fin.flags.contains(TcpFlags::FIN));
    let MptcpOption::Dss(d) = mptcp::parse(mpc(fin.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    assert_eq!(d.mapping.unwrap().ssn, 0);
    assert_eq!(d.mapping.unwrap().data_len, 1);
    input(
        &mut ep,
        &peer_data(&syn, 5001, &data_ack(fin_dsn.wrapping_add(1)), &[]),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(4));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));
}

#[test]
fn fastclose_valid_key_closes_once_on_ack_or_rst_after_tcp_validation() {
    for flags in [TcpFlags::ACK, TcpFlags::RST] {
        for valid in [false, true] {
            let (mut ep, h, syn, _) = connected_with_capacity(4096);
            let syn = packet::parse(&syn).unwrap();
            let key_packet = {
                // PreConfirmed ACK repeats the local key.
                reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
                transmit(&mut ep, Instant::from_nanos(2))
            };
            let MptcpOption::Capable(keys) =
                mptcp::parse(mpc(packet::parse(&key_packet).unwrap().options)[0]).unwrap()
            else {
                panic!()
            };
            let mut opts = [0; 40];
            let n = mptcp::encode(
                &MptcpOption::FastClose {
                    receiver_key: keys.sender_key.unwrap() ^ u64::from(!valid),
                },
                &mut opts,
            )
            .unwrap();
            let seg = Segment {
                flags,
                ..peer_data(&syn, 5001, &opts[..n], &[])
            };
            for bad in [
                Segment {
                    seq: SeqNum(999_999),
                    ..seg.clone()
                },
                Segment {
                    seq: SeqNum(999_999),
                    payload: b"x",
                    ..seg.clone()
                },
            ] {
                input(&mut ep, &bad);
                assert_eq!(ep.poll_event(), None);
            }
            if flags == TcpFlags::ACK {
                input(
                    &mut ep,
                    &Segment {
                        ack: syn.seq.wrapping_add(100),
                        ..seg.clone()
                    },
                );
                assert_eq!(ep.poll_event(), None);
            }
            input(&mut ep, &seg);
            if valid {
                assert_eq!(
                    ep.poll_event(),
                    Some((
                        h,
                        Event::Closed {
                            reason: CloseReason::Reset
                        }
                    ))
                );
                // A RST is never answered (RFC 9293 §3.10.7); an ACK carrying it is.
                let mut buf = [0; 1500];
                let out = ep.poll_transmit(Instant::from_nanos(3), &mut buf);
                let rst = out.map(|n| packet::parse(&buf[..n]).unwrap().flags);
                let want = (flags == TcpFlags::ACK).then_some(TcpFlags::RST);
                assert_eq!(rst, want, "{flags:?}");
                input(&mut ep, &seg);
                assert_eq!(ep.poll_event(), None);
            } else {
                // A RST without a valid key is an ordinary RST: the no-subflow wait starts.
                let down = (flags == TcpFlags::RST).then(|| (h, initial_down(CloseReason::Reset)));
                assert_eq!(ep.poll_event(), down);
            }
        }
    }
}

/// The initial subflow's `SubflowDown` as the last one: the no-subflow wait starts.
fn initial_down(reason: CloseReason) -> Event {
    Event::SubflowDown {
        subflow: SubflowId::INITIAL,
        reason,
        rst: None,
    }
}

#[test]
fn ordinary_rst_keeps_data_until_no_subflow_timeout() {
    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"retained").unwrap();
    transmit(&mut ep, Instant::from_nanos(2));
    input(
        &mut ep,
        &Segment {
            flags: TcpFlags::RST,
            ..peer_data(&syn, 5001, &[], &[])
        },
    );
    assert_eq!(ep.poll_event(), Some((h, initial_down(CloseReason::Reset))));
    ep.handle_timeout(Instant::from_nanos(3));
    assert!(ep.connection(h).is_some());
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 1]),
        Err(crate::connection::ReadError::WouldBlock)
    );
    let deadline = ep.poll_timeout().unwrap();
    assert_eq!(deadline, Instant::from_nanos(2) + Duration::from_secs(60));
    ep.handle_timeout(deadline);
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Timeout
            }
        ))
    );
    assert_eq!(ep.poll_event(), None);
    assert!(ep.connection(h).is_none());
}

#[test]
fn combined_tcp_and_data_fin_allows_reply_and_local_close() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    let opts = fin_option(dsn, 0, 1, None);
    input(
        &mut ep,
        &Segment {
            flags: TcpFlags::ACK | TcpFlags::FIN,
            ..peer_data(&syn, 5001, &opts, &[])
        },
    );
    transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(ep.connection(h).unwrap().read(&mut [0; 1]), Ok(0));
    ep.connection(h).unwrap().write(b"reply").unwrap();
    ep.connection(h).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.payload, b"reply");
    let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    assert_eq!(d.mapping.unwrap().data_len, 6);
    assert!(!seg.flags.contains(TcpFlags::FIN));
}

#[test]
fn data_fin_retry_backs_off_without_consuming_tcp_sequence_space() {
    let (mut ep, h, _, _) = connected_with_capacity(4096);
    ep.connection(h).unwrap().close();
    let first = transmit(&mut ep, Instant::from_nanos(2));
    let first = packet::parse(&first).unwrap();
    let mut previous = Instant::from_nanos(2);
    for interval in [1, 2, 4, 8] {
        let at = ep.poll_timeout().unwrap();
        assert_eq!(at - previous, Duration::from_secs(interval));
        ep.handle_timeout(at);
        let bytes = transmit(&mut ep, at);
        let retry = packet::parse(&bytes).unwrap();
        assert_eq!(retry.seq, first.seq);
        assert_eq!(retry.options, first.options);
        previous = at;
    }
}

#[test]
fn attached_data_fin_waits_for_dsn_hole_and_reads_before_eof() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    input(
        &mut ep,
        &peer_data(
            &syn,
            5003,
            &fin_option(dsn.wrapping_add(2), 3, 3, None),
            b"cd",
        ),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(dack(&packet::parse(&bytes).unwrap()), dsn);
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 4]),
        Err(crate::connection::ReadError::WouldBlock)
    );
    input(&mut ep, &peer_data(&syn, 5001, &mapping(1, dsn, 2), b"ab"));
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    assert_eq!(dack(&packet::parse(&bytes).unwrap()), dsn.wrapping_add(5));
    let mut out = [0; 4];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(4));
    assert_eq!(&out, b"abcd");
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(0));
}

#[test]
fn malformed_or_out_of_window_data_fin_does_not_close_or_fall_back() {
    for (ssn, len, offset, payload) in [
        (1, 1, 0, &b""[..]),
        (0, 0, 0, &b""[..]),
        (0, 1, 4096, &b""[..]),
        (1, 2, 0, &b""[..]),
    ] {
        let (mut ep, h, syn, dsn) = connected_with_capacity(4096);
        let syn = packet::parse(&syn).unwrap();
        input(
            &mut ep,
            &peer_data(
                &syn,
                5001,
                &fin_option(dsn.wrapping_add(offset), ssn, len, None),
                payload,
            ),
        );
        assert!(ep.conns[&h].hooks.active());
        assert_eq!(
            ep.connection(h).unwrap().read(&mut [0; 1]),
            Err(crate::connection::ReadError::WouldBlock)
        );
        assert_eq!(ep.conns[&h].hooks.data.as_ref().unwrap().recv.next, dsn);
    }
}

#[test]
fn bare_tcp_fin_retires_subflow_without_data_eof_or_new_assignments() {
    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.next;
    ep.connection(h).unwrap().write(b"queued").unwrap();
    input(
        &mut ep,
        &Segment {
            flags: TcpFlags::ACK | TcpFlags::FIN,
            ..peer_data(&syn, 5001, &[], &[])
        },
    );
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 1]),
        Err(crate::connection::ReadError::WouldBlock)
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    let fin = packet::parse(&bytes).unwrap();
    assert!(fin.flags.contains(TcpFlags::FIN));
    assert!(fin.payload.is_empty());
    assert_eq!(ep.conns[&h].hooks.data.as_ref().unwrap().send.next, head);
    let ack = Segment {
        ack: fin.seq.wrapping_add(1),
        ..peer_data(&syn, 5002, &[], &[])
    };
    input(&mut ep, &ack);
    assert_eq!(
        ep.poll_event(),
        Some((h, initial_down(CloseReason::Normal)))
    );
    assert_eq!(ep.connection(h).unwrap().write(b"more"), Ok(4));
    let at = ep.poll_timeout().unwrap();
    assert_eq!(at, Instant::from_nanos(2) + Duration::from_secs(60));
    ep.handle_timeout(at);
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Timeout
            }
        ))
    );
}

#[test]
fn queued_close_initial_capable_mapping_gets_separate_data_fin() {
    let (mut ep, h, _, _) = connected_with_capacity(4096);
    ep.connection(h).unwrap().write(b"initial").unwrap();
    ep.connection(h).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let first = packet::parse(&bytes).unwrap();
    assert_eq!(first.payload, b"initial");
    assert!(matches!(
        mptcp::parse(mpc(first.options)[0]).unwrap(),
        MptcpOption::Capable(_)
    ));
    assert!(!first.flags.contains(TcpFlags::FIN));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let second = packet::parse(&bytes).unwrap();
    let MptcpOption::Dss(d) = mptcp::parse(mpc(second.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    assert_eq!(d.mapping.unwrap().ssn, 0);
    assert_eq!(d.mapping.unwrap().data_len, 1);
    assert_eq!(second.seq, first.seq.wrapping_add(7));
}

#[test]
fn fallback_cancels_data_fin_timer_and_keeps_tcp_halfclose_reply() {
    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"initial").unwrap();
    ep.connection(h).unwrap().close();
    transmit(&mut ep, Instant::from_nanos(2));
    transmit(&mut ep, Instant::from_nanos(2)); // standalone DATA_FIN
    let seg = Segment {
        ack: syn.seq.wrapping_add(8),
        ..peer_data(&syn, 5001, &[], &[])
    };
    input(&mut ep, &seg); // options stripped: TCP fallback
    assert!(!ep.conns[&h].hooks.active());
    assert!(ep.conns[&h].hooks.recovery_deadline().is_none());
    assert_eq!(ep.poll_event(), Some((h, Event::FellBack)));
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));

    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"initial").unwrap();
    transmit(&mut ep, Instant::from_nanos(2));
    input(
        &mut ep,
        &Segment {
            ack: syn.seq.wrapping_add(8),
            flags: TcpFlags::ACK | TcpFlags::FIN,
            ..peer_data(&syn, 5001, &[], &[])
        },
    );
    transmit(&mut ep, Instant::from_nanos(3));
    ep.connection(h).unwrap().write(b"reply").unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(4));
    assert_eq!(packet::parse(&bytes).unwrap().payload, b"reply");
}

#[test]
fn attached_data_fin_reinjects_with_data_before_standalone_retry() {
    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    input(&mut ep, &peer_data(&syn, 5001, &data_ack(head), &[]));
    ep.connection(h).unwrap().write(b"final").unwrap();
    ep.connection(h).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let data = packet::parse(&bytes).unwrap();
    let MptcpOption::Dss(d) = mptcp::parse(mpc(data.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    input(
        &mut ep,
        &Segment {
            ack: data.seq.wrapping_add(5),
            ..peer_data(&syn, 5001, &data_ack(head), &[])
        },
    );
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    let bytes = transmit(&mut ep, at);
    let retry = packet::parse(&bytes).unwrap();
    assert_eq!(retry.payload, b"final");
    let MptcpOption::Dss(d) = mptcp::parse(mpc(retry.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    assert_eq!(d.mapping.unwrap().data_len, 6);
    assert_eq!(d.mapping.unwrap().ssn, 6);
    // DATA_ACK for the bytes alone leaves only the FIN to retransmit.
    input(
        &mut ep,
        &Segment {
            ack: retry.seq.wrapping_add(5),
            ..peer_data(&syn, 5001, &data_ack(head.wrapping_add(5)), &[])
        },
    );
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    let bytes = transmit(&mut ep, at);
    let fin = packet::parse(&bytes).unwrap();
    assert!(fin.payload.is_empty());
    let MptcpOption::Dss(d) = mptcp::parse(mpc(fin.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    assert_eq!(d.mapping.unwrap().ssn, 0);
}

#[test]
fn combined_fin_with_dsn_hole_keeps_local_half_open() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    let opts = fin_option(dsn.wrapping_add(2), 1, 3, None);
    input(
        &mut ep,
        &Segment {
            flags: TcpFlags::ACK | TcpFlags::FIN,
            ..peer_data(&syn, 5001, &opts, b"cd")
        },
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    assert!(!packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 4]),
        Err(crate::connection::ReadError::WouldBlock)
    );
    ep.connection(h).unwrap().write(b"reply").unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(4));
    assert_eq!(packet::parse(&bytes).unwrap().payload, b"reply");
}

#[test]
fn fastclose_outside_closed_tcp_window_is_not_an_ack_only_probe() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(1);
    let syn = packet::parse(&syn).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let MptcpOption::Capable(keys) =
        mptcp::parse(mpc(packet::parse(&bytes).unwrap().options)[0]).unwrap()
    else {
        panic!()
    };
    input(&mut ep, &peer_data(&syn, 5001, &mapping(1, dsn, 1), b"x"));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().wnd, 0);
    let mut opts = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::FastClose {
            receiver_key: keys.sender_key.unwrap(),
        },
        &mut opts,
    )
    .unwrap();
    input(&mut ep, &peer_data(&syn, 5003, &opts[..n], &[]));
    assert_eq!(ep.poll_event(), None);
    assert!(ep.conns[&h].hooks.retained());
}

#[test]
fn close_before_third_ack_preserves_keys_and_fin_progress() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(2));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    ep.connection(h).unwrap().close();
    assert!(
        ep.poll_transmit(Instant::from_nanos(2), &mut [0; 20])
            .is_none()
    );
    assert_eq!(ep.poll_event(), None);
    // No peer DSS is needed to finish an empty stream. Repeated SYN/ACKs
    // must still get keys, even when the DATA_FIN retry is simultaneously due.
    for now in [Instant::from_nanos(2), Instant::from_nanos(2_000_000_000)] {
        if now != Instant::from_nanos(2) {
            reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
        }
        let bytes = transmit(&mut ep, now);
        let ack = packet::parse(&bytes).unwrap();
        assert!(matches!(mptcp::parse(mpc(ack.options)[0]),
            Ok(MptcpOption::Capable(c)) if c.sender_key.is_some() && c.receiver_key == Some(PEER_KEY)));
        let bytes = transmit(&mut ep, now);
        let fin = packet::parse(&bytes).unwrap();
        assert!(matches!(mptcp::parse(mpc(fin.options)[0]),
            Ok(MptcpOption::Dss(d)) if d.data_fin && d.mapping.unwrap().ssn == 0));
        assert!(!fin.flags.contains(TcpFlags::FIN));
        assert!(ep.poll_transmit(now, &mut [0; 1500]).is_none());
    }
    assert_eq!(ep.poll_event(), Some((h, Event::Connected { mptcp: true })));
    assert_eq!(ep.poll_event(), None);
}

#[test]
fn fastclose_reset_survives_timeout_drive() {
    for flags in [TcpFlags::ACK, TcpFlags::RST] {
        let (mut ep, h, syn, _) = connected_with_capacity(4096);
        let syn = packet::parse(&syn).unwrap();
        reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
        let keys = transmit(&mut ep, Instant::from_nanos(2));
        let MptcpOption::Capable(keys) =
            mptcp::parse(mpc(packet::parse(&keys).unwrap().options)[0]).unwrap()
        else {
            panic!()
        };
        let mut opts = [0; 40];
        let n = mptcp::encode(
            &MptcpOption::FastClose {
                receiver_key: keys.sender_key.unwrap(),
            },
            &mut opts,
        )
        .unwrap();
        input(
            &mut ep,
            &Segment {
                flags,
                ..peer_data(&syn, 5001, &opts[..n], &[])
            },
        );
        assert_eq!(
            ep.poll_event(),
            Some((
                h,
                Event::Closed {
                    reason: CloseReason::Reset
                }
            ))
        );
        let now = Instant::from_nanos(3);
        if flags == TcpFlags::RST {
            // A RST is never answered (RFC 9293 §3.10.7): nothing is due, the TCB is freed.
            assert!(ep.poll_transmit(now, &mut [0; 1500]).is_none());
            ep.handle_timeout(now);
            assert!(ep.connection(h).is_none());
            assert_eq!((ep.poll_timeout(), ep.poll_event()), (None, None));
            continue;
        }
        ep.handle_timeout(now);
        assert!(ep.poll_transmit(now, &mut [0; 20]).is_none());
        ep.handle_timeout(now);
        assert!(
            ep.connection(h).is_some(),
            "retain until RST actually fits the output buffer"
        );
        let bytes = transmit(&mut ep, now);
        assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::RST));
        assert!(ep.poll_transmit(now, &mut [0; 1500]).is_none());
        let cleanup = ep
            .poll_timeout()
            .expect("closed connection must schedule cleanup");
        assert!(cleanup <= now);
        ep.handle_timeout(now);
        assert!(ep.connection(h).is_none());
        assert_eq!(ep.poll_timeout(), None);
        assert_eq!(ep.poll_event(), None);
    }
}

/// A peer that fills the advertised data-level window with segments of `size(i)` octets while
/// the application does not read, as Linux does when the TUN driver floods before `read()`.
/// Returns the octets sent and the last subflow ACK seen.
fn flood_unread(
    ep: &mut Endpoint<ChaCha20Rng>,
    syn: &Segment,
    dsn: u64,
    scale: u8,
    mut size: impl FnMut(u64) -> usize,
) -> (u64, SeqNum) {
    let (mut sent, mut edge, mut tcp_ack) = (0u64, dsn.wrapping_add(65535), SeqNum(5001));
    let payload = vec![7; 4096];
    let mut now = Instant::from_nanos(2);
    for i in 0.. {
        let room = edge.wrapping_sub(dsn.wrapping_add(sent));
        if room > 0 {
            let len = (size(i) as u64).min(room) as usize;
            let opts = mapping(1 + sent as u32, dsn.wrapping_add(sent), len as u16);
            let seg = peer_data(syn, 5001 + sent as u32, &opts, &payload[..len]);
            let mut wire = [0; 4200];
            let n = packet::build(&seg, 0, &mut wire).unwrap();
            ep.handle_packet(now, &wire[..n]);
            sent += len as u64;
        } else {
            // Window used up: let a delayed ACK go out; stop once it opens nothing.
            now = now + Duration::from_secs(1);
            ep.handle_timeout(now);
        }
        let before = edge;
        let mut out = [0; 1500];
        while let Some(n) = ep.poll_transmit(now, &mut out) {
            let ack = packet::parse(&out[..n]).unwrap();
            tcp_ack = ack.ack;
            let advertised = dack(&ack).wrapping_add(u64::from(ack.wnd) << scale);
            if advertised.wrapping_sub(edge) as i64 > 0 {
                edge = advertised;
            }
        }
        if room == 0 && edge == before {
            break;
        }
        now = now + Duration::from_micros(10);
    }
    (sent, tcp_ack)
}

type Connected = (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Segment<'static>,
    u64,
);
fn connected_scaled(cap: u32) -> Connected {
    connected_scaled_cc(cap, None)
}
fn connected_scaled_cc(
    cap: u32,
    cc: Option<fn() -> Box<dyn crate::tcp::cc::CongestionControl>>,
) -> Connected {
    connected_with(cap, cc, false)
}
/// `connected_scaled_cc`, with SACK-Permitted in the peer's SYN/ACK if `sack`.
fn connected_with(
    cap: u32,
    cc: Option<fn() -> Box<dyn crate::tcp::cc::CongestionControl>>,
    sack: bool,
) -> Connected {
    connected_between("10.0.0.1", "10.0.0.2:80", cap, cc, sack)
}
/// `connected_with`, from `local` to `remote`.
fn connected_between(
    local: &str,
    remote: &str,
    cap: u32,
    cc: Option<fn() -> Box<dyn crate::tcp::cc::CongestionControl>>,
    sack: bool,
) -> Connected {
    let cfg = ConnectConfig {
        recv_buffer: cap,
        ..checksums_cfg(false)
    };
    connected_cfg(local, remote, cfg, cc, sack)
}
/// `connected_between` with the whole `ConnectConfig`.
fn connected_cfg(
    local: &str,
    remote: &str,
    cfg: ConnectConfig,
    cc: Option<fn() -> Box<dyn crate::tcp::cc::CongestionControl>>,
    sack: bool,
) -> Connected {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(31));
    ep.cc = cc;
    let h = ep
        .connect_mptcp(
            Instant::from_nanos(0),
            local.parse().unwrap(),
            remote.parse().unwrap(),
            cfg,
        )
        .unwrap();
    let syn_bytes = transmit(&mut ep, Instant::from_nanos(0)).leak();
    let syn = packet::parse(syn_bytes).unwrap();
    let mut opts = capable(1, CAP_H);
    let mut o = [0; 4];
    let n = crate::wire::tcp_options::write_mss(&mut o, 1460);
    opts.extend_from_slice(&o[..n]);
    let n = crate::wire::tcp_options::write_ws(&mut o, 7);
    opts.extend_from_slice(&o[..n]);
    if sack {
        let n = crate::wire::tcp_options::write_sack_permitted(&mut o);
        opts.extend_from_slice(&o[..n]);
    }
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    ep.poll_event();
    let dsn = crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1);
    (ep, h, syn, dsn)
}

fn read_all(ep: &mut Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> u64 {
    let mut total = 0;
    let mut buf = [0; 65536];
    while let Ok(n) = ep.connection(h).unwrap().read(&mut buf) {
        total += n as u64;
    }
    total
}

#[test]
fn unread_flood_keeps_data_up_to_the_rounded_data_level_edge() {
    // Scale 3 rounds the shared edge to 8 octets; 1001-octet segments leave 7 octets of
    // rounding per DATA_ACK, so the advertised edge passes the 256 KiB memory edge.
    let cap = 1 << 18;
    let (mut ep, h, syn, dsn) = connected_scaled(cap);
    let (sent, tcp_ack) = flood_unread(&mut ep, &syn, dsn, 3, |_| 1001);
    assert!(
        sent > u64::from(cap),
        "the rounded edge promised {sent} octets"
    );
    // Every octet the peer sent was inside the advertised window and is subflow-ACKed ...
    assert_eq!(tcp_ack, SeqNum(5001 + sent as u32));
    // ... so it must be delivered and DATA_ACKed without a connection-level retransmission.
    assert_eq!(read_all(&mut ep, h), sent);
    let ack = transmit(&mut ep, Instant::from_nanos(3));
    assert_eq!(dack(&packet::parse(&ack).unwrap()), dsn.wrapping_add(sent));
}

// M2 Task 3: the scheduler boundary with one subflow.

use crate::mptcp::sched::SubflowSnapshot;
use crate::mptcp::sched::{HealthEvent, HealthVerdict, MinRtt, Payload, Pending, Plan, Scheduler};
use std::sync::{Arc, Mutex};

/// What a `Probe` scheduler saw: every plan it returned and every `on_assigned` call.
#[derive(Default)]
struct Log {
    plans: Vec<Plan>,
    assigned: Vec<(SubflowId, u32, bool)>,
}

/// Deliberately wrong plans a buggy scheduler might return.
#[derive(Clone, Copy)]
enum Rogue {
    /// One octet more than the New budget allows.
    OverBudget,
    /// A New plan within budget for a subflow that does not exist.
    NoSuchSubflow,
    /// A New plan within budget for the first subflow, whatever its state.
    FirstSubflow,
    /// A New plan with the first subflow's budget for the named subflow, whatever its state.
    Named(SubflowId),
    /// A reinjection `(dsn, len)` that is not a prefix of the head candidate.
    ForeignReinject(u64, u32),
    /// Never sends anything.
    Idle,
    /// MinRTT over the named subflow alone: always picks it, whatever the others offer.
    Pin(SubflowId),
}

/// MinRTT, or a rogue plan when one is set; records everything.
struct Probe {
    log: Arc<Mutex<Log>>,
    rogue: Arc<Mutex<Option<Rogue>>>,
}
impl Scheduler for Probe {
    fn plan(&mut self, now: Instant, pending: &Pending<'_>, subflows: &[SubflowSnapshot]) -> Plan {
        let first = subflows[0];
        let budget = first.new_budget.bytes() as u32;
        let new = |subflow, bytes| Plan::Send {
            subflow,
            payload: Payload::New { bytes },
        };
        let plan = match *self.rogue.lock().unwrap() {
            None => MinRtt.plan(now, pending, subflows),
            Some(Rogue::OverBudget) => new(first.id, budget + 1),
            Some(Rogue::NoSuchSubflow) => new(SubflowId(7), budget),
            Some(Rogue::FirstSubflow) => new(first.id, budget),
            Some(Rogue::Named(id)) => new(id, budget),
            Some(Rogue::ForeignReinject(dsn, len)) => Plan::Send {
                subflow: first.id,
                payload: Payload::Reinject { dsn, len },
            },
            Some(Rogue::Idle) => Plan::Idle,
            Some(Rogue::Pin(id)) => {
                let only: Vec<_> = subflows.iter().copied().filter(|s| s.id == id).collect();
                MinRtt.plan(now, pending, &only)
            }
        };
        self.log.lock().unwrap().plans.push(plan);
        plan
    }
    fn on_health(&mut self, ev: &HealthEvent, subflows: &[SubflowSnapshot]) -> HealthVerdict {
        MinRtt.on_health(ev, subflows)
    }
    fn on_assigned(&mut self, subflow: SubflowId, bytes: u32, reinject: bool) {
        self.log
            .lock()
            .unwrap()
            .assigned
            .push((subflow, bytes, reinject));
    }
}
type Rogues = Arc<Mutex<Option<Rogue>>>;
/// Sets the probe's plan. `poll_transmit` consults the scheduler of a ready connection only,
/// and a plan changed from outside reaches the connection through no endpoint call: mark it.
fn set_rogue(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    rogue: &Rogues,
    r: Option<Rogue>,
) {
    *rogue.lock().unwrap() = r;
    ep.conns.touch(h);
}
fn install_probe(ep: &mut Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> (Arc<Mutex<Log>>, Rogues) {
    let (log, rogue) = (Arc::default(), Arc::default());
    ep.conns.get_mut(&h).unwrap().hooks.scheduler = Box::new(Probe {
        log: Arc::clone(&log),
        rogue: Arc::clone(&rogue),
    });
    (log, rogue)
}

fn una(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> u64 {
    ep.conns[&h].hooks.data.as_ref().unwrap().send.una
}
fn queue_first(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> Option<(u64, u64)> {
    ep.conns[&h].hooks.data.as_ref().unwrap().reinject.first()
}
/// Every packet due at `now`.
fn drain(ep: &mut Endpoint<ChaCha20Rng>, now: Instant) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0; 1500];
    while let Some(n) = ep.poll_transmit(now, &mut buf) {
        out.push(buf[..n].to_vec());
    }
    out
}
/// `drain` at `now` and at every deadline (a pacing release) before `until`.
fn drain_until(ep: &mut Endpoint<ChaCha20Rng>, now: Instant, until: Instant) -> Vec<Vec<u8>> {
    let mut out = drain(ep, now);
    while let Some(t) = ep.poll_timeout().filter(|&t| t < until) {
        ep.handle_timeout(t);
        out.extend(drain(ep, t));
    }
    out
}
/// Reno, which never paces: for tests whose sends assume the whole budget at once.
fn reno() -> Box<dyn crate::tcp::cc::CongestionControl> {
    Box::new(crate::tcp::cc::Reno::new())
}
/// The peer's ACK: TCP up to `ack`, DATA_ACK `data`, window field `wnd` (scale 7).
fn peer_ack(
    ep: &mut Endpoint<ChaCha20Rng>,
    syn: &Segment,
    now: Instant,
    ack: SeqNum,
    data: u64,
    wnd: u16,
) {
    let opts = data_ack(data);
    let seg = Segment {
        ack,
        wnd,
        ..peer_data(syn, 5001, &opts, &[])
    };
    let mut wire = [0; 1500];
    let n = packet::build(&seg, 0, &mut wire).unwrap();
    ep.handle_packet(now, &wire[..n]);
}
/// Opens the peer's window to 128,000 octets at both levels (scale 7).
fn open_window(ep: &mut Endpoint<ChaCha20Rng>, syn: &Segment, h: ConnectionHandle) {
    let head = una(ep, h);
    peer_ack(
        ep,
        syn,
        Instant::from_nanos(2),
        syn.seq.wrapping_add(1),
        head,
        1000,
    );
}
/// DSN of the segment's first payload octet and its mapping's Data-Level Length.
fn dsn_of(seg: &Segment, iss: SeqNum) -> Option<(u64, u16)> {
    let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options).first()?).ok()? else {
        return None;
    };
    let m = d.mapping?;
    let mptcp::Dsn::Dsn64(dsn) = m.dsn else {
        panic!("64-bit DSNs only")
    };
    let rel = seg.seq.0.wrapping_sub(iss.0);
    (!seg.payload.is_empty()).then(|| (dsn + u64::from(rel.wrapping_sub(m.ssn)), m.data_len))
}

#[test]
fn snapshot_is_side_effect_free() {
    fn mid_transfer() -> (Endpoint<ChaCha20Rng>, ConnectionHandle, Instant) {
        let (mut ep, h, syn, _) = connected_scaled(1 << 20);
        open_window(&mut ep, &syn, h);
        ep.connection(h).unwrap().write(&[3; 50_000]).unwrap();
        let sent = drain(&mut ep, Instant::from_nanos(10));
        assert_eq!(sent.len(), 3, "IW");
        let seg = packet::parse(&sent[1]).unwrap();
        let end = seg.seq.wrapping_add(seg.payload.len() as u32);
        let now = Instant::from_nanos(1_000_000);
        let head = una(&ep, h);
        peer_ack(&mut ep, &syn, now, end, head + 2864, 1000);
        (ep, h, now)
    }
    let (mut a, h, now) = mid_transfer();
    let (mut b, _, _) = mid_transfer();
    let head = Some((una(&a, h), 1000));
    for _ in 0..100 {
        a.conns
            .get_mut(&h)
            .unwrap()
            .build_snapshots(now, head, None, 1500);
    }
    let snapshot = a.conns[&h].snapshots()[0];
    assert!(snapshot.new_budget.bytes() > 0 && snapshot.reinject_budget.bytes() > 0);
    assert_eq!(a.poll_timeout(), b.poll_timeout());
    let (ta, tb) = (&a.conns[&h].subflows[0].tcb, &b.conns[&h].subflows[0].tcb);
    assert_eq!((ta.cwnd(), ta.rto_streak()), (tb.cwnd(), tb.rto_streak()));
    assert_eq!(format!("{ta:?}"), format!("{tb:?}"), "no Tcb state changed");
    let out = drain(&mut a, now);
    assert!(!out.is_empty());
    assert_eq!(out, drain(&mut b, now));
}

#[test]
fn rogue_scheduler_plan_rejected() {
    let (mut ep, h, syn, _) = connected_scaled(1 << 20);
    open_window(&mut ep, &syn, h);
    let (log, rogue) = install_probe(&mut ep, h);
    let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    ep.connection(h).unwrap().write(&data).unwrap();
    let mut now = Instant::from_nanos(10);
    let head = una(&ep, h);
    for r in [
        Rogue::OverBudget,
        Rogue::NoSuchSubflow,
        Rogue::ForeignReinject(head, 1),
    ] {
        set_rogue(&mut ep, h, &rogue, Some(r));
        assert!(
            drain(&mut ep, now).is_empty(),
            "nothing is sent for a rejected plan"
        );
    }
    assert_eq!(log.lock().unwrap().plans.len(), 3);
    assert_eq!(ep.conns[&h].hooks.rejected_plans, 3);
    // A Joining subflow: with no Active subflow `plan` is not even called ...
    set_rogue(&mut ep, h, &rogue, Some(Rogue::FirstSubflow));
    ep.conns.get_mut(&h).unwrap().subflows[0].state = SubflowState::Joining;
    assert!(drain(&mut ep, now).is_empty());
    assert_eq!(log.lock().unwrap().plans.len(), 3);
    // ... and a plan naming it is rejected by validation (as with a second, Active subflow).
    let c = ep.conns.get_mut(&h).unwrap();
    c.build_snapshots(now, None, None, 1500);
    let snapshot = c.snapshots()[0];
    let plan = Plan::Send {
        subflow: SubflowId(0),
        payload: Payload::New {
            bytes: snapshot.new_budget.bytes() as u32,
        },
    };
    assert!(snapshot.new_budget.bytes() > 0);
    assert_eq!(
        crate::mptcp::accept_plan(plan, &[snapshot], None, None),
        None
    );
    let active = SubflowSnapshot {
        state: SubflowState::Active,
        ..snapshot
    };
    assert!(crate::mptcp::accept_plan(plan, &[active], None, None).is_some());
    c.subflows[0].state = SubflowState::Active;
    assert!(
        log.lock().unwrap().assigned.is_empty(),
        "no on_assigned for a rejected plan"
    );
    // Valid plans: one on_assigned per installed mapping, with its byte count.
    set_rogue(&mut ep, h, &rogue, None);
    let mut mappings = Vec::new();
    let mut received = vec![None; data.len()];
    while una(&ep, h) != head + data.len() as u64 {
        let mut last = None;
        for pkt in drain(&mut ep, now) {
            let seg = packet::parse(&pkt).unwrap();
            if let Some((dsn, len)) = dsn_of(&seg, syn.seq) {
                let rel = seg.seq.0.wrapping_sub(syn.seq.0);
                let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
                    panic!()
                };
                if d.mapping.unwrap().ssn == rel {
                    mappings.push((SubflowId(0), u32::from(len), false));
                }
                for (i, b) in seg.payload.iter().enumerate() {
                    received[(dsn - head) as usize + i] = Some(*b);
                }
                let end = dsn + seg.payload.len() as u64;
                last = Some((seg.seq.wrapping_add(seg.payload.len() as u32), end));
            }
        }
        let (ack, data_end) = last.expect("progress");
        now = now + Duration::from_millis(10);
        peer_ack(&mut ep, &syn, now, ack, data_end, 1000);
    }
    let received: Vec<u8> = received.into_iter().map(Option::unwrap).collect();
    assert_eq!(
        received, data,
        "the transfer completes once MinRTT is restored"
    );
    assert_eq!(log.lock().unwrap().assigned, mappings);
    assert!(mappings.len() > 1);
    assert_eq!(ep.conns[&h].hooks.rejected_plans, 3);
    assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
}

#[test]
fn rule5_reinjection_goes_through_plan() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    let (log, _) = install_probe(&mut ep, h);
    ep.connection(h).unwrap().write(b"lost").unwrap();
    let first = transmit(&mut ep, Instant::from_nanos(2));
    let first = packet::parse(&first).unwrap();
    let head = una(&ep, h);
    let options = data_ack(head); // TCP received it, the DSN assembler discarded it.
    let mut ack = peer_data(&syn, 5001, &options, &[]);
    ack.ack = first.seq.wrapping_add(4);
    input(&mut ep, &ack);
    let deadline = ep.poll_timeout().expect("connection recovery timer");
    assert_eq!(queue_first(&ep, h), None);
    ep.handle_timeout(deadline);
    assert_eq!(
        queue_first(&ep, h),
        Some((head, 4)),
        "rule 5 fills the queue"
    );
    let plans = log.lock().unwrap().plans.len();
    let retry = transmit(&mut ep, deadline);
    let retry = packet::parse(&retry).unwrap();
    assert_eq!(
        retry.seq,
        first.seq.wrapping_add(4),
        "same subflow, new SSN mapping"
    );
    assert_eq!(retry.payload, b"lost");
    assert_eq!(dsn_of(&retry, syn.seq), Some((head, 4)));
    let log = log.lock().unwrap();
    assert_eq!(
        log.plans[plans..],
        [Plan::Send {
            subflow: SubflowId(0),
            payload: Payload::Reinject { dsn: head, len: 4 }
        }]
    );
    assert_eq!(
        log.assigned,
        [(SubflowId(0), 4, false), (SubflowId(0), 4, true)]
    );
    assert_eq!(queue_first(&ep, h), None);
    assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
}

/// Sends `len` octets in full segments, then lets the peer TCP-ACK them while DATA_ACK stays
/// at the head (it discarded them). Returns the head DSN and the last segment's end.
fn sent_and_discarded(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    syn: &Segment,
    writes: &[&[u8]],
    wnd: u16,
) -> (u64, SeqNum) {
    for w in writes {
        ep.connection(h).unwrap().write(w).unwrap();
    }
    let head = una(ep, h);
    let total: usize = writes.iter().map(|w| w.len()).sum();
    let sent = drain(ep, Instant::from_nanos(10));
    let payload: usize = sent
        .iter()
        .map(|p| packet::parse(p).unwrap().payload.len())
        .sum();
    assert_eq!(payload, total);
    let end = syn.seq.wrapping_add(1 + total as u32);
    peer_ack(ep, syn, Instant::from_nanos(1_000_000), end, head, wnd);
    (head, end)
}

#[test]
fn rule5_recovers_with_no_new_data() {
    let (mut ep, h, syn, _) = connected_scaled_cc(1 << 20, Some(reno));
    open_window(&mut ep, &syn, h);
    let (log, _) = install_probe(&mut ep, h);
    let (head, _) = sent_and_discarded(&mut ep, h, &syn, &[&[4; 2864]], 1000);
    assert!(drain(&mut ep, Instant::from_nanos(1_000_000)).is_empty());
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert_eq!(
        (d.send.next, d.send.end),
        (head + 2864, head + 2864),
        "no new data"
    );
    let deadline = ep.poll_timeout().unwrap();
    ep.handle_timeout(deadline);
    let out = drain(&mut ep, deadline);
    let seg = packet::parse(&out[0]).unwrap();
    assert_eq!(
        dsn_of(&seg, syn.seq),
        Some((head, 2864)),
        "the recovery segment"
    );
    assert!(matches!(
        log.lock().unwrap().plans.last(),
        Some(Plan::Send { payload: Payload::Reinject { dsn, len: 2864 }, .. }) if *dsn == head
    ));
}

#[test]
fn rule5_recovers_while_new_data_waits_on_nagle() {
    let (mut ep, h, syn, _) = connected_scaled_cc(1 << 20, Some(reno));
    open_window(&mut ep, &syn, h);
    ep.connection(h)
        .unwrap()
        .write(&[5; 3 * 1432 + 100])
        .unwrap();
    let head = una(&ep, h);
    let sent = drain(&mut ep, Instant::from_nanos(10));
    assert_eq!(sent.len(), 3, "the 100-octet tail waits on Nagle");
    let seg = |i: usize| packet::parse(&sent[i]).unwrap();
    let t1 = Instant::from_nanos(1_000_000);
    peer_ack(&mut ep, &syn, t1, seg(1).seq, head, 1000);
    assert!(drain(&mut ep, t1).is_empty());
    let t2 = t1 + Duration::from_millis(500); // restarts the TCP RTO, not rule 5's timer
    peer_ack(&mut ep, &syn, t2, seg(2).seq, head, 1000);
    assert!(drain(&mut ep, t2).is_empty());
    let deadline = ep.poll_timeout().unwrap();
    assert_eq!(deadline, t1 + Duration::from_secs(1));
    ep.handle_timeout(deadline);
    let c = ep.conns.get_mut(&h).unwrap();
    let head_candidate = c.reinject_head();
    c.build_snapshots(deadline, head_candidate, None, 1500);
    let s = c.snapshots()[0];
    assert_eq!(
        s.new_budget.bytes(),
        0,
        "Nagle holds the tail with data in flight"
    );
    assert!(s.reinject_budget.bytes() > 0);
    let out = drain(&mut ep, deadline);
    let seg = packet::parse(&out[0]).unwrap();
    assert_eq!(
        dsn_of(&seg, syn.seq),
        Some((head, 2864)),
        "the recovery segment"
    );
    for pkt in &out {
        let seg = packet::parse(pkt).unwrap();
        let dsn = dsn_of(&seg, syn.seq).unwrap().0;
        assert!(
            dsn + (seg.payload.len() as u64) <= head + 2864,
            "the tail stays held"
        );
    }
}

#[test]
fn reinject_queue_pruned_by_late_data_ack() {
    for (late_ack, queued) in [(500, (500, 500)), (2500, (2500, 1796))] {
        let (mut ep, h, syn, _) = connected_scaled(1 << 20);
        open_window(&mut ep, &syn, h);
        // A zero TCP window keeps the queued ranges from draining.
        let (head, end) = sent_and_discarded(&mut ep, h, &syn, &[&[6; 4296]], 0);
        let deadline = ep.poll_timeout().unwrap();
        ep.handle_timeout(deadline);
        assert_eq!(queue_first(&ep, h), Some((head, 4296)));
        let d = ep.conns.get_mut(&h).unwrap().hooks.data.as_mut().unwrap();
        d.reinject.remove(head + 1000, 1000); // two ranges: [0,1000) and [2000,4296)
        for pkt in drain(&mut ep, deadline) {
            assert!(packet::parse(&pkt).unwrap().payload.is_empty());
        }
        peer_ack(&mut ep, &syn, deadline, end, head + late_ack, 0);
        let una_now = una(&ep, h);
        assert_eq!(una_now, head + late_ack);
        assert_eq!(queue_first(&ep, h), Some((head + queued.0, queued.1)));
        peer_ack(&mut ep, &syn, deadline, end, una_now, 1000);
        let out = drain(&mut ep, deadline);
        let first = packet::parse(&out[0]).unwrap();
        assert_eq!(
            dsn_of(&first, syn.seq).unwrap().0,
            una_now,
            "reinjected from una"
        );
        for pkt in &out {
            if let Some((dsn, _)) = dsn_of(&packet::parse(pkt).unwrap(), syn.seq) {
                assert!(dsn >= una_now, "nothing below send.una is sent again");
            }
        }
        assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
    }
}

#[test]
fn full_mapping_slots_zero_budgets() {
    let (mut ep, h, syn, _) = connected_scaled(1 << 20);
    open_window(&mut ep, &syn, h);
    let (log, _) = install_probe(&mut ep, h);
    ep.connection(h).unwrap().set_nodelay(true);
    let now = Instant::from_nanos(10);
    for i in 0..1024u32 {
        ep.connection(h).unwrap().write(&[i as u8]).unwrap();
        assert_eq!(drain(&mut ep, now).len(), 1);
    }
    assert!(ep.conns[&h].subflows[0].mp.tx.is_full());
    ep.connection(h).unwrap().write(&[9; 100]).unwrap();
    let plans = log.lock().unwrap().plans.len();
    assert!(drain(&mut ep, now).is_empty());
    assert_eq!(log.lock().unwrap().plans.len(), plans, "plan is not called");
    let head = una(&ep, h);
    let c = ep.conns.get_mut(&h).unwrap();
    c.build_snapshots(now, Some((head, 1)), None, 1500);
    let s = c.snapshots()[0];
    assert_eq!((s.new_budget, s.reinject_budget), Default::default());
    assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
    // A TCP ACK frees one slot: assignment resumes.
    peer_ack(&mut ep, &syn, now, syn.seq.wrapping_add(2), head + 1, 1000);
    let out = drain(&mut ep, now);
    assert!(
        out.iter()
            .any(|p| packet::parse(p).unwrap().payload == [9; 100])
    );
    assert_eq!(
        log.lock().unwrap().assigned.last(),
        Some(&(SubflowId(0), 100, false))
    );
    assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
}

#[test]
fn reinject_across_adjacent_write_chunks() {
    let (mut ep, h, syn, _) = connected_scaled_cc(1 << 20, Some(reno));
    open_window(&mut ep, &syn, h);
    let writes: [&[u8]; 3] = [&[0xa; 1000], &[0xb; 1000], &[0xc; 864]];
    let (head, _) = sent_and_discarded(&mut ep, h, &syn, &writes, 1000);
    let deadline = ep.poll_timeout().unwrap();
    ep.handle_timeout(deadline);
    assert_eq!(queue_first(&ep, h), Some((head, 2864)));
    let out = drain(&mut ep, deadline);
    let mut peer = vec![None; 2864];
    for pkt in &out {
        let seg = packet::parse(pkt).unwrap();
        let Some((dsn, len)) = dsn_of(&seg, syn.seq) else {
            continue;
        };
        let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
            panic!()
        };
        let mptcp::Dsn::Dsn64(start) = d.mapping.unwrap().dsn else {
            panic!()
        };
        let run = ep.conns[&h]
            .hooks
            .data
            .as_ref()
            .unwrap()
            .send
            .run_len(start);
        assert!(
            usize::from(len) <= run.min(65535),
            "within the stored run and DLL limit"
        );
        for (i, b) in seg.payload.iter().enumerate() {
            peer[(dsn - head) as usize + i] = Some(*b);
        }
    }
    assert_eq!(queue_first(&ep, h), None, "the queue empties");
    let peer: Vec<u8> = peer
        .into_iter()
        .map(|b| b.expect("every octet reinjected"))
        .collect();
    assert_eq!(peer, writes.concat(), "byte-exact");
    assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
}

#[test]
fn rogue_reinject_outside_head_rejected() {
    let (mut ep, h, syn, _) = connected_scaled_cc(1 << 20, Some(reno));
    open_window(&mut ep, &syn, h);
    let (log, rogue) = install_probe(&mut ep, h);
    let (head, _) = sent_and_discarded(&mut ep, h, &syn, &[&[4; 2864]], 1000);
    let deadline = ep.poll_timeout().unwrap();
    ep.handle_timeout(deadline);
    assert_eq!(queue_first(&ep, h), Some((head, 2864)));
    let c = ep.conns.get_mut(&h).unwrap();
    let candidate = c.reinject_head();
    assert_eq!(candidate, Some((head, 2864)));
    c.build_snapshots(deadline, candidate, None, 1500);
    let snapshot = c.snapshots()[0];
    assert!(
        snapshot.reinject_budget.bytes() >= 1,
        "the budget admits a 1-octet reinjection"
    );
    let assigned = log.lock().unwrap().assigned.len();
    // Queued but not the head, beyond the queue, and longer than the head candidate.
    for (dsn, len) in [(head + 1, 1), (head + 5000, 1), (head, 2865)] {
        set_rogue(&mut ep, h, &rogue, Some(Rogue::ForeignReinject(dsn, len)));
        let before = ep.conns[&h].hooks.rejected_plans;
        assert!(
            drain(&mut ep, deadline).is_empty(),
            "nothing is sent for ({dsn}, {len})"
        );
        assert_eq!(ep.conns[&h].hooks.rejected_plans, before + 1);
        assert_eq!(
            log.lock().unwrap().assigned.len(),
            assigned,
            "no on_assigned"
        );
        assert_eq!(queue_first(&ep, h), Some((head, 2864)), "queue unchanged");
    }
    // The connection's own budgets never exceed the candidate, so `len <= c` is checked on a
    // snapshot whose Reinject budget would admit more than the candidate.
    let wide = SubflowSnapshot {
        reinject_budget: crate::tcp::SendBudget {
            seg_payload: 1432,
            full_segments: 0,
            partial: 5000,
        },
        ..snapshot
    };
    let reinject = |len| Plan::Send {
        subflow: SubflowId(0),
        payload: Payload::Reinject { dsn: head, len },
    };
    assert_eq!(
        crate::mptcp::accept_plan(reinject(2865), &[wide], candidate, None),
        None
    );
    assert!(crate::mptcp::accept_plan(reinject(2864), &[wide], candidate, None).is_some());
    // MinRTT restored: the head itself is reinjected.
    set_rogue(&mut ep, h, &rogue, None);
    let out = drain(&mut ep, deadline);
    let seg = packet::parse(&out[0]).unwrap();
    assert_eq!(dsn_of(&seg, syn.seq), Some((head, 2864)));
    assert_eq!(
        log.lock().unwrap().assigned.last(),
        Some(&(SubflowId(0), 2864, true))
    );
    assert_eq!(queue_first(&ep, h), None);
    assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
}

// M2 Task 3b: pacing gate, release timer and app-limited marking.

use crate::tcp::AppLimited;
use crate::tcp::cc::{AckSample, CongestionControl, CongestionEvent, RecoveryAck};
use std::cell::RefCell;

thread_local! {
    /// Every ACK sample a `FixedPacing` controller on this test's thread received.
    static SAMPLES: RefCell<Vec<AckSample>> = const { RefCell::new(Vec::new()) };
    /// The same for controllers built with `b` set (a second subflow's).
    static SAMPLES_B: RefCell<Vec<AckSample>> = const { RefCell::new(Vec::new()) };
}

/// One MPTCP data segment (1460 − 28 octets of DSS) per 10 ms.
const RATE: u64 = 143_200;

/// Fixed cwnd and, if `rate` is set, a fixed pacing rate; records ACK samples in `SAMPLES`.
struct FixedPacing {
    rate: Option<u64>,
    cwnd: u32,
    /// Record into `SAMPLES_B` instead of `SAMPLES`.
    b: bool,
}
impl CongestionControl for FixedPacing {
    fn on_ack(&mut self, a: &AckSample) {
        let sink = if self.b { &SAMPLES_B } else { &SAMPLES };
        sink.with(|s| s.borrow_mut().push(*a));
    }
    fn on_congestion(&mut self, _: CongestionEvent, _: u32, _: Instant) {}
    fn on_recovery_ack(&mut self, _: RecoveryAck) {}
    fn cwnd(&self) -> u32 {
        self.cwnd
    }
    fn pacing_rate(&self) -> Option<u64> {
        self.rate
    }
}
fn paced() -> Box<dyn CongestionControl> {
    Box::new(FixedPacing {
        rate: Some(RATE),
        cwnd: 64 << 10,
        b: false,
    })
}
fn recording() -> Box<dyn CongestionControl> {
    Box::new(FixedPacing {
        rate: None,
        cwnd: 64 << 10,
        b: false,
    })
}
fn app_limited_reason(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> Option<AppLimited> {
    ep.conns[&h].subflows[0].tcb.app_limited()
}

/// A paced connection with the peer's window open and `len` octets written; the first
/// release quantum (at `RATE` the 2-segment floor) goes out at `T0`. Returns the endpoint,
/// handle, SYN, head DSN and the first segment.
fn paced_first_segment(
    len: usize,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Segment<'static>,
    u64,
    Vec<u8>,
) {
    let (mut ep, h, syn, _) = connected_scaled_cc(1 << 20, Some(paced));
    open_window(&mut ep, &syn, h);
    let head = una(&ep, h);
    ep.connection(h).unwrap().write(&vec![1; len]).unwrap();
    let out = drain(&mut ep, T0);
    assert_eq!(
        out.len(),
        (len / 1432).clamp(1, 2),
        "one quantum per release"
    );
    assert!(
        out.iter()
            .all(|p| packet::parse(p).unwrap().payload.len() == 1432)
    );
    (ep, h, syn, head, out[0].clone())
}
#[test]
fn paced_bulk_flight_is_not_bounded_by_mapping_slots() {
    // A 4 MiB cwnd paced at 1.432 GB/s and 8 MiB peer windows: with one mapping per
    // release quantum, flight passes 1024 mapping slots × 1432 octets.
    fn bulk() -> Box<dyn CongestionControl> {
        Box::new(FixedPacing {
            rate: Some(1_432_000_000),
            cwnd: 4 << 20,
            b: false,
        })
    }
    let (mut ep, h, syn, _) = connected_scaled_cc(1 << 20, Some(bulk));
    let head = una(&ep, h);
    peer_ack(
        &mut ep,
        &syn,
        Instant::from_nanos(2),
        syn.seq.wrapping_add(1),
        head,
        65535,
    );
    let chunk = vec![7; 1 << 16];
    let (mut now, mut sent) = (Instant::from_nanos(10), 0usize);
    let end = Instant::from_nanos(100_000_000);
    loop {
        while ep.connection(h).unwrap().write(&chunk).is_ok_and(|n| n > 0) {}
        sent += drain(&mut ep, now)
            .iter()
            .map(|p| packet::parse(p).unwrap().payload.len())
            .sum::<usize>();
        match ep.poll_timeout() {
            Some(t) if t < end && sent < 2_000_000 => {
                now = t.max(now);
                ep.handle_timeout(now);
            }
            _ => break,
        }
    }
    assert!(sent > 1024 * 1432, "{sent} octets in flight");
}

const T0: Instant = Instant::from_nanos(10);
/// The release after the 2-segment quantum at `T0`: 2 × 1432 octets at `RATE`.
fn release() -> Instant {
    T0 + Duration::from_millis(20)
}

#[test]
fn closed_subflow_does_not_wake_idle_connection() {
    let (mut ep, h, syn, _) = connected_scaled_cc(1 << 20, None);
    open_window(&mut ep, &syn, h);
    // Give CUBIC a nonzero RTT before arming its pacing release.
    let head = una(&ep, h);
    ep.connection(h).unwrap().write(&[1; 1432]).unwrap();
    let initial = drain(&mut ep, T0);
    let first = packet::parse(&initial[0]).unwrap();
    let sent_at = T0 + Duration::from_millis(10);
    peer_ack(
        &mut ep,
        &syn,
        sent_at,
        first.seq.wrapping_add(1432),
        head + 1432,
        1000,
    );
    ep.connection(h).unwrap().write(&[1; 32_000]).unwrap();
    drain(&mut ep, sent_at);
    assert!(ep.conns[&h].subflows[0].tcb.release_at().is_some());
    // The initial subflow remains while MPTCP waits for a replacement path.
    let reset = Segment {
        flags: TcpFlags::RST | TcpFlags::ACK,
        ..peer_data(&syn, 5001, &[], &[])
    };
    let mut buf = [0u8; 1500];
    let n = packet::build(&reset, 0, &mut buf).unwrap();
    ep.handle_packet(sent_at + Duration::from_millis(1), &buf[..n]);
    assert_eq!(ep.conns[&h].subflows[0].tcb.state(), TcpState::Closed);
    let now = T0 + Duration::from_millis(100);
    drain(&mut ep, now);
    let visits = ep.visits;
    for _ in 0..100 {
        assert!(ep.poll_transmit(now, &mut buf).is_none());
    }
    assert_eq!(
        ep.visits - visits,
        0,
        "a closed TCB must not wake an idle connection"
    );
}

#[test]
fn endpoint_poll_timeout_wakes_paced_subflow() {
    let (mut ep, _, syn, head, first) = paced_first_segment(3 * 1432);
    let first = packet::parse(&first).unwrap();
    // ACKed at once: nothing in flight, no RTO; only the release can wake the driver.
    let t1 = T0 + Duration::from_millis(1);
    peer_ack(
        &mut ep,
        &syn,
        t1,
        first.seq.wrapping_add(2 * 1432),
        head + 2 * 1432,
        1000,
    );
    assert!(drain(&mut ep, t1).is_empty());
    assert_eq!(ep.poll_timeout(), Some(release()));
    ep.handle_timeout(release());
    let out = drain(&mut ep, release());
    assert_eq!(out.len(), 1);
    let seg = packet::parse(&out[0]).unwrap();
    assert_eq!(dsn_of(&seg, syn.seq), Some((head + 2 * 1432, 1432)));
}

#[test]
fn paced_subflow_budget_zero_reaches_scheduler() {
    let (mut ep, h, _, head, _) = paced_first_segment(3 * 1432);
    let c = ep.conns.get_mut(&h).unwrap();
    c.build_snapshots(T0, Some((head, 1432)), None, 1500);
    let s = c.snapshots()[0];
    assert_eq!((s.new_budget, s.reinject_budget), Default::default());
    c.build_snapshots(release(), Some((head, 1432)), None, 1500);
    let s = c.snapshots()[0];
    assert_eq!(
        (s.new_budget.bytes(), s.reinject_budget.bytes()),
        (1432, 1432)
    );
}

#[test]
fn pacing_deadline_consumed_when_scheduler_idle() {
    // Case (c) of `tcb::tests::pacing_deadline_consumed_when_blocked_otherwise`.
    let (mut ep, h, _, _, _) = paced_first_segment(3 * 1432);
    let (_, rogue) = install_probe(&mut ep, h);
    *rogue.lock().unwrap() = Some(Rogue::Idle);
    assert_eq!(ep.poll_timeout(), Some(release()));
    ep.handle_timeout(release());
    let next = ep.poll_timeout().expect("the RTO");
    assert!(next > release(), "{next:?}");
    for _ in 0..3 {
        assert!(drain(&mut ep, release()).is_empty());
        assert_eq!(ep.poll_timeout(), Some(next), "fires once");
    }
}

#[test]
fn paced_reinjection_alone_wakes_at_release() {
    // Carried from Task 3: a queued reinjection is demand although nothing is unassigned.
    let (mut ep, h, syn, head, first) = paced_first_segment(1432);
    let first = packet::parse(&first).unwrap();
    let t1 = T0 + Duration::from_millis(1);
    // TCP-ACKed, DATA_ACK still at the head: the peer discarded it.
    peer_ack(&mut ep, &syn, t1, first.seq.wrapping_add(1432), head, 1000);
    let d = ep.conns.get_mut(&h).unwrap().hooks.data.as_mut().unwrap();
    assert_eq!((d.send.next, d.send.end), (head + 1432, head + 1432));
    d.reinject.insert(head, 1432);
    assert!(
        drain(&mut ep, t1).is_empty(),
        "the reinjection waits for the release"
    );
    // One segment went out at T0: its release is 1432 octets at `RATE` later.
    let release = T0 + Duration::from_millis(10);
    assert_eq!(ep.poll_timeout(), Some(release));
    ep.handle_timeout(release);
    let out = drain(&mut ep, release);
    let seg = packet::parse(&out[0]).unwrap();
    assert_eq!(dsn_of(&seg, syn.seq), Some((head, 1432)));
    assert_eq!(queue_first(&ep, h), None);
}

#[test]
fn connection_window_exhausted_is_not_app_limited() {
    SAMPLES.with(|s| s.borrow_mut().clear());
    let (mut ep, h, syn, _) = connected_scaled_cc(1 << 20, Some(recording));
    let head = una(&ep, h);
    // A window of 179 << 7 = 22,912 octets: exactly 16 segments of 1432.
    const WND: u16 = 179;
    peer_ack(&mut ep, &syn, T0, syn.seq.wrapping_add(1), head, WND);
    ep.connection(h).unwrap().write(&[2; 50_000]).unwrap();
    let out = drain(&mut ep, T0);
    let sent: usize = out
        .iter()
        .map(|p| packet::parse(p).unwrap().payload.len())
        .sum();
    assert_eq!(sent, 22_912);
    let end = syn.seq.wrapping_add(1 + 22_912);
    // All TCP-ACKed (the subflow window is open again, cwnd has room), DATA_ACK unmoved: the
    // connection-level window stays exhausted with data queued.
    let t1 = T0 + Duration::from_millis(1);
    peer_ack(&mut ep, &syn, t1, end, head, WND);
    for pkt in drain(&mut ep, t1) {
        let seg = packet::parse(&pkt).unwrap();
        assert!(seg.payload.is_empty(), "connection window exhausted");
    }
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert!(d.send.next != d.send.end && d.reinject.is_empty());
    let edge = ep.conns[&h]
        .hooks
        .negotiation
        .as_ref()
        .unwrap()
        .send_right_edge;
    assert_eq!(
        edge,
        Some(d.send.next),
        "nothing unassigned fits the window"
    );
    assert_eq!(
        app_limited_reason(&ep, h),
        None,
        "neither NoData nor NotScheduled"
    );
    // The window opens: everything from here on is cwnd- or window-limited until the queue
    // drains.
    let mut now = t1 + Duration::from_millis(1);
    let (mut tcp_ack, mut data_ack) = (end, head + 22_912);
    while data_ack != head + 50_000 {
        peer_ack(&mut ep, &syn, now, tcp_ack, data_ack, 1000);
        for pkt in drain(&mut ep, now) {
            let seg = packet::parse(&pkt).unwrap();
            if let Some((dsn, _)) = dsn_of(&seg, syn.seq) {
                tcp_ack = seg.seq.wrapping_add(seg.payload.len() as u32);
                data_ack = dsn + seg.payload.len() as u64;
            }
        }
        now = now + Duration::from_millis(10);
    }
    peer_ack(&mut ep, &syn, now, tcp_ack, data_ack, 1000);
    SAMPLES.with(|s| {
        let s = s.borrow();
        assert!(s.len() > 2);
        assert!(s.iter().all(|a| !a.app_limited), "{s:?}");
    });
}

/// Spec §1.6: `Connection::write` runs the sampler's app-limited check on the queue state
/// from before it enqueues. A plain TCP connection that has sent nothing is app-limited when
/// written to, so its first data goes out marked.
#[test]
fn app_limited_marked_before_write() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(31));
    let h = ep
        .connect(
            Instant::from_nanos(0),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            ConnectConfig::default(),
        )
        .unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &[], syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let marked =
        |ep: &Endpoint<ChaCha20Rng>| ep.conns[&h].subflows[0].tcb.sampler().is_app_limited();
    assert!(!marked(&ep));
    ep.connection(h).unwrap().write(&[1; 1000]).unwrap();
    assert!(marked(&ep));
}

#[test]
fn idle_scheduler_marks_not_scheduled() {
    let (mut ep, h, syn, _) = connected_scaled(1 << 20);
    open_window(&mut ep, &syn, h);
    let (_, rogue) = install_probe(&mut ep, h);
    let now = Instant::from_nanos(10);
    drain(&mut ep, now);
    assert_eq!(
        app_limited_reason(&ep, h),
        Some(AppLimited::NoData),
        "nothing to send"
    );
    *rogue.lock().unwrap() = Some(Rogue::Idle);
    ep.connection(h).unwrap().write(&[3; 5000]).unwrap();
    assert!(drain(&mut ep, now).is_empty());
    assert_eq!(app_limited_reason(&ep, h), Some(AppLimited::NotScheduled));
    let c = ep.conns.get_mut(&h).unwrap();
    c.build_snapshots(now, None, None, 1500);
    assert_eq!(c.snapshots()[0].app_limited, Some(AppLimited::NotScheduled));
    *rogue.lock().unwrap() = None;
    assert!(!drain(&mut ep, now).is_empty());
    assert_eq!(app_limited_reason(&ep, h), None, "MinRTT assigned data");
}

#[test]
fn cubic_connection_window_limited_does_not_grow_cwnd() {
    // RFC 9438 §5.8: limited by the receiver's (here the connection-level) window is
    // application-limited for CUBIC, though not app-limited for BBR's samples.
    let (mut ep, h, syn, _) = connected_scaled(1 << 20);
    open_window(&mut ep, &syn, h);
    let head = una(&ep, h);
    ep.connection(h).unwrap().write(&vec![6; 400_000]).unwrap();
    let cwnd = |ep: &Endpoint<ChaCha20Rng>| ep.conns[&h].subflows[0].tcb.cwnd();
    // Phase 1: the peer TCP-ACKs everything but holds DATA_ACK at the head, so the
    // connection-level edge stays at head + 128,000 while the subflow window stays open.
    let mut now = Instant::from_nanos(10);
    let (mut tcp_ack, mut data_end) = (syn.seq.wrapping_add(1), head);
    let mut dack = head;
    let mut rounds = 0;
    loop {
        // CUBIC paces after its first RTT sample: send at every release of the round.
        for pkt in drain_until(&mut ep, now, now + Duration::from_millis(10)) {
            let seg = packet::parse(&pkt).unwrap();
            if let Some((dsn, _)) = dsn_of(&seg, syn.seq) {
                tcp_ack = seg.seq.wrapping_add(seg.payload.len() as u32);
                data_end = dsn + seg.payload.len() as u64;
            }
        }
        now = now + Duration::from_millis(10);
        if rounds > 0 && data_end == head + 128_000 {
            // Phase 2: two segments of connection credit per round, every one TCP-ACKed.
            peer_ack(&mut ep, &syn, now, tcp_ack, dack, 1000);
            break;
        }
        peer_ack(&mut ep, &syn, now, tcp_ack, dack, 1000);
        rounds += 1;
        assert!(rounds < 20);
    }
    let before = cwnd(&ep);
    assert!(
        before > 20 * 1460,
        "slow start ran while cwnd-limited: {before}"
    );
    for _ in 0..30 {
        dack += 2864;
        peer_ack(&mut ep, &syn, now, tcp_ack, dack, 1000);
        let mut sent = 0;
        for pkt in drain_until(&mut ep, now, now + Duration::from_millis(10)) {
            let seg = packet::parse(&pkt).unwrap();
            if dsn_of(&seg, syn.seq).is_some() {
                tcp_ack = seg.seq.wrapping_add(seg.payload.len() as u32);
                sent += seg.payload.len();
            }
        }
        assert_eq!(sent, 2864, "connection-window-limited");
        now = now + Duration::from_millis(10);
        peer_ack(&mut ep, &syn, now, tcp_ack, dack, 1000);
    }
    assert_eq!(cwnd(&ep), before, "no growth while not cwnd-limited");
    assert_eq!(
        app_limited_reason(&ep, h),
        None,
        "and not app-limited for BBR samples"
    );
}

// M2 Task 4: MP_JOIN, reusing the helpers above.
#[path = "join_tests.rs"]
mod join_tests;

/// Once Confirmed, a pure ACK carries DSS DATA_ACK64 (12 octets) and so exactly three SACK
/// blocks (2 + 24 + 2 padding): the 40 octets are full.
#[test]
fn confirmed_pure_ack_carries_three_sack_blocks() {
    let (mut ep, h, syn, dsn) = connected_with(1 << 20, None, true);
    open_window(&mut ep, &syn, h);
    for (k, ssn) in [11u32, 21, 31, 41].into_iter().enumerate() {
        let opts = mapping(ssn, dsn + u64::from(ssn) - 1, 1);
        input(&mut ep, &peer_data(&syn, 5000 + ssn, &opts, b"x"));
        let bytes = transmit(&mut ep, Instant::from_nanos(3));
        let ack = packet::parse(&bytes).unwrap();
        assert!(ack.payload.is_empty());
        let opts: Vec<_> = walk(ack.options).map(Result::unwrap).collect();
        assert!(matches!(opts[0], TcpOpt::Mptcp(raw) if raw.len() == 12));
        let TcpOpt::Sack(blocks) = opts[1] else {
            panic!("{opts:?}")
        };
        assert_eq!(blocks.len(), 8 * (k + 1).min(3), "after {} ranges", k + 1);
        // The block holding the newest segment first (RFC 2018 §4).
        assert_eq!(&blocks[..4], &(5000 + ssn).to_be_bytes());
        assert_eq!(
            ack.options.len(),
            if k < 2 { 12 + 4 + 8 * (k + 1) } else { 40 }
        );
    }
}

/// Server MP_CAPABLE, one test per negotiation-table row (M4a Task 5).
mod server_capable;

/// DSS checksums: negotiation, sent mappings, presence check (M4b Task 2).
mod checksum;
use checksum::checksums_cfg;

/// MP_FAIL: the reset carrying it, `infinite_ok`, ignored MP_FAILs (M4b Task 5).
mod mp_fail;
