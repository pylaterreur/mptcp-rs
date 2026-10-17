# mptcp-rs

A userspace, sans-I/O library for Multipath TCP v1 (RFC 8684), client and server, in Rust.

mptcp-rs implements MPTCP itself, on its own TCP engine; it does not use the MPTCP in the
Linux kernel. You give it incoming packets and the current time. It gives you back packets to
send and data to read. So it can run over any packet I/O, such as a TUN device or a userspace
network stack.

Status: the latest release, 0.2.0, is client only. The server role is on main and not released yet.

## Features

- TCP: CUBIC with HyStart++, pacing, and SACK loss recovery (RFC 6675). BBRv3
  (draft-ietf-ccwg-bbr-06, experimental) is opt-in.
- MPTCP v1: MP_CAPABLE, DSS, DATA_ACK, DATA_FIN, MP_TCPRST, and MP_FASTCLOSE in both
  directions. Falls back to plain TCP when MPTCP cannot be used.
- Multiple paths: MP_JOIN, a MinRTT scheduler with reinjection, and opportunistic
  retransmission so that one stalled path does not block the others.
- Path management: the application can add, close and remove subflows (for example, to rejoin
  when a link returns). Backup subflows, MP_PRIO, and ADD_ADDR and REMOVE_ADDR from the server.
- IPv4, IPv6 and mixed-family paths.

- Server role (on main, unreleased): `Endpoint::listen` and `unlisten`, passive MP_CAPABLE, and
  MP_JOIN from clients. Each accepted connection is one `Event::Accepted`.

DSS checksums are on by default (A=1, `ConnectConfig::checksums`) in both roles, with MP_FAIL.
A peer that requires them is honoured even when ours is off. Not yet supported (planned):
sending 32-bit DSNs.

Server limits: the server sends no ADD_ADDR, and there are no SYN cookies, so SYNs beyond
the `max_half_open` cap are dropped. `poll_transmit` visits only the connections that may
have something to send, and `poll_timeout` and `handle_timeout` only those that an endpoint
call reached or whose deadline passed.

## Interoperability

Tested against Linux kernel MPTCP (kernel 7.0) as the server, over IPv4, IPv6 and mixed-family
paths:

- The Interop Suite: 33 scripted cases covering joins (including refused and failed ones),
  backup subflows and MP_PRIO, failover, ADD_ADDR and REMOVE_ADDR, subflow re-establishment,
  MP_TCPRST and MP_FASTCLOSE. Every case passes; CI runs the suite on every push.
- Transfers: 64 MiB each way, byte-exact; fallback when middleboxes strip MPTCP options;
  zero-window recovery; a different MTU per path; and 1 GiB transfers that complete while one
  of two paths is blackholed for 15 seconds.
- Two paths with different speeds give at least 1.2× the goodput of the better single path.

Goodput next to the Linux kernel MPTCP client, with the same server and links. Setup
(`tests/interop/run.sh`, `bench.py`): two network namespaces, client and server, joined by two
veth pairs, path A and path B, with netem on both directions of each. The server is a kernel
MPTCP socket in every run. On the mptcp-rs side, `mptcp-rs-tun` runs the whole TCP/MPTCP stack
in userspace and reads and writes IP packets on a TUN device; the client namespace's kernel
routes them out over path A or B by source address. The kernel client is an `IPPROTO_MPTCP`
socket in the same namespace, with an `ip mptcp endpoint` on path B. Each run is a 30 s
transfer in one direction, and both clients open the first subflow on A and join on B:

![Goodput of mptcp-rs and the Linux kernel MPTCP client over two netem paths](docs/images/kernel-compare.svg)

Paths A (10 ms one-way, 300 Mbit/s) and B (30 ms, 80 Mbit/s) are netem on veth on one host; CUBIC, median of 5 runs, one segment per packet at netem; the dashed line is each client's ceiling after header overhead. Measured with checksums off (A=0).

Without netem the CPU is the limit, and the kernel is far ahead (same paths A+B, offloads at their defaults, median of 5 runs, checksums off (A=0)):

| direction | client | goodput | host CPU per GB |
|---|---|---|---|
| c2s (client sending) | mptcp-rs over TUN | 1.44 Gbit/s | 12.4 s |
| c2s (client sending) | Linux kernel | 34.3 Gbit/s | 0.53 s |
| s2c (client receiving) | mptcp-rs over TUN | 1.31 Gbit/s | 10.9 s |
| s2c (client receiving) | Linux kernel | 35.7 Gbit/s | 0.45 s |

The kernel figures are one connection with one sending thread saturating a core. In s2c the kernel server sends in both cases, so those rows compare the clients as receivers. Host CPU per GB is all busy CPU time on the host over a 20 s window of the transfer, divided by the TCP payload the server's subflows moved in that window.

The server role is tested against the Linux kernel MPTCP client (`INTEROP_CLIENT=kernel`) and
against our own client, with `mptcp-rs-tun --listen` as the server: `INTEROP_SERVER=mptcp-rs
tests/interop/run.sh <scenario>`, for the scenarios `run.sh` accepts in that mode.

It has not been tested against other MPTCP implementations yet.

## Known limits

- If the application has no more data to send and a path fails, the data stuck on that path is
  resent on another path only after the path is marked stale (about 7 seconds in our tests).
- A backup subflow carries data only after the primary subflow stops working.
- After a normal close, `Closed` is reported only after every subflow leaves TIME-WAIT. This can
  take up to 120 seconds.

## Usage

`Endpoint::connect_mptcp` starts an MPTCP connection and falls back to TCP if the server does
not support MPTCP. `Endpoint::connect` starts a plain TCP connection. Both use the same APIs for
packets, timers and the application. See the [API documentation](https://docs.rs/mptcp-rs) for
an example.

The repository also has a Linux TUN client, `mptcp-rs-tun` (not on crates.io):

```sh
cargo build --release -p mptcp-rs-tun
sudo target/release/mptcp-rs-tun --mode mptcp --tun mtun0 \
  --local 10.0.9.2 --remote 10.0.1.2:5201 --send 67108864 --expect 67108864
```

With `--listen IP:PORT` instead of `--local` and `--remote`, it is a server: it serves the first
accepted connection and aborts any other.

Rust 1.85 or later is required.

## Congestion control

Two congestion controllers are available, chosen per connection with
`ConnectConfig::congestion_control`:

- `CongestionControlKind::Cubic` (the default): CUBIC with HyStart++ and pacing.
- `CongestionControlKind::BbrV3`: BBRv3 (draft-ietf-ccwg-bbr-06, experimental).

```rust
let mut cfg = ConnectConfig::default();
cfg.congestion_control = CongestionControlKind::BbrV3;
```

`mptcp-rs-tun` takes `--cc cubic|bbr3`. Every subflow of a connection runs the same
controller, and the subflows are not coupled: two subflows that share one bottleneck take about
the share of two TCP flows, with either controller.

## Testing

Run `cargo test --workspace` for the unit and integration tests.

The interop tests run the TUN client against Linux kernel MPTCP inside Docker. They need a
Linux kernel with MPTCP, TUN, and the iptables TCPOPTSTRIP, u32 and CONNMARK modules. Build the
release client first (`cargo build --release -p mptcp-rs-tun`).

```sh
tests/interop/run.sh m1                     # one transfer scenario
bash tests/interop/suite/run.sh --runs 3    # the Interop Suite: 33 cases, about 20 min per run
bash tests/interop/suite/run.sh --case NAME # one case
```

Each run saves pcaps and logs under `artifacts/interop/`.

## Roadmap

Next: the server role is released with checksums and MP_FAIL. TCP work continues
alongside: RACK-TLP and timestamps. Async runtime integration, `no_std` and coupled
congestion control are not planned yet.

## License

Licensed under either of MIT or Apache-2.0, at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
