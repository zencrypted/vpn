# vpn

VPN Overlay Network for the Zencrypted ecosystem.

This repository currently contains a minimal Erlang/OTP VPN dataplane prototype.
It intentionally does not implement encryption, peer/session management, or PKI
logic yet.

## Architecture

The current local validation path is:

```text
TUN/TAP <-> Erlang <-> UDP <-> Erlang <-> TUN/TAP
```

X.509 PKI integration is expected to use `synrc/ca` in a later milestone.

## Modules

- `vpn_app` - OTP application entry point.
- `vpn_sup` - top-level supervisor.
- `vpn` - public API.
- `vpn_tun` - TUN/TAP integration layer.
- `vpn_udp` - UDP transport worker.
- `vpn_link` - bidirectional TUN/TAP to UDP link.
- `vpn_udp_sink` - local UDP test sink.
- `vpn_peer` - future peer/session abstraction.

## Build

```sh
rebar3 compile
```

## Test

```sh
rebar3 eunit
```

## Local Tunnel Validation

The Erlang VM must have permission to create and configure TAP interfaces. Give
the active `beam.smp` binary `cap_net_admin` before starting the shell:

```sh
sudo setcap cap_net_admin=ep <beam.smp>
```

Start the project shell:

```sh
rebar3 shell
```

Start both local tunnel endpoints:

```erlang
{ok, B} = vpn_link:start_link(
    <<"vpn1">>,
    "10.10.10.2",
    5556,
    {127,0,0,1},
    5555).

{ok, A} = vpn_link:start_link(
    <<"vpn0">>,
    "10.10.10.1",
    5555,
    {127,0,0,1},
    5556).
```

Reset counters before a focused run:

```erlang
vpn_link:reset_stats(A).
vpn_link:reset_stats(B).
```

Run IPv4 ping from another terminal:

```sh
ping -4 -c 10 10.10.10.2
```

Inspect counters:

```erlang
vpn_link:stats(A).
vpn_link:stats(B).
```

Expected ping result:

```text
10 packets transmitted
10 packets received
0% packet loss
```

Packet diagnostics classify frames as:

```text
arp
ipv4_icmp_echo_request
ipv4_icmp_echo_reply
ipv4_udp
ipv4_other
ipv6
unknown
```

## TUN Mode Validation

### 1. Start shell

```sh
rebar3 shell
```

### 2. Start endpoint B

```erlang
{ok, B} =
    vpn_link:start_link(
        <<"tun1">>,
        "10.20.20.2",
        tun,
        5556,
        {127,0,0,1},
        5555).
```

### 3. Start endpoint A

```erlang
{ok, A} =
    vpn_link:start_link(
        <<"tun0">>,
        "10.20.20.1",
        tun,
        5555,
        {127,0,0,1},
        5556).
```

### 4. Reset counters

```erlang
vpn_link:reset_stats(A).
vpn_link:reset_stats(B).
```

### 5. Run validation ping

```sh
ping -4 -c 10 10.20.20.2
```

Expected result:

```text
10 packets transmitted
10 packets received
0% packet loss
```

### 6. Inspect statistics

```erlang
vpn_link:stats(A).
vpn_link:stats(B).
```

Example healthy result:

```erlang
#{
  tun_rx_packets => N,
  udp_tx_packets => N,
  udp_rx_packets => N,
  tun_tx_packets => N
}
```

Packet counters should be approximately symmetric between both endpoints.

### 7. Packet diagnostics

Current packet classification:

```text
arp
ipv4_icmp_echo_request
ipv4_icmp_echo_reply
ipv4_udp
ipv4_other
ipv6
unknown
```

Diagnostics are intended for tunnel validation and troubleshooting.

## Notes

- No Elixir.
- No umbrella project.
- No external framework dependencies.
- No encryption or CA/PKI logic yet.
