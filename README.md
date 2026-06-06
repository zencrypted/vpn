# vpn

VPN Overlay Network for the Zencrypted ecosystem.

This repository currently contains a minimal Erlang/OTP VPN dataplane prototype.
It currently uses a temporary PSK encrypted dataplane. It intentionally does not
implement peer/session management, CA services, or key exchange yet.

## Architecture

The current local validation path is:

```text
TUN/TAP <-> Erlang <-> UDP <-> Erlang <-> TUN/TAP
```

Runtime layering:

```text
vpn_peer
    |
vpn_link
    |
vpn_udp
vpn_tun
```

`vpn_peer` is the stable public runtime API. `vpn_link` is a lower-level
transport component.

X.509 PKI integration is expected to use `synrc/ca` in a later milestone.
The current development trust store only verifies that configured peer
certificates are signed by the local development CA fixture.

## Modules

- `vpn_app` - OTP application entry point.
- `vpn_sup` - top-level supervisor.
- `vpn` - public API.
- `vpn_tun` - TUN/TAP integration layer.
- `vpn_udp` - UDP transport worker.
- `vpn_link` - bidirectional TUN/TAP to UDP link.
- `vpn_udp_sink` - local UDP test sink.
- `vpn_peer` - public runtime peer abstraction.
- `vpn_manager` - read-only management API for supervised peers.
- `vpn_trust_store` - development CA certificate trust store.

## Build

```sh
rebar3 compile
```

## Test

```sh
rebar3 eunit
```

## VPN Management API

`vpn_manager` is the initial read-only management layer for supervised peers. It
is intended to become the backend surface for the future N2O/EXO admin UI.

```erlang
vpn_manager:list_peers().
vpn_manager:peer_info(peer_a).
vpn_manager:peer_stats(peer_a).
```

`peer_info/1` returns identity and operational config:

```erlang
#{
    id => peer_a,
    identity => IdentityInfo,
    config => Config
}
```

Unknown peers return:

```erlang
{error, not_found}
```

## Peer-Based Validation

Use `vpn_peer` for runtime validation. It owns the peer config and wraps the
lower-level `vpn_link`.

```erlang
PeerB = #{
    id => peer_b,
    remote_peer_id => peer_a,
    psk => <<"0123456789abcdef0123456789abcdef">>,
    mode => tun,
    ifname => <<"tun1">>,
    ip => "10.20.20.2",
    local_udp_port => 5556,
    remote_ip => {127,0,0,1},
    remote_udp_port => 5555,
    certificate_path => "priv/certs/peer_b.crt",
    private_key_path => "priv/certs/peer_b.key",
    ca_certificate_path => "priv/certs/ca.crt"
}.

PeerA = #{
    id => peer_a,
    remote_peer_id => peer_b,
    psk => <<"0123456789abcdef0123456789abcdef">>,
    mode => tun,
    ifname => <<"tun0">>,
    ip => "10.20.20.1",
    local_udp_port => 5555,
    remote_ip => {127,0,0,1},
    remote_udp_port => 5556,
    certificate_path => "priv/certs/peer_a.crt",
    private_key_path => "priv/certs/peer_a.key",
    ca_certificate_path => "priv/certs/ca.crt"
}.
```

Start both peers and reset counters:

```erlang
{ok, B} = vpn_peer:start_link(PeerB).
{ok, A} = vpn_peer:start_link(PeerA).

vpn_peer:reset_stats(A).
vpn_peer:reset_stats(B).
```

Run validation ping from another terminal:

```sh
ping -4 -c 10 10.20.20.2
```

Inspect peer statistics:

```erlang
vpn_peer:identity(A).
vpn_peer:config(A).
vpn_peer:stats(A).
vpn_peer:stats(B).
```

`identity/1` returns identity metadata, `config/1` returns operational
configuration without certificate paths, and `stats/1` returns runtime counters:

```erlang
#{
    id => PeerId,
    link => LinkStats
}
```

## Encrypted PSK Dataplane

Required peer config fields:

```text
id
remote_peer_id
psk
mode
ifname
ip
local_udp_port
remote_ip
remote_udp_port
certificate_path
private_key_path
ca_certificate_path
```

Packet pipeline:

```text
TUN -> vpn_frame -> vpn_crypto -> UDP
UDP -> vpn_crypto -> vpn_frame -> peer validation -> TUN
```

Successful validation:

```sh
rebar3 compile
rebar3 eunit
rebar3 shell
ping -4 -c 10 10.20.20.2
```

Expected ping result:

```text
10 packets transmitted
10 packets received
0% packet loss
```

Expected link stats:

```erlang
#{
    crypto_failures => 0,
    frames_rejected => 0,
    frames_accepted => N
}
```

where `N > 0`.

Negative PSK test: set different `psk` values for `peer_a` and `peer_b`.
Expected result: ping fails and `crypto_failures` increases.

The PSK is temporary and will later be replaced by CA/PKI-based key
establishment.

## Development Certificate Trust

Development fixtures live in `priv/certs`:

```text
ca.crt
ca.key
peer_a.crt
peer_a.key
peer_b.crt
peer_b.key
```

`peer_a.crt` and `peer_b.crt` are signed by the development CA. During peer
startup, `vpn_identity` loads the peer certificate/key PEM files, parses safe
certificate metadata, loads `ca_certificate_path` through `vpn_trust_store`, and
verifies that the peer certificate issuer matches the trusted CA and its
signature validates against that CA.

This is only local trust-store verification. It does not implement CRL, OCSP,
enrollment, certificate renewal, key exchange, or replacement of the temporary
PSK dataplane.

## Certificate Ownership Verification

A trusted certificate alone is insufficient. During peer startup,
`vpn_identity` also parses the configured private key and verifies that its
public part matches the public key in the configured certificate.

For example, configuring `peer_a.crt` with `peer_b.key` causes peer startup to
fail with a key mismatch. This check proves local certificate/key ownership for
the development fixtures; it does not implement certificate-based session keys
or a handshake yet.

## Config Driven Startup

Peers can be started from application configuration. Add `peers` under the `vpn`
application environment:

```erlang
{vpn, [
    {peers, [
        #{
            id => peer_a,
            name => <<"Peer A">>,
            remote_peer_id => peer_b,
            psk => <<"0123456789abcdef0123456789abcdef">>,
            mode => tun,
            ifname => <<"tun0">>,
            ip => "10.20.20.1",
            local_udp_port => 5555,
            remote_ip => {127,0,0,1},
            remote_udp_port => 5556,
            certificate_path => "priv/certs/peer_a.crt",
            private_key_path => "priv/certs/peer_a.key",
            ca_certificate_path => "priv/certs/ca.crt"
        },
        #{
            id => peer_b,
            remote_peer_id => peer_a,
            psk => <<"0123456789abcdef0123456789abcdef">>,
            mode => tun,
            ifname => <<"tun1">>,
            ip => "10.20.20.2",
            local_udp_port => 5556,
            remote_ip => {127,0,0,1},
            remote_udp_port => 5555,
            certificate_path => "priv/certs/peer_b.crt",
            private_key_path => "priv/certs/peer_b.key",
            ca_certificate_path => "priv/certs/ca.crt"
        }
    ]}
]}.
```

When the application starts, `vpn_peer_sup` reads:

```erlang
application:get_env(vpn, peers, []).
```

Then it starts and supervises one `vpn_peer` child per config entry. With no
configured peers, the application boots normally.

Start the shell and inspect configured children:

```sh
rebar3 shell
```

```erlang
supervisor:which_children(vpn_peer_sup).
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
- No CA/PKI logic or key exchange yet.
