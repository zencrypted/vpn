# vpn

VPN Overlay Network for the Zencrypted ecosystem.

This repository currently contains a minimal Erlang/OTP VPN dataplane prototype.
Certificate-control peers now derive directional dataplane keys with ephemeral ECDH and HKDF-SHA256. Legacy non-certificate peers may still use PSK mode. A runtime peer registry now supports trusted inventory mutation and automatic live reconciliation; persistent provisioning, CA services, and IAS policy synchronization remain future work.

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

## Canonical OVPN Envelope

Stage 27A defines the canonical IAS-to-VPN provisioning envelope in
[`docs/OVPN-ENVELOPE.md`](docs/OVPN-ENVELOPE.md). The format is a strict subset
of ordinary `.ovpn` syntax carrying the endpoint, public certificates, and a
Device-local key reference. It defines no vendor-prefixed metadata.

This is an interchange envelope only. It does **not** mean that this runtime
implements the OpenVPN wire protocol or accepts arbitrary third-party `.ovpn`
configuration.

Device lock, 2FA, authorization, and provisioning lineage remain in trusted
IAS/VPN runtime state outside the file. The machine-readable contract surface is `vpn_ovpn_envelope`; a public example
is available at `priv/examples/peer_a.ovpn`. Stage 27B adds the strict
`vpn_ovpn_parser`, which accepts only this subset and converts it into a
normalized peer configuration without resolving keys or starting a session.

Stage 27C adds `vpn_ovpn_identity`, which resolves the relative `key` reference
from the directory containing the `.ovpn` file, validates the inline CA and
client certificate, verifies the certificate chain and validity policy, and
proves that RSA or EC P-384 private-key ownership matches the certificate. The
private-key body is never returned or logged.

## Modules

- `vpn_app` - OTP application entry point.
- `vpn_sup` - top-level supervisor.
- `vpn` - public API.
- `vpn_tun` - TUN/TAP integration layer.
- `vpn_udp` - UDP transport worker.
- `vpn_link` - bidirectional TUN/TAP to UDP link.
- `vpn_udp_sink` - local UDP test sink.
- `vpn_peer` - public runtime peer abstraction.
- `vpn_manager` - management API for supervised peers.
- `vpn_peer_registry` - ETS-backed runtime registry bootstrapped from trusted application configuration.
- `vpn_provisioning` - revisioned, idempotent IAS-to-VPN desired-state command contract.
- `vpn_trust_store` - development CA certificate trust store.
- `vpn_ovpn_envelope` - canonical OVPN subset constants and value validators.
- `vpn_ovpn_parser` - strict OVPN parser and normalized peer-config conversion.
- `vpn_ovpn_identity` - local OVPN certificate, trust, and key-ownership validation.

## Runtime peer registry

`vpn_peer_registry` is the trusted runtime inventory for provisioned peers. It is
bootstrapped from `peers` and `ovpn_sessions` in application configuration, so
existing deployments keep their startup behavior. Public `list/0` and `get/1`
results contain only safe provisioning metadata and never include PSKs, private
key paths, or complete runtime configuration.

The first registry stage supports runtime inventory mutation:

```erlang
vpn_peer_registry:list().
vpn_peer_registry:get(PeerId).
vpn_peer_registry:put(PeerConfig).
vpn_peer_registry:disable(PeerId).
vpn_peer_registry:enable(PeerId).
vpn_peer_registry:remove(PeerId).
```

`vpn_manager:reload_config/0` reconciles supervised peers against the enabled
registry entries. Live automatic reconciliation and IAS synchronization remain
separate follow-up stages.

## Revisioned provisioning commands

`vpn_provisioning:apply/1` accepts monotonic per-peer commands from a trusted
provisioning source. Repeated delivery of the same revision and payload is
idempotent, lower revisions are rejected as stale, and conflicting payloads at
the same revision are rejected. Supported operations are `upsert`, `enable`,
`disable`, `revoke`, and `remove`.

```erlang
vpn_provisioning:apply(#{
    peer_id => client_a,
    revision => 3,
    operation => upsert,
    source => ias,
    desired_state => #{
        enabled => true,
        device_id => <<"device-123">>,
        authorization_mode => policy,
        authorized => true,
        certificate_fingerprint => <<"ABCD...">>
    }
}).
```

A new peer must include `runtime_config` inside `desired_state`; updates to an
existing peer merge trusted desired-state metadata into its internal runtime
configuration. `revoke` disables the peer, clears authorization, and prevents a
plain `enable` command until a higher-revision `upsert` explicitly sets
`revoked => false`. Public registry and provisioning history responses never
contain PSKs or private-key material.

IAS canonical commands intentionally do not own VPN transport internals. When a
new IAS peer has no stored runtime config, VPN may resolve it locally through
`runtime_config_resolver`:

- `disabled` keeps the default fail-closed behavior and returns
  `{error, runtime_config_required}`;
- `static_template` derives runtime config from trusted VPN application
  configuration.

`static_template` is for development and integration flows. It may reuse
explicit configured local key, certificate, or OVPN references, but it does not
inherit session keys, replay state, ECDH material, PIDs, counters, or other
ephemeral runtime data from the template.

A single `runtime_config_template` remains supported for backward
compatibility. A trusted `runtime_config_templates` map can define a bounded
pool keyed by runtime peer ID. The shipped debug profile provides `client_a`
and `client_b`; each slot has its own OVPN identity, TUN/UDP resources, and a
compatible gateway-side peer. Unknown slot IDs fail closed. This pool is for a
two-user demo and is not dynamic production allocation.

Use `vpn_provisioning:status/0` for counters and
`vpn_provisioning:history/1` for bounded per-peer audit history.

## Build

```sh
rebar3 compile
```

## Test

```sh
rebar3 eunit
```

## Validate an IAS-generated OVPN identity

Keep the envelope and its relative `keys/` directory together, for example:

```text
local/
├── client.ovpn
└── keys/
    └── client.key
```

`local/` is ignored by Git. Validate from the Erlang shell:

```erlang
vpn_ovpn_identity:load("/absolute/path/to/local/client.ovpn").
```

A successful result contains `trusted => true`, `key_match => true`, and
`identity_ready => true`. Use `vpn_ovpn_identity:safe_info/1` before presenting
identity state; it excludes the embedded public PEM material and never exposes
the private-key body.

## Generate a Device key and CSR

The shared helper supports both an ad-hoc timestamped mode and exact filenames
selected by an IAS provisioning plan.

Ad-hoc mode:

```sh
./tools/generate-device-csr.sh laptop
```

IAS-planned mode:

```sh
./tools/generate-device-csr.sh \
  --common-name laptop-20260622-164258-106 \
  --key-file local/keys/laptop-20260622-164258-106.key \
  --csr-file local/csr/laptop-20260622-164258-106.csr
```

The planned mode creates the exact private-key reference that IAS will later
place in the `.ovpn` envelope. Paths must be safe and relative; existing files
are never overwritten. The private key is written with mode `600`, while the
public CSR is written with mode `644`.

Run the helper smoke tests with:

```sh
./tools/test-generate-device-csr.sh
```

## Generate a standalone local OVPN bundle

Local development does not require IAS. Initialize a development-only CA once:

```sh
./tools/init-local-ca.sh
```

Then generate a Device-local EC P-384 key, CSR, CA-signed client certificate,
and canonical OVPN envelope:

```sh
./tools/generate-local-ovpn.sh \
  --name client_a \
  --remote 127.0.0.1 \
  --port 5556
```

The generated material is written beneath the Git-ignored `local/` directory:

```text
local/
├── ca/
│   ├── ca.key
│   └── ca.crt
├── keys/
├── csr/
├── certs/
└── client_a-<timestamp>.ovpn
```

The OVPN file contains only public CA/client certificates and a relative
`key keys/...` reference. The private key remains local with mode `600`. This
flow is intentionally development-only and does not reproduce IAS Device
binding, authorization, 2FA, audit, or revocation state.

Run the local provisioning smoke tests with:

```sh
./tools/test-local-ovpn.sh
```

## One-command debug startup

The debug bootstrap keeps stable local identities for both trusted client
slots and the second gateway peer. It creates the development CA and the
`client_a` and `client_b` OVPN bundles plus the RSA `peer_c` gateway identity only when they are missing or incompatible, then
reuses them on later starts:

```sh
./tools/run-debug.sh
```

This is the supported entry point for the two-slot debug topology. It prepares
all required files before starting `rebar3 as debug shell` with
`config/sys.debug.config`. When `ERL_FLAGS` is not already set, it starts the
node as `vpn@127.0.0.1` with cookie `node_runner`. The configured pairs are
`client_a <-> peer_b` and `client_b <-> peer_c`.

Do not use a raw `rebar3 as debug shell` on a fresh checkout: the application
fails closed when a configured OVPN identity is missing. To prepare files
without starting Erlang, run:

```sh
./tools/prepare-debug-topology.sh
```

Use an explicit rotation only when needed:

```sh
./tools/run-debug.sh --force
```

`--force` replaces the Device key, CSR, certificate, and OVPN envelope while
keeping the existing local development CA. The bootstrap can also be run
without starting Erlang:

```sh
./tools/ensure-debug-ovpn.sh
```

Run its smoke test with:

```sh
./tools/test-debug-ovpn.sh
```

## Demo Guide

This guide shows the current end-to-end VPN milestone: encrypted TUN peers,
X.509 identity, CA trust verification, JSON/HTML administration, and the
interactive N2O dashboard.

Architecture overview:

```text
peer_a (10.20.20.1)
      |
 encrypted UDP
      |
peer_b (10.20.20.2)
```

Packet path:

```text
TUN -> VPN -> UDP -> VPN -> TUN
```

### Start the demo

Build and start the application:

```sh
rebar3 compile
rebar3 shell
```

The configured peers are started by the OTP supervision tree from
`config/sys.config`.

### Verify the tunnel

From another terminal, ping `peer_b` through the local tunnel:

```sh
ping -4 -c 5 10.20.20.2
```

Expected result:

```text
0% packet loss
```

### Verify certificate identity

In the Erlang shell:

```erlang
Children = supervisor:which_children(vpn_peer_sup).
{_, Peer, _, _} = lists:keyfind({vpn_peer, peer_a}, 1, Children).
vpn_peer:identity_info(Peer).
```

Expected certificate metadata includes:

```text
issuer  = Zencrypted Dev CA
subject = peer_a
```

### Verify management APIs

```erlang
vpn_manager:running_peers().
vpn_manager:status().
vpn_manager:certificates().
```

### Verify JSON API

```sh
curl http://localhost:8080/api/admin/summary | jq .
```

Expected JSON includes:

```text
counts
peers
certificate information
```

### Verify Cowboy dashboard

Open:

```text
http://localhost:8080/admin
```

Expected:

```text
peer table visible
counts visible
```

### Verify N2O dashboard

Open:

```text
http://localhost:8080/admin/n2o
```

Expected:

```text
Reload Config button
peer table
Start / Stop actions
```

### Interactive demo

Stop `peer_a` from the N2O dashboard. Expected result:

```text
Running Peers: 1
Stopped Peers: 1
```

Start `peer_a` again. Expected result:

```text
Running Peers: 2
Stopped Peers: 0
```

Click `Reload Config`. Expected result:

```text
Configuration reloaded
```

### Current Milestone

```text
VPN dataplane operational
PKI identity operational
CA trust validation operational
Certificate/key ownership verification operational
JSON API operational
Cowboy dashboard operational
N2O dashboard operational
Interactive peer management operational
Canonical OVPN envelope contract defined
Canonical OVPN parser operational
OVPN local identity validation operational
```

The OVPN import milestone now includes strict parsing and EC P-384 local
identity validation. It does not yet include certificate-authenticated session
establishment, Device-lock enforcement, or a 2FA provider. These gaps are tracked in
[`docs/TECHNICAL-DEBT.md`](docs/TECHNICAL-DEBT.md).

## VPN Management API

`vpn_manager` is the initial management layer for supervised peers. It is
intended to become the backend surface for the future N2O/EXO admin UI.

```erlang
vpn_manager:list_peers().
vpn_manager:running_peers().
vpn_manager:status().
vpn_manager:peer_status(peer_a).
vpn_manager:peer_info(peer_a).
vpn_manager:peer_stats(peer_a).

vpn_manager:stop_peer(peer_a).
vpn_manager:start_peer(peer_a).
vpn_manager:reload_config().
```

`list_peers/0` returns configured peers from application config.
`running_peers/0` returns currently active supervised peers.
`status/0` returns an aggregate snapshot for dashboard consumers:

```erlang
#{
    configured => [peer_a, peer_b],
    running => [peer_a, peer_b],
    peers => #{peer_a => #{running => true}}
}
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

Starting an already running peer returns:

```erlang
{error, already_started}
```

`reload_config/0` synchronizes runtime peers with the current application
configuration. It starts configured peers that are not running, stops running
peers that are no longer configured, and leaves already running configured peers
untouched:

```erlang
#{
    started => [peer_c],
    stopped => [peer_x],
    unchanged => [peer_a, peer_b],
    failed => []
}
```

The management API can start, stop, and reload configured peers. It does not
create, delete, persist, or hot-update peer configuration yet.

## Administration API

`vpn_admin` is the read-only facade intended as the future backend contract for
N2O/EXO dashboard pages:

```erlang
vpn_admin:dashboard().
vpn_admin:summary().
vpn_admin:summary_view().
vpn_admin:overview().
vpn_admin:peer_counts().
```

`dashboard/0` aggregates raw manager status and certificate inventory.
`summary/0` returns a compact first-screen view:

```erlang
#{
    counts => #{configured => 2, running => 2, stopped => 0, certificates => 2},
    peers => [
        #{
            id => peer_a,
            running => true,
            mode => tun,
            ip => "10.20.20.1",
            remote_peer_id => peer_b,
            crypto_failures => 0,
            frames_rejected => 0,
            certificate => #{trusted => true, key_match => true}
        }
    ]
}
```

## Admin View Model

`summary_view/0` converts the compact summary into JSON-safe values for future
N2O/Cowboy/REST/UI layers. It does not encode JSON and does not add a JSON
library dependency.

```erlang
vpn_admin:summary_view().
```

Example shape:

```erlang
#{
    counts => #{configured => 2, running => 2, stopped => 0, certificates => 2},
    peers => [
        #{
            id => <<"peer_a">>,
            running => true,
            mode => <<"tun">>,
            ip => <<"10.20.20.1">>,
            remote_peer_id => <<"peer_b">>,
            crypto_failures => 0,
            frames_rejected => 0,
            certificate => #{
                subject_cn => <<"peer_a">>,
                issuer_cn => <<"Zencrypted Dev CA">>,
                trusted => true,
                key_match => true,
                not_after => <<"270606195431Z">>
            }
        }
    ]
}
```

`overview/0` returns compact dashboard counts:

```erlang
#{
    configured_peers => 2,
    running_peers => 2,
    stopped_peers => 0,
    certificates => 2
}
```

Lifecycle operations remain in `vpn_manager`.

## Administration JSON Export

`summary_json/0` encodes the JSON-safe administration summary for future
Cowboy/N2O handlers. `summary_json_pretty/0` currently returns the same binary
and is reserved as a formatting extension point.

```erlang
vpn_admin:summary_json().
vpn_admin:summary_json_pretty().
```

Shell validation:

```erlang
Json = vpn_admin:summary_json().
is_binary(Json).

Decoded = jiffy:decode(Json, [return_maps]).
maps:get(<<"counts">>, Decoded).
maps:get(<<"peers">>, Decoded).
```

## HTTP Admin Endpoint

The application starts a local read-only Cowboy endpoint for the admin summary.
The port is configured with `{http_port, 8080}` under the `vpn` application
environment.

```bash
curl http://localhost:8080/api/admin/summary
```

Expected response:

```json
{
  "counts": {},
  "peers": []
}
```

The endpoint only supports `GET /api/admin/summary`. Peer lifecycle actions,
configuration writes, certificate issuance, TLS, authentication, and UI routes
are intentionally not exposed here.

## HTML Dashboard

The same Cowboy listener also serves a minimal read-only HTML dashboard:

```text
http://localhost:8080/
http://localhost:8080/admin
```

The page renders counts and a peer table from `vpn_admin:summary_view/0`.
It does not use JavaScript, templates, N2O, Nitro, WebSockets, or management
actions.

Runtime validation:

```bash
curl -i http://localhost:8080/
curl -i http://localhost:8080/admin
```

Expected:

```text
HTTP/1.1 200 OK
content-type: text/html
```

## Dashboard Actions

The dashboard includes simple HTML forms for local peer control:

```text
Start peer
Stop peer
Reload config
```

Routes:

```text
POST /admin/peer/peer_a/start
POST /admin/peer/peer_a/stop
POST /admin/reload
```

Each action redirects back to `/admin` with `HTTP 303 See Other`. The controls
delegate to the existing `vpn_manager` functions and do not add JavaScript,
N2O, WebSockets, authentication, authorization, or certificate management.

## N2O Dashboard

A read-only N2O/Nitro dashboard page is available separately from the plain
Cowboy dashboard:

```text
http://localhost:8080/admin/n2o
```

It renders `VPN Dashboard (N2O)`, peer counts, and the peer table from
`vpn_admin:summary_view/0`. It does not include start/stop/reload actions, live
updates, WebSockets, authentication, authorization, or certificate actions.

Both dashboard paths use the same UI model:

```text
vpn_manager
    ↓
vpn_admin
    ↓
summary_view
    ↓
Cowboy UI

vpn_manager
    ↓
vpn_admin
    ↓
summary_view
    ↓
N2O UI
```

Runtime validation:

```bash
curl -i http://localhost:8080/admin/n2o
```

Expected:

```text
HTTP/1.1 200 OK
content-type: text/html
```

## Interactive N2O Dashboard

The N2O dashboard includes interactive controls that update the counts and peer
table without a browser page reload:

```text
Start peer
Stop peer
Reload config
```

The controls use N2O events and Nitro DOM updates. Displayed state still comes
from `vpn_admin:summary_view/0`.

## Certificate Inventory

`vpn_manager` exposes certificate inventory helpers for administration screens:

```erlang
vpn_manager:certificates().
vpn_manager:certificate_info(peer_a).
```

An inventory entry includes runtime state and safe certificate metadata:

```erlang
#{
    peer_id => peer_a,
    running => true,
    trusted => true,
    key_match => true,
    subject => Subject,
    issuer => Issuer,
    serial_number => Serial,
    certificate_path => "priv/certs/peer_a.crt"
}
```

The inventory uses already-loaded peer identity data for running peers. It does
not re-read private keys or re-run trust validation for every request.

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

The Erlang VM must have permission to create and configure TAP/TUN interfaces.

### Linux Setup

On Linux, give the active `beam.smp` binary `cap_net_admin` before starting the shell:

```sh
sudo setcap cap_net_admin=ep <beam.smp>
```

### macOS Setup

On macOS, setuid permissions must be configured for the `procket` helper binary.

1. Build the project first to compile `procket`:
   ```sh
   rebar3 compile
   ```

2. Copy the compiled helper binary to a system directory (like `/usr/local/bin`) and make it owned by root with setuid permissions enabled:
   ```sh
   sudo cp _build/default/lib/procket/priv/procket /usr/local/bin/procket
   sudo chown root /usr/local/bin/procket
   sudo chmod 4750 /usr/local/bin/procket
   ```

   *Note: In `config/sys.config`, the `procket` app is configured to use `/usr/local/bin/procket` for the helper executable via `{port_executable, "/usr/local/bin/procket"}`.*

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

## OVPN-backed Session Startup

A validated IAS-generated OVPN envelope can now supply the certificate identity,
remote endpoint, transport, and tunnel mode for a runtime peer. Runtime-only
values remain in trusted application configuration.

Configure `ovpn_sessions` under the `vpn` application environment:

```erlang
{ovpn_sessions, [
    #{
        id => client_a,
        name => <<"Client A">>,
        ovpn_path => "local/client_a.ovpn",
        ifname => <<"tun0">>,
        ip => "10.20.20.1",
        local_udp_port => 5555,
        remote_peer_id => gateway,
        psk => <<"temporary-development-psk-32bytes">>
    }
]}
```

At startup, `vpn_session_config` validates the OVPN identity before any peer is
started. It then maps the OVPN endpoint and `dev tun` settings into the existing
runtime peer configuration. An invalid certificate, mismatched private key,
unsafe key permissions, missing key, or malformed OVPN envelope fails the
session startup.

The static `psk` remains a temporary dataplane requirement. This stage wires the
validated certificate identity into startup but does not yet implement a
certificate-authenticated handshake or derive traffic keys from certificates.

For a direct inspection without starting the tunnel:

```erlang
Runtime = #{
    id => client_a,
    ifname => <<"tun0">>,
    ip => "10.20.20.1",
    local_udp_port => 5555,
    remote_peer_id => gateway,
    psk => <<"temporary-development-psk-32bytes">>
},
{ok, Session} = vpn_session_config:load("local/client_a.ovpn", Runtime),
vpn_session_config:safe_info(Session).
```

### Debug authorization

The debug profile explicitly sets `authorization_mode => development_bypass`. Ordinary OVPN sessions fail closed unless trusted runtime configuration supplies `authorized => true`; this state is never accepted from OVPN input.

### Development control-plane handshake

The debug profile enables `handshake_mode => development_control` for both
local peers. Before encrypted PSK data frames are accepted, the peers exchange
distinct `VPNH` control frames, verify the configured peer identifiers and
move to `established`. TUN packets are blocked until establishment.

This is a protocol skeleton, not certificate authentication. The existing PSK
still protects data frames. Certificate exchange, transcript signatures and
ephemeral key agreement are intentionally left for the next stages.

Inspect the state after `./tools/run-debug.sh`:

```erlang
vpn_manager:peer_stats(client_a).
vpn_manager:peer_stats(peer_b).
```

The nested link stats contain `handshake.status`, control-frame counters and
blocked-packet/failure counters.

### Mutual certificate proof in debug mode

The debug profile uses `handshake_mode => certificate_control` for both peers. Each side trusts an explicitly configured remote CA, exchanges its certificate, and signs the session IDs and nonces before TUN traffic is enabled. Inspect the result with:

```erlang
vpn_manager:peer_stats(client_a).
vpn_manager:peer_stats(peer_b).
```

The handshake map should report `status => established`, `remote_authenticated => true`, `session_keys_ready => true`, `key_source => ephemeral_ecdh_hkdf_sha256`, and a `remote_certificate_fingerprint`. Certificate-control peers no longer require `psk`: the authenticated ephemeral ECDH exchange is expanded with HKDF-SHA256 into distinct TX and RX keys before the dataplane opens.


### Ephemeral ECDH session keys

Handshake version 3 carries a fresh P-384 ephemeral public key in each certificate hello. The certificate proof transcript binds both ephemeral public keys, peer IDs, session IDs, nonces, and the sender certificate fingerprint. After mutual proof succeeds, each peer computes ECDH and applies HKDF-SHA256 to derive two directional ChaCha20-Poly1305 keys. The lower lexical peer ID uses the first derived key for TX and the second for RX; the other peer uses the reverse mapping.

The debug profile therefore contains no `psk` values. Inspect the active key source without exposing key bytes:

```erlang
#{link := Link} = vpn_manager:peer_stats(client_a),
maps:get(crypto, Link),
maps:get(handshake, Link).
```

Expected fields include `#{key_source => ephemeral_ecdh_hkdf_sha256}` and `session_keys_ready => true`. Legacy disabled/development-control peers retain the PSK path for compatibility. Rekeying and replay windows remain separate follow-up work.

### Session lifecycle and key epochs

Certificate-authenticated sessions now expose lifecycle metadata for the active
ephemeral traffic-key generation. Data frames carry an explicit `key_epoch`,
and the AEAD nonce derivation binds both the epoch and sequence number. The
initial certificate handshake installs epoch `1`; later authenticated rekeying
will advance it without reusing nonce space.

Inspect the current lifecycle with:

```erlang
#{link := Link} = vpn_manager:peer_stats(client_a),
maps:get(session, Link).
```

The session map contains `established_at`, `session_age_seconds`, `key_epoch`,
`last_rekey_at`, directional packet/byte counters, and aggregate
`packets_since_rekey` / `bytes_since_rekey`. This stage records lifecycle data
only; automatic or manual rekey exchange is implemented separately.

### Manual authenticated rekey

Certificate-control peers can rotate their traffic keys without restarting the TUN or UDP workers:

```erlang
vpn_manager:rekey(client_a).
```

The rekey performs a fresh certificate-authenticated ephemeral P-384 ECDH exchange, advances the key epoch, resets per-epoch counters, and temporarily retains the previous receive key for delayed UDP packets.

### Replay protection and previous-epoch grace
Dataplane packets carry an authenticated cleartext epoch/sequence header so stale epochs are rejected before AEAD decryption; the header itself is bound as AEAD associated data.

Authenticated data frames carry a key epoch and monotonic sequence number. Each
receive epoch has an independent 64-packet sliding replay window: limited UDP
reordering is accepted, while duplicate and out-of-window frames are rejected.
After an authenticated rekey, the previous receive key and its replay window are
kept for a configurable grace interval so delayed UDP packets can finish in
flight; the previous key is then erased from the link state. The production
default is five seconds. The debug profile uses fifteen seconds so the live
state can be inspected comfortably from the Erlang shell.

Runtime verification:

```erlang
#{link := Link} = vpn_manager:peer_stats(client_a),
maps:get(replay, Link),
maps:with([replay_drops, duplicate_frames, stale_epoch_drops,
           previous_epoch_accepted], Link).
```

### Debug replay verification

The debug profile enables an explicit encrypted-frame replay hook. It is disabled by default and must never be enabled in production. After `./tools/run-debug.sh`, inspect retained outbound frames with:

```erlang
vpn_manager:debug_frame_history(client_a).
```

Replay a retained frame by epoch and sequence number:

```erlang
vpn_manager:debug_replay_frame(client_a, 1, 0).
```

This sends the exact retained ciphertext again, allowing the remote peer replay window to be verified without exposing session keys or plaintext. Generate more than 64 packets and replay an old retained sequence to test the too-old path. Retain an epoch-1 frame, rekey, wait for the previous-epoch grace period to expire, and replay it to test stale-epoch rejection.


### Debug dataplane burst for replay-window verification

When `debug_replay_controls => true`, a running certificate session can send a
controlled burst of unique encrypted dataplane frames without relying on host
routing through the local TUN addresses:

```erlang
vpn_manager:debug_send_frames(client_a, 70).
```

The call returns the current key epoch and the generated sequence range. The
frames use the normal VPN framing, AEAD encryption, UDP transport, peer checks,
and receive replay window. Counts from 1 through 256 are accepted. The helper is
debug-only and returns `debug_replay_disabled` when the controls are disabled.

A retained early frame from the same epoch can then be replayed with
`debug_replay_frame/3` to verify the `too_old` path once the receive window has
advanced by at least 64 sequence numbers.

### Automatic authenticated rekey

Certificate-control peers may trigger the existing authenticated ECDH rekey automatically.
The feature is disabled unless at least one threshold is positive:

```erlang
#{auto_rekey_after_seconds => 3600,
  auto_rekey_after_packets => 1000000,
  auto_rekey_check_interval_ms => 1000,
  auto_rekey_failure_cooldown_ms => 5000}
```

The first reached threshold starts one rekey operation. Concurrent automatic attempts are
suppressed, failures enter a cooldown, and runtime/admin statistics expose the trigger,
progress, and completion counters. Production defaults keep automatic rekey disabled.


### Automatic rekey jitter

Automatic rekey checks may add a bounded random delay before initiating a new authenticated exchange:

```erlang
#{auto_rekey_jitter_ms => 1000}
```

A value of `0` preserves immediate triggering. While the delay is pending, repeated checks do not schedule duplicate rekeys. Runtime statistics expose `pending`, `pending_reason`, and `pending_remaining_ms`. If another exchange refreshes the key epoch before the delay expires, the pending trigger is re-evaluated and safely abandoned.

### Authenticated peer restart recovery

Handshake version 4 marks initial exchanges separately from rekeys. When an
already authenticated peer presents a fresh initial session, the remote link
pauses dataplane delivery until certificate authentication completes, then
installs a fresh epoch-1 session and clears obsolete replay/key state. This
prevents restart traffic from being misclassified as AEAD failures while
preserving normal epoch-incrementing rekeys.

### IAS certificate fingerprint binding

When an IAS provisioning command includes `certificate_fingerprint`, the VPN
runtime resolver compares it with the certificate fingerprint loaded from the
resolved OVPN identity. A missing or different runtime fingerprint is rejected
fail-closed with `certificate_fingerprint_unavailable` or
`certificate_fingerprint_mismatch`; the runtime template cannot silently replace
the IAS certificate identity. Development tests must therefore provision the
actual fingerprint of the certificate referenced by the configured OVPN
artifact.


### Debug dataplane payload probe

When `debug_replay_controls` is enabled for a peer, the runtime exposes a
userspace dataplane probe that exercises the real session framing, encryption,
UDP transport, decryption, peer validation, epoch validation, and replay
window without requiring a kernel TUN assertion.

```erlang
ok = vpn_manager:debug_clear_received_payloads(peer_b),
Payload = <<"ias-vpn-dataplane-probe">>,
{ok, Sent} = vpn_manager:debug_send_payload(client_a, Payload),
{ok, Received} = vpn_manager:debug_received_payloads(peer_b).
```

Each received entry contains the original payload, byte count, key epoch,
sequence number, peer id, and SHA-256 digest. The history is bounded and is
available only when debug replay controls are enabled.

### Debug rekey probes

Debug runtimes with `debug_replay_controls` enabled expose a concise, secret-free
session snapshot and an epoch wait helper for cross-repository integration tests:

```erlang
{ok, Before} = vpn_manager:debug_session_state(client_a),
CurrentEpoch = maps:get(current_epoch, Before),
{ok, NextEpoch} = vpn_manager:rekey(client_a),
{ok, After} = vpn_manager:debug_wait_for_epoch(client_a, NextEpoch, 5000).
```

The snapshot reports handshake status, current and previous key epochs, previous
epoch grace time, rekey counters, and packet counters since the latest rekey. It
never exposes session keys or private key material.

### Debug peer restart probes

When `debug_replay_controls` is enabled, integration tests may force a supervised peer restart without changing provisioning state:

```erlang
{ok, OldPid} = vpn_manager:debug_peer_pid(client_a),
{ok, OldPid} = vpn_manager:debug_restart_peer(client_a),
{ok, NewPid} = vpn_manager:debug_wait_for_peer_restart(client_a, OldPid, 5000).
```

The supervisor restarts the existing permanent child specification, so the runtime registry entry and provisioning revision are preserved. These APIs expose process identifiers only and never return session keys or private identity material.
