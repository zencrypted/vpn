# vpn

VPN Overlay Network for the Zencrypted ecosystem.

The repository implements an Erlang/OTP VPN runtime with TUN/TAP and UDP transport, certificate-authenticated peer sessions, ephemeral directional traffic keys, revisioned IAS provisioning, VPN-owned dynamic peer allocation, durable KVS/Mnesia projections, and fail-closed startup recovery.

The runtime is **not** an OpenVPN wire-protocol implementation. A strict subset of ordinary `.ovpn` syntax is used as an IAS-to-VPN identity and endpoint envelope.

## Architecture

The dataplane remains deliberately small:

```text
TUN/TAP <-> Erlang <-> UDP <-> Erlang <-> TUN/TAP
```

The main runtime layering is:

```text
vpn_peer
    |
vpn_link
    |
vpn_udp
vpn_tun
```

`vpn_peer` is the stable public peer API. `vpn_link` owns the lower-level bidirectional transport path.

The broader runtime adds explicit control and persistence boundaries:

```text
IAS desired state
      |
      v
vpn_provisioning
      |
      +--> vpn_peer_allocator
      +--> vpn_runtime_config_resolver
      +--> vpn_dynamic_identity_factory
      |
      v
vpn_peer_registry
      |
      v
vpn_manager / vpn_dynamic_pair
      |
      v
certificate-control session
      |
      v
TUN/TAP <-> encrypted UDP dataplane

vpn_projection + KVS/Mnesia
      |
      +--> allocator state
      +--> provisioning heads and barriers
      +--> startup recovery input
```

IAS owns Device identity, authorization decisions, certificate policy, and desired revisions. VPN owns transport allocation, peer IDs, pair topology, runtime lifecycle, allocator generations, and durable VPN projection state.

## Current capabilities

The current runtime provides:

- TUN/TAP and UDP dataplane transport;
- strict `ovpn/v1` parsing and local identity validation;
- X.509 trust and certificate/private-key ownership validation;
- certificate-authenticated control-plane handshakes;
- ephemeral P-384 ECDH with HKDF-SHA256 directional traffic keys;
- key epochs, authenticated rekey, replay windows, and previous-epoch grace;
- trusted runtime peer registry and live reconciliation;
- revisioned, idempotent IAS-to-VPN provisioning commands;
- VPN-owned durable dynamic peer allocation;
- single-RPC dynamic pair provisioning through `vpn_provisioning:apply_dynamic/2`;
- durable allocator/provisioning projections and fail-closed startup recovery;
- JSON/HTML administration surfaces and an interactive N2O dashboard.

Active production hardening work is tracked in [`docs/TECHNICAL-DEBT.md`](docs/TECHNICAL-DEBT.md).

## Canonical OVPN envelope

The IAS-to-VPN interchange contract is documented in [`docs/OVPN-ENVELOPE.md`](docs/OVPN-ENVELOPE.md).

The envelope is a strict subset of ordinary `.ovpn` syntax carrying:

- endpoint and transport metadata;
- inline public CA and client certificate material;
- a Device-local relative private-key reference.

The envelope does not carry IAS authorization, Device-lock, 2FA, provisioning lineage, session keys, replay state, or private-key bodies.

Implementation boundaries are explicit:

- `vpn_ovpn_envelope` defines the machine-readable `ovpn/v1` contract;
- `vpn_ovpn_parser` performs strict, side-effect-free parsing and normalization;
- `vpn_ovpn_identity` resolves the local key reference and validates trust, certificate policy, and key ownership;
- session/runtime modules consume validated configuration through their normal lifecycle boundaries.

A public example is available at `priv/examples/peer_a.ovpn`.

## Certificate session model

For certificate-control peers, the current session path is:

```text
validated OVPN identity
        |
        v
trusted runtime authorization
        |
        v
mutual certificate proof
        |
        v
P-384 ECDH
        |
        v
HKDF-SHA256 directional keys
        |
        v
established encrypted dataplane
        |
        +--> authenticated rekey
        +--> replay-window enforcement
        +--> previous-epoch grace
```

Legacy/debug PSK modes remain bounded development and test paths. They are not the current certificate-control security model and are not part of the canonical `ovpn/v1` envelope contract.

## Dynamic allocation and provisioning

The current dynamic allocation contract is documented in [`docs/DYNAMIC-PEER-ALLOCATION.md`](docs/DYNAMIC-PEER-ALLOCATION.md).

The preferred IAS bootstrap for a reserved Device is:

```erlang
vpn_provisioning:apply_dynamic(DeviceId, Command).
```

The operation validates revision/idempotency rules, binds the Device to the allocated client peer, materializes the configured identity bundle, resolves both runtime peers, writes the registry pair, reconciles the gateway before the client, waits for both certificate-control handshakes, and commits the durable provisioning head only after success.

A repeated command with the same revision and digest is idempotent. Stale or conflicting revisions fail before runtime mutation. Matching pending commands can be safely retried after interruption.

Dynamic pair lifecycle operations are exposed by:

```erlang
vpn_dynamic_pair:ensure(DeviceId, Desired).
vpn_dynamic_pair:status(DeviceId).
vpn_dynamic_pair:decommission(DeviceId).
vpn_dynamic_pair:decommission(DeviceId, #{remove_identity => true}).
```

Disable, enable, and revoke are pair-aware. Gateway shutdown/start ordering is preserved, and failed enable returns the pair to the disabled state.

The remaining atomic cross-section decommission gap is tracked as TD-013 in [`docs/TECHNICAL-DEBT.md`](docs/TECHNICAL-DEBT.md).

## Durable state and recovery

VPN persists allocator and provisioning projections through KVS/Mnesia. Projection updates are serialized and versioned. The current projection checksum uses a repository-owned canonical encoding rather than Erlang External Term Format bytes.

Startup recovery reconstructs eligible registry and runtime state before peer supervision. Corrupt, unsupported, or ownership-inconsistent durable state fails closed.

The durable projection intentionally excludes private-key material, PSKs, session keys, replay windows, ECDH material, PIDs, counters, raw runtime configuration, and packet state.

Detailed contracts and migration procedures are in:

- [`docs/DYNAMIC-PEER-ALLOCATION.md`](docs/DYNAMIC-PEER-ALLOCATION.md) — allocator, provisioning, lifecycle, and recovery semantics;
- [`docs/PROJECTION-CHECKSUM-MIGRATION.md`](docs/PROJECTION-CHECKSUM-MIGRATION.md) — outer projection checksum migration;
- [`docs/VPN-UPGRADE-MIGRATION.md`](docs/VPN-UPGRADE-MIGRATION.md) — coordinated VPN/IAS durable-state upgrade procedure.

## Main modules

- `vpn_app` — OTP application entry point.
- `vpn_sup` — top-level supervisor.
- `vpn` — public API.
- `vpn_tun` — TUN/TAP integration layer.
- `vpn_udp` — UDP transport worker.
- `vpn_link` — bidirectional TUN/TAP-to-UDP link.
- `vpn_peer` — public runtime peer abstraction.
- `vpn_manager` — management and reconciliation API for supervised peers.
- `vpn_peer_registry` — trusted runtime inventory reconstructed from bootstrap and durable provisioning state.
- `vpn_peer_allocator` — durable VPN-owned Device-to-pair resource allocation.
- `vpn_projection` — serialized versioned projection process.
- `vpn_projection_store` — durable projection backend contract.
- `vpn_projection_store_kvs` — KVS-backed compare-and-set projection store.
- `vpn_runtime_recovery` — fail-closed registry/runtime reconstruction before peer supervision.
- `vpn_dynamic_identity_factory` — development-only dynamic identity materialization.
- `vpn_dynamic_pair` — dynamic pair reconciliation and lifecycle boundary.
- `vpn_provisioning` — revisioned IAS-to-VPN desired-state command contract.
- `vpn_trust_store` — development CA trust store.
- `vpn_ovpn_envelope` — canonical OVPN subset contract.
- `vpn_ovpn_parser` — strict OVPN parser and normalized peer-config conversion.
- `vpn_ovpn_identity` — local certificate, trust, and key-ownership validation.

## Build

```sh
rebar3 compile
```

## Test

```sh
rebar3 eunit
./tools/test-dynamic-identity.sh
```

Repository-specific shell helpers also have focused smoke tests, including:

```sh
./tools/test-generate-device-csr.sh
./tools/test-local-ovpn.sh
./tools/test-debug-ovpn.sh
```

## Validate an IAS-generated OVPN identity

Keep the envelope and its relative `keys/` directory together:

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

A successful result contains `trusted => true`, `key_match => true`, and `identity_ready => true`. Use `vpn_ovpn_identity:safe_info/1` before presenting identity state; it excludes embedded public PEM material and never exposes the private-key body.

## Generate a Device key and CSR

The helper supports an ad-hoc mode:

```sh
./tools/generate-device-csr.sh laptop
```

The current IAS Device enrollment flow can also supply the exact common name and local paths:

```sh
./tools/generate-device-csr.sh \
  --common-name laptop-20260622-164258-106 \
  --key-file local/keys/laptop-20260622-164258-106.key \
  --csr-file local/csr/laptop-20260622-164258-106.csr
```

The second form creates the exact Device-local private-key reference used by IAS Device CSR enrollment. Paths must be safe and relative; existing files are never overwritten. The private key is written with mode `600`, while the public CSR is written with mode `644`.

## Generate a standalone local OVPN bundle

Local development does not require IAS. Initialize a development-only CA once:

```sh
./tools/init-local-ca.sh
```

Then generate a Device-local EC P-384 key, CSR, CA-signed client certificate, and canonical OVPN envelope:

```sh
./tools/generate-local-ovpn.sh \
  --name client_a \
  --remote 127.0.0.1 \
  --port 5556
```

Generated material is written beneath the Git-ignored `local/` directory. The OVPN file contains public CA/client certificates and a relative `key keys/...` reference. The private key remains local with mode `600`.

This flow is development-only and does not reproduce IAS Device binding, authorization, 2FA, audit, or revocation state.

## One-command debug startup

The supported entry point for the bounded two-slot debug topology is:

```sh
./tools/run-debug.sh
```

It prepares stable development identities before starting `rebar3 as debug shell` with `config/sys.debug.config`. When `ERL_FLAGS` is not set, the node starts as `vpn@127.0.0.1` with cookie `node_runner`.

The configured pairs are:

```text
client_a <-> peer_b
client_b <-> peer_c
```

Prepare files without starting Erlang:

```sh
./tools/prepare-debug-topology.sh
```

Rotate Device identity material explicitly:

```sh
./tools/run-debug.sh --force
```

Do not use a raw `rebar3 as debug shell` on a fresh checkout: configured OVPN identities are required and startup fails closed when they are missing.

## Bounded two-user IAS demo topology

The debug topology supports two IAS-managed client slots simultaneously:

```text
IAS Alice Device -> client_a <-> peer_b
IAS Bob Device   -> client_b <-> peer_c
```

`client_a` and `client_b` are trusted runtime slots. `peer_b` and `peer_c` are infrastructure-side debug peers and are not IAS user identities.

Useful runtime checks are:

```erlang
vpn_manager:running_peers().
vpn_manager:debug_session_state(client_a).
vpn_manager:debug_session_state(peer_b).
vpn_manager:debug_session_state(client_b).
vpn_manager:debug_session_state(peer_c).
vpn_peer_registry:get(client_a).
vpn_peer_registry:get(client_b).
vpn_admin:summary().
```

This topology remains a bounded development fixture. Normal IAS provisioning uses VPN-owned dynamic reservations and `vpn_provisioning:apply_dynamic/2`.

## Materialize a dynamic development identity bundle

With the debug identity factory configured:

```erlang
{ok, Allocation} = vpn_peer_allocator:ensure(<<"device-a">>).
{ok, Bundle} = vpn_dynamic_identity_factory:ensure(Allocation).
vpn_dynamic_identity_factory:lookup(maps:get(allocation_id, Allocation)).
```

The resulting Git-ignored tree is:

```text
local/dynamic/<allocation-id>/
├── <client-peer-id>.ovpn
├── keys/
├── csr/
├── certs/
└── identity.manifest
```

The client uses a canonical OVPN envelope with a Device-local EC P-384 key. The gateway uses a directly configured RSA key/certificate pair compatible with `vpn_identity`.

Erase one development bundle explicitly with:

```erlang
vpn_dynamic_identity_factory:release(maps:get(allocation_id, Allocation)).
```

Allocator release and identity release are intentionally separate operations.

## Reconcile a reserved dynamic pair

```erlang
DeviceId = <<"device-dynamic-smoke">>.
{ok, _Allocation} = vpn_peer_allocator:ensure(DeviceId).
Desired = #{device_id => DeviceId,
            profile_id => default_user,
            authorization_mode => policy,
            authorized => true,
            authorization_reason => profile_allows_vpn,
            enabled => true,
            revoked => false}.
{ok, PairStatus} = vpn_dynamic_pair:ensure(DeviceId, Desired).
vpn_dynamic_pair:status(DeviceId).
```

Public results contain safe allocation, registry, running, and handshake metadata only.

## Decommission a dynamic pair

Quiesce the pair through the revisioned lifecycle, then decommission it:

```erlang
vpn_dynamic_pair:decommission(DeviceId).
```

Development identity removal is explicit:

```erlang
vpn_dynamic_pair:decommission(DeviceId, #{remove_identity => true}).
```

Decommission validates ownership and quiescence, removes both registry entries as one batch, releases the VPN-owned allocation, and returns safe ownership metadata. It is not equivalent to `disable` or `revoke`.

## Runtime peer registry

`vpn_peer_registry` is the trusted runtime inventory for provisioned peers. It loads trusted bootstrap configuration and validated durable provisioning heads before peer supervision starts.

Public `list/0` and `get/1` results contain safe provisioning metadata and never expose PSKs, private-key paths, or complete runtime configuration.

Core mutation API:

```erlang
vpn_peer_registry:list().
vpn_peer_registry:get(PeerId).
vpn_peer_registry:put(PeerConfig).
vpn_peer_registry:disable(PeerId).
vpn_peer_registry:enable(PeerId).
vpn_peer_registry:remove(PeerId).
```

`vpn_manager:reload_config/0` reconciles supervised peers against enabled registry entries. Completed reconciliations are published through `vpn_event_bus` as sanitized wake-up events; subscribers must re-read current state through the management API.

## Revisioned provisioning commands

`vpn_provisioning:apply/1` accepts monotonic per-peer commands from a trusted provisioning source. Supported operations are `upsert`, `enable`, `disable`, `revoke`, and `remove`.

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

Repeated delivery of the same revision and payload is idempotent. Lower revisions are rejected as stale. Conflicting payloads at the same revision are rejected.

Use:

```erlang
vpn_provisioning:status().
vpn_provisioning:history(PeerId).
```

for bounded operational counters and per-peer history.

## Management and administration

The current runtime exposes management, read-only administration, JSON, HTML, and N2O dashboard surfaces.

Common management calls:

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

Read-only administration summaries:

```erlang
vpn_admin:summary().
vpn_admin:peers().
vpn_admin:peer(peer_a).
```

JSON summary endpoint:

```sh
curl http://localhost:8080/api/admin/summary | jq .
```

HTML dashboard:

```text
http://localhost:8080/admin
```

The administration surfaces expose sanitized state and certificate metadata. Private-key bodies, PSKs, session keys, and secret-bearing runtime configuration are not presentation data.

## Local demo

Build and start the application:

```sh
rebar3 compile
rebar3 shell
```

Configured peers are started by the OTP supervision tree from `config/sys.config`.

For the standard local tunnel, verify the peer address:

```sh
ping -4 -c 5 10.20.20.2
```

Inspect runtime state in the Erlang shell:

```erlang
vpn_manager:running_peers().
vpn_manager:status().
vpn_manager:certificates().
vpn_admin:summary().
```

## TUN/TAP prerequisites

The runtime requires platform TUN/TAP support and permissions appropriate to the selected interface mode.

On Linux, verify `/dev/net/tun` and the privileges/capabilities required to create and configure the interface. On macOS, use the platform-supported tunnel backend configured for the project.

The repository test suite and debug profiles are designed to keep privileged integration paths separate from pure Erlang unit tests.

## Debug session probes

Debug profiles expose bounded inspection and fault-injection helpers for handshake, rekey, replay-window, burst, and peer-restart verification. These controls are development/test surfaces and are tracked for production hardening under TD-010.

Useful examples include:

```erlang
vpn_manager:debug_session_state(client_a).
vpn_manager:debug_session_state(peer_b).
```

Detailed replay and lifecycle controls should be exercised only under the debug configuration. Production policy and packaging boundaries are tracked in [`docs/TECHNICAL-DEBT.md`](docs/TECHNICAL-DEBT.md).

## Documentation

- [`docs/OVPN-ENVELOPE.md`](docs/OVPN-ENVELOPE.md) — canonical OVPN profile and identity-validation boundary.
- [`docs/DYNAMIC-PEER-ALLOCATION.md`](docs/DYNAMIC-PEER-ALLOCATION.md) — durable allocation, dynamic provisioning, pair lifecycle, and startup recovery contract.
- [`docs/PROJECTION-CHECKSUM-MIGRATION.md`](docs/PROJECTION-CHECKSUM-MIGRATION.md) — projection checksum migration procedure.
- [`docs/VPN-UPGRADE-MIGRATION.md`](docs/VPN-UPGRADE-MIGRATION.md) — coordinated VPN/IAS durable-state upgrade runbook.
- [`docs/TECHNICAL-DEBT.md`](docs/TECHNICAL-DEBT.md) — active technical debt only.

## Project boundaries

- Erlang/OTP implementation.
- Not an OpenVPN wire-protocol implementation.
- Canonical `.ovpn` support is intentionally a strict ordinary-syntax subset.
- Production Device-lock enforcement and 2FA provider integration are not yet implemented.
- Production authentication and authorization of IAS delivery callers remains an active hardening item.
- Dynamic allocator release and the matching provisioning tombstone are durable but not yet one atomic cross-section decommission transaction.
