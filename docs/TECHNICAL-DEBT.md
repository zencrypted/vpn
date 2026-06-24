# VPN Technical Debt

## Completed — Canonical OVPN import and local identity validation

`vpn_ovpn_parser` accepts only the documented `ovpn/v1` subset and returns a
normalized peer configuration without mutating runtime state. `vpn_ovpn_identity`
resolves Device-local keys, validates the inline CA and certificate, and verifies
RSA or EC P-384 certificate/key ownership without exposing private-key material.

## Completed — OVPN-backed runtime startup and local development provisioning

`vpn_session_config` starts validated OVPN sessions from trusted runtime settings.
Development helpers create an isolated EC P-384 CA and generate Device-local key,
CSR, certificate, and canonical OVPN envelope beneath the Git-ignored `local/`
tree. The local authorization bypass remains explicit, debug-only, and auditable.

## Completed — Certificate-authenticated session lifecycle

Certificate-control peers mutually authenticate certificate ownership, derive
directional traffic keys from ephemeral P-384 ECDH with HKDF-SHA256, rotate key
epochs manually or automatically, and enforce replay windows with previous-epoch
grace. Automatic rekey supports packet and age thresholds, failure cooldown, and
jitter. Authenticated peer restart recovery replaces stale session state without
counting the transition as a cryptographic failure.

## Completed — Runtime peer registry and live reconciliation

`vpn_peer_registry` provides an ETS-backed desired-state inventory bootstrapped
from trusted application configuration. Safe registry reads expose provisioning
metadata without PSKs, private-key paths, or complete runtime configuration.
Registry mutations are reconciled automatically by `vpn_peer_reconciler`, so
`put`, `enable`, `disable`, and `remove` update running peer processes without a
manual `vpn_manager:reload_config/0` call. The explicit reload operation remains
available as a recovery/full-reconcile path.

## Completed — Revisioned provisioning contract

`vpn_provisioning` accepts monotonic, idempotent provisioning commands for
`upsert`, `enable`, `disable`, `revoke`, and `remove`. Stale revisions and
revision conflicts are rejected, remove operations retain in-memory tombstones,
and revoke prevents ordinary re-enable until a newer identity reissue arrives.
Accepted, unchanged, stale, conflicting, and revoked commands are represented in
bounded per-peer audit history. Authorization metadata is normalized when policy
state changes, and explicit revoke reasons are preserved.

## In progress — Dynamic peer allocation

The first three stages are complete. `vpn_peer_allocator` reserves a unique
binary client/gateway peer pair and non-overlapping TUN, address, and UDP
resources for each binary IAS Device ID. Reservations are idempotent while the
allocator process remains alive and intentionally do not contain identity or
session secrets.

`vpn_runtime_config_resolver` has a `dynamic_allocator` mode and a lookup-only
`resolve_pair/2` API. It converts an existing reservation into validated client
and gateway runtime maps while rejecting Device mismatches and transport or
identity ownership in trusted defaults or IAS desired state.

`vpn_dynamic_identity_factory` now creates development-only client OVPN and
gateway RSA identity bundles under the Git-ignored `local/dynamic/` tree. It
binds certificate CNs to binary allocated peer IDs, validates trust and key
ownership, rejects partial or unsafe bundles, and exposes only file references
and public fingerprints. The resolver consumes those references but still does
not write or start the pair.

The allocator is still volatile. The remaining work is tracked in
[`DYNAMIC-PEER-ALLOCATION.md`](DYNAMIC-PEER-ALLOCATION.md):

- integrate IAS Device reservation before certificate issuance;
- reconcile and start both sides of each allocated pair;
- remove the hard-coded Alice/Bob slot mapping from the normal path;
- persist and restore assignments before provisioning reconciliation;
- coordinate release and reuse with revision, revoke, and tombstone barriers.

Until those stages are complete, `client_a/client_b` remain the supported
two-user integration topology and dynamic allocations must not be treated as
runnable peers.

## Deferred until IAS integration — Durable provisioning projection

The VPN provisioning registry is currently an in-memory runtime projection. A
process or node restart rebuilds bootstrap entries from trusted application
configuration but does not retain IAS-applied revisions, tombstones, revocations,
or provisioning history. This is intentional until the IAS-to-VPN command format
and delivery path are exercised end to end.

The target ownership model is:

```text
IAS                          VPN
source of truth              runtime projection
identity and policy state -> revisioned desired state
                              -> peer registry
                              -> reconciled processes
```

Once IAS command generation and delivery are stable, add a minimal durable
projection with these constraints:

- persist the last accepted revision and canonical command identity per peer;
- persist remove tombstones and revoked state so stale commands cannot resurrect
  a peer after restart;
- persist only the desired-state fields required to reconstruct runtime entries;
- never persist session keys, replay windows, ephemeral ECDH material, PSKs, or
  private-key contents;
- private-key references may be stored only as trusted local references already
  subject to import-root policy;
- use a versioned on-disk format with explicit migration handling;
- write atomically through a temporary file, flush, and rename, or use another
  storage mechanism with equivalent crash-consistency guarantees;
- fail closed on corrupt or unsupported state instead of silently discarding
  revocations or revision barriers;
- treat IAS replay/snapshot delivery as the recovery authority when local state
  is absent or rejected;
- define audit retention separately from the minimal revision/tombstone state.

The implementation choice remains open. A small versioned term snapshot is the
current preferred starting point because the state is bounded and operationally
transparent, but DETS or another embedded store may be selected if concurrent
updates, compaction, or migration requirements justify it.

## TD-005 — Device-lock authorization

Bind each authenticated certificate/session to the IAS Device identifier from
trusted provisioning state and fail closed when the authorization decision does
not match. The Device identifier must never be trusted from the OVPN envelope.

## TD-006 — Two-factor provider hook

Add policy states `disabled`, `optional`, and `required`. A required second factor
must block session activation until an explicit provider succeeds. Provider
identity, challenge state, result, and expiry must be auditable.

## TD-007 — IAS revocation and policy synchronization

Connect IAS output to `vpn_provisioning` through an authenticated delivery
adapter. Synchronize certificate revocation, Device disablement, certificate
rotation, authorization denial, and identity reissue to configured and active
VPN peers. Delivery must preserve revision ordering and idempotency semantics.

## TD-008 — Safe import-root resolution

Resolve private-key references beneath a configured import root, reject path
traversal and absolute paths, and prevent symlink escape or time-of-check/time-of-
use substitution.

## TD-009 — OpenVPN compatibility boundary

Keep the `.ovpn` format as a strict ordinary-syntax subset with no vendor
metadata. Do not silently grow the importer into a general OpenVPN configuration
or wire-protocol implementation.

## TD-010 — Production removal of debug controls

The encrypted-frame history, replay API, frame-burst generator, local CA helpers,
and development authorization bypass are intentionally debug-only. Production
configurations must keep them disabled. A release-hardening pass should compile
or package these controls out of production artifacts rather than relying only on
runtime configuration.

## TD-011 — Session-key erasure hardening

Fresh handshakes, rekey, previous-epoch retirement, and peer restart recovery
replace obsolete session material logically. Add explicit best-effort key erasure
and document the limits imposed by BEAM binary lifetime, process heaps, crash
dumps, tracing, and allocator behavior.

## TD-012 — Replay and lifecycle policy controls

Make replay-window size, previous-epoch grace, maximum key age, and packet limits
policy-controlled rather than only runtime configuration. Consider a bounded
packet-count condition in addition to the grace timer when retiring the previous
epoch. Replay state must never survive a process restart; recovery requires a
fresh authenticated handshake.
