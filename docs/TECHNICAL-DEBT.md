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
manual `vpn_manager:reload_config/0` call. Registry writes classify revision
bookkeeping fields as non-restart metadata, preserving an established process
when IAS only advances revision/source/operation timestamps. Any other desired
runtime change remains restart-reconciled. Static peers retain ordinary
single-peer enable/disable behavior, while dynamic client lifecycle operations
control the whole client/gateway pair in gateway-first order. Pair enable waits
for both handshakes and rolls back to disabled if establishment fails. The
explicit reload operation remains available as a recovery/full-reconcile path.

## Completed — Revisioned provisioning contract

`vpn_provisioning` accepts monotonic, idempotent provisioning commands for
`upsert`, `enable`, `disable`, `revoke`, and `remove`. Stale revisions and
revision conflicts are rejected, remove operations retain durable tombstones,
and revoke prevents ordinary re-enable until a newer identity reissue arrives.
Accepted, unchanged, stale, conflicting, and revoked commands are represented in
bounded per-peer audit history. Authorization metadata is normalized when policy
state changes, and explicit revoke reasons are preserved.

## Completed — Dynamic peer allocation and lifecycle

VPN-owned allocation now reserves binary client/gateway peer IDs and
non-overlapping transport resources. The runtime resolver, development identity
factory, IAS reservation/delivery cutover, pair reconciliation, synchronized
enable/disable/revoke behavior, startup quarantine, and explicit decommission
are exercised end to end. Static `client_a/client_b` peers remain low-level
debug fixtures rather than the normal IAS delivery target.

`vpn_dynamic_pair:decommission/1,2` removes only quiesced pairs. It validates
ownership, batch-removes client and gateway registry entries, releases the
allocator slot, and optionally removes the local development identity bundle.
Stale revisions remain blocked by the live provisioning head, and allocation
release prevents resolver-based reconstruction of the old peer IDs.

Allocator assignments, revisioned provisioning barriers, registry
reconstruction, and eligible peer restart now survive process and node restart
through the Stage 8A durable projection. The remaining local durability gap is
atomic decommission state: allocator release and the provisioning tombstone must
commit as one cross-section barrier without persisting private or session
material. See
[`DYNAMIC-PEER-ALLOCATION.md`](DYNAMIC-PEER-ALLOCATION.md).

## Completed — TD-018 single-RPC revisioned dynamic bootstrap

`vpn_provisioning:apply_dynamic/2` removes the former failure window between
`vpn_dynamic_pair:ensure/2` and the following revisioned `upsert`. A reserved
Device is now materialized and established through one serialized provisioning
call. Both client and gateway registry entries receive the accepted revision
metadata before startup, and the provisioning head is committed only after
required process replacement and both handshakes establish. Failures restore previous registry/runtime state and best-effort remove
identity material created by the failed operation. The old
two-step APIs remain temporarily available for IAS migration compatibility.

## In progress — Durable provisioning and allocation projection

The allocator and revisioned provisioning ledger are backed by the durable VPN
projection. Stage 8A.4 now reconstructs eligible registry entries before peer
supervision and starts only applied active peers. Disabled/revoked heads remain
stopped, remove and incomplete active pending heads are suppressed, and a durable
allocator release barrier suppresses stale dynamic heads after completed
decommission. Old peer-keyed heads are also prevented from rebinding to a newer
allocation generation for the same Device. Active dynamic recovery requires the matching durable allocation
and validated local identity bundle. The VPN supervisor now restarts dependent
children with
`rest_for_one` so local recovery ordering is preserved after child failure.
Bounded provisioning history remains volatile operational telemetry.

Stage 8A.1 now provides the separate durable foundation: a replaceable
`vpn_projection_store` behaviour, a KVS/Mnesia synchronous compare-and-set backend, one
versioned and checksummed projection record, fail-closed schema/checksum
validation, and a serialized `vpn_projection` process started before allocator
and provisioning workers. Known secret-bearing fields are rejected before
commit.

Stage 8A.2 connects allocator initialization, reserve, and release mutations to
the projection. One stable allocator instance ID, `next_generation`, active
Device allocations, and per-Device release barriers are restored before the
allocator becomes ready. Mutations are published only after synchronous commit,
and malformed or configuration-incompatible allocator state fails startup closed.

Stage 8A.3 adds a versioned provisioning section. A new revision is committed as
a durable pending barrier before its idempotent runtime action and finalized as
applied only after success. Matching re-delivery resumes a pending action; newer
revisions are rejected until recovery completes. Applied revision/digest heads,
revoked lifecycle state, safe desired-state metadata, and remove tombstones are
validated and restored fail-closed. Runtime configuration, PSKs, private-key
references, session material, and replay state are not written to the ledger.

The target ownership model is:

```text
IAS                          VPN
source of truth              runtime projection
identity and policy state -> revisioned desired state
                              -> peer registry
                              -> reconciled processes
```

The durable provisioning ledger now provides these guarantees:

- the last accepted revision and canonical command digest are stored per peer;
- remove tombstones and revoked state survive restart;
- only a conservative safe desired-state projection is retained;
- pending/applied phases close the crash window around runtime mutation;
- corrupt, unsupported, or structurally invalid ledger state fails startup closed;
- session keys, replay windows, ephemeral ECDH material, PSKs, private-key
  references, and raw runtime configuration are excluded;
- audit retention remains separate from the minimal revision/tombstone state.

Registry/runtime reconstruction now occurs only after this ledger and the
allocator projection have both passed validation. IAS replay remains the
authority when local desired state is absent or when an interrupted command must
be completed.

The storage boundary is now fixed while the backend remains replaceable. The
first backend uses `zencrypted/kvs` with local Mnesia `disc_copies` and an
explicit transaction rather than the KVS default dirty context. Allocator state
and provisioning heads/tombstones are connected. Stage 8A.4 reconstructs the
registry and eligible peer processes only after projection validation. The
remaining local durability gap is an atomic allocator-plus-provisioning
decommission barrier.

## TD-005 — Device-lock authorization

Bind each authenticated certificate/session to the IAS Device identifier from
trusted provisioning state and fail closed when the authorization decision does
not match. The Device identifier must never be trusted from the OVPN envelope.

## TD-006 — Two-factor provider hook

Add policy states `disabled`, `optional`, and `required`. A required second factor
must block session activation until an explicit provider succeeds. Provider
identity, challenge state, result, and expiry must be auditable.

## TD-007 — Production authentication for IAS delivery

IAS lifecycle synchronization, revision ordering, idempotency, dynamic
provisioning, disable/enable, revoke, and decommission are implemented. The
remaining item is production authentication and hardening of the delivery
transport, including node identity, authorization of provisioning callers, and
operational key/cookie rotation. Durable replay and restart recovery are tracked
separately by the projection work above.

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
