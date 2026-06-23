# VPN Technical Debt

## Completed — Canonical OVPN parser and validator

`vpn_ovpn_parser` now accepts only the documented `ovpn/v1` subset, reports
line-oriented validation failures, and returns a normalized peer configuration
without resolving keys, mutating runtime state, or starting a session.

## Completed — OVPN local identity validation and EC P-384 ownership

`vpn_ovpn_identity` now resolves the Device-local key relative to the envelope,
validates the inline CA and certificate, and verifies RSA or EC P-384
certificate/key ownership without exposing private-key material. The legacy
file-config path in `vpn_identity` still uses its existing RSA record comparison;
new OVPN imports use the algorithm-neutral OpenSSL ownership check.

## Completed — OVPN-backed validated session startup

`vpn_session_config` now combines a validated OVPN identity with trusted
runtime-only settings, and `vpn_peer_sup` starts those sessions from the
`ovpn_sessions` application environment. OVPN-derived certificate material is
validated before the existing dataplane starts and is exposed only through safe
identity summaries.

## Completed — Standalone local OVPN provisioning

Development helpers now create an isolated EC P-384 local CA and generate a
Device-local key, CSR, CA-signed client certificate, and canonical OVPN envelope
without IAS. Generated material remains beneath the Git-ignored `local/` tree.
This flow is explicitly test-only and carries no IAS authorization semantics.

## Completed — Explicit development authorization bypass

OVPN sessions now fail closed unless trusted runtime state explicitly authorizes
them. The debug profile opts into `development_bypass`, which is surfaced in
runtime summaries together with its reason. OVPN certificate validity metadata,
including expiration, is also exposed through safe management status. This bypass
remains debug-only and is never read from the OVPN envelope.

## Completed — Certificate-authenticated session lifecycle

Certificate-control peers mutually authenticate certificate ownership, derive
directional keys from ephemeral P-384 ECDH with HKDF-SHA256, rotate key epochs
manually or automatically, and enforce replay windows with previous-epoch grace.
The legacy PSK path remains only as an explicit compatibility mode.

## In progress — Runtime provisioning registry

`vpn_peer_registry` now provides an ETS-backed runtime inventory bootstrapped
from trusted application configuration. Safe registry reads expose provisioning
metadata without PSKs, private-key paths, or complete runtime configuration.
Enabled entries drive startup and explicit `vpn_manager:reload_config/0`
reconciliation. Remaining work includes automatic live reconciliation, IAS
synchronization, revocation, Device binding, 2FA policy, and persistent/audited
provisioning storage.

## TD-005 — Device-lock authorization

For Device-bound authorization, bind the authenticated certificate/session to
the IAS Device identifier from trusted provisioning state and fail closed when
authorization does not match. The Device identifier must not be trusted from the
OVPN file.

## TD-006 — Two-factor provider hook

Add the policy states `disabled`, `optional`, and `required`. A required second
factor must block session activation until a provider returns success. The first
implementation may use a stub provider, but it must be explicit and auditable.

## TD-007 — Revocation and policy synchronization

Synchronize certificate revocation, Device disablement, certificate rotation,
and authorization denial from IAS to active and configured VPN sessions.

## TD-008 — Safe import-root resolution

Resolve private-key references beneath a configured import root, reject path
traversal and absolute paths, and prevent symlink escape or time-of-check/time-of-
use substitution.

## TD-009 — OpenVPN compatibility boundary

Keep the `.ovpn` format as a strict ordinary-syntax subset with no vendor
metadata. Do not silently grow the importer into a general OpenVPN configuration
or wire-protocol implementation.


### Debug bootstrap remains development-only

The one-command debug flow creates and reuses credentials under Git-ignored
`local/`. It intentionally does not model IAS authorization, revocation, Device
attestation, 2FA, or production CA lifecycle. The temporary PSK dataplane also
remains in `config/sys.debug.config` until certificate-authenticated session
key establishment replaces it.

## Handshake skeleton follow-up

The development control handshake currently proves only UDP liveness and
configured peer-id agreement. Control frames are not authenticated and the
PSK dataplane remains active after establishment. Replace this skeleton with
certificate exchange, transcript signatures, ephemeral ECDH/HKDF session keys,
replay-safe session identifiers, rekeying and production authorization binding.

## Certificate handshake follow-up

The control plane now proves mutual possession of configured certificate private keys, validates each remote certificate against an explicit trust anchor, and derives directional traffic keys with ephemeral P-384 ECDH plus HKDF-SHA256. Remaining work includes replay windows, periodic rekeying, key erasure hardening, certificate revocation, production authorization binding, and removal of the legacy PSK compatibility path.

## Authenticated session lifecycle

Authenticated dataplane frames now carry an explicit key epoch, nonce
derivation includes that epoch, and runtime statistics expose establishment
time plus per-epoch traffic counters. The initial certificate session uses
epoch 1. Authenticated epoch rollover, previous-epoch grace handling, replay
windows and session-expiration enforcement remain future work.

- Manual and automatic authenticated rekey are implemented. Automatic rekey can be
  triggered by elapsed time or packets since the previous key epoch, suppresses
  concurrent attempts, and applies a cooldown after failures. Production defaults
  leave both thresholds disabled. Session-expiration enforcement remains to be added.

## Replay-window follow-ups

The authenticated dataplane now keeps a 64-packet sliding replay window per key
epoch and retains the immediately previous receive key for a configurable
grace period after rekey (five seconds by default; fifteen seconds in the debug
profile). The following hardening remains intentionally separate:

- make replay-window size policy controlled;
- persist no replay state across process restarts (a fresh handshake is required);
- add deterministic integration injection hooks for duplicate and delayed UDP
  packets without exposing them in production APIs;
- consider a bounded packet-count condition in addition to the grace timer for
  retiring the previous epoch.

## Debug replay controls

The encrypted-frame history and replay API are intentionally debug-only. Production configurations must keep `debug_replay_controls` disabled. The retained history is bounded to 256 ciphertext frames and exposes only metadata through the read API. A future hardening pass should compile these controls out of release builds or protect them behind a dedicated development feature flag.

## Revisioned provisioning contract

The runtime now accepts serialized, monotonic provisioning commands through
`vpn_provisioning`. Delivery is idempotent by revision and payload, stale
commands are rejected, and remove operations retain an in-memory tombstone.
Durable persistence and authenticated transport from IAS remain follow-up work.
