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

## TD-003 — Certificate-authenticated session

The current dataplane uses a static PSK. Replace or encapsulate it with a
standard authenticated handshake that proves certificate/private-key ownership,
validates the remote service, derives per-session traffic keys, and prevents
replay. Do not invent an unaudited custom handshake.

## TD-004 — Runtime provisioning registry

Peers are currently loaded from `sys.config`. Add a runtime registry and a
provisioning API that can create, update, disable, revoke, and reconcile peers
without exposing client private keys. The registry, not OVPN comments, must hold
Device binding, 2FA policy, certificate lineage, and authorization state.

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
