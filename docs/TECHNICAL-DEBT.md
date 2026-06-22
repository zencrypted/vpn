# VPN Technical Debt

## TD-001 — Canonical OVPN parser and validator

Implement a strict `ovpn/v1` parser that accepts only the contract in
`OVPN-ENVELOPE.md`, reports precise validation failures, and converts a valid
envelope into an internal peer configuration without starting a session.

## TD-002 — EC P-384 identity support

`vpn_identity` currently extracts the public part only from RSA private keys.
IAS-managed Device enrollment uses EC `secp384r1`, so EC private-key parsing and
certificate/key matching are required before IAS envelopes can be consumed.

## TD-003 — Certificate-authenticated session

The current dataplane uses a static PSK. Replace or encapsulate it with a
standard authenticated handshake that proves certificate/private-key ownership,
validates the remote service, derives per-session traffic keys, and prevents
replay. Do not invent an unaudited custom handshake.

## TD-004 — Runtime provisioning registry

Peers are currently loaded from `sys.config`. Add a runtime registry and a
provisioning API that can create, update, disable, revoke, and reconcile peers
without exposing client private keys.

## TD-005 — Device-lock authorization

For `device-bound` envelopes, bind the authenticated certificate/session to the
IAS Device identifier and fail closed when authorization does not match.

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

Keep the `.ovpn` format as a canonical Zencrypted provisioning envelope. Do not
silently grow the importer into a general OpenVPN configuration or wire-protocol
implementation.
