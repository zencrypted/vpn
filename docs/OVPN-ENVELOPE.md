# Canonical OVPN Envelope

Status: **Implemented current contract**

Implemented in the current runtime:

- canonical `ovpn/v1` envelope constants and validation rules;
- strict parsing, normalization, and peer-config conversion;
- local CA, certificate, and Device-local private-key ownership validation;
- RSA and EC P-384 development/IAS identity support;
- OVPN-backed runtime configuration;
- certificate-authenticated control-plane handshakes;
- ephemeral P-384 ECDH traffic-key derivation;
- dataplane replay windows and key-epoch rollover.

The envelope does not carry IAS authorization policy, Device-lock or 2FA
requirements, provisioning ownership, session keys, or replay state.

Contract version: **`ovpn/v1`**

## Purpose

The canonical OVPN envelope is the provisioning interchange format between IAS
and the VPN runtime.

It reuses ordinary `.ovpn` syntax for the remote endpoint, public certificates,
and a Device-local private-key reference. It deliberately does not invent
vendor-prefixed directives or comment metadata.

The envelope does **not** mean that this runtime implements the OpenVPN wire
protocol or accepts arbitrary third-party configurations. The consumer supports
a strict subset and maps it into its own peer/session model.

`ovpn/v1` is the version of this document and parser contract. It is not written
into the file. `vpn_ovpn_envelope` exposes the same contract constants to Erlang
code.

## Normative language

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are requirements for
producers and consumers of this envelope.

## File requirements

A canonical envelope:

- uses UTF-8 text without a byte-order mark;
- uses LF line endings when produced by IAS;
- has the `.ovpn` extension;
- contains exactly one remote endpoint;
- contains exactly one inline CA certificate block;
- contains exactly one inline client certificate block;
- contains exactly one relative private-key reference;
- MUST NOT contain private-key material;
- MUST NOT rely on comments for security or runtime semantics;
- SHOULD remain below 1 MiB.

Comments MAY be present and MAY be ignored. A consumer MUST NOT derive Device
binding, authorization, 2FA policy, provisioning identity, or runtime selection
from comments.

## Security policy is external

Portable versus Device-bound provisioning, the IAS Device identifier, 2FA
policy, certificate lineage, revocation state, and authorization decisions are
not encoded in the OVPN file.

They belong to trusted IAS/VPN runtime state and are associated through the
provisioning registry and authenticated certificate identity. Editing a local
configuration file therefore cannot weaken Device lock or 2FA requirements.

The envelope itself proves no Device identity. Session activation requires:

1. possession of the matching private key;
2. successful certificate and trust validation;
3. current external authorization;
4. Device-lock and 2FA enforcement when required by that authorization context.

## Canonical directive subset

Version 1 supports a TUN-over-UDP overlay profile.

Required directives and blocks:

```ovpn
client
dev tun
proto udp
remote <host> <port>

<ca>
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</cert>

key <relative-private-key-reference>
```

Optional compatibility directives:

```ovpn
nobind
persist-key
persist-tun
remote-cert-tls server
verb <0..11>
```

IAS SHOULD emit directives in this order:

1. `client`;
2. `dev tun`;
3. `proto udp`;
4. `remote`;
5. optional compatibility directives;
6. `<ca>` block;
7. `<cert>` block;
8. `key` reference.

A consumer MAY parse required entries independent of order, but MUST reject
duplicate singleton directives and duplicate certificate blocks.

## Private-key reference

The `key` directive points to a Device-local private key:

```ovpn
key keys/laptop-20260622-014748-19.key
```

The reference:

- MUST be relative to the envelope import root;
- MUST NOT be empty;
- MUST use `/` separators;
- MUST NOT contain `.` or `..` path segments;
- MUST NOT contain an absolute path, drive prefix, control character, or space;
- MUST contain only path segments made from ASCII letters, digits, `.`, `_`,
  and `-`;
- MUST resolve inside the configured import root;
- MUST NOT be replaced by an inline `<key>` block.

A consumer MUST protect against symlink-based escape while resolving the path.
The private-key body MUST never be copied into IAS, logs, status responses, or
provisioning metadata.

## Endpoint rules

The `remote` directive contains one DNS name or IP literal and one port:

```ovpn
remote vpn.example.net 5555
```

The host MUST be non-empty and contain no whitespace, slash, backslash, or
control character. The port MUST be in the range `1..65535`.

In `ovpn/v1`, `proto` MUST be `udp` and `dev` MUST be `tun`.

## Certificate rules

The `<ca>` block carries the trust anchor used to validate the remote VPN
service identity.

The `<cert>` block carries the client public certificate. The matching private
key remains at the path named by `key`.

The `vpn_ovpn_identity` consumer now performs the local portions of this flow.
Before session activation, the consumer MUST:

1. parse both PEM blocks;
2. validate certificate time and chain policy;
3. prove that the local private key matches the client certificate public key;
4. check revocation and current IAS authorization;
5. apply Device-lock and 2FA policy from trusted external runtime state.

Certificate blocks are public material. Private-key blocks are forbidden.

## Forbidden directives and content

The following are outside `ovpn/v1` and MUST be rejected:

```text
<key>
auth-user-pass
askpass
plugin
script-security
up
down
management
tls-auth
tls-crypt
secret
pkcs12
```

A strict consumer MUST also reject every unknown non-comment directive. This
prevents the importer from becoming an accidental general-purpose OpenVPN
configuration parser and blocks directives that execute commands, load plugins,
or introduce unmanaged credentials.

## Mapping to the internal peer model

| Envelope value | Internal value |
|---|---|
| `remote host port` | remote endpoint |
| `proto udp` | UDP transport |
| `dev tun` | TUN mode |
| `<ca>` | trust anchor |
| `<cert>` | local peer certificate |
| `key` | Device-local private-key reference |

The importer combines this parsed configuration with separate trusted runtime
state containing authorization, Device binding, 2FA requirements, and
provisioning lineage.

The mapping does not make the envelope a session-authorization token or a traffic
key container. The current runtime can use OVPN-backed identity with
`handshake_mode => certificate_control`; that control plane authenticates peers
with certificates and derives directional ephemeral traffic keys before enabling
the dataplane. Legacy/debug PSK configuration remains a separate bounded runtime
mode and is not part of the `ovpn/v1` envelope contract.

## Canonical example

A complete public example is stored at:

```text
priv/examples/peer_a.ovpn
```

It contains only ordinary OVPN directives, embeds the repository development CA
and `peer_a` public certificate, and references the private key by the safe
relative path `keys/peer_a.key`.

## Local development producer

The repository also provides a standalone development producer for local
testing without IAS:

```sh
./tools/init-local-ca.sh
./tools/generate-local-ovpn.sh --name client_a --remote 127.0.0.1 --port 5556
```

It emits the same strict ordinary-syntax `ovpn/v1` envelope and keeps the
private key outside the file. Its local CA and issued identities are test-only.
It does not provide Device binding, authorization, 2FA, audit lineage,
revocation synchronization, or any other IAS policy semantics.

## Producer responsibilities

IAS, as producer, MUST:

- emit only this canonical ordinary OVPN subset;
- not emit custom vendor metadata;
- never embed a private key;
- emit a safe relative key reference;
- use a real configured endpoint before strict export;
- preserve Device binding, 2FA, certificate, and provisioning lineage in trusted
  state outside the file.

## Consumer responsibilities

The VPN runtime, as consumer, MUST:

- parse strictly and reject ambiguity;
- reject unknown directives;
- ignore comments for security semantics;
- resolve files beneath an explicit import root;
- validate certificate and key ownership;
- obtain authorization, Device lock, and 2FA requirements from trusted external
  state;
- convert the envelope into internal runtime configuration;
- never interpret the envelope as permission to execute arbitrary OpenVPN
  directives.

## Versioning

`ovpn/v1` is an implementation and documentation contract label, not an on-wire
field. Incompatible parser changes require a new contract version in code and
documentation, together with explicit producer/consumer coordination.

No security-relevant version, profile, Device identifier, or 2FA value is stored
in comments.

## Implementation boundary

`vpn_ovpn_envelope` exposes the machine-readable `ovpn/v1` contract and
validation constants. `vpn_ovpn_parser` performs strict parsing, normalization,
and internal peer-config conversion. Parsing is intentionally side-effect free:
it does not resolve a private-key file, validate X.509 cryptography, mutate the
runtime registry, or start a VPN session.

`vpn_ovpn_identity` owns local identity validation after parsing. Session and
runtime modules consume the validated identity/configuration through their own
lifecycle boundaries. Authorization, Device-lock, and 2FA decisions remain
external policy inputs and are not implemented by the parser or encoded in the
envelope.

## Local identity validation

`vpn_ovpn_identity:load/1` accepts an envelope path and performs a side-effect-free
local validation step:

1. parse the canonical envelope;
2. resolve `key` relative to the envelope directory, never the process working
   directory;
3. require a regular, non-symlink private-key file;
4. decode the inline CA and client certificates;
5. verify the client certificate against the inline CA and current validity
   policy;
6. compare the certificate public key with the local private key through the
   configured OpenSSL executable;
7. return SHA-256 certificate fingerprints and readiness metadata without
   returning private-key material.

Both RSA development fixtures and IAS EC `secp384r1` keys are supported by the
key-ownership check. `OPENSSL3` may name an alternate OpenSSL executable;
otherwise `openssl` is resolved from `PATH`.

The current lexical containment check and final-file symlink rejection are
defense in depth. Full import-root and parent-directory symlink hardening remains
tracked as technical debt.


## Stable debug producer

`tools/ensure-debug-ovpn.sh` is the idempotent producer for one local debug
identity. `tools/prepare-debug-topology.sh` invokes it for `client_a`,
`client_b`, and `peer_c`, verifies the required OVPN, certificate, and key
files, and can be run without starting Erlang. A complete bundle is reused, an
incomplete bundle fails closed, and `--force` performs an explicit identity
rotation without rotating the development CA. `tools/run-debug.sh` is the
supported two-slot entry point: it prepares the full topology and only then
launches the debug Rebar3 profile. A raw `rebar3 as debug shell` requires the
same files to have been prepared already.

## Certificate-authenticated control plane

An OVPN-backed peer can run with `handshake_mode => certificate_control`. Its inline client certificate and Device-local private key are used to sign a handshake transcript. The remote peer validates that certificate against `handshake_remote_ca_certificate_path`, checks that the certificate common name equals the configured remote peer ID, and verifies the signature before the dataplane is enabled. The private key is never transmitted. Certificate-control peers derive directional dataplane keys from an authenticated ephemeral P-384 ECDH exchange and HKDF-SHA256. The OVPN envelope still carries no symmetric traffic secret.


## Ephemeral traffic keys

For `handshake_mode => certificate_control`, each startup creates a fresh P-384 ECDH key pair. Both ephemeral public keys are included in the certificate-signed transcript. Successful mutual proof derives independent TX/RX ChaCha20-Poly1305 keys with HKDF-SHA256. The private ECDH key, certificate private key, and derived traffic keys are never serialized into OVPN or management output.

## Dataplane replay state

Replay windows and key-epoch rollover are runtime session state. They are not
OVPN directives and must never be serialized into the portable envelope.
