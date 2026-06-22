# Canonical Zencrypted OVPN Envelope

Status: **Stage 27A contract**
Version: **`ovpn/v1`**

## Purpose

The canonical OVPN envelope is the provisioning interchange format between IAS
and the Zencrypted VPN runtime.

It intentionally reuses the familiar `.ovpn` text container so that endpoint,
certificate, trust-anchor, and local-key-reference data do not require a new
ad-hoc file format.

The envelope **does not mean that `zencrypted/vpn` implements or promises
compatibility with the OpenVPN wire protocol**. The runtime consumes a strict,
Zencrypted-controlled subset and maps it into its own peer/session model.

The normative contract is this document. `vpn_ovpn_envelope` exposes the same
version and value sets to Erlang code so that future parser and runtime work has
a machine-readable source.

## Normative language

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as
requirements for producers and consumers of this envelope.

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
- SHOULD remain below 1 MiB.

A consumer MUST reject an unsupported envelope version instead of attempting a
best-effort import.

## Required Zencrypted metadata

Metadata is encoded as comments before the compatibility directives:

```ovpn
# zencrypted-envelope: ovpn/v1
# zencrypted-runtime: zencrypted-overlay
# zencrypted-profile: device-bound
# zencrypted-device-id: manual_device_123
# zencrypted-2fa: optional
```

Required keys:

| Key | Allowed value |
|---|---|
| `zencrypted-envelope` | exactly `ovpn/v1` |
| `zencrypted-runtime` | exactly `zencrypted-overlay` |
| `zencrypted-profile` | `portable` or `device-bound` |
| `zencrypted-2fa` | `disabled`, `optional`, or `required` |

Conditional key:

| Key | Rule |
|---|---|
| `zencrypted-device-id` | required for `device-bound`; forbidden for `portable` |

Device and provisioning identifiers MUST be 1 to 255 ASCII characters and use
only letters, digits, `.`, `_`, and `-`.

Optional traceability keys:

```ovpn
# zencrypted-provisioning-id: provisioning_123
# zencrypted-certificate-sha256: 5CEB02C7849E1CD9C12E124DFBFAD66366F4B2E9ED860C9A71B99A7412979CB9
```

Unknown `zencrypted-*` metadata MUST be rejected in strict mode. Ordinary
non-Zencrypted comments MAY be ignored and MUST NOT alter security semantics.

## Profiles

### Portable

```ovpn
# zencrypted-profile: portable
```

A portable envelope is not authorized against one fixed Device identifier. The
operator may place the envelope and its matching private key on a selected
Device. Possession of the matching private key and successful certificate and
policy validation remain mandatory.

A portable envelope MUST NOT contain `zencrypted-device-id`.

### Device-bound

```ovpn
# zencrypted-profile: device-bound
# zencrypted-device-id: manual_device_123
```

A device-bound envelope is issued for one IAS Device object. The runtime MUST
verify the certificate/key proof and MUST obtain an authorization result for the
same Device identifier before activating the session.

The identifier itself is not a secret and is not proof of Device ownership.
Ownership is established by the private-key proof during the authenticated
session and by IAS authorization policy.

## Two-factor policy

| Value | Session rule |
|---|---|
| `disabled` | no second-factor step is requested |
| `optional` | a configured policy/provider MAY request a challenge |
| `required` | the session MUST NOT become active before a successful challenge |

The current runtime does not implement a 2FA provider. Until it does, a future
importer MAY accept `required` metadata for inspection, but session activation
MUST fail closed.

## Canonical directive subset

Version 1 supports only a TUN-over-UDP overlay profile.

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

IAS SHOULD emit directives in this canonical order:

1. Zencrypted metadata;
2. `client`;
3. `dev tun`;
4. `proto udp`;
5. `remote`;
6. optional compatibility directives;
7. `<ca>` block;
8. `<cert>` block;
9. `key` reference.

A consumer MAY parse the required entries independent of order, but MUST reject
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

Before session activation, the consumer MUST:

1. parse both PEM blocks;
2. validate certificate time and chain policy;
3. prove that the local private key matches the client certificate public key;
4. check revocation or current IAS authorization when available;
5. enforce the selected profile and 2FA policy.

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
prevents a canonical envelope from becoming an accidental general-purpose
OpenVPN configuration parser and blocks directives that execute local commands,
load plugins, or introduce unmanaged credentials.

## Mapping to the internal peer model

| Envelope value | Future internal value |
|---|---|
| `remote host port` | remote endpoint |
| `proto udp` | UDP transport |
| `dev tun` | TUN mode |
| `<ca>` | trust anchor |
| `<cert>` | local peer certificate |
| `key` | Device-local private-key reference |
| `zencrypted-profile` | portable/device-lock authorization policy |
| `zencrypted-device-id` | IAS Device identifier |
| `zencrypted-2fa` | second-factor policy |

The mapping does not imply that the current `vpn_peer` PSK configuration is the
final session model. Stage 27C must replace or encapsulate the temporary PSK
dataplane with a certificate-authenticated session.

## Canonical example

A complete public example is stored at:

```text
priv/examples/peer_a-device-bound.ovpn
```

It embeds the repository development CA and `peer_a` public certificate, but
references a private key only by the safe relative path `keys/peer_a.key`.

## Producer responsibilities

IAS, as producer, MUST:

- emit only this canonical subset;
- emit the exact version and runtime metadata;
- never embed a private key;
- emit a safe relative key reference;
- emit a Device identifier only for device-bound profiles;
- use a real configured endpoint before strict export;
- preserve certificate and provisioning lineage.

## Consumer responsibilities

`zencrypted/vpn`, as consumer, MUST:

- parse strictly and reject ambiguity;
- reject unsupported versions and unknown directives;
- resolve files beneath an explicit import root;
- validate certificate, key ownership, authorization, device lock, and 2FA;
- convert the envelope into internal runtime configuration;
- never interpret the envelope as permission to execute arbitrary OpenVPN
  directives.

## Versioning

`ovpn/v1` is immutable once implemented by a released consumer. Any incompatible
change requires a new version value such as `ovpn/v2`.

Optional metadata can be added only when an older strict consumer can reject it
safely and the producer can negotiate the newer contract.

## Implementation stages

```text
Stage 27A  Canonical envelope contract and machine-readable constants
Stage 27B  Strict parser, validator, and internal peer-config conversion
Stage 27C  Certificate-authenticated session, Device lock, and 2FA hook
```

Stage 27A does not claim that import or authenticated sessions are operational.
