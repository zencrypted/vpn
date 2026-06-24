# Dynamic VPN Peer Allocation

## Purpose

The verified IAS demo currently maps two Devices into a bounded pair of trusted
runtime slots:

```text
Alice Device -> client_a <-> peer_b
Bob Device   -> client_b <-> peer_c
```

That topology proves concurrent provisioning and encrypted dataplane operation,
but it cannot admit a third Device without editing trusted VPN configuration.
Dynamic allocation replaces that fixed mapping with VPN-owned reservations.
IAS remains the identity and policy source of truth; VPN owns transport
resources and runtime topology.

## Ownership model

```text
IAS Device ID
    |
    | ensure allocation
    v
VPN peer allocator
    |
    +-> client peer ID
    +-> gateway peer ID
    +-> client/gateway TUN names
    +-> client/gateway tunnel addresses
    +-> client/gateway UDP ports
```

Peer IDs are binaries. Dynamic allocation must never create atoms from external
or Device-derived values.

## Stage 1 — volatile reservation allocator

`vpn_peer_allocator` is the first completed stage. It exposes:

```erlang
vpn_peer_allocator:ensure(DeviceId).
vpn_peer_allocator:lookup(DeviceId).
vpn_peer_allocator:release(DeviceId).
vpn_peer_allocator:list().
vpn_peer_allocator:status().
```

`ensure/1` is idempotent for a non-empty binary Device ID while the allocator
process remains alive. Distinct active Devices receive distinct peer IDs, TUN
names, tunnel addresses, and UDP ports. `release/1` makes the numeric transport
slot reusable, returns a snapshot marked `state => released`, and a later
allocation receives a fresh peer-ID generation so a different Device does not
inherit the released peer identifiers. Each allocator process also generates a
random instance namespace. Allocation IDs and peer IDs include that namespace,
so a volatile allocator restart cannot accidentally reuse the directory or
certificate names of identity bundles left by an earlier VPN node.

An allocation contains only resource metadata, for example:

```erlang
#{device_id => <<"device-123">>,
  slot => 1,
  generation => 42,
  allocator_instance_id => <<"7f32a91bc4de">>,
  state => reserved,
  persistence => volatile,
  client_peer_id => <<"client_dyn_1_7f32a91bc4de_42">>,
  gateway_peer_id => <<"gateway_dyn_1_7f32a91bc4de_42">>,
  client => #{peer_id => <<"client_dyn_1_7f32a91bc4de_42">>,
              ifname => <<"vpc1">>,
              ip => "10.30.0.10",
              local_udp_port => 20000,
              remote_peer_id => <<"gateway_dyn_1_7f32a91bc4de_42">>,
              remote_udp_port => 30000},
  gateway => #{peer_id => <<"gateway_dyn_1_7f32a91bc4de_42">>,
               ifname => <<"vpg1">>,
               ip => "10.31.0.10",
               local_udp_port => 30000,
               remote_peer_id => <<"client_dyn_1_7f32a91bc4de_42">>,
               remote_udp_port => 20000}}.
```

The allocator does not create certificate material and does not start peer
processes. Stage 2 can consume an existing reservation, but reservation itself
remains an explicit operation.

### Configuration

Defaults are safe for the current local debug topology and avoid its existing
TUN names, addresses, and ports. They can be overridden through the
`dynamic_peer_allocator` application environment:

```erlang
{dynamic_peer_allocator, #{
  capacity => 200,
  first_host => 10,
  client_network => {10,30,0},
  gateway_network => {10,31,0},
  client_udp_port_base => 20000,
  gateway_udp_port_base => 30000,
  client_peer_prefix => <<"client_dyn_">>,
  gateway_peer_prefix => <<"gateway_dyn_">>,
  client_ifname_prefix => <<"vpc">>,
  gateway_ifname_prefix => <<"vpg">>,
  remote_ip => {127,0,0,1}
}}.
```

Configuration fails closed when host or port ranges are invalid, client and
gateway UDP ranges overlap, or generated interface names can exceed Linux's
15-byte interface-name limit.

## Planned stages

### Stage 2 — dynamic runtime resolver (completed)

`vpn_runtime_config_resolver` now supports `dynamic_allocator` and exposes:

```erlang
vpn_runtime_config_resolver:resolve(PeerId, Desired).
vpn_runtime_config_resolver:resolve_pair(DeviceId, Desired).
```

Resolution is lookup-only: the Device must already have an active reservation.
`resolve_pair/2` returns validated client-side and gateway-side runtime maps.
The following fields always come from `vpn_peer_allocator` and cannot be
provided by IAS or trusted defaults:

- runtime peer IDs;
- TUN interface names;
- tunnel addresses;
- local and remote UDP endpoints;
- client/gateway pairing.

IAS desired state contributes only client profile, certificate fingerprint,
authorization, enabled, and revoked metadata. Trusted VPN configuration supplies non-transport and non-identity defaults
through:

```erlang
{dynamic_runtime_config_defaults, #{
  common => #{
    mode => tun,
    peer_module => vpn_peer,
    handshake_mode => certificate_control,
    authorization_mode => development_bypass,
    authorized => true
  },
  client => #{name => <<"Dynamic client">>},
  gateway => #{name => <<"Dynamic gateway">>}
}}.
```

Transport, OVPN, certificate, private-key, CA, or unknown keys in these defaults
fail closed. The resolver consumes peer-specific identity paths only from the
dynamic identity provider. It materializes the client through
`vpn_session_config:from_spec/1`, validates the gateway direct runtime map, and
still neither writes the pair to `vpn_peer_registry` nor starts it.

### Stage 3 — development identity factory (completed)

`vpn_dynamic_identity_factory` provides:

```erlang
vpn_dynamic_identity_factory:ensure(Allocation).
vpn_dynamic_identity_factory:lookup(AllocationId).
vpn_dynamic_identity_factory:release(AllocationId).
```

The factory is development-only and requires explicit configuration:

```erlang
{dynamic_identity_factory, #{
  mode => development,
  root_dir => "local/dynamic",
  ca_dir => "local/ca",
  tool_path => "tools/ensure-dynamic-identity.sh",
  command_module => vpn_dynamic_identity_command
}}.
```

For each allocation it creates or reuses:

- an EC P-384 client key, CSR, CA-signed certificate, and canonical OVPN
  envelope whose CN equals the allocated client peer ID;
- an RSA gateway key, CSR, and CA-signed certificate whose CN equals the
  allocated gateway peer ID;
- a small versioned manifest containing only allocation/peer metadata.

The factory validates chain trust, key ownership, file type, private-key
permissions, OVPN key containment, certificate-file/OVPN fingerprint equality,
and exact CN-to-peer-ID binding. A partial, symlinked, mismatched, or damaged
bundle fails closed rather than being silently trusted. `release/1` explicitly
erases the bundle directory; allocator release remains a separate operation.

Returned maps contain file references and certificate fingerprints only. PEM
bodies and private-key contents are never stored in allocator state, the
manifest, or public factory results. Production identity issuance still belongs
to IAS/the configured CA workflow.

### Stage 4 — IAS reservation integration

IAS will call `ensure(DeviceId)` before certificate issuance and store the
returned client and gateway peer IDs with the Device provisioning draft. The
current hard-coded mapping:

```erlang
#{alice => client_a,
  bob => client_b}
```

will then be removed from the normal wizard path. Reopening the same Device must
reuse the same active reservation rather than allocate another pair.

### Stage 5 — end-to-end reconciliation and tests

Provisioning will materialize and start both peers, establish the authenticated
session, and expose the allocation in administration status. Tests must prove:

- a third arbitrary Device requires no `sys.config` edit;
- repeated allocation for one Device is idempotent;
- different Devices never share peer IDs, interfaces, addresses, or ports;
- release/reallocation cannot bypass revision or revocation barriers;
- allocator exhaustion fails closed;
- no dynamic atoms or secret material enter allocation state or public status.

### Stage 6 — durable allocation projection

The current allocator is deliberately volatile. A VPN restart loses all
reservations, and allocation order may change. A fresh random allocator
namespace prevents old on-disk identity bundles from colliding with newly
reserved allocation IDs, but it does not restore Device-to-slot ownership or
make old bundles active again. Before dynamic allocation is used
outside the local development milestone, persist Device-to-resource assignments
atomically and restore them before provisioning reconciliation starts.

Durable state must contain only allocation metadata. It must never contain
private-key bodies, session keys, replay windows, ECDH material, or packet state.
Release, tombstone, and migration semantics must be coordinated with the durable
provisioning projection described in `TECHNICAL-DEBT.md`.

## Current non-goals after Stage 3

The completed allocator, resolver, and development identity stages do not:

- replace `client_a/client_b` in the existing two-user demo;
- automatically reserve a Device during provisioning;
- mutate `vpn_peer_registry` with both sides of the pair;
- start TUN/UDP processes;
- survive a VPN application or node restart;
- accept allocator resource choices from IAS, trusted defaults, or an OVPN file.
