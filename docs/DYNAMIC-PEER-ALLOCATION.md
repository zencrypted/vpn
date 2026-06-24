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
slot reusable, but a later allocation receives a fresh peer-ID generation so a
different Device does not inherit the released peer identifiers.

An allocation contains only resource metadata, for example:

```erlang
#{device_id => <<"device-123">>,
  slot => 1,
  generation => 42,
  state => reserved,
  persistence => volatile,
  client_peer_id => <<"client_dyn_1_42">>,
  gateway_peer_id => <<"gateway_dyn_1_42">>,
  client => #{peer_id => <<"client_dyn_1_42">>,
              ifname => <<"vpc1">>,
              ip => "10.30.0.10",
              local_udp_port => 20000,
              remote_peer_id => <<"gateway_dyn_1_42">>,
              remote_udp_port => 30000},
  gateway => #{peer_id => <<"gateway_dyn_1_42">>,
               ifname => <<"vpg1">>,
               ip => "10.31.0.10",
               local_udp_port => 30000,
               remote_peer_id => <<"client_dyn_1_42">>,
               remote_udp_port => 20000}}.
```

The allocator is not yet connected to `vpn_provisioning`, does not create
certificate material, and does not start peer processes.

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

### Stage 2 — dynamic runtime resolver

Add an allocator-backed resolver mode. A provisioning command for a reserved
client peer will resolve trusted transport configuration from its allocation
instead of requiring a predeclared `runtime_config_templates` entry. The
resolver will create both client-side and gateway-side desired runtime configs
without accepting transport internals from IAS.

### Stage 3 — development identity factory

Create debug-only certificate and OVPN material for both peer IDs in a reserved
pair. Certificate subjects and handshake peer IDs must match the binary runtime
IDs. CA and private-key generation remain outside the allocator itself.
Production identity issuance will continue to belong to the configured CA/IAS
workflow.

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
reservations, and allocation order may change. Before dynamic allocation is used
outside the local development milestone, persist Device-to-resource assignments
atomically and restore them before provisioning reconciliation starts.

Durable state must contain only allocation metadata. It must never contain
private-key bodies, session keys, replay windows, ECDH material, or packet state.
Release, tombstone, and migration semantics must be coordinated with the durable
provisioning projection described in `TECHNICAL-DEBT.md`.

## Non-goals of Stage 1

Stage 1 does not:

- replace `client_a/client_b` in the existing two-user demo;
- mutate `vpn_peer_registry`;
- generate certificates or private keys;
- start TUN/UDP processes;
- survive a VPN application or node restart;
- accept allocator resource choices from IAS or an OVPN file.
