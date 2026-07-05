# Dynamic VPN Peer Allocation

## Purpose

Dynamic peer allocation replaces the bounded `client_a` / `client_b` debug
slots with VPN-owned transport reservations for arbitrary IAS Devices.

IAS remains the identity, policy, and desired-state authority. VPN owns dynamic
transport resources, runtime peer topology, local identity materialization for
development mode, and durable allocation/provisioning projections.

The current contract is:

```text
IAS Device ID
    |
    | reserve allocation
    v
vpn_peer_allocator
    |
    +-> client peer ID
    +-> gateway peer ID
    +-> client/gateway TUN names
    +-> client/gateway tunnel addresses
    +-> client/gateway UDP ports
    |
    | revisioned dynamic provisioning
    v
vpn_provisioning:apply_dynamic/2
    |
    +-> identity materialization
    +-> runtime configuration resolution
    +-> pair registry update
    +-> gateway-first reconciliation
    +-> certificate-control establishment
    +-> durable provisioning-head commit
```

Peer IDs are binaries. Dynamic allocation must never create atoms from external
or Device-derived values.

## Ownership Boundary

VPN owns:

- allocation slots and allocation generations;
- allocator instance identity;
- peer IDs;
- TUN interface names;
- tunnel addresses;
- local and remote UDP ports;
- client/gateway pairing;
- runtime peer registry entries;
- durable VPN allocation and provisioning projections.

IAS may supply only the Device identity and approved desired-state metadata.
IAS must not choose dynamic transport resources or runtime peer identifiers.

Private-key bodies, session keys, replay windows, ECDH material, packet state,
and raw runtime configuration are not durable allocation or provisioning data.

## Durable Allocation Contract

`vpn_peer_allocator` exposes:

```erlang
vpn_peer_allocator:ensure(DeviceId).
vpn_peer_allocator:lookup(DeviceId).
vpn_peer_allocator:released(DeviceId).
vpn_peer_allocator:release(DeviceId).
vpn_peer_allocator:list().
vpn_peer_allocator:status().
```

`ensure/1` is idempotent for a non-empty binary Device ID. Distinct active
Devices receive distinct peer IDs, TUN names, tunnel addresses, and UDP ports.

An allocation has a stable identity only for its current generation. The durable
allocator projection stores:

- one allocator instance namespace;
- monotonic `next_generation` state;
- active Device-to-allocation mappings;
- the most recent release barrier per Device.

A representative allocation is:

```erlang
#{device_id => <<"device-123">>,
  slot => 1,
  generation => 42,
  allocator_instance_id => <<"7f32a91bc4de">>,
  state => reserved,
  persistence => durable,
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

Reserve and release operations become visible only after projection commit.
When persistence fails, the allocator call returns an error and the previous
in-memory state remains authoritative for the running process.

`release/1` makes the numeric transport slot reusable and records a released
snapshot. Repeated release of the same generation is idempotent. A later
allocation receives a fresh generation and therefore fresh peer IDs; a reused
slot cannot recreate its former allocation identity.

Allocator recovery reconstructs the slot index from the durable projection and
validates it against current allocator configuration. Malformed, duplicated, or
configuration-incompatible state fails startup closed.

### Allocator Configuration

The allocator is configured through `dynamic_peer_allocator`:

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

## Dynamic Runtime Resolution

`vpn_runtime_config_resolver` supports the `dynamic_allocator` source and
exposes:

```erlang
vpn_runtime_config_resolver:resolve(PeerId, Desired).
vpn_runtime_config_resolver:resolve_pair(DeviceId, Desired).
```

Resolution is lookup-only. The Device must already own an active allocation.
The resolver never reserves transport resources as a side effect.

The following values always come from the allocator:

- runtime peer IDs;
- TUN interface names;
- tunnel addresses;
- local and remote UDP endpoints;
- client/gateway pairing.

IAS desired state contributes only approved profile, certificate fingerprint,
authorization, enabled, revoked, revision, source, and operation metadata.

Trusted VPN configuration supplies non-transport defaults through
`dynamic_runtime_config_defaults`, for example:

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
fail closed.

The resolver consumes peer-specific identity paths only from the configured
dynamic identity provider. It materializes the client through
`vpn_session_config:from_spec/1`, validates the gateway runtime map, and does not
write registry entries or start peers.

## Development Identity Materialization

`vpn_dynamic_identity_factory` provides:

```erlang
vpn_dynamic_identity_factory:ensure(Allocation).
vpn_dynamic_identity_factory:lookup(AllocationId).
vpn_dynamic_identity_factory:release(AllocationId).
```

The built-in factory is development-only and must be explicitly configured:

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
- a versioned manifest containing only safe allocation and peer metadata.

The factory validates chain trust, key ownership, file type, private-key
permissions, OVPN key containment, certificate-file/OVPN fingerprint equality,
and exact CN-to-peer-ID binding. Partial, symlinked, mismatched, or damaged
bundles fail closed.

Returned maps contain file references and certificate fingerprints only. PEM
bodies and private-key contents are not stored in allocator state, manifests, or
public factory results.

Production identity issuance remains outside this development factory and
belongs to IAS and the configured CA workflow.

## Revisioned Dynamic Provisioning

`vpn_provisioning:apply_dynamic/2` is the canonical provisioning boundary for an
allocated Device:

```erlang
vpn_provisioning:apply_dynamic(DeviceId, Command).
```

The command must be a positive-revision dynamic `upsert` whose `peer_id` is the
client peer owned by the Device allocation. The Device identifier is normalized
into desired state and bound into the deterministic command digest.

One serialized operation:

1. validates revision ordering and idempotency;
2. verifies the Device-to-client allocation binding;
3. creates or reuses the configured identity bundle;
4. resolves client and gateway runtime maps;
5. writes both registry entries with final IAS revision/source/operation
   metadata in one batch;
6. reconciles the gateway before the client;
7. waits for required peer replacement and for both certificate-control
   handshakes to become established;
8. commits the durable provisioning head only after the intended runtime
   generation is established.

A duplicate command returns `unchanged`. Stale or conflicting revisions are
rejected before runtime mutation.

Resolution, registry, startup, or handshake failure restores previous
registry/runtime state. If the operation created a development identity bundle,
rollback also attempts to remove that bundle. The allocation remains reserved,
so the same revision can be retried safely.

The older composition:

```text
vpn_dynamic_pair:ensure/2
    -> vpn_provisioning:apply/1
```

remains a compatibility path for older IAS delivery. New dynamic IAS `upsert`
delivery uses `apply_dynamic/2`. Allocation reservation remains a separate
operation because a reserved-only allocation must not start peers or expose a
revision-zero runtime pair.

## Pair Runtime and Lifecycle Semantics

`vpn_dynamic_pair` exposes the pair-level compatibility and administration API:

```erlang
vpn_dynamic_pair:ensure(DeviceId, Desired).
vpn_dynamic_pair:status(DeviceId).
vpn_dynamic_pair:decommission(DeviceId).
vpn_dynamic_pair:decommission(DeviceId, #{remove_identity => true}).
```

For pair reconciliation, VPN:

1. materializes or reuses the identity bundle;
2. resolves client and gateway runtime maps;
3. validates that existing registry entries belong to the same allocation and
   Device;
4. writes both peers through one registry batch;
5. reconciles the gateway before the client;
6. waits until both certificate-control handshakes report `established`.

The registry batch prevents observers from seeing only one desired side of a new
pair. A startup or handshake timeout restores the previous registry state and
stops newly started partial peers.

Repeating unchanged reconciliation does not restart an established pair.
Revision-only bookkeeping changes can update registry metadata in place; runtime,
identity, authorization, or transport changes still trigger reconciliation.

Dynamic lifecycle operations are pair-aware:

- `disable` updates both registry entries in one batch, reconciles the gateway
  first, and returns only after both processes are stopped;
- `enable` enables the gateway first, then the client, and returns only after
  both certificate-control handshakes are established;
- failed enable rolls both sides back to `enabled => false`;
- `revoke` uses the same gateway-first quiesce path and returns only after both
  processes are stopped, while only the client is marked revoked.

The gateway remains authorized and unrevoked after client revoke so an explicit
higher-level reissue can reuse the reserved pair without leaving an orphaned
handshake timer.

Dynamic peers use a VPN-owned handshake-start quarantine before emitting the
first control frame. Packets arriving on newly rebound UDP sockets while the
timer is pending are discarded, which drains delayed frames from the previous
pair incarnation. The debug default is:

```erlang
handshake_start_delay_ms => 250
```

Static peers retain the zero-delay default.

The pair wait policy is configured through:

```erlang
{dynamic_pair_reconcile, #{
  establish_timeout_ms => 5000,
  poll_interval_ms => 50
}}.
```

Public pair status exposes allocation ownership, runtime state, and handshake
state without OVPN identity internals, private-key paths, PEM bodies, or session
secrets. Pair `state` is derived from both runtime peers (`established`,
`stopped`, `reconciling`, or `reserved` before runtime materialization).
`allocation_state` reports the durable allocator lifecycle separately.

## Decommission Boundary

Decommission is intentionally separate from disable and revoke.

The pair must already be quiesced: both runtime processes must be stopped and
both registry entries disabled. Active pairs fail closed.

For a valid owned pair, decommission:

1. validates Device, allocation, and peer-role ownership;
2. removes gateway and client registry entries as one batch;
3. releases the allocator slot;
4. optionally erases the development identity bundle.

A reserved allocation that never reached runtime may also be decommissioned.
Partial or ambiguous registry ownership fails closed.

The result contains only safe allocation identifiers and cleanup state. It does
not contain PEM, OVPN internals, private-key paths, or session material.

If optional identity erasure fails, registry and allocation cleanup remain
completed and the caller receives a safe decommission summary so identity
cleanup can be retried explicitly by allocation ID.

A completed allocator release persists a generation barrier. Stale dynamic
provisioning state for the former client peer cannot recreate the released peer
IDs or attach to a later allocation generation.

## Durable Provisioning Projection and Startup Recovery

VPN stores allocator and provisioning sections in the versioned, checksummed
projection managed behind `vpn_projection_store`.

The provisioning section stores only safe durable metadata:

- accepted peer revisions;
- deterministic command digests;
- approved desired-state fields;
- revoked lifecycle state;
- remove tombstones;
- `pending` and `applied` operation barriers.

Matching retry can finish an interrupted idempotent operation while newer
revisions remain blocked by the durable pending head.

Durable projection state never contains private-key bodies or paths, PSKs,
session keys, replay windows, ECDH material, raw runtime configuration, or packet
state.

`vpn_runtime_recovery` reconstructs registry state after the projection and
allocator have passed validation and before `vpn_peer_sup` starts.

For active allocations, recovery combines:

- the durable allocation;
- the durable provisioning head;
- the validated local identity bundle;
- trusted runtime configuration defaults.

Disabled and revoked dynamic pairs are restored with both runtime peers stopped.
Remove tombstones and incomplete active/enable pending heads suppress peer IDs.
A persisted allocator release barrier also suppresses stale provisioning state
left by completed decommission.

Missing identity material, allocation mismatch, or peer ownership collision
fails startup closed.

The top-level supervisor uses `rest_for_one`, so projection, allocator, or
registry restart also restarts dependent runtime children after durable recovery.

## IAS/VPN Integration Boundary

The dynamic IAS/VPN contract is deliberately split:

```text
IAS
  owns Device identity, authorization, certificate policy, desired revision
  reserves a VPN allocation before Device CSR preparation
  stores only safe allocation identifiers in IAS durable state
  delivers revisioned desired state to the allocated client peer

VPN
  owns transport allocation and generation
  validates Device-to-client allocation binding
  owns runtime pair topology
  materializes configured local identity references
  applies and persists dynamic provisioning state
  reconciles both runtime peers
  owns release and runtime decommission mechanics
```

The original `client_a` / `client_b` topology remains only as a bounded low-level
debug fixture and compatibility fallback. It is not the dynamic allocation
model.

## Current Remaining Gap

The allocator release and provisioning tombstone are durable, and startup
recovery suppresses stale released generations. They are not yet committed as
one atomic cross-section decommission transaction.

A crash between the allocator and provisioning projection commits is therefore
handled by recovery barriers rather than by one atomic decommission record.
Closing this gap requires an explicit atomic allocator-plus-provisioning
decommission barrier. The active backlog is tracked in `TECHNICAL-DEBT.md`.

## Non-Goals

Dynamic peer allocation does not:

- accept transport resource choices from IAS, trusted defaults, or OVPN input;
- persist private-key bodies, session secrets, replay state, or raw runtime
  configuration;
- make the development identity factory a production issuance mechanism;
- automatically erase retained development identities unless decommission is
  explicitly requested with identity removal;
- remove the requirement for IAS authorization and certificate policy.
