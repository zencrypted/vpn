# VPN OTP 28 migration runbook

This runbook covers an existing VPN installation whose durable KVS/Mnesia state
was written on an older Erlang/OTP release and is being started on OTP 28.

The VPN contains two independent integrity layers. They must not be confused:

1. the checksum of the complete durable projection record;
2. the digest stored in each IAS provisioning head inside that projection.

Both legacy formats used Erlang External Term Format bytes and could therefore
change across OTP major releases even when the stored state was semantically
unchanged.

## Before upgrading

Stop the VPN node and create a filesystem backup of its Mnesia directory:

```bash
cd ~/vpn
cp -a local/mnesia local/mnesia.before-otp-28
```

Keep the backup until VPN startup and IAS reconciliation have both completed.
Do not delete the projection or use IAS Replay merely to remove a digest
mismatch.

## 1. Migrate the projection checksum

The outer projection checksum is migrated explicitly while `vpn_projection` is
stopped. Start only the storage applications with the same node name and cookie
used by the normal VPN node:

```bash
ERL_FLAGS="-name vpn@127.0.0.1 -setcookie node_runner" \
rebar3 shell --apps mnesia,kvs
```

Inspect the stored record:

```erlang
vpn_projection_migration:inspect().
```

When the legacy checksum is reproducible on the current runtime:

```erlang
vpn_projection_migration:migrate_legacy_checksum().
```

When an independently reviewed cross-OTP record is structurally valid but its
legacy checksum can no longer be reproduced:

```erlang
vpn_projection_migration:migrate_legacy_checksum(
    accept_unverifiable_legacy_checksum).
```

Exit the migration shell after `inspect/0` reports the current projection
schema. Full constraints and failure modes are documented in
`PROJECTION-CHECKSUM-MIGRATION.md`.

## 2. Start VPN and migrate provisioning heads

Start VPN normally on OTP 28:

```bash
ERL_FLAGS="-name vpn@127.0.0.1 -setcookie node_runner" rebar3 shell
```

Legacy IAS provisioning heads are migrated automatically when recovery heads
are loaded. The migration:

- reconstructs the canonical command from the peer ID and safe durable head;
- removes projection-only defaults such as `revoked => false` before hashing;
- replaces the legacy digest with the portable command digest;
- writes `digest_version => 2` and provisioning `schema_version => 2`;
- leaves revisions, registry entries, runtime peers and allocation state
  unchanged;
- does not replay or reprovision the command.

The operation is idempotent. A subsequent startup leaves already migrated heads
unchanged.

Inspect the result from the VPN shell:

```erlang
{ok, Heads} = vpn_provisioning:recovery_heads().
[{PeerId, maps:get(digest_version, Head, undefined)}
 || {PeerId, Head} <- maps:to_list(Heads)].
```

Every migrated IAS head should report digest version `2`.

## 3. Verify IAS reconciliation

After IAS has completed its own authority-digest migration, inspect
reconciliation from the IAS node:

```erlang
{ok, Report} = ias_vpn_reconciliation:report().
maps:get(counts, Report).
```

Existing semantically equal records should be reported as `synchronized`, with
no `command_digest_mismatch` divergence.

If a head is still divergent, compare its revision, peer ID, safe desired state
and digest version before taking any action. Do not use Replay until a real
state difference has been established.

## 4. OTP JSON dependency cleanup

OTP 28 provides the standard `json` module in `stdlib`. VPN therefore no longer
requires the external `jiffy` NIF dependency. After applying the source update,
remove stale build artifacts and rebuild:

```bash
rebar3 unlock jiffy
rm -rf _build
rebar3 eunit
rebar3 ct
```

`vpn_admin:summary_json/0` still returns a binary; the implementation converts
`json:encode/1` iodata with `iolist_to_binary/1`.

## Recommended order for the paired IAS/VPN upgrade

1. Stop both nodes and back up both Mnesia directories.
2. Apply and build the OTP 28-compatible VPN and IAS code.
3. Explicitly migrate the VPN outer projection checksum.
4. Start VPN normally so provisioning heads migrate to digest version 2.
5. Explicitly migrate IAS authority records.
6. Start IAS normally.
7. Verify VPN heads and IAS reconciliation before deleting backups.
