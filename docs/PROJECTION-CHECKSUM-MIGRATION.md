# VPN projection checksum migration

## Why schema version 2 exists

Projection schema version 1 hashed `term_to_binary/1` output. That byte stream is
an Erlang runtime serialization detail and must not be used as a durable format
contract across OTP major releases. A projection created on an older OTP release
can therefore contain a structurally valid payload whose legacy checksum cannot
be reproduced after an upgrade.

Schema version 2 uses `vpn_projection_checksum`, a repository-owned canonical
encoding with explicit type and length boundaries. Map entries are ordered by
their canonical key bytes. Its checksum no longer depends on ETF map encoding or
map traversal order.

## Normal upgrade

A schema-version-1 projection whose checksum still verifies on the current OTP
release is accepted at startup. Migrate it while the `vpn_projection` process is
stopped:

```erlang
vpn_projection_migration:inspect().
vpn_projection_migration:migrate_legacy_checksum().
```

The migration preserves the projection version, payload, and timestamp and only
rewrites the integrity envelope as schema version 2.

## Cross-OTP legacy checksum mismatch

Do not delete or overwrite the original Mnesia directory immediately. First make
a filesystem backup while the Erlang node is stopped.

If `inspect/0` reports a legacy record with
`legacy_checksum_valid => false`, the old checksum cannot be authenticated on
the current OTP release. The safe options are:

1. Start the old OTP release, verify the schema-version-1 projection there, and
   run `migrate_legacy_checksum/0` before upgrading.
2. For a development or otherwise independently verified database, explicitly
   accept structural validation of the payload:

```erlang
vpn_projection_migration:migrate_legacy_checksum(
  accept_unverifiable_legacy_checksum).
```

The confirmation atom is intentionally verbose. This operation validates the
projection shape and secret-material policy but cannot prove the legacy
checksum, so it must never be run as an automatic boot fallback.

## Operational constraints

- Stop the VPN application before migration. The migration returns
  `projection_must_be_stopped` while `vpn_projection` is running.
- Back up the Mnesia directory before accepting an unverifiable legacy checksum.
- Migration is an in-place compare-and-rewrite operation. A concurrent change
  produces `conflict` rather than overwriting newer state.
- Application startup never ignores an invalid checksum and never migrates
  records automatically.
## Separate provisioning-head migration

This document covers only the outer checksum of the complete projection record.
IAS provisioning heads stored inside the projection have their own command
digest and schema version. Legacy provisioning-head digests are migrated
automatically during normal VPN recovery after the outer projection checksum has
been accepted. See `VPN-UPGRADE-MIGRATION.md` for the complete upgrade order and
verification procedure.
