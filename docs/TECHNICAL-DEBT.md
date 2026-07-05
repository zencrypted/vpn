# VPN Technical Debt

This document contains only active or partially addressed architectural debt in
the VPN repository. Completed design history belongs in git history and in the
current implementation contracts under `docs/`.

## Active debt summary

| ID | Item | Status | Severity |
|---|---|---|---|
| TD-005 | Device-lock authorization | Open | High |
| TD-006 | Two-factor provider hook | Open | High |
| TD-007 | Production authentication for IAS delivery | Open | High |
| TD-008 | Safe import-root resolution | Partially addressed | High |
| TD-010 | Production removal of debug controls | Open | Medium |
| TD-011 | Session-key erasure hardening | Open | Medium |
| TD-012 | Replay and lifecycle policy controls | Open | Medium |
| TD-013 | Atomic dynamic decommission barrier | Open | High |

## TD-005 — Device-lock authorization

**Status:** Open

**Severity:** High

Bind each authenticated certificate/session to the IAS Device identifier from
trusted provisioning state and fail closed when the authorization decision does
not match. The Device identifier must never be trusted from the OVPN envelope.

The current runtime has no `device_lock` authorization enforcement path. This
control must consume trusted IAS provisioning or policy state rather than add a
vendor directive to the OVPN envelope.

### Acceptance boundary

- session activation is associated with the trusted IAS Device identifier;
- a required Device-lock decision is checked before activation succeeds;
- mismatch or unavailable required authorization fails closed;
- the decision and reason are visible in bounded operational/audit metadata;
- no Device identity is accepted from untrusted OVPN text.

## TD-006 — Two-factor provider hook

**Status:** Open

**Severity:** High

Add policy states `disabled`, `optional`, and `required`. A required second factor
must block session activation until an explicit provider succeeds. Provider
identity, challenge state, result, and expiry must be auditable.

The current OVPN contract intentionally has no `two_factor_modes` field and the
runtime has no two-factor provider integration. This remains a policy/runtime
control, not OVPN envelope metadata.

### Acceptance boundary

- a provider interface is explicit and replaceable;
- `required` blocks activation until a successful, unexpired provider result;
- provider failure and timeout fail closed for required policy;
- challenge/result metadata is bounded and auditable;
- secret challenge material is not written to durable VPN projection state.

## TD-007 — Production authentication for IAS delivery

**Status:** Open

**Severity:** High

IAS lifecycle synchronization, revision ordering, idempotency, dynamic
provisioning, disable/enable, revoke, decommission, and durable replay/recovery
are implemented. The remaining item is production authentication and hardening
of the IAS-to-VPN delivery transport.

The boundary must cover node identity, authorization of provisioning callers,
and operational key/cookie rotation. A successful Erlang distribution or RPC
connection is not by itself a sufficient production authorization decision.

### Acceptance boundary

- VPN authenticates the delivery peer using configured production identity;
- provisioning callers are authorized independently of command validity;
- unauthorized delivery attempts fail before provisioning mutation;
- credential/cookie rotation has an operational procedure;
- authentication failures are observable without logging secrets.

## TD-008 — Safe import-root resolution

**Status:** Partially addressed

**Severity:** High

Private-key references are resolved relative to the OVPN file directory. The
current implementation already:

- converts the candidate to an absolute path;
- applies lexical containment below the OVPN directory;
- rejects path escape;
- requires the final private-key object to be a regular file;
- rejects a final private-key symlink;
- rejects group/other permissions on the private-key file.

The remaining gap is filesystem-aware containment. A parent directory inside the
lexically accepted path may itself be a symlink, and resolution is not protected
against time-of-check/time-of-use substitution between validation and key use.

### Acceptance boundary

- the configured/import root and every traversed parent component are resolved
  without permitting symlink escape;
- the final key object remains a regular non-symlink file with private
  permissions;
- validation and subsequent key use have a documented TOCTOU-resistant boundary;
- absolute paths and traversal outside the approved root remain rejected;
- tests cover parent-directory symlink escape as well as final-file symlinks.

## TD-010 — Production removal of debug controls

**Status:** Open

**Severity:** Medium

The encrypted-frame history, replay API, frame-burst generator, local CA helpers,
and development authorization bypass are intentionally debug/development-only.
Production configurations currently rely on explicit runtime controls such as
`debug_replay_controls => false`, while development paths still include
`development_bypass`.

A release-hardening pass should compile, package, or otherwise exclude these
controls from production artifacts rather than relying only on runtime
configuration.

### Acceptance boundary

- production builds cannot enable replay/frame-burst debug APIs accidentally;
- development authorization bypass is unavailable in production packaging;
- local CA/identity helpers are separated from production runtime artifacts;
- release tests prove the debug controls are absent or unreachable.

## TD-011 — Session-key erasure hardening

**Status:** Open

**Severity:** Medium

Fresh handshakes, rekey, previous-epoch retirement, and peer restart recovery
replace obsolete session material logically. Add explicit best-effort key erasure
and document the limits imposed by BEAM binary lifetime, process heaps, crash
dumps, tracing, and allocator behavior.

### Acceptance boundary

- explicit retirement paths overwrite or discard owned key containers on a
  best-effort basis before state replacement;
- crash-dump and tracing guidance documents the residual exposure boundary;
- no claim of guaranteed physical memory erasure is made for BEAM binaries;
- tests verify logical retirement and the absence of obsolete keys from public
  runtime status.

## TD-012 — Replay and lifecycle policy controls

**Status:** Open

**Severity:** Medium

Replay windows, previous-epoch grace, automatic rekey age/packet thresholds, and
related lifecycle timers exist in the runtime. They are still runtime
configuration rather than controls derived from an explicit security policy
contract.

Make replay-window size, previous-epoch grace, maximum key age, and packet limits
policy-controlled. Consider a bounded packet-count condition in addition to the
grace timer when retiring the previous epoch.

Replay state must never survive a process restart; recovery requires a fresh
authenticated handshake.

### Acceptance boundary

- policy state can constrain replay-window and key-lifecycle parameters;
- invalid or unsupported policy values fail closed;
- previous-epoch retirement has bounded time and packet semantics;
- runtime status exposes the effective policy without session secrets;
- restart recovery does not restore replay-window state.

## TD-013 — Atomic dynamic decommission barrier

**Status:** Open

**Severity:** High

Dynamic decommission already validates pair ownership and quiescence, removes the
client/gateway registry entries together, releases the allocator slot, and can
remove development identity material. Allocator release barriers and provisioning
remove/tombstone state are durable, and startup recovery suppresses stale dynamic
heads across allocation generations.

The remaining durability gap is that allocator release and the corresponding
provisioning tombstone are not committed as one atomic cross-section transaction.
A crash between those projection commits is repaired or suppressed by recovery
barriers rather than represented by one durable decommission record.

See [`DYNAMIC-PEER-ALLOCATION.md`](DYNAMIC-PEER-ALLOCATION.md) for the current
allocation and decommission contract.

### Acceptance boundary

- decommission writes one durable operation/barrier that binds Device,
  allocation identity/generation, and affected provisioning heads;
- allocator release and provisioning tombstone become atomically visible, or a
  persisted resumable phase makes incomplete work explicit;
- retry of the same decommission operation is idempotent;
- stale allocation generations cannot complete or overwrite a newer lifecycle;
- startup recovery resumes or safely resolves an incomplete decommission;
- private keys, PSKs, session keys, replay windows, ECDH material, and raw runtime
  configuration are never persisted in the decommission barrier.
