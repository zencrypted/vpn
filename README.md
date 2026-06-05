# vpn

VPN Overlay Network for the Zencrypted ecosystem.

This repository is currently an Erlang/OTP skeleton only. It intentionally does
not implement VPN, TUN/TAP, UDP transport, peer/session, or PKI logic yet.

## Architecture

The future target architecture is:

```text
TUN <-> Erlang <-> UDP <-> Erlang <-> TUN
```

X.509 PKI integration is expected to use `synrc/ca` in a later milestone.

## Modules

- `vpn_app` - OTP application entry point.
- `vpn_sup` - top-level supervisor.
- `vpn` - public API.
- `vpn_tun` - future TUN/TAP integration layer.
- `vpn_udp` - future UDP transport layer.
- `vpn_peer` - future peer/session abstraction.

## Build

```sh
rebar3 compile
```

## Test

```sh
rebar3 eunit
```

## Notes

- No Elixir.
- No umbrella project.
- No external framework dependencies.
- `tunctl` is not included yet. Integration points are left as TODO comments.
