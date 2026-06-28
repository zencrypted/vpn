%%%-------------------------------------------------------------------
%% @doc Helpers for automatic rekey scheduling state.
%%%-------------------------------------------------------------------
-module(vpn_auto_rekey).

-export([cooldown_active/2,
         cooldown_remaining_ms/2,
         cooldown_until/2,
         jitter_delay/1]).

cooldown_active(undefined, _NowMs) ->
    false;
cooldown_active(UntilMs, NowMs)
  when is_integer(UntilMs), is_integer(NowMs) ->
    UntilMs > NowMs.

cooldown_remaining_ms(undefined, _NowMs) ->
    0;
cooldown_remaining_ms(UntilMs, NowMs)
  when is_integer(UntilMs), is_integer(NowMs) ->
    max(0, UntilMs - NowMs).

cooldown_until(NowMs, CooldownMs)
  when is_integer(NowMs), is_integer(CooldownMs), CooldownMs > 0 ->
    NowMs + CooldownMs.


jitter_delay(0) ->
    0;
jitter_delay(MaxMs) when is_integer(MaxMs), MaxMs > 0 ->
    rand:uniform(MaxMs + 1) - 1.
