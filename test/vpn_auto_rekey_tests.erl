-module(vpn_auto_rekey_tests).

-include_lib("eunit/include/eunit.hrl").

missing_cooldown_is_inactive_test() ->
    Now = erlang:monotonic_time(millisecond),
    ?assertNot(vpn_auto_rekey:cooldown_active(undefined, Now)),
    ?assertEqual(0, vpn_auto_rekey:cooldown_remaining_ms(undefined, Now)).

negative_monotonic_origin_does_not_create_cooldown_test() ->
    Now = -576460722053,
    ?assertNot(vpn_auto_rekey:cooldown_active(undefined, Now)),
    ?assertEqual(0, vpn_auto_rekey:cooldown_remaining_ms(undefined, Now)).

active_cooldown_is_reported_test() ->
    Now = -10000,
    Until = vpn_auto_rekey:cooldown_until(Now, 3000),
    ?assert(vpn_auto_rekey:cooldown_active(Until, Now)),
    ?assertEqual(3000, vpn_auto_rekey:cooldown_remaining_ms(Until, Now)),
    ?assertNot(vpn_auto_rekey:cooldown_active(Until, Until)),
    ?assertEqual(0, vpn_auto_rekey:cooldown_remaining_ms(Until, Until + 1)).
