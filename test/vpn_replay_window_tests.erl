-module(vpn_replay_window_tests).

-include_lib("eunit/include/eunit.hrl").

first_sequence_is_accepted_test() ->
    {ok, State1} = vpn_replay_window:check(0, vpn_replay_window:new()),
    Info = vpn_replay_window:info(State1),
    ?assertEqual(0, maps:get(highest, Info)),
    ?assertEqual(1, maps:get(accepted, Info)).

limited_reordering_is_accepted_test() ->
    {ok, State1} = vpn_replay_window:check(5, vpn_replay_window:new(8)),
    {ok, State2} = vpn_replay_window:check(3, State1),
    {ok, State3} = vpn_replay_window:check(4, State2),
    ?assertEqual(3, maps:get(accepted, vpn_replay_window:info(State3))).

duplicate_is_rejected_test() ->
    {ok, State1} = vpn_replay_window:check(7, vpn_replay_window:new()),
    {error, duplicate, State2} = vpn_replay_window:check(7, State1),
    ?assertEqual(1, maps:get(duplicates, vpn_replay_window:info(State2))).

sequence_outside_window_is_rejected_test() ->
    {ok, State1} = vpn_replay_window:check(20, vpn_replay_window:new(8)),
    {error, too_old, State2} = vpn_replay_window:check(12, State1),
    ?assertEqual(1, maps:get(too_old, vpn_replay_window:info(State2))).

large_jump_resets_window_test() ->
    {ok, State1} = vpn_replay_window:check(1, vpn_replay_window:new(8)),
    {ok, State2} = vpn_replay_window:check(100, State1),
    {error, too_old, _State3} = vpn_replay_window:check(1, State2).
