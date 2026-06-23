-module(vpn_session_lifecycle_tests).

-include_lib("eunit/include/eunit.hrl").

new_session_metadata_test() ->
    State = vpn_session_lifecycle:new(1),
    Info = vpn_session_lifecycle:info(State, maps:get(established_at, State) + 7),
    ?assertEqual(1, maps:get(key_epoch, Info)),
    ?assertEqual(7, maps:get(session_age_seconds, Info)),
    ?assertEqual(0, maps:get(packets_since_rekey, Info)),
    ?assertEqual(0, maps:get(bytes_since_rekey, Info)),
    ?assertEqual(maps:get(established_at, Info), maps:get(last_rekey_at, Info)).

traffic_counters_are_scoped_to_epoch_test() ->
    State0 = vpn_session_lifecycle:new(3),
    State1 = vpn_session_lifecycle:record_tx(120, State0),
    State2 = vpn_session_lifecycle:record_rx(80, State1),
    Info = vpn_session_lifecycle:info(State2, maps:get(established_at, State2)),
    ?assertEqual(3, maps:get(key_epoch, Info)),
    ?assertEqual(1, maps:get(tx_packets_since_rekey, Info)),
    ?assertEqual(120, maps:get(tx_bytes_since_rekey, Info)),
    ?assertEqual(1, maps:get(rx_packets_since_rekey, Info)),
    ?assertEqual(80, maps:get(rx_bytes_since_rekey, Info)),
    ?assertEqual(2, maps:get(packets_since_rekey, Info)),
    ?assertEqual(200, maps:get(bytes_since_rekey, Info)).
