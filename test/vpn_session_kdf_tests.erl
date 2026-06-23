-module(vpn_session_kdf_tests).
-include_lib("eunit/include/eunit.hrl").

directional_keys_match_opposite_side_test() ->
    {PubA, PrivA} = vpn_session_kdf:generate_key_pair(),
    {PubB, PrivB} = vpn_session_kdf:generate_key_pair(),
    SessionA = <<1:128>>, SessionB = <<2:128>>,
    NonceA = <<3:128>>, NonceB = <<4:128>>,
    {ok, KeysA} = vpn_session_kdf:derive(
                    <<"peer_a">>, <<"peer_b">>,
                    SessionA, SessionB, NonceA, NonceB,
                    PrivA, PubA, PubB),
    {ok, KeysB} = vpn_session_kdf:derive(
                    <<"peer_b">>, <<"peer_a">>,
                    SessionB, SessionA, NonceB, NonceA,
                    PrivB, PubB, PubA),
    ?assertEqual(maps:get(tx_key, KeysA), maps:get(rx_key, KeysB)),
    ?assertEqual(maps:get(rx_key, KeysA), maps:get(tx_key, KeysB)),
    ?assertEqual(maps:get(shared_secret_fingerprint, KeysA),
                 maps:get(shared_secret_fingerprint, KeysB)).

different_ephemeral_key_changes_session_keys_test() ->
    {PubA, PrivA} = vpn_session_kdf:generate_key_pair(),
    {PubB, _PrivB} = vpn_session_kdf:generate_key_pair(),
    {PubC, _PrivC} = vpn_session_kdf:generate_key_pair(),
    Args = [<<"peer_a">>, <<"peer_b">>, <<1:128>>, <<2:128>>, <<3:128>>, <<4:128>>],
    {ok, KeysAB} = apply(vpn_session_kdf, derive, Args ++ [PrivA, PubA, PubB]),
    {ok, KeysAC} = apply(vpn_session_kdf, derive, Args ++ [PrivA, PubA, PubC]),
    ?assertNotEqual(maps:get(tx_key, KeysAB), maps:get(tx_key, KeysAC)).
