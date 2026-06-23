-module(vpn_frame_tests).

-include_lib("eunit/include/eunit.hrl").

binary_peer_id_roundtrip_test() ->
    Payload = <<"payload">>,
    Encoded = vpn_frame:encode(<<"peer_a">>, 7, 42, Payload),
    ?assertEqual({ok, #{version => 2,
                        type => data,
                        key_epoch => 7,
                        seq => 42,
                        peer_id => <<"peer_a">>,
                        payload => Payload}},
                 vpn_frame:decode(Encoded)).

atom_peer_id_roundtrip_test() ->
    Payload = <<"payload">>,
    Encoded = vpn_frame:encode(peer_b, 9, 43, Payload),
    ?assertEqual({ok, #{version => 2,
                        type => data,
                        key_epoch => 9,
                        seq => 43,
                        peer_id => <<"peer_b">>,
                        payload => Payload}},
                 vpn_frame:decode(Encoded)).

legacy_frame_is_still_decoded_test() ->
    Frame = <<1:8, 1:8, 42:64/unsigned, 6:16/unsigned, "peer_a", "payload">>,
    ?assertEqual({ok, #{version => 1, type => data, key_epoch => 0, seq => 42,
                        peer_id => <<"peer_a">>, payload => <<"payload">>}},
                 vpn_frame:decode(Frame)).

invalid_version_test() ->
    Frame = <<3:8, 1:8, 0:64/unsigned, 0:16/unsigned, "payload">>,
    ?assertEqual({error, {unsupported_version, 3}}, vpn_frame:decode(Frame)).

truncated_frame_test() ->
    ?assertEqual({error, truncated_frame}, vpn_frame:decode(<<1, 1, 0>>)).

truncated_peer_id_test() ->
    Frame = <<1:8, 1:8, 0:64/unsigned, 4:16/unsigned, "abc">>,
    ?assertEqual({error, truncated_peer_id}, vpn_frame:decode(Frame)).

matching_peer_id_is_accepted_test() ->
    ?assertEqual(ok, vpn_link:validate_frame_peer_id(<<"peer_a">>, <<"peer_a">>)).

mismatched_peer_id_is_rejected_test() ->
    ?assertEqual({error, {peer_id_mismatch, <<"peer_a">>, <<"peer_x">>}},
                 vpn_link:validate_frame_peer_id(<<"peer_x">>, <<"peer_a">>)).

atom_binary_peer_id_normalization_test() ->
    ?assertEqual(ok, vpn_link:validate_frame_peer_id(peer_a, <<"peer_a">>)),
    ?assertEqual(ok, vpn_link:validate_frame_peer_id(<<"peer_b">>, peer_b)).
