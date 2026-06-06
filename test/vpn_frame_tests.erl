-module(vpn_frame_tests).

-include_lib("eunit/include/eunit.hrl").

binary_peer_id_roundtrip_test() ->
    Payload = <<"payload">>,
    Encoded = vpn_frame:encode(<<"peer_a">>, 42, Payload),
    ?assertEqual({ok, #{version => 1,
                        type => data,
                        seq => 42,
                        peer_id => <<"peer_a">>,
                        payload => Payload}},
                 vpn_frame:decode(Encoded)).

atom_peer_id_roundtrip_test() ->
    Payload = <<"payload">>,
    Encoded = vpn_frame:encode(peer_b, 43, Payload),
    ?assertEqual({ok, #{version => 1,
                        type => data,
                        seq => 43,
                        peer_id => <<"peer_b">>,
                        payload => Payload}},
                 vpn_frame:decode(Encoded)).

invalid_version_test() ->
    Frame = <<2:8, 1:8, 0:64/unsigned, 0:16/unsigned, "payload">>,
    ?assertEqual({error, {unsupported_version, 2}}, vpn_frame:decode(Frame)).

truncated_frame_test() ->
    ?assertEqual({error, truncated_frame}, vpn_frame:decode(<<1, 1, 0>>)).

truncated_peer_id_test() ->
    Frame = <<1:8, 1:8, 0:64/unsigned, 4:16/unsigned, "abc">>,
    ?assertEqual({error, truncated_peer_id}, vpn_frame:decode(Frame)).
