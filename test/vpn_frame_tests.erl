-module(vpn_frame_tests).

-include_lib("eunit/include/eunit.hrl").

roundtrip_test() ->
    Payload = <<"payload">>,
    Encoded = vpn_frame:encode(peer_a, 42, Payload),
    ?assertEqual({ok, #{version => 1,
                        type => data,
                        seq => 42,
                        payload => Payload}},
                 vpn_frame:decode(Encoded)).

invalid_version_test() ->
    Frame = <<2:8, 1:8, 0:64/unsigned, "payload">>,
    ?assertEqual({error, {unsupported_version, 2}}, vpn_frame:decode(Frame)).

truncated_frame_test() ->
    ?assertEqual({error, truncated_frame}, vpn_frame:decode(<<1, 1, 0>>)).
