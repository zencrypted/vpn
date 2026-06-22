-module(vpn_handshake_frame_tests).
-include_lib("eunit/include/eunit.hrl").

hello_roundtrip_test() ->
    Session = <<1:128>>, Nonce = <<2:128>>,
    Frame = vpn_handshake_frame:encode_hello(peer_a, Session, Nonce),
    ?assert(vpn_handshake_frame:is_control(Frame)),
    ?assertEqual({ok, #{version => 1, type => hello,
                        session_id => Session, peer_id => <<"peer_a">>, nonce => Nonce}},
                 vpn_handshake_frame:decode(Frame)).

ack_roundtrip_test() ->
    Session = <<1:128>>, AckFor = <<3:128>>, Nonce = <<2:128>>,
    Frame = vpn_handshake_frame:encode_ack(peer_b, Session, AckFor, Nonce),
    ?assertMatch({ok, #{type := ack, session_id := Session,
                        ack_for := AckFor, peer_id := <<"peer_b">>, nonce := Nonce}},
                 vpn_handshake_frame:decode(Frame)).

truncated_control_frame_test() ->
    ?assertEqual({error, truncated_control_frame},
                 vpn_handshake_frame:decode(<<"VPNH", 1, 1>>)).
