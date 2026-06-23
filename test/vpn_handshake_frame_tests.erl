-module(vpn_handshake_frame_tests).
-include_lib("eunit/include/eunit.hrl").

hello_roundtrip_test() ->
    Session = <<1:128>>, Nonce = <<2:128>>,
    EphemeralPublicKey = <<4,5,6>>,
    Frame = vpn_handshake_frame:encode_hello(peer_a, Session, Nonce,
                                             EphemeralPublicKey),
    ?assert(vpn_handshake_frame:is_control(Frame)),
    ?assertEqual({ok, #{version => 3, type => hello,
                        session_id => Session, peer_id => <<"peer_a">>,
                        nonce => Nonce,
                        ephemeral_public_key => EphemeralPublicKey}},
                 vpn_handshake_frame:decode(Frame)).

ack_roundtrip_test() ->
    Session = <<1:128>>, AckFor = <<3:128>>, Nonce = <<2:128>>,
    Frame = vpn_handshake_frame:encode_ack(peer_b, Session, AckFor, Nonce),
    ?assertMatch({ok, #{type := ack, session_id := Session,
                        ack_for := AckFor, peer_id := <<"peer_b">>, nonce := Nonce}},
                 vpn_handshake_frame:decode(Frame)).

proof_roundtrip_test() ->
    Session = <<1:128>>, AckFor = <<3:128>>, Nonce = <<2:128>>,
    EphemeralPublicKey = <<8,9,10>>,
    Certificate = <<1,2,3,4>>, Signature = <<5,6,7>>,
    Frame = vpn_handshake_frame:encode_proof(peer_b, Session, AckFor, Nonce,
                                             EphemeralPublicKey, Certificate, Signature),
    ?assertMatch({ok, #{type := proof, session_id := Session,
                        ack_for := AckFor, peer_id := <<"peer_b">>, nonce := Nonce,
                        ephemeral_public_key := EphemeralPublicKey,
                        certificate_der := Certificate, signature := Signature}},
                 vpn_handshake_frame:decode(Frame)).

truncated_control_frame_test() ->
    ?assertEqual({error, truncated_control_frame},
                 vpn_handshake_frame:decode(<<"VPNH", 3, 1>>)).
