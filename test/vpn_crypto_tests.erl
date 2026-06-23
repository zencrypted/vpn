-module(vpn_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

-define(KEY_A, <<"0123456789abcdef0123456789abcdef">>).
-define(KEY_B, <<"abcdef0123456789abcdef0123456789">>).
-define(HEADER_SIZE, 17).

roundtrip_test() ->
    Frame = vpn_frame:encode(peer_a, 7, <<"payload">>),
    State = vpn_crypto:new(?KEY_A, peer_a),
    {ok, Encrypted, State1} = vpn_crypto:encode(Frame, State),
    ?assertMatch(<<"VPND", 1, _/binary>>, Encrypted),
    ?assertEqual({ok, Frame, State1}, vpn_crypto:decode(Encrypted, State1)).

packet_context_is_visible_before_decrypt_test() ->
    Frame = vpn_frame:encode(peer_a, 3, 77, <<"payload">>),
    {ok, Encrypted, _} = vpn_crypto:encode(Frame, vpn_crypto:new(?KEY_A, peer_a)),
    ?assertEqual({ok, #{key_epoch => 3, seq => 77}},
                 vpn_crypto:packet_context(Encrypted)).

wrong_key_fails_test() ->
    Frame = vpn_frame:encode(peer_a, 7, <<"payload">>),
    {ok, Encrypted, _StateA} = vpn_crypto:encode(Frame, vpn_crypto:new(?KEY_A, peer_a)),
    StateB = vpn_crypto:new(?KEY_B, peer_a),
    ?assertEqual({error, authentication_failed, StateB},
                 vpn_crypto:decode(Encrypted, StateB)).

modified_authenticated_header_fails_test() ->
    Frame = vpn_frame:encode(peer_a, 3, 7, <<"payload">>),
    State = vpn_crypto:new(?KEY_A, peer_a),
    {ok, <<"VPND", 1, Epoch:32/unsigned, Rest/binary>>, State1} =
        vpn_crypto:encode(Frame, State),
    Modified = <<"VPND", 1, (Epoch + 1):32/unsigned, Rest/binary>>,
    ?assertEqual({error, authentication_failed, State1},
                 vpn_crypto:decode(Modified, State1)).

modified_ciphertext_fails_test() ->
    Frame = vpn_frame:encode(peer_a, 7, <<"payload">>),
    State = vpn_crypto:new(?KEY_A, peer_a),
    {ok, Encrypted, State1} = vpn_crypto:encode(Frame, State),
    <<Header:?HEADER_SIZE/binary, Nonce:12/binary, First:8, Rest/binary>> = Encrypted,
    Modified = <<Header/binary, Nonce/binary, (First bxor 1):8, Rest/binary>>,
    ?assertEqual({error, authentication_failed, State1},
                 vpn_crypto:decode(Modified, State1)).

modified_tag_fails_test() ->
    Frame = vpn_frame:encode(peer_a, 7, <<"payload">>),
    State = vpn_crypto:new(?KEY_A, peer_a),
    {ok, Encrypted, State1} = vpn_crypto:encode(Frame, State),
    Size = byte_size(Encrypted),
    PayloadSize = Size - 1,
    <<Prefix:PayloadSize/binary, Last:8>> = Encrypted,
    Modified = <<Prefix/binary, (Last bxor 1):8>>,
    ?assertEqual({error, authentication_failed, State1},
                 vpn_crypto:decode(Modified, State1)).

different_peer_ids_produce_different_nonces_test() ->
    FrameA = vpn_frame:encode(peer_a, 7, <<"payload-a">>),
    FrameB = vpn_frame:encode(peer_b, 7, <<"payload-b">>),
    {ok, <<_:?HEADER_SIZE/binary, NonceA:12/binary, _/binary>>, _} =
        vpn_crypto:encode(FrameA, vpn_crypto:new(?KEY_A, peer_a)),
    {ok, <<_:?HEADER_SIZE/binary, NonceB:12/binary, _/binary>>, _} =
        vpn_crypto:encode(FrameB, vpn_crypto:new(?KEY_A, peer_b)),
    ?assertNotEqual(NonceA, NonceB).

same_peer_id_and_seq_produce_same_nonce_test() ->
    Frame1 = vpn_frame:encode(peer_a, 7, <<"payload-a">>),
    Frame2 = vpn_frame:encode(peer_a, 7, <<"payload-b">>),
    {ok, <<_:?HEADER_SIZE/binary, Nonce1:12/binary, _/binary>>, _} =
        vpn_crypto:encode(Frame1, vpn_crypto:new(?KEY_A, peer_a)),
    {ok, <<_:?HEADER_SIZE/binary, Nonce2:12/binary, _/binary>>, _} =
        vpn_crypto:encode(Frame2, vpn_crypto:new(?KEY_A, <<"peer_a">>)),
    ?assertEqual(Nonce1, Nonce2).

session_directional_keys_roundtrip_test() ->
    Frame = vpn_frame:encode(peer_a, 9, <<"session-payload">>),
    TxKey = <<16#AA:256>>, RxKey = <<16#BB:256>>,
    Sender = vpn_crypto:new_session(TxKey, RxKey, peer_a),
    Receiver = vpn_crypto:new_session(RxKey, TxKey, peer_b),
    {ok, Encrypted, Sender1} = vpn_crypto:encode(Frame, Sender),
    ?assertEqual({ok, Frame, Receiver}, vpn_crypto:decode(Encrypted, Receiver)),
    ?assertEqual(#{key_source => ephemeral_ecdh_hkdf_sha256, key_epoch => 1},
                 vpn_crypto:info(Sender1)).

different_key_epochs_produce_different_nonces_test() ->
    Frame1 = vpn_frame:encode(peer_a, 1, 7, <<"payload">>),
    Frame2 = vpn_frame:encode(peer_a, 2, 7, <<"payload">>),
    State = vpn_crypto:new_session(?KEY_A, ?KEY_A, peer_a, 1),
    {ok, <<_:?HEADER_SIZE/binary, Nonce1:12/binary, _/binary>>, _} =
        vpn_crypto:encode(Frame1, State),
    {ok, <<_:?HEADER_SIZE/binary, Nonce2:12/binary, _/binary>>, _} =
        vpn_crypto:encode(Frame2, State),
    ?assertNotEqual(Nonce1, Nonce2).
