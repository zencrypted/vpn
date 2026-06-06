-module(vpn_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

-define(KEY_A, <<"0123456789abcdef0123456789abcdef">>).
-define(KEY_B, <<"abcdef0123456789abcdef0123456789">>).

roundtrip_test() ->
    Frame = vpn_frame:encode(peer_a, 7, <<"payload">>),
    State = vpn_crypto:new(?KEY_A),
    {ok, Encrypted, State1} = vpn_crypto:encode(Frame, State),
    ?assertMatch(<<_:12/binary, _/binary>>, Encrypted),
    ?assertEqual({ok, Frame, State1}, vpn_crypto:decode(Encrypted, State1)).

wrong_key_fails_test() ->
    Frame = vpn_frame:encode(peer_a, 7, <<"payload">>),
    {ok, Encrypted, _StateA} = vpn_crypto:encode(Frame, vpn_crypto:new(?KEY_A)),
    StateB = vpn_crypto:new(?KEY_B),
    ?assertEqual({error, authentication_failed, StateB},
                 vpn_crypto:decode(Encrypted, StateB)).

modified_ciphertext_fails_test() ->
    Frame = vpn_frame:encode(peer_a, 7, <<"payload">>),
    State = vpn_crypto:new(?KEY_A),
    {ok, Encrypted, State1} = vpn_crypto:encode(Frame, State),
    <<Nonce:12/binary, First:8, Rest/binary>> = Encrypted,
    Modified = <<Nonce/binary, (First bxor 1):8, Rest/binary>>,
    ?assertEqual({error, authentication_failed, State1},
                 vpn_crypto:decode(Modified, State1)).

modified_tag_fails_test() ->
    Frame = vpn_frame:encode(peer_a, 7, <<"payload">>),
    State = vpn_crypto:new(?KEY_A),
    {ok, Encrypted, State1} = vpn_crypto:encode(Frame, State),
    Size = byte_size(Encrypted),
    PayloadSize = Size - 1,
    <<Prefix:PayloadSize/binary, Last:8>> = Encrypted,
    Modified = <<Prefix/binary, (Last bxor 1):8>>,
    ?assertEqual({error, authentication_failed, State1},
                 vpn_crypto:decode(Modified, State1)).
