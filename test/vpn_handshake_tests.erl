-module(vpn_handshake_tests).
-include_lib("eunit/include/eunit.hrl").

disabled_mode_is_immediately_established_test() ->
    State = vpn_handshake:new(peer_a, peer_b, #{mode => disabled}),
    {established, State1} = vpn_handshake:begin_handshake(State),
    ?assert(vpn_handshake:established(State1)).

symmetric_hello_ack_establishes_both_sides_test() ->
    A0 = vpn_handshake:new(peer_a, peer_b, #{mode => development_control}),
    B0 = vpn_handshake:new(peer_b, peer_a, #{mode => development_control}),
    {send, HelloA, A1} = vpn_handshake:begin_handshake(A0),
    {send, HelloB, B1} = vpn_handshake:begin_handshake(B0),
    {send, AckToA, B2} = vpn_handshake:handle_frame(HelloA, B1),
    {send, AckToB, A2} = vpn_handshake:handle_frame(HelloB, A1),
    {established, A3} = vpn_handshake:handle_frame(AckToA, A2),
    {established, B3} = vpn_handshake:handle_frame(AckToB, B2),
    ?assert(vpn_handshake:established(A3)),
    ?assert(vpn_handshake:established(B3)).

unexpected_peer_is_rejected_test() ->
    A0 = vpn_handshake:new(peer_a, peer_b, #{mode => development_control}),
    X0 = vpn_handshake:new(peer_x, peer_a, #{mode => development_control}),
    {send, HelloX, _X1} = vpn_handshake:begin_handshake(X0),
    ?assertMatch({reject, {error, handshake_peer_id_mismatch}, _},
                 vpn_handshake:handle_frame(HelloX, A0)).

retry_limit_fails_test() ->
    S0 = vpn_handshake:new(peer_a, peer_b,
                           #{mode => development_control, max_retries => 2}),
    {send, _Hello, S1} = vpn_handshake:begin_handshake(S0),
    {send, _Retry, S2} = vpn_handshake:retry(S1),
    ?assertMatch({failed, timeout, _}, vpn_handshake:retry(S2)).
