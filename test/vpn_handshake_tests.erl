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

mutual_certificate_proof_establishes_both_sides_test() ->
    A0 = vpn_handshake:new(peer_a, peer_b, certificate_options("peer_a")),
    B0 = vpn_handshake:new(peer_b, peer_a, certificate_options("peer_b")),
    {send, HelloA, A1} = vpn_handshake:begin_handshake(A0),
    {send, HelloB, B1} = vpn_handshake:begin_handshake(B0),
    {send, ProofB, B2} = vpn_handshake:handle_frame(HelloA, B1),
    {send, ProofA, A2} = vpn_handshake:handle_frame(HelloB, A1),
    {send, AckToB, A3} = vpn_handshake:handle_frame(ProofB, A2),
    {send, AckToA, B3} = vpn_handshake:handle_frame(ProofA, B2),
    {established, A4} = vpn_handshake:handle_frame(AckToA, A3),
    {established, B4} = vpn_handshake:handle_frame(AckToB, B3),
    ?assert(vpn_handshake:established(A4)),
    ?assert(vpn_handshake:established(B4)),
    InfoA = vpn_handshake:info(A4),
    InfoB = vpn_handshake:info(B4),
    ?assertEqual(true, maps:get(remote_authenticated, InfoA)),
    ?assertEqual(true, maps:get(remote_authenticated, InfoB)),
    ?assertEqual(true, maps:get(session_keys_ready, InfoA)),
    ?assertEqual(true, maps:get(session_keys_ready, InfoB)),
    ?assertEqual(ephemeral_ecdh_hkdf_sha256, maps:get(key_source, InfoA)),
    {ok, KeysA} = vpn_handshake:session_keys(A4),
    {ok, KeysB} = vpn_handshake:session_keys(B4),
    ?assertEqual(maps:get(tx_key, KeysA), maps:get(rx_key, KeysB)),
    ?assertEqual(maps:get(rx_key, KeysA), maps:get(tx_key, KeysB)).

certificate_ack_before_proof_is_deferred_test() ->
    A0 = vpn_handshake:new(peer_a, peer_b, certificate_options("peer_a")),
    B0 = vpn_handshake:new(peer_b, peer_a, certificate_options("peer_b")),
    {send, HelloA, A1} = vpn_handshake:begin_handshake(A0),
    {send, HelloB, B1} = vpn_handshake:begin_handshake(B0),
    {send, ProofB, B2} = vpn_handshake:handle_frame(HelloA, B1),
    {send, ProofA, A2} = vpn_handshake:handle_frame(HelloB, A1),
    {send, AckToB, A3} = vpn_handshake:handle_frame(ProofB, A2),
    {defer, B3} = vpn_handshake:handle_frame(AckToB, B2),
    ?assertEqual(false, vpn_handshake:established(B3)),
    {send_established, _AckToA, B4} = vpn_handshake:handle_frame(ProofA, B3),
    ?assert(vpn_handshake:established(B4)),
    ?assertEqual(true, maps:get(remote_authenticated, vpn_handshake:info(B4))).

unexpected_peer_is_rejected_test() ->
    A0 = vpn_handshake:new(peer_a, peer_b, #{mode => development_control}),
    X0 = vpn_handshake:new(peer_x, peer_a, #{mode => development_control}),
    {send, HelloX, _X1} = vpn_handshake:begin_handshake(X0),
    ?assertMatch({reject, {error, handshake_peer_id_mismatch}, _},
                 vpn_handshake:handle_frame(HelloX, A0)).

certificate_common_name_mismatch_is_rejected_test() ->
    A0 = vpn_handshake:new(peer_a, peer_x, certificate_options("peer_a")),
    %% Use the expected control-plane peer id so the frame passes the early
    %% peer-id check, while deliberately presenting peer_b's certificate.
    %% The rejection must therefore come from certificate CN validation.
    B0 = vpn_handshake:new(peer_x, peer_a, certificate_options("peer_b")),
    {send, HelloA, A1} = vpn_handshake:begin_handshake(A0),
    {send, HelloB, B1} = vpn_handshake:begin_handshake(B0),
    {send, ProofB, _B2} = vpn_handshake:handle_frame(HelloA, B1),
    {send, _ProofA, A2} = vpn_handshake:handle_frame(HelloB, A1),
    ?assertMatch({reject,
                  {error, {certificate_proof_verification_failed,
                           {certificate_peer_id_mismatch, <<"peer_x">>, <<"peer_b">>}}},
                  _},
                 vpn_handshake:handle_frame(ProofB, A2)).

retry_limit_fails_test() ->
    S0 = vpn_handshake:new(peer_a, peer_b,
                           #{mode => development_control, max_retries => 2}),
    {send, _Hello, S1} = vpn_handshake:begin_handshake(S0),
    {send, _Retry, S2} = vpn_handshake:retry(S1),
    ?assertMatch({failed, timeout, _}, vpn_handshake:retry(S2)).

certificate_options(PeerName) ->
    Priv = code:priv_dir(vpn),
    CertPath = filename:join([Priv, "certs", PeerName ++ ".crt"]),
    KeyPath = filename:join([Priv, "certs", PeerName ++ ".key"]),
    CaPath = filename:join([Priv, "certs", "ca.crt"]),
    {ok, CertPem} = file:read_file(CertPath),
    #{mode => certificate_control,
      local_certificate_pem => CertPem,
      local_private_key_path => KeyPath,
      remote_ca_certificate_path => CaPath}.
