-module(vpn_identity_tests).

-include_lib("eunit/include/eunit.hrl").

valid_config_loads_identity_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               private_key_path => "priv/certs/peer_a.key",
               ca_certificate_path => "priv/certs/ca.crt"},
    {ok, Identity} = vpn_identity:load(Config),
    ?assertMatch(#{peer_id := peer_a,
                   certificate_path := "priv/certs/peer_a.crt",
                   private_key_path := "priv/certs/peer_a.key",
                   certificate_pem := <<"-----BEGIN CERTIFICATE-----", _/binary>>,
                   private_key_pem := <<"-----BEGIN PRIVATE KEY-----", _/binary>>,
                   certificate := #{subject := _Subject,
                                    issuer := _Issuer,
                                    serial_number := _SerialNumber,
                                    not_before := _NotBefore,
                                    not_after := _NotAfter}},
                 Identity).

valid_fixture_certificate_parses_successfully_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               private_key_path => "priv/certs/peer_a.key",
               ca_certificate_path => "priv/certs/ca.crt"},
    {ok, Identity} = vpn_identity:load(Config),
    ?assertMatch(#{certificate := #{subject := _Subject,
                                    issuer := _Issuer,
                                    serial_number := _SerialNumber}},
                 Identity).

valid_certificate_key_pair_passes_test() ->
    {ok, Identity} = vpn_identity:load(peer_a_config()),
    ?assertMatch(#{private_key_public_part := _PublicPart}, Identity),
    ?assertEqual(ok, vpn_identity:verify_key_match(Identity)).

peer_a_certificate_with_peer_b_key_fails_test() ->
    Config = peer_a_config(#{private_key_path => "priv/certs/peer_b.key"}),
    ?assertEqual({error, key_mismatch}, vpn_identity:load(Config)).

peer_b_certificate_with_peer_a_key_fails_test() ->
    Config = peer_b_config(#{private_key_path => "priv/certs/peer_a.key"}),
    ?assertEqual({error, key_mismatch}, vpn_identity:load(Config)).

missing_certificate_path_fails_test() ->
    Config = #{id => peer_a,
               private_key_path => "priv/certs/peer_a.key",
               ca_certificate_path => "priv/certs/ca.crt"},
    ?assertEqual({error, {missing_identity_key, certificate_path}},
                 vpn_identity:load(Config)).

missing_private_key_path_fails_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               ca_certificate_path => "priv/certs/ca.crt"},
    ?assertEqual({error, {missing_identity_key, private_key_path}},
                 vpn_identity:load(Config)).

missing_ca_certificate_path_fails_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               private_key_path => "priv/certs/peer_a.key"},
    ?assertEqual({error, {missing_identity_key, ca_certificate_path}},
                 vpn_identity:load(Config)).

missing_certificate_file_returns_error_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/missing.crt",
               private_key_path => "priv/certs/peer_a.key",
               ca_certificate_path => "priv/certs/ca.crt"},
    ?assertEqual({error, {certificate_read_failed, "priv/certs/missing.crt", enoent}},
                 vpn_identity:load(Config)).

missing_private_key_file_returns_error_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               private_key_path => "priv/certs/missing.key",
               ca_certificate_path => "priv/certs/ca.crt"},
    ?assertEqual({error, {private_key_read_failed, "priv/certs/missing.key", enoent}},
                 vpn_identity:load(Config)).

invalid_certificate_file_returns_error_test() ->
    CertPath = filename:join([os:getenv("TMPDIR", "/tmp"), "vpn-invalid-cert.pem"]),
    ok = file:write_file(CertPath, <<"not a certificate">>),
    Config = #{id => peer_a,
               certificate_path => CertPath,
               private_key_path => "priv/certs/peer_a.key",
               ca_certificate_path => "priv/certs/ca.crt"},
    ?assertMatch({error, {certificate_parse_failed, CertPath, _Reason}},
                 vpn_identity:load(Config)),
    ok = file:delete(CertPath).

malformed_key_file_returns_error_test() ->
    KeyPath = filename:join([os:getenv("TMPDIR", "/tmp"), "vpn-invalid-key.pem"]),
    ok = file:write_file(KeyPath, <<"not a private key">>),
    Config = peer_a_config(#{private_key_path => KeyPath}),
    ?assertMatch({error, {private_key_parse_failed, KeyPath, _Reason}},
                 vpn_identity:load(Config)),
    ok = file:delete(KeyPath).

safe_info_contains_certificate_metadata_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               private_key_path => "priv/certs/peer_a.key",
               ca_certificate_path => "priv/certs/ca.crt"},
    {ok, Identity} = vpn_identity:load(Config),
    ?assertMatch(#{peer_id := peer_a,
                   certificate_path := "priv/certs/peer_a.crt",
                   private_key_path := "priv/certs/peer_a.key",
                   certificate := #{subject := _Subject,
                                    issuer := _Issuer,
                                    serial_number := _SerialNumber,
                                    not_before := _NotBefore,
                                    not_after := _NotAfter}},
                 vpn_identity:safe_info(Identity)).

safe_info_does_not_expose_pem_binaries_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               private_key_path => "priv/certs/peer_a.key",
               ca_certificate_path => "priv/certs/ca.crt"},
    {ok, Identity} = vpn_identity:load(Config),
    SafeInfo = vpn_identity:safe_info(Identity),
    ?assertNot(maps:is_key(certificate_pem, SafeInfo)),
    ?assertNot(maps:is_key(private_key_pem, SafeInfo)),
    ?assertNot(maps:is_key(private_key, SafeInfo)),
    ?assertNot(maps:is_key(private_key_public_part, SafeInfo)).

peer_a_config() ->
    peer_a_config(#{}).

peer_a_config(Overrides) ->
    maps:merge(#{id => peer_a,
                 certificate_path => "priv/certs/peer_a.crt",
                 private_key_path => "priv/certs/peer_a.key",
                 ca_certificate_path => "priv/certs/ca.crt"},
               Overrides).

peer_b_config(Overrides) ->
    maps:merge(#{id => peer_b,
                 certificate_path => "priv/certs/peer_b.crt",
                 private_key_path => "priv/certs/peer_b.key",
                 ca_certificate_path => "priv/certs/ca.crt"},
               Overrides).
