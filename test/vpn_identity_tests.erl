-module(vpn_identity_tests).

-include_lib("eunit/include/eunit.hrl").

valid_config_loads_identity_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               private_key_path => "priv/certs/peer_a.key"},
    {ok, Identity} = vpn_identity:load(Config),
    ?assertMatch(#{peer_id := peer_a,
                   certificate_path := "priv/certs/peer_a.crt",
                   private_key_path := "priv/certs/peer_a.key",
                   certificate_pem := <<"-----BEGIN CERTIFICATE-----", _/binary>>,
                   private_key_pem := <<"-----BEGIN PRIVATE KEY-----", _/binary>>},
                 Identity).

missing_certificate_path_fails_test() ->
    Config = #{id => peer_a,
               private_key_path => "priv/certs/peer_a.key"},
    ?assertEqual({error, {missing_identity_key, certificate_path}},
                 vpn_identity:load(Config)).

missing_private_key_path_fails_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt"},
    ?assertEqual({error, {missing_identity_key, private_key_path}},
                 vpn_identity:load(Config)).

missing_certificate_file_returns_error_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/missing.crt",
               private_key_path => "priv/certs/peer_a.key"},
    ?assertEqual({error, {certificate_read_failed, "priv/certs/missing.crt", enoent}},
                 vpn_identity:load(Config)).

missing_private_key_file_returns_error_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               private_key_path => "priv/certs/missing.key"},
    ?assertEqual({error, {private_key_read_failed, "priv/certs/missing.key", enoent}},
                 vpn_identity:load(Config)).

safe_info_does_not_expose_pem_binaries_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               private_key_path => "priv/certs/peer_a.key"},
    {ok, Identity} = vpn_identity:load(Config),
    ?assertEqual(#{peer_id => peer_a,
                   certificate_path => "priv/certs/peer_a.crt",
                   private_key_path => "priv/certs/peer_a.key"},
                 vpn_identity:safe_info(Identity)).
