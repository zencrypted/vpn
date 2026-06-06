-module(vpn_identity_tests).

-include_lib("eunit/include/eunit.hrl").

valid_config_loads_identity_test() ->
    Config = #{id => peer_a,
               certificate_path => "priv/certs/peer_a.crt",
               private_key_path => "priv/certs/peer_a.key"},
    ?assertEqual({ok, #{peer_id => peer_a,
                        certificate_path => "priv/certs/peer_a.crt",
                        private_key_path => "priv/certs/peer_a.key"}},
                 vpn_identity:load(Config)).

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
