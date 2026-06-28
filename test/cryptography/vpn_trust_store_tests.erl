-module(vpn_trust_store_tests).

-include_lib("eunit/include/eunit.hrl").

ca_loads_successfully_test() ->
    ?assertMatch({ok, #{ca_path := "priv/certs/ca.crt",
                        ca_certificate := _CaCertificate}},
                 vpn_trust_store:load("priv/certs/ca.crt")).

peer_cert_signed_by_ca_is_accepted_test() ->
    {ok, TrustStore} = vpn_trust_store:load("priv/certs/ca.crt"),
    {ok, Identity} = vpn_identity:load(peer_a_config()),
    ?assertEqual(ok, vpn_trust_store:verify(TrustStore,
                                            maps:get(x509_certificate, Identity))).

self_signed_cert_is_rejected_test() ->
    {ok, TrustStore = #{ca_certificate := CaCertificate}} =
        vpn_trust_store:load("priv/certs/ca.crt"),
    ?assertEqual({error, self_signed_certificate},
                 vpn_trust_store:verify(TrustStore, CaCertificate)).

cert_signed_by_another_ca_is_rejected_test() ->
    Dir = make_tmp_dir(),
    try
        OtherPeerCert = generate_other_ca_signed_peer(Dir),
        {ok, TrustStore} = vpn_trust_store:load("priv/certs/ca.crt"),
        {ok, OtherPeer} = load_cert(OtherPeerCert),
        ?assertEqual({error, issuer_mismatch},
                     vpn_trust_store:verify(TrustStore, OtherPeer))
    after
        cleanup_tmp_dir(Dir)
    end.

missing_ca_file_fails_test() ->
    ?assertEqual({error, {ca_certificate_read_failed, "priv/certs/missing-ca.crt", enoent}},
                 vpn_trust_store:load("priv/certs/missing-ca.crt")).

peer_a_config() ->
    #{id => peer_a,
      certificate_path => "priv/certs/peer_a.crt",
      private_key_path => "priv/certs/peer_a.key",
      ca_certificate_path => "priv/certs/ca.crt"}.

make_tmp_dir() ->
    Dir = filename:join([os:getenv("TMPDIR", "/tmp"),
                         "vpn-trust-store-" ++ integer_to_list(erlang:unique_integer([positive]))]),
    ok = file:make_dir(Dir),
    Dir.

generate_other_ca_signed_peer(Dir) ->
    OtherCaKey = filename:join(Dir, "other_ca.key"),
    OtherCaCert = filename:join(Dir, "other_ca.crt"),
    OtherPeerKey = filename:join(Dir, "other_peer.key"),
    OtherPeerCsr = filename:join(Dir, "other_peer.csr"),
    OtherPeerCert = filename:join(Dir, "other_peer.crt"),
    run("openssl req -x509 -newkey rsa:2048 -keyout " ++ OtherCaKey ++
        " -out " ++ OtherCaCert ++
        " -days 365 -nodes -subj /CN=OtherDevCA"),
    run("openssl req -newkey rsa:2048 -keyout " ++ OtherPeerKey ++
        " -out " ++ OtherPeerCsr ++
        " -nodes -subj /CN=other_peer"),
    run("openssl x509 -req -in " ++ OtherPeerCsr ++
        " -CA " ++ OtherCaCert ++
        " -CAkey " ++ OtherCaKey ++
        " -CAcreateserial -out " ++ OtherPeerCert ++
        " -days 365"),
    OtherPeerCert.

load_cert(CertPath) ->
    {ok, Pem} = file:read_file(CertPath),
    [{_, Der, _} | _] = public_key:pem_decode(Pem),
    {ok, public_key:pkix_decode_cert(Der, otp)}.

run(Command) ->
    [] = os:cmd(Command ++ " >/dev/null 2>&1"),
    ok.

cleanup_tmp_dir(Dir) ->
    lists:foreach(fun(Path) -> _ = file:delete(Path) end, filelib:wildcard(filename:join(Dir, "*"))),
    _ = file:del_dir(Dir),
    ok.
