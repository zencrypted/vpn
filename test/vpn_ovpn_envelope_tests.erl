-module(vpn_ovpn_envelope_tests).

-include_lib("eunit/include/eunit.hrl").

contract_declares_plain_ovpn_subset_test() ->
    Contract = vpn_ovpn_envelope:contract(),
    ?assertEqual(<<"ovpn/v1">>, maps:get(version, Contract)),
    ?assertEqual(false, maps:get(serialized_version, Contract)),
    ?assertEqual(none, maps:get(custom_metadata, Contract)),
    ?assertEqual(external, maps:get(security_policy, Contract)),
    ?assertEqual(false, maps:is_key(runtime, Contract)),
    ?assertEqual(false, maps:is_key(profiles, Contract)),
    ?assertEqual(false, maps:is_key(two_factor_modes, Contract)),
    ?assert(lists:member(<<"<key>">>,
                         maps:get(forbidden_directives, Contract))).

canonical_directive_sets_are_disjoint_test() ->
    Required = vpn_ovpn_envelope:required_directives(),
    Optional = vpn_ovpn_envelope:optional_directives(),
    Forbidden = vpn_ovpn_envelope:forbidden_directives(),
    ?assertEqual([], [D || D <- Required, lists:member(D, Optional)]),
    ?assertEqual([], [D || D <- Required, lists:member(D, Forbidden)]),
    ?assertEqual([], [D || D <- Optional, lists:member(D, Forbidden)]).

safe_relative_key_references_are_accepted_test() ->
    ?assertEqual(ok,
                 vpn_ovpn_envelope:validate_key_reference(<<"client.key">>)),
    ?assertEqual(ok,
                 vpn_ovpn_envelope:validate_key_reference(
                   <<"keys/laptop-20260622-014748-19.key">>)).

unsafe_key_references_are_rejected_test() ->
    ?assertMatch({error, _},
                 vpn_ovpn_envelope:validate_key_reference(<<"/tmp/client.key">>)),
    ?assertMatch({error, _},
                 vpn_ovpn_envelope:validate_key_reference(<<"../client.key">>)),
    ?assertMatch({error, _},
                 vpn_ovpn_envelope:validate_key_reference(<<"keys\\client.key">>)),
    ?assertMatch({error, _},
                 vpn_ovpn_envelope:validate_key_reference(<<"C:client.key">>)),
    ?assertMatch({error, _},
                 vpn_ovpn_envelope:validate_key_reference(<<"keys/client key">>)),
    ?assertMatch({error, _},
                 vpn_ovpn_envelope:validate_key_reference(<<"keys/client$key">>)).

remote_endpoint_validation_test() ->
    ?assertEqual(ok, vpn_ovpn_envelope:validate_remote(<<"vpn.example.net">>, 5555)),
    ?assertEqual(ok, vpn_ovpn_envelope:validate_remote(<<"127.0.0.1">>, 1194)),
    ?assertEqual({error, invalid_remote_host},
                 vpn_ovpn_envelope:validate_remote(<<"vpn example.net">>, 5555)),
    ?assertEqual({error, invalid_remote_port},
                 vpn_ovpn_envelope:validate_remote(<<"vpn.example.net">>, 0)).

canonical_example_uses_plain_ovpn_syntax_test() ->
    PrivDir = code:priv_dir(vpn),
    Path = filename:join([PrivDir, "examples", "peer_a.ovpn"]),
    {ok, Envelope} = file:read_file(Path),
    ?assertMatch({_, _}, binary:match(Envelope, <<"client\n">>)),
    ?assertMatch({_, _}, binary:match(Envelope, <<"remote 127.0.0.1 5556">>)),
    ?assertMatch({_, _}, binary:match(Envelope, <<"<ca>">>)),
    ?assertMatch({_, _}, binary:match(Envelope, <<"<cert>">>)),
    ?assertMatch({_, _}, binary:match(Envelope, <<"key keys/peer_a.key">>)),
    ?assertEqual(nomatch, binary:match(Envelope, <<"zencrypted", "-">>)),
    ?assertEqual(nomatch, binary:match(Envelope, <<"<key>">>)),
    ?assertEqual(nomatch, binary:match(Envelope, <<"PRIVATE KEY">>)).
