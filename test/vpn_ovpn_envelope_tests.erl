-module(vpn_ovpn_envelope_tests).

-include_lib("eunit/include/eunit.hrl").

contract_declares_canonical_version_test() ->
    Contract = vpn_ovpn_envelope:contract(),
    ?assertEqual(<<"ovpn/v1">>, maps:get(version, Contract)),
    ?assertEqual(<<"zencrypted-overlay">>, maps:get(runtime, Contract)),
    ?assertEqual([<<"portable">>, <<"device-bound">>],
                 maps:get(profiles, Contract)),
    ?assert(lists:member(<<"<key>">>,
                         maps:get(forbidden_directives, Contract))).

portable_metadata_is_valid_without_device_binding_test() ->
    Metadata = #{envelope => <<"ovpn/v1">>,
                 runtime => <<"zencrypted-overlay">>,
                 profile => <<"portable">>,
                 two_factor => <<"optional">>},
    ?assertEqual(ok, vpn_ovpn_envelope:validate_metadata(Metadata)).

portable_metadata_rejects_device_binding_test() ->
    Metadata = #{envelope => <<"ovpn/v1">>,
                 runtime => <<"zencrypted-overlay">>,
                 profile => <<"portable">>,
                 device_id => <<"peer_a">>,
                 two_factor => <<"optional">>},
    ?assertEqual({error, {unexpected_metadata, device_id}},
                 vpn_ovpn_envelope:validate_metadata(Metadata)).

device_bound_metadata_requires_device_id_test() ->
    Metadata = #{envelope => <<"ovpn/v1">>,
                 runtime => <<"zencrypted-overlay">>,
                 profile => <<"device-bound">>,
                 two_factor => <<"required">>},
    ?assertEqual({error, {missing_metadata, device_id}},
                 vpn_ovpn_envelope:validate_metadata(Metadata)).

device_bound_metadata_is_valid_test() ->
    Metadata = #{envelope => <<"ovpn/v1">>,
                 runtime => <<"zencrypted-overlay">>,
                 profile => <<"device-bound">>,
                 device_id => <<"manual_device_123">>,
                 two_factor => <<"disabled">>},
    ?assertEqual(ok, vpn_ovpn_envelope:validate_metadata(Metadata)).

unsupported_version_is_rejected_test() ->
    Metadata = #{envelope => <<"ovpn/v2">>,
                 runtime => <<"zencrypted-overlay">>,
                 profile => <<"portable">>,
                 two_factor => <<"disabled">>},
    ?assertEqual({error,
                  {unsupported_metadata_value, envelope, <<"ovpn/v2">>}},
                 vpn_ovpn_envelope:validate_metadata(Metadata)).

unknown_metadata_is_rejected_test() ->
    Metadata = #{envelope => <<"ovpn/v1">>,
                 runtime => <<"zencrypted-overlay">>,
                 profile => <<"portable">>,
                 two_factor => <<"disabled">>,
                 arbitrary_extension => true},
    ?assertEqual({error, {unknown_metadata, arbitrary_extension}},
                 vpn_ovpn_envelope:validate_metadata(Metadata)).

optional_traceability_metadata_is_validated_test() ->
    Metadata = #{envelope => <<"ovpn/v1">>,
                 runtime => <<"zencrypted-overlay">>,
                 profile => <<"device-bound">>,
                 device_id => <<"peer_a">>,
                 two_factor => <<"optional">>,
                 provisioning_id => <<"demo-peer-a">>,
                 certificate_sha256 =>
                   <<"5CEB02C7849E1CD9C12E124DFBFAD66366F4B2E9ED860C9A71B99A7412979CB9">>},
    ?assertEqual(ok, vpn_ovpn_envelope:validate_metadata(Metadata)),
    ?assertEqual({error, {invalid_metadata_value, certificate_sha256}},
                 vpn_ovpn_envelope:validate_metadata(
                   Metadata#{certificate_sha256 => <<"not-a-fingerprint">>})).

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

canonical_example_contains_public_material_only_test() ->
    PrivDir = code:priv_dir(vpn),
    Path = filename:join([PrivDir, "examples", "peer_a-device-bound.ovpn"]),
    {ok, Envelope} = file:read_file(Path),
    ?assertMatch({_, _},
                 binary:match(Envelope,
                              <<"# zencrypted-envelope: ovpn/v1">>)),
    ?assertMatch({_, _}, binary:match(Envelope, <<"<ca>">>)),
    ?assertMatch({_, _}, binary:match(Envelope, <<"<cert>">>)),
    ?assertMatch({_, _}, binary:match(Envelope, <<"key keys/peer_a.key">>)),
    ?assertEqual(nomatch, binary:match(Envelope, <<"<key>">>)),
    ?assertEqual(nomatch, binary:match(Envelope, <<"PRIVATE KEY">>)).
