-module(vpn_ovpn_parser_tests).

-include_lib("eunit/include/eunit.hrl").

canonical_example_is_parsed_test() ->
    Path = filename:join([code:priv_dir(vpn), "examples", "peer_a.ovpn"]),
    {ok, Config} = vpn_ovpn_parser:parse_file(Path),
    ?assertEqual(<<"ovpn/v1">>, maps:get(contract, Config)),
    ?assertEqual(client, maps:get(mode, Config)),
    ?assertEqual(tun, maps:get(tunnel_device, Config)),
    ?assertEqual(udp, maps:get(transport, Config)),
    ?assertEqual(<<"127.0.0.1">>, maps:get(remote_host, Config)),
    ?assertEqual(5556, maps:get(remote_port, Config)),
    ?assertEqual(<<"keys/peer_a.key">>, maps:get(private_key_ref, Config)),
    ?assertMatch({_, _}, binary:match(maps:get(ca_pem, Config),
                                     <<"BEGIN CERTIFICATE">>)),
    ?assertMatch({_, _}, binary:match(maps:get(certificate_pem, Config),
                                     <<"BEGIN CERTIFICATE">>)),
    ?assertEqual(nomatch, binary:match(maps:get(certificate_pem, Config),
                                      <<"PRIVATE KEY">>)).

required_entries_may_be_reordered_test() ->
    {ok, Config} = vpn_ovpn_parser:parse(envelope([
        <<"key keys/client.key">>,
        cert_block(),
        <<"remote vpn.example.net 5555">>,
        <<"proto udp">>,
        ca_block(),
        <<"dev tun">>,
        <<"client">>
    ])),
    ?assertEqual(<<"vpn.example.net">>, maps:get(remote_host, Config)).

optional_directives_are_normalized_test() ->
    {ok, Config} = vpn_ovpn_parser:parse(envelope([
        required_prefix(),
        <<"nobind">>,
        <<"persist-key">>,
        <<"persist-tun">>,
        <<"remote-cert-tls server">>,
        <<"verb 4">>,
        ca_block(), cert_block(), <<"key keys/client.key">>
    ])),
    Options = maps:get(options, Config),
    ?assertEqual(true, maps:get(nobind, Options)),
    ?assertEqual(true, maps:get(persist_key, Options)),
    ?assertEqual(true, maps:get(persist_tun, Options)),
    ?assertEqual(server, maps:get(remote_cert_tls, Options)),
    ?assertEqual(4, maps:get(verb, Options)).

comments_are_ignored_but_not_interpreted_test() ->
    {ok, _} = vpn_ovpn_parser:parse(envelope([
        <<"# device-bound=false">>,
        <<"; 2fa=disabled">>,
        required_prefix(), ca_block(), cert_block(), <<"key keys/client.key">>
    ])).

unknown_and_forbidden_directives_are_rejected_test() ->
    ?assertEqual({error, {line, 5, {unknown_directive, <<"compress">>}}},
                 vpn_ovpn_parser:parse(envelope([
                     required_prefix(), <<"compress lz4">>,
                     ca_block(), cert_block(), <<"key keys/client.key">>
                 ]))),
    ?assertEqual({error, {line, 5, {forbidden_directive, <<"auth-user-pass">>}}},
                 vpn_ovpn_parser:parse(envelope([
                     required_prefix(), <<"auth-user-pass secrets.txt">>,
                     ca_block(), cert_block(), <<"key keys/client.key">>
                 ]))).

duplicate_singletons_and_blocks_are_rejected_test() ->
    ?assertEqual({error, {line, 5, {duplicate_directive, remote}}},
                 vpn_ovpn_parser:parse(envelope([
                     required_prefix(), <<"remote other.example 5556">>,
                     ca_block(), cert_block(), <<"key keys/client.key">>
                 ]))),
    ?assertMatch({error, {line, _, {duplicate_directive, ca}}},
                 vpn_ovpn_parser:parse(envelope([
                     required_prefix(), ca_block(), ca_block(),
                     cert_block(), <<"key keys/client.key">>
                 ]))).

missing_and_unterminated_entries_are_reported_test() ->
    ?assertEqual({error, {missing_required_entries, [cert]}},
                 vpn_ovpn_parser:parse(envelope([
                     required_prefix(), ca_block(), <<"key keys/client.key">>
                 ]))),
    ?assertMatch({error, {line, _, {unterminated_block, ca}}},
                 vpn_ovpn_parser:parse(envelope([
                     required_prefix(), <<"<ca>">>, certificate_pem()
                 ]))).

invalid_values_are_rejected_test() ->
    ?assertMatch({error, {line, 4, invalid_remote_port}},
                 vpn_ovpn_parser:parse(envelope([
                     <<"client">>, <<"dev tun">>, <<"proto udp">>,
                     <<"remote vpn.example.net nope">>,
                     ca_block(), cert_block(), <<"key keys/client.key">>
                 ]))),
    ?assertMatch({error, {line, _, unsafe_key_reference_segment}},
                 vpn_ovpn_parser:parse(envelope([
                     required_prefix(), ca_block(), cert_block(),
                     <<"key ../client.key">>
                 ]))),
    ?assertMatch({error, {line, 2, unsupported_tunnel_device}},
                 vpn_ovpn_parser:parse(envelope([
                     <<"client">>, <<"dev tap">>, <<"proto udp">>,
                     <<"remote vpn.example.net 5555">>,
                     ca_block(), cert_block(), <<"key keys/client.key">>
                 ]))).

private_key_material_is_rejected_from_public_blocks_test() ->
    BadCa = [<<"<ca>">>,
             <<"-----BEGIN PRIVATE KEY-----">>,
             <<"AA==">>,
             <<"-----END PRIVATE KEY-----">>,
             <<"</ca>">>],
    ?assertMatch({error, {line, _, private_key_material_forbidden}},
                 vpn_ovpn_parser:parse(envelope([
                     required_prefix(), BadCa, cert_block(),
                     <<"key keys/client.key">>
                 ]))).

bom_and_oversized_input_are_rejected_test() ->
    ?assertEqual({error, byte_order_mark_forbidden},
                 vpn_ovpn_parser:parse(<<16#EF, 16#BB, 16#BF, "client\n">>)),
    ?assertEqual({error, envelope_too_large},
                 vpn_ovpn_parser:parse(binary:copy(<<"x">>, 1048577))).

required_prefix() ->
    [<<"client">>,
     <<"dev tun">>,
     <<"proto udp">>,
     <<"remote vpn.example.net 5555">>].

ca_block() ->
    [<<"<ca>">>, certificate_pem(), <<"</ca>">>].

cert_block() ->
    [<<"<cert>">>, certificate_pem(), <<"</cert>">>].

certificate_pem() ->
    [<<"-----BEGIN CERTIFICATE-----">>,
     <<"AQIDBA==">>,
     <<"-----END CERTIFICATE-----">>].

envelope(Parts) ->
    Lines = flatten(Parts),
    iolist_to_binary([lists:join(<<"\n">>, Lines), <<"\n">>]).

flatten([]) -> [];
flatten([Head | Tail]) when is_list(Head) -> flatten(Head) ++ flatten(Tail);
flatten([Head | Tail]) -> [Head | flatten(Tail)].
