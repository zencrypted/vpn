-module(vpn_runtime_config_resolver_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

dynamic_allocation_resolver_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Allocator) ->
             [?_test(begin
                          DeviceId = <<"device-runtime-a">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation),
                          ClientPeerId = maps:get(client_peer_id, Allocation),
                          GatewayPeerId = maps:get(gateway_peer_id, Allocation),
                          Desired = #{device_id => DeviceId,
                                      profile_id => default_user,
                                      authorization_mode => policy,
                                      authorized => true,
                                      authorization_reason => profile_allows_vpn,
                                      ifname => <<"ias-must-not-own-this">>,
                                      local_udp_port => 1,
                                      remote_udp_port => 2,
                                      remote_peer_id => <<"also-ignored">>},

                          {ok, Pair} =
                              vpn_runtime_config_resolver:resolve_pair(DeviceId,
                                                                       Desired),
                          Client = maps:get(client, Pair),
                          Gateway = maps:get(gateway, Pair),
                          AllocClient = maps:get(client, Allocation),
                          AllocGateway = maps:get(gateway, Allocation),

                          ?assertEqual(maps:get(allocation_id, Allocation),
                                       maps:get(allocation_id, Pair)),
                          ?assertEqual(ClientPeerId, maps:get(id, Client)),
                          ?assertEqual(GatewayPeerId, maps:get(id, Gateway)),
                          ?assertEqual(client, maps:get(allocation_role, Client)),
                          ?assertEqual(gateway, maps:get(allocation_role, Gateway)),
                          ?assertEqual(maps:get(ifname, AllocClient),
                                       maps:get(ifname, Client)),
                          ?assertEqual(maps:get(local_udp_port, AllocClient),
                                       maps:get(local_udp_port, Client)),
                          ?assertEqual(maps:get(remote_udp_port, AllocClient),
                                       maps:get(remote_udp_port, Client)),
                          ?assertEqual(maps:get(remote_peer_id, AllocClient),
                                       maps:get(remote_peer_id, Client)),
                          ?assertEqual(maps:get(ifname, AllocGateway),
                                       maps:get(ifname, Gateway)),
                          ?assertEqual(maps:get(local_udp_port, AllocGateway),
                                       maps:get(local_udp_port, Gateway)),
                          ?assertEqual(default_user, maps:get(profile_id, Client)),
                          ?assertEqual(policy, maps:get(authorization_mode, Client)),
                          ?assertEqual(true, maps:get(authorized, Client)),
                          ?assertEqual(development_bypass,
                                       maps:get(authorization_mode, Gateway)),
                          ?assertEqual(75,
                                       maps:get(handshake_start_delay_ms,
                                                Client)),
                          ?assertEqual(75,
                                       maps:get(handshake_start_delay_ms,
                                                Gateway)),
                          ?assertEqual(undefined,
                                       maps:get(profile_id, Gateway, undefined)),
                          ?assertMatch(#{ovpn_identity := #{identity_ready := true}},
                                       Client),
                          ?assertEqual(fixture_path("peer_b.crt"),
                                       maps:get(certificate_path, Gateway)),
                          ?assertEqual(ok, vpn_peer:validate_runtime_config(Client)),
                          ?assertEqual(ok, vpn_peer:validate_runtime_config(Gateway)),
                          ?assertEqual({ok, Client},
                                       vpn_runtime_config_resolver:resolve(ClientPeerId,
                                                                           Desired)),
                          ?assertEqual({ok, Gateway},
                                       vpn_runtime_config_resolver:resolve(GatewayPeerId,
                                                                           Desired)),
                          ?assertEqual({error,
                                        {dynamic_peer_not_in_allocation,
                                         <<"client_dyn_unknown">>}},
                                       vpn_runtime_config_resolver:resolve(
                                         <<"client_dyn_unknown">>, Desired))
                      end)]
     end}.

dynamic_allocation_resolver_errors_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Allocator) ->
             MissingIdentityDevice = <<"device-missing-identity">>,
             {ok, MissingIdentityAllocation} =
                 vpn_peer_allocator:ensure(MissingIdentityDevice),
             MissingAllocationId = maps:get(allocation_id,
                                            MissingIdentityAllocation),
             [?_assertEqual({error, dynamic_peer_device_id_required},
                            vpn_runtime_config_resolver:resolve(
                              <<"client_dyn_missing">>, #{})),
              ?_assertEqual({error,
                             {dynamic_identity_required,
                              MissingAllocationId,
                              not_found}},
                            vpn_runtime_config_resolver:resolve_pair(
                              MissingIdentityDevice,
                              #{device_id => MissingIdentityDevice})),
              ?_assertEqual({error,
                             {dynamic_peer_allocation_required,
                              <<"device-not-reserved">>}},
                            vpn_runtime_config_resolver:resolve_pair(
                              <<"device-not-reserved">>,
                              #{device_id => <<"device-not-reserved">>})),
              ?_assertEqual({error, dynamic_peer_device_id_mismatch},
                            vpn_runtime_config_resolver:resolve_pair(
                              <<"device-a">>, #{device_id => <<"device-b">>}))]
     end}.

dynamic_defaults_reject_transport_ownership_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Allocator) ->
             DeviceId = <<"device-invalid-defaults">>,
             {ok, _} = vpn_peer_allocator:ensure(DeviceId),
             application:set_env(vpn,
                                 dynamic_runtime_config_defaults,
                                 #{common => (runtime_common_defaults())#{ifname => <<"bad">>}}),
             [?_assertEqual({error,
                             {dynamic_runtime_transport_or_unknown_key, ifname}},
                            vpn_runtime_config_resolver:resolve_pair(
                              DeviceId, #{device_id => DeviceId}))]
     end}.

dynamic_defaults_reject_identity_ownership_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Allocator) ->
             DeviceId = <<"device-invalid-identity-defaults">>,
             {ok, _} = vpn_peer_allocator:ensure(DeviceId),
             application:set_env(vpn,
                                 dynamic_runtime_config_defaults,
                                 #{common => (runtime_common_defaults())#{certificate_path => "bad.crt"}}),
             [?_assertEqual({error,
                             {dynamic_runtime_transport_or_unknown_key,
                              certificate_path}},
                            vpn_runtime_config_resolver:resolve_pair(
                              DeviceId, #{device_id => DeviceId}))]
     end}.

binary_dynamic_mode_test() ->
    application:set_env(vpn, runtime_config_resolver, <<"dynamic_allocator">>),
    try
        ?assertEqual(dynamic_allocator, vpn_runtime_config_resolver:mode())
    after
        application:unset_env(vpn, runtime_config_resolver)
    end.

setup() ->
    stop_registered(vpn_peer_allocator),
    application:set_env(vpn,
                        dynamic_peer_allocator,
                        #{capacity => 4,
                          first_host => 40,
                          client_network => {10, 60, 0},
                          gateway_network => {10, 61, 0},
                          client_udp_port_base => 24000,
                          gateway_udp_port_base => 25000}),
    application:set_env(vpn, runtime_config_resolver, dynamic_allocator),
    application:set_env(vpn,
                        dynamic_identity_factory_module,
                        vpn_dynamic_identity_factory_test_provider),
    application:set_env(vpn,
                        dynamic_runtime_config_defaults,
                        #{common => runtime_common_defaults(),
                          client => #{name => <<"Dynamic client">>},
                          gateway => #{name => <<"Dynamic gateway">>,
                                       authorization_mode => development_bypass,
                                       authorized => true,
                                       authorization_reason => dynamic_gateway}}),
    {ok, Pid} = vpn_peer_allocator:start_link(),
    Pid.

cleanup(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            exit(Pid, shutdown),
            wait_until_stopped(Pid, 20);
        false ->
            ok
    end,
    application:unset_env(vpn, dynamic_peer_allocator),
    application:unset_env(vpn, runtime_config_resolver),
    application:unset_env(vpn, dynamic_runtime_config_defaults),
    application:unset_env(vpn, dynamic_identity_factory_module),
    case application:get_env(vpn, dynamic_identity_test_root) of
        {ok, Root} -> remove_tree(Root);
        undefined -> ok
    end,
    application:unset_env(vpn, dynamic_identity_test_bundle),
    application:unset_env(vpn, dynamic_identity_test_root),
    ok.

runtime_common_defaults() ->
    #{peer_module => vpn_peer,
      mode => tun,
      psk => <<"dynamic-resolver-test-psk">>,
      authorization_mode => development_bypass,
      authorized => true,
      handshake_start_delay_ms => 75,
      authorization_reason => dynamic_allocator_test}.

install_identity_bundle(Allocation) ->
    Root = filename:join(os:getenv("TMPDIR", "/tmp"),
                         lists:flatten(io_lib:format("vpn-dynamic-resolver-~p",
                                                     [erlang:unique_integer([positive,
                                                                             monotonic])]))),
    Keys = filename:join(Root, "keys"),
    ok = file:make_dir(Root),
    ok = file:make_dir(Keys),
    ClientKey = filename:join(Keys, "client.key"),
    ok = copy_fixture("peer_a.key", ClientKey),
    ok = file:change_mode(ClientKey, 8#600),
    OvpnPath = filename:join(Root, "client.ovpn"),
    {ok, CaPem} = file:read_file(fixture_path("ca.crt")),
    {ok, CertPem} = file:read_file(fixture_path("peer_a.crt")),
    Gateway = maps:get(gateway, Allocation),
    RemotePort = integer_to_binary(maps:get(local_udp_port, Gateway)),
    Ovpn = iolist_to_binary([
        "client\n",
        "dev tun\n",
        "proto udp\n",
        "remote 127.0.0.1 ", RemotePort, "\n",
        "nobind\n",
        "persist-key\n",
        "persist-tun\n",
        "remote-cert-tls server\n",
        "<ca>\n", CaPem, "</ca>\n",
        "<cert>\n", CertPem, "</cert>\n",
        "key keys/client.key\n"
    ]),
    ok = file:write_file(OvpnPath, Ovpn),
    Bundle = #{allocation_id => maps:get(allocation_id, Allocation),
               device_id => maps:get(device_id, Allocation),
               client => #{peer_id => maps:get(client_peer_id, Allocation),
                           ovpn_path => OvpnPath,
                           ca_certificate_path => fixture_path("ca.crt")},
               gateway => #{peer_id => maps:get(gateway_peer_id, Allocation),
                            certificate_path => fixture_path("peer_b.crt"),
                            private_key_path => fixture_path("peer_b.key"),
                            ca_certificate_path => fixture_path("ca.crt")}},
    application:set_env(vpn, dynamic_identity_test_root, Root),
    application:set_env(vpn, dynamic_identity_test_bundle, Bundle),
    ok.

fixture_path(Name) ->
    filename:join([code:priv_dir(vpn), "certs", Name]).

copy_fixture(Name, Destination) ->
    {ok, Binary} = file:read_file(fixture_path(Name)),
    file:write_file(Destination, Binary).

remove_tree(Path) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = directory}} ->
            case file:list_dir(Path) of
                {ok, Entries} ->
                    lists:foreach(fun(Entry) ->
                                          remove_tree(filename:join(Path, Entry))
                                  end,
                                  Entries),
                    file:del_dir(Path);
                {error, _} -> ok
            end;
        {ok, _} -> file:delete(Path);
        {error, _} -> ok
    end.

stop_registered(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            unlink(Pid),
            exit(Pid, shutdown),
            wait_until_stopped(Pid, 20)
    end.

wait_until_stopped(_Pid, 0) ->
    ok;
wait_until_stopped(Pid, Attempts) ->
    case is_process_alive(Pid) of
        false -> ok;
        true -> timer:sleep(10), wait_until_stopped(Pid, Attempts - 1)
    end.
