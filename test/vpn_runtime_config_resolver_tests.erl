-module(vpn_runtime_config_resolver_tests).

-include_lib("eunit/include/eunit.hrl").

dynamic_allocation_resolver_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Allocator) ->
             [?_test(begin
                          DeviceId = <<"device-runtime-a">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
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
                          ?assertEqual(undefined,
                                       maps:get(profile_id, Gateway, undefined)),
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
             [?_assertEqual({error, dynamic_peer_device_id_required},
                            vpn_runtime_config_resolver:resolve(
                              <<"client_dyn_missing">>, #{})),
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
    ok.

runtime_common_defaults() ->
    #{peer_module => vpn_peer,
      mode => tun,
      psk => <<"dynamic-resolver-test-psk">>,
      certificate_path => "test-dynamic.crt",
      private_key_path => "test-dynamic.key",
      ca_certificate_path => "test-ca.crt",
      authorization_mode => development_bypass,
      authorized => true,
      authorization_reason => dynamic_allocator_test}.

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
