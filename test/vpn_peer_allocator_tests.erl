-module(vpn_peer_allocator_tests).

-include_lib("eunit/include/eunit.hrl").

allocation_lifecycle_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Pid) ->
             [?_test(begin
                          DeviceA = <<"device-a">>,
                          DeviceB = <<"device-b">>,
                          DeviceC = <<"device-c">>,

                          {ok, AllocationA1} = vpn_peer_allocator:ensure(DeviceA),
                          {ok, AllocationA2} = vpn_peer_allocator:ensure(DeviceA),
                          ?assertEqual(AllocationA1, AllocationA2),
                          ?assertEqual(1, maps:get(slot, AllocationA1)),
                          ?assertEqual(12,
                                       byte_size(maps:get(allocator_instance_id,
                                                          AllocationA1))),
                          assert_binary_prefix(<<"client_dyn_1_">>,
                                               maps:get(client_peer_id,
                                                        AllocationA1)),
                          assert_binary_prefix(<<"gateway_dyn_1_">>,
                                               maps:get(gateway_peer_id,
                                                        AllocationA1)),
                          ?assert(is_binary(maps:get(client_peer_id, AllocationA1))),
                          ?assert(is_binary(maps:get(gateway_peer_id, AllocationA1))),
                          ?assertEqual({ok, AllocationA1},
                                       vpn_peer_allocator:lookup(DeviceA)),

                          ClientA = maps:get(client, AllocationA1),
                          GatewayA = maps:get(gateway, AllocationA1),
                          ?assertEqual(<<"vpc1">>, maps:get(ifname, ClientA)),
                          ?assertEqual(<<"vpg1">>, maps:get(ifname, GatewayA)),
                          ?assertEqual("10.40.0.20", maps:get(ip, ClientA)),
                          ?assertEqual("10.41.0.20", maps:get(ip, GatewayA)),
                          ?assertEqual(22000, maps:get(local_udp_port, ClientA)),
                          ?assertEqual(23000, maps:get(local_udp_port, GatewayA)),
                          ?assertEqual(maps:get(peer_id, GatewayA),
                                       maps:get(remote_peer_id, ClientA)),
                          ?assertEqual(maps:get(peer_id, ClientA),
                                       maps:get(remote_peer_id, GatewayA)),

                          {ok, AllocationB} = vpn_peer_allocator:ensure(DeviceB),
                          ?assertEqual(2, maps:get(slot, AllocationB)),
                          assert_distinct_resources(AllocationA1, AllocationB),
                          ?assertEqual(#{persistence => volatile,
                                         capacity => 2,
                                         allocated => 2,
                                         free => 0},
                                       vpn_peer_allocator:status()),
                          ?assertEqual({error, exhausted},
                                       vpn_peer_allocator:ensure(DeviceC)),

                          {ok, ReleasedA} = vpn_peer_allocator:release(DeviceA),
                          ?assertEqual(released, maps:get(state, ReleasedA)),
                          ?assert(is_integer(maps:get(released_at, ReleasedA))),
                          ?assertEqual(maps:remove(state, AllocationA1),
                                       maps:remove(released_at,
                                                   maps:remove(state, ReleasedA))),
                          ?assertEqual({error, not_found},
                                       vpn_peer_allocator:lookup(DeviceA)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_allocator:release(DeviceA)),

                          {ok, AllocationC} = vpn_peer_allocator:ensure(DeviceC),
                          ?assertEqual(1, maps:get(slot, AllocationC)),
                          assert_binary_prefix(<<"client_dyn_1_">>,
                                               maps:get(client_peer_id,
                                                        AllocationC)),
                          ?assertNotEqual(maps:get(client_peer_id, AllocationA1),
                                          maps:get(client_peer_id, AllocationC)),
                          ?assertNotEqual(maps:get(gateway_peer_id, AllocationA1),
                                          maps:get(gateway_peer_id, AllocationC)),
                          ?assertEqual([1, 2],
                                       [maps:get(slot, Allocation)
                                        || Allocation <- vpn_peer_allocator:list()])
                      end)]
     end}.


allocator_restart_uses_fresh_identity_namespace_test() ->
    stop_registered(vpn_peer_allocator),
    application:set_env(vpn,
                        dynamic_peer_allocator,
                        #{capacity => 2,
                          first_host => 20,
                          client_network => {10, 40, 0},
                          gateway_network => {10, 41, 0},
                          client_udp_port_base => 22000,
                          gateway_udp_port_base => 23000}),
    try
        {ok, FirstPid} = vpn_peer_allocator:start_link(),
        {ok, First} = vpn_peer_allocator:ensure(<<"device-restart">>),
        stop_pid(FirstPid),
        {ok, SecondPid} = vpn_peer_allocator:start_link(),
        {ok, Second} = vpn_peer_allocator:ensure(<<"device-restart">>),
        ?assertEqual(1, maps:get(slot, First)),
        ?assertEqual(1, maps:get(slot, Second)),
        ?assertNotEqual(maps:get(allocator_instance_id, First),
                        maps:get(allocator_instance_id, Second)),
        ?assertNotEqual(maps:get(allocation_id, First),
                        maps:get(allocation_id, Second)),
        ?assertNotEqual(maps:get(client_peer_id, First),
                        maps:get(client_peer_id, Second)),
        ?assertNotEqual(maps:get(gateway_peer_id, First),
                        maps:get(gateway_peer_id, Second)),
        stop_pid(SecondPid)
    after
        stop_registered(vpn_peer_allocator),
        application:unset_env(vpn, dynamic_peer_allocator)
    end.

invalid_device_id_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Pid) ->
             [?_assertEqual({error, invalid_device_id},
                            vpn_peer_allocator:ensure(anonymous)),
              ?_assertEqual({error, invalid_device_id},
                            vpn_peer_allocator:ensure(<<>>)),
              ?_assertEqual({error, invalid_device_id},
                            vpn_peer_allocator:lookup(undefined)),
              ?_assertEqual({error, invalid_device_id},
                            vpn_peer_allocator:release([]))]
     end}.

invalid_config_test() ->
    stop_registered(vpn_peer_allocator),
    application:set_env(vpn,
                        dynamic_peer_allocator,
                        #{capacity => 10,
                          client_udp_port_base => 22000,
                          gateway_udp_port_base => 22005}),
    try
        ?assertEqual({error,
                      {invalid_dynamic_peer_allocator_config,
                       overlapping_udp_port_ranges}},
                     isolated_start_link())
    after
        stop_registered(vpn_peer_allocator),
        application:unset_env(vpn, dynamic_peer_allocator)
    end.

isolated_start_link() ->
    Parent = self(),
    Ref = make_ref(),
    {Pid, MonitorRef} =
        spawn_monitor(
          fun() ->
                  process_flag(trap_exit, true),
                  Parent ! {Ref, vpn_peer_allocator:start_link()}
          end),
    receive
        {Ref, Result} ->
            receive
                {'DOWN', MonitorRef, process, Pid, normal} ->
                    Result;
                {'DOWN', MonitorRef, process, Pid, Reason} ->
                    erlang:error({allocator_start_helper_failed, Reason})
            after 1000 ->
                    erlang:demonitor(MonitorRef, [flush]),
                    Result
            end;
        {'DOWN', MonitorRef, process, Pid, Reason} ->
            erlang:error({allocator_start_helper_failed, Reason})
    after 1000 ->
            exit(Pid, kill),
            receive
                {'DOWN', MonitorRef, process, Pid, _Reason} -> ok
            after 1000 -> ok
            end,
            erlang:error(allocator_start_helper_timeout)
    end.

setup() ->
    stop_registered(vpn_peer_allocator),
    application:set_env(vpn,
                        dynamic_peer_allocator,
                        #{capacity => 2,
                          first_host => 20,
                          client_network => {10, 40, 0},
                          gateway_network => {10, 41, 0},
                          client_udp_port_base => 22000,
                          gateway_udp_port_base => 23000}),
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
    ok.

assert_binary_prefix(Prefix, Value) when is_binary(Prefix), is_binary(Value) ->
    PrefixSize = byte_size(Prefix),
    ?assert(byte_size(Value) > PrefixSize),
    ?assertEqual(Prefix, binary:part(Value, 0, PrefixSize)).

assert_distinct_resources(AllocationA, AllocationB) ->
    ?assertNotEqual(maps:get(client_peer_id, AllocationA),
                    maps:get(client_peer_id, AllocationB)),
    ?assertNotEqual(maps:get(gateway_peer_id, AllocationA),
                    maps:get(gateway_peer_id, AllocationB)),
    ClientA = maps:get(client, AllocationA),
    ClientB = maps:get(client, AllocationB),
    GatewayA = maps:get(gateway, AllocationA),
    GatewayB = maps:get(gateway, AllocationB),
    ?assertNotEqual(maps:get(ifname, ClientA), maps:get(ifname, ClientB)),
    ?assertNotEqual(maps:get(ifname, GatewayA), maps:get(ifname, GatewayB)),
    ?assertNotEqual(maps:get(ip, ClientA), maps:get(ip, ClientB)),
    ?assertNotEqual(maps:get(ip, GatewayA), maps:get(ip, GatewayB)),
    ?assertNotEqual(maps:get(local_udp_port, ClientA),
                    maps:get(local_udp_port, ClientB)),
    ?assertNotEqual(maps:get(local_udp_port, GatewayA),
                    maps:get(local_udp_port, GatewayB)).


stop_pid(Pid) when is_pid(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            exit(Pid, shutdown),
            wait_until_stopped(Pid, 20);
        false ->
            ok
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
