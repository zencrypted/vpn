-module(vpn_peer_allocator_tests).

-include_lib("eunit/include/eunit.hrl").

allocation_lifecycle_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Context) ->
             [?_test(begin
                          DeviceA = <<"device-a">>,
                          DeviceB = <<"device-b">>,
                          DeviceC = <<"device-c">>,

                          {ok, AllocationA1} = vpn_peer_allocator:ensure(DeviceA),
                          {ok, AllocationA2} = vpn_peer_allocator:ensure(DeviceA),
                          ?assertEqual(AllocationA1, AllocationA2),
                          ?assertEqual(1, maps:get(slot, AllocationA1)),
                          ?assertEqual(durable,
                                       maps:get(persistence, AllocationA1)),
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
                          ?assertEqual(#{persistence => durable,
                                         capacity => 2,
                                         allocated => 2,
                                         free => 0},
                                       vpn_peer_allocator:status()),
                          ?assertEqual({error, exhausted},
                                       vpn_peer_allocator:ensure(DeviceC)),

                          {ok, ReleasedA} = vpn_peer_allocator:release(DeviceA),
                          ?assertEqual(released, maps:get(state, ReleasedA)),
                          ?assertEqual(durable,
                                       maps:get(persistence, ReleasedA)),
                          ?assert(is_integer(maps:get(released_at, ReleasedA))),
                          ?assertEqual(maps:remove(state, AllocationA1),
                                       maps:remove(released_at,
                                                   maps:remove(state, ReleasedA))),
                          ?assertEqual({error, not_found},
                                       vpn_peer_allocator:lookup(DeviceA)),
                          ?assertEqual({ok, ReleasedA},
                                       vpn_peer_allocator:released(DeviceA)),
                          ?assertEqual({ok, ReleasedA},
                                       vpn_peer_allocator:release(DeviceA)),

                          {ok, AllocationC} = vpn_peer_allocator:ensure(DeviceC),
                          ?assertEqual(1, maps:get(slot, AllocationC)),
                          ?assert(maps:get(generation, AllocationC) >
                                  maps:get(generation, AllocationA1)),
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

allocator_and_projection_restart_restore_state_test() ->
    stop_registered(vpn_peer_allocator),
    stop_registered(vpn_projection),
    ok = vpn_projection_test_store:reset(),
    application:set_env(vpn,
                        dynamic_peer_allocator,
                        allocator_config()),
    try
        {ok, ProjectionPid1} =
            vpn_projection:start_link(vpn_projection_test_store),
        {ok, AllocatorPid1} = vpn_peer_allocator:start_link(),
        DeviceId = <<"device-restart">>,
        {ok, First} = vpn_peer_allocator:ensure(DeviceId),
        stop_pid(AllocatorPid1),
        stop_pid(ProjectionPid1),

        {ok, ProjectionPid2} =
            vpn_projection:start_link(vpn_projection_test_store),
        {ok, AllocatorPid2} = vpn_peer_allocator:start_link(),
        ?assertEqual({ok, First}, vpn_peer_allocator:lookup(DeviceId)),
        ?assertEqual({ok, First}, vpn_peer_allocator:ensure(DeviceId)),
        ?assertEqual(durable, maps:get(persistence, First)),

        {ok, Released} = vpn_peer_allocator:release(DeviceId),
        ?assertEqual(released, maps:get(state, Released)),
        stop_pid(AllocatorPid2),
        stop_pid(ProjectionPid2),

        {ok, ProjectionPid3} =
            vpn_projection:start_link(vpn_projection_test_store),
        {ok, AllocatorPid3} = vpn_peer_allocator:start_link(),
        ?assertEqual({error, not_found},
                     vpn_peer_allocator:lookup(DeviceId)),
        ?assertEqual({ok, Released},
                     vpn_peer_allocator:released(DeviceId)),
        ?assertEqual({ok, Released},
                     vpn_peer_allocator:release(DeviceId)),
        {ok, Second} = vpn_peer_allocator:ensure(DeviceId),
        ?assertEqual(maps:get(allocator_instance_id, First),
                     maps:get(allocator_instance_id, Second)),
        ?assertEqual(maps:get(slot, First), maps:get(slot, Second)),
        ?assert(maps:get(generation, Second) > maps:get(generation, First)),
        ?assertNotEqual(maps:get(allocation_id, First),
                        maps:get(allocation_id, Second)),
        ?assertNotEqual(maps:get(client_peer_id, First),
                        maps:get(client_peer_id, Second)),
        ?assertNotEqual(maps:get(gateway_peer_id, First),
                        maps:get(gateway_peer_id, Second)),
        stop_pid(AllocatorPid3),
        stop_pid(ProjectionPid3)
    after
        stop_registered(vpn_peer_allocator),
        stop_registered(vpn_projection),
        ok = vpn_projection_test_store:reset(),
        application:unset_env(vpn, dynamic_peer_allocator)
    end.

failed_projection_commit_does_not_publish_mutation_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Context) ->
             [?_test(begin
                          DeviceId = <<"device-persistence-failure">>,
                          ok = vpn_projection_test_store:fail_next_commit(
                                 disk_full),
                          ?assertEqual(
                             {error,
                              {allocator_persistence_failed,
                               {projection_commit_failed, disk_full}}},
                             vpn_peer_allocator:ensure(DeviceId)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_allocator:lookup(DeviceId)),
                          ?assertEqual(#{persistence => durable,
                                         capacity => 2,
                                         allocated => 0,
                                         free => 2},
                                       vpn_peer_allocator:status()),

                          {ok, Allocation} =
                              vpn_peer_allocator:ensure(DeviceId),
                          ok = vpn_projection_test_store:fail_next_commit(
                                 read_only),
                          ?assertEqual(
                             {error,
                              {allocator_persistence_failed,
                               {projection_commit_failed, read_only}}},
                             vpn_peer_allocator:release(DeviceId)),
                          ?assertEqual({ok, Allocation},
                                       vpn_peer_allocator:lookup(DeviceId))
                      end)]
     end}.

invalid_device_id_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Context) ->
             [?_assertEqual({error, invalid_device_id},
                            vpn_peer_allocator:ensure(anonymous)),
              ?_assertEqual({error, invalid_device_id},
                            vpn_peer_allocator:ensure(<<>>)),
              ?_assertEqual({error, invalid_device_id},
                            vpn_peer_allocator:lookup(undefined)),
              ?_assertEqual({error, invalid_device_id},
                            vpn_peer_allocator:released(undefined)),
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
    stop_registered(vpn_projection),
    ok = vpn_projection_test_store:reset(),
    application:set_env(vpn,
                        dynamic_peer_allocator,
                        allocator_config()),
    {ok, ProjectionPid} =
        vpn_projection:start_link(vpn_projection_test_store),
    {ok, AllocatorPid} = vpn_peer_allocator:start_link(),
    #{projection => ProjectionPid, allocator => AllocatorPid}.

cleanup(#{projection := ProjectionPid, allocator := AllocatorPid}) ->
    stop_pid(AllocatorPid),
    stop_pid(ProjectionPid),
    ok = vpn_projection_test_store:reset(),
    application:unset_env(vpn, dynamic_peer_allocator),
    ok.

allocator_config() ->
    #{capacity => 2,
      first_host => 20,
      client_network => {10, 40, 0},
      gateway_network => {10, 41, 0},
      client_udp_port_base => 22000,
      gateway_udp_port_base => 23000}.

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
            ok = gen_server:stop(Pid, normal, 5000),
            wait_until_stopped(Pid, 50);
        false ->
            ok
    end.

stop_registered(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> stop_pid(Pid)
    end.

wait_until_stopped(_Pid, 0) ->
    ok;
wait_until_stopped(Pid, Attempts) ->
    case is_process_alive(Pid) of
        false -> ok;
        true -> timer:sleep(10), wait_until_stopped(Pid, Attempts - 1)
    end.
