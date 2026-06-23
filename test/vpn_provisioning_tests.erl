-module(vpn_provisioning_tests).
-include_lib("eunit/include/eunit.hrl").

provisioning_contract_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             [?_test(begin
                          Upsert = command(1, upsert, #{device_id => <<"device-a">>,
                                                         authorized => true}),
                          ?assertMatch({ok, #{operation := upsert}},
                                       vpn_provisioning:apply(Upsert)),
                          {ok, Entry1} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(1, maps:get(revision, Entry1)),
                          ?assertEqual(<<"device-a">>, maps:get(device_id, Entry1)),
                          ?assertEqual(false, maps:get(revoked, Entry1)),

                          ?assertEqual({ok, unchanged}, vpn_provisioning:apply(Upsert)),
                          ?assertEqual({error, revision_conflict},
                                       vpn_provisioning:apply(command(1, disable, #{}))),
                          ?assertEqual({error, stale_revision},
                                       vpn_provisioning:apply(command(0, disable, #{}))),

                          ?assertMatch({ok, #{operation := disable}},
                                       vpn_provisioning:apply(command(2, disable, #{}))),
                          {ok, Entry2} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(false, maps:get(enabled, Entry2)),

                          ?assertMatch({ok, #{operation := revoke}},
                                       vpn_provisioning:apply(command(3, revoke, #{}))),
                          {ok, Revoked} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(true, maps:get(revoked, Revoked)),
                          ?assertEqual(false, maps:get(authorized, Revoked)),
                          ?assertEqual({error, revoked},
                                       vpn_provisioning:apply(command(4, enable, #{}))),

                          Reissue = command(5, upsert, #{revoked => false,
                                                         enabled => true,
                                                         authorized => true}),
                          ?assertMatch({ok, #{operation := upsert}},
                                       vpn_provisioning:apply(Reissue)),
                          {ok, Reissued} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(false, maps:get(revoked, Reissued)),
                          ?assertEqual(true, maps:get(enabled, Reissued)),

                          ?assertEqual({ok, removed},
                                       vpn_provisioning:apply(command(6, remove, #{}))),
                          ?assertEqual({error, not_found}, vpn_peer_registry:get(peer_a)),
                          ?assertEqual({error, stale_revision},
                                       vpn_provisioning:apply(command(5, upsert, #{}))),

                          Status = vpn_provisioning:status(),
                          ?assertEqual(8, maps:get(commands_received, Status)),
                          ?assertEqual(5, maps:get(commands_applied, Status)),
                          ?assertEqual(1, maps:get(commands_unchanged, Status)),
                          ?assertEqual(1, maps:get(revocations, Status)),
                          ?assert(length(vpn_provisioning:history(peer_a)) >= 6)
                      end)]
     end}.

new_peer_requires_runtime_config_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             [?_assertEqual({error, runtime_config_required},
                            vpn_provisioning:apply(#{peer_id => peer_b,
                                                     revision => 1,
                                                     operation => upsert,
                                                     source => ias,
                                                     desired_state => #{enabled => true}})),
              ?_assertMatch({ok, #{operation := upsert}},
                            vpn_provisioning:apply(#{peer_id => peer_b,
                                                     revision => 2,
                                                     operation => upsert,
                                                     source => ias,
                                                     desired_state => #{runtime_config => peer_config(peer_b),
                                                                        enabled => false}}))]
     end}.

invalid_command_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             [?_assertEqual({error, invalid_command}, vpn_provisioning:apply(#{})),
              ?_assertEqual({error, invalid_command}, vpn_provisioning:apply(not_a_map))]
     end}.

command(Revision, Operation, Desired) ->
    #{peer_id => peer_a,
      revision => Revision,
      operation => Operation,
      source => ias,
      desired_state => Desired}.

setup() ->
    stop(vpn_provisioning),
    stop(vpn_peer_registry),
    application:set_env(vpn, peers, [peer_config(peer_a)]),
    application:set_env(vpn, ovpn_sessions, []),
    {ok, Registry} = vpn_peer_registry:start_link(),
    {ok, Provisioning} = vpn_provisioning:start_link(),
    {Registry, Provisioning}.

cleanup({Registry, Provisioning}) ->
    shutdown(Provisioning),
    shutdown(Registry),
    application:unset_env(vpn, peers),
    application:unset_env(vpn, ovpn_sessions),
    ok.

peer_config(PeerId) ->
    #{id => PeerId,
      peer_module => vpn_peer_registry_tests,
      mode => tun,
      ifname => atom_to_list(PeerId),
      ip => "10.20.20.1",
      remote_peer_id => peer_a,
      psk => <<"secret">>}.

stop(Name) ->
    case whereis(Name) of undefined -> ok; Pid -> shutdown(Pid) end.

shutdown(Pid) ->
    case is_process_alive(Pid) of
        true -> unlink(Pid), exit(Pid, shutdown), wait(Pid, 30);
        false -> ok
    end.

wait(_Pid, 0) -> ok;
wait(Pid, N) ->
    case is_process_alive(Pid) of
        false -> ok;
        true -> timer:sleep(10), wait(Pid, N - 1)
    end.
