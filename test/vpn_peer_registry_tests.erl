-module(vpn_peer_registry_tests).

-include_lib("eunit/include/eunit.hrl").

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

registry_lifecycle_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Pid) ->
             [?_test(begin
                          [Bootstrap] = vpn_peer_registry:list(),
                          ?assertMatch(#{id := peer_a,
                                         enabled := true,
                                         provisioning_source := bootstrap_sys_config},
                                       Bootstrap),
                          ?assertNot(maps:is_key(config, Bootstrap)),
                          ?assertNot(contains_key(psk, Bootstrap)),
                          ?assertNot(contains_key(private_key_path, Bootstrap)),

                          {ok, PeerA} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(Bootstrap, PeerA),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(unknown_peer)),

                          RuntimePeer = (peer_config(peer_b))#{device_id => <<"device-b">>,
                                                            profile_id => default_user,
                                                            authorization_mode => policy,
                                                            authorized => true,
                                                            authorization_reason => profile_allows_vpn},
                          {ok, Added} = vpn_peer_registry:put(RuntimePeer),
                          ?assertMatch(#{id := peer_b,
                                         enabled := true,
                                         provisioning_source := runtime_api,
                                         device_id := <<"device-b">>,
                                         profile_id := default_user,
                                         authorized := true},
                                       Added),
                          ?assertNot(contains_key(psk, Added)),
                          ?assertNot(contains_key(private_key_path, Added)),

                          {ok, Disabled} = vpn_peer_registry:disable(peer_b),
                          ?assertEqual(false, maps:get(enabled, Disabled)),
                          ?assertEqual([peer_a], config_ids(vpn_peer_registry:enabled_configs())),

                          {ok, Enabled} = vpn_peer_registry:enable(peer_b),
                          ?assertEqual(true, maps:get(enabled, Enabled)),
                          ?assertEqual([peer_a, peer_b],
                                       config_ids(vpn_peer_registry:enabled_configs())),

                          {ok, InternalConfig} = vpn_peer_registry:config(peer_b),
                          ?assertEqual(<<"test-secret-psk">>, maps:get(psk, InternalConfig)),

                          ?assertEqual(ok, vpn_peer_registry:remove(peer_b)),
                          ?assertEqual({error, not_found}, vpn_peer_registry:get(peer_b)),
                          ?assertEqual({error, not_found}, vpn_peer_registry:remove(peer_b))
                      end)]
     end}.

invalid_put_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Pid) ->
             [?_assertEqual({error, invalid_peer_config}, vpn_peer_registry:put(#{})),
              ?_assertEqual({error, invalid_peer_config}, vpn_peer_registry:put(not_a_map)),
              ?_assertEqual({error, invalid_peer_config}, vpn_peer_registry:put_many([])),
              ?_assertEqual({error, duplicate_peer_id},
                            vpn_peer_registry:put_many([peer_config(peer_b),
                                                        peer_config(peer_b)])),
              ?_assertEqual({error, invalid_peer_ids},
                            vpn_peer_registry:remove_many([]))]
     end}.

batch_registry_mutation_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Pid) ->
             [?_test(begin
                          PeerB = (peer_config(peer_b))#{allocation_id => <<"alloc-1">>,
                                                         allocation_role => client},
                          PeerC = (peer_config(peer_c))#{allocation_id => <<"alloc-1">>,
                                                         allocation_role => gateway},
                          {ok, Entries} = vpn_peer_registry:put_many([PeerC, PeerB]),
                          ?assertEqual([peer_c, peer_b],
                                       [maps:get(id, Entry) || Entry <- Entries]),
                          ?assertEqual([peer_a, peer_b, peer_c],
                                       [maps:get(id, Entry)
                                        || Entry <- vpn_peer_registry:list()]),
                          ?assertEqual(ok,
                                       vpn_peer_registry:remove_many([peer_b, peer_c])),
                          ?assertEqual([peer_a],
                                       [maps:get(id, Entry)
                                        || Entry <- vpn_peer_registry:list()])
                      end)]
     end}.


durable_registry_recovery_enforces_lifecycle_barriers_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Pid) ->
             [?_test(begin
                          Disabled = durable_head(
                                       1,
                                       applied,
                                       disable,
                                       disabled,
                                       #{enabled => false}),
                          ok = persist_heads(#{peer_a => Disabled}),
                          {ok, _Registry1} = restart_registry(),
                          {ok, DisabledEntry} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(false,
                                       maps:get(enabled, DisabledEntry)),
                          ?assertEqual(1,
                                       maps:get(revision, DisabledEntry)),
                          ?assertEqual(ias,
                                       maps:get(provisioning_source,
                                                DisabledEntry)),
                          Recovery1 = vpn_peer_registry:recovery_status(),
                          ?assertEqual(durable,
                                       maps:get(persistence, Recovery1)),
                          ?assertEqual([peer_a],
                                       maps:get(restored_peers, Recovery1)),

                          Removed = durable_head(
                                      2,
                                      applied,
                                      remove,
                                      removed,
                                      #{enabled => false}),
                          ok = persist_heads(#{peer_a => Removed}),
                          {ok, _Registry2} = restart_registry(),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(peer_a)),
                          Recovery2 = vpn_peer_registry:recovery_status(),
                          ?assertEqual([peer_a],
                                       maps:get(suppressed_peers,
                                                Recovery2)),

                          PendingEnable = durable_head(
                                            3,
                                            pending,
                                            enable,
                                            active,
                                            #{enabled => true}),
                          ok = persist_heads(#{peer_a => PendingEnable}),
                          {ok, _Registry3} = restart_registry(),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(peer_a)),
                          Recovery3 = vpn_peer_registry:recovery_status(),
                          ?assertEqual(1,
                                       maps:get(pending_heads, Recovery3)),
                          ?assertEqual([peer_a],
                                       maps:get(suppressed_peers,
                                                Recovery3))
                      end)]
     end}.


revoked_durable_runtime_recovers_stopped_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Pid) ->
             [?_test(begin
                          application:set_env(vpn,
                                              runtime_config_resolver,
                                              static_template),
                          application:set_env(vpn,
                                              runtime_config_template,
                                              recovery_runtime_template()),
                          Revoked = durable_head(
                                      4,
                                      applied,
                                      revoke,
                                      revoked,
                                      #{device_id => <<"revoked-device">>,
                                        profile_id => default_user,
                                        authorization_mode => policy,
                                        authorized => false,
                                        authorization_reason => certificate_revoked,
                                        enabled => false,
                                        revoked => true}),
                          ok = persist_heads(#{peer_b => Revoked}),
                          {ok, _Registry} = restart_registry(),

                          {ok, Entry} = vpn_peer_registry:get(peer_b),
                          ?assertEqual(false, maps:get(enabled, Entry)),
                          ?assertEqual(false, maps:get(authorized, Entry)),
                          ?assertEqual(true, maps:get(revoked, Entry)),
                          ?assertEqual(certificate_revoked,
                                       maps:get(authorization_reason, Entry)),
                          ?assertNot(lists:member(
                                       peer_b,
                                       config_ids(
                                         vpn_peer_registry:enabled_configs()))),
                          Recovery = vpn_peer_registry:recovery_status(),
                          ?assert(lists:member(
                                    peer_b,
                                    maps:get(restored_peers, Recovery)))
                      end)]
     end}.


unrecoverable_active_runtime_fails_closed_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Pid) ->
             [?_test(begin
                          Active = durable_head(
                                     1,
                                     applied,
                                     upsert,
                                     active,
                                     #{enabled => true,
                                       authorized => true}),
                          ok = persist_heads(#{peer_b => Active}),
                          ?assertEqual(
                             {error,
                              {runtime_recovery_failed,
                               peer_b,
                               {runtime_config_recovery_failed,
                                runtime_config_required}}},
                             vpn_runtime_recovery:restore([]))
                      end)]
     end}.


automatic_manager_reconcile_test_() ->
    {setup,
     fun setup_with_reconciler/0,
     fun cleanup_with_reconciler/1,
     fun({_RegistryPid, _PeerSupPid, _ReconcilerPid}) ->
             [?_test(begin
                          ?assertEqual([peer_a], vpn_manager:running_peers()),

                          {ok, _} = vpn_peer_registry:put(peer_config(peer_b)),
                          ?assert(wait_until(fun() ->
                                                    lists:sort(vpn_manager:running_peers()) =:=
                                                        [peer_a, peer_b]
                                            end, 50)),
                          {ok, PeerBPid1} = vpn_manager:find_peer(peer_b),
                          EventsBeforeMetadata = maps:get(
                                                   events_received,
                                                   vpn_peer_reconciler:status()),

                          MetadataPeerB = (peer_config(peer_b))#{revision => 1,
                                                                  provisioning_source => ias,
                                                                  last_provisioning_operation => upsert,
                                                                  updated_at => 12345},
                          {ok, _} = vpn_peer_registry:put(MetadataPeerB),
                          ?assert(wait_until(fun() ->
                                                    Status0 = vpn_peer_reconciler:status(),
                                                    maps:get(events_received, Status0) >
                                                        EventsBeforeMetadata
                                            end, 50)),
                          ?assertEqual({ok, PeerBPid1},
                                       vpn_manager:find_peer(peer_b)),
                          MetadataStatus = vpn_peer_reconciler:status(),
                          ?assertEqual([peer_b],
                                       maps:get(unchanged,
                                                maps:get(last_result,
                                                         MetadataStatus))),

                          UpdatedPeerB = MetadataPeerB#{ifname => "peer_b_updated"},
                          {ok, _} = vpn_peer_registry:put(UpdatedPeerB),
                          ?assert(wait_until(fun() ->
                                                    case vpn_manager:peer_info(peer_b) of
                                                        #{config := #{ifname := "peer_b_updated"}} -> true;
                                                        _ -> false
                                                    end
                                            end, 50)),
                          {ok, PeerBPid2} = vpn_manager:find_peer(peer_b),
                          ?assertNotEqual(PeerBPid1, PeerBPid2),

                          {ok, _} = vpn_peer_registry:disable(peer_a),
                          ?assert(wait_until(fun() ->
                                                    vpn_manager:running_peers() =:= [peer_b]
                                            end, 50)),

                          {ok, _} = vpn_peer_registry:enable(peer_a),
                          ?assert(wait_until(fun() ->
                                                    lists:sort(vpn_manager:running_peers()) =:=
                                                        [peer_a, peer_b]
                                            end, 50)),

                          ?assertEqual(ok, vpn_peer_registry:remove(peer_b)),
                          ?assert(wait_until(fun() ->
                                                    vpn_manager:running_peers() =:= [peer_a]
                                            end, 50)),

                          Status = vpn_peer_reconciler:status(),
                          ?assert(maps:get(events_received, Status) >= 4),
                          ?assertEqual(0, maps:get(failures, Status))
                      end)]
     end}.


runtime_reconciled_event_is_published_after_application_test_() ->
    {setup,
     fun setup_with_event_bus_and_reconciler/0,
     fun cleanup_with_event_bus_and_reconciler/1,
     fun({_RegistryPid, _PeerSupPid, _EventBusPid, _ReconcilerPid}) ->
             [?_test(begin
                          {ok, _Subscription} = vpn_event_bus:subscribe(self()),
                          {ok, _} = vpn_peer_registry:put(peer_config(peer_b)),
                          Event = receive_vpn_event(),
                          ?assertMatch(#{schema_version := 1,
                                         type := runtime_reconciled,
                                         cause := #{action := put,
                                                    peer_id := peer_b},
                                         result := #{outcome := ok,
                                                     started := 1,
                                                     failed := 0,
                                                     peer_ids := [peer_b]}},
                                       Event),
                          %% Receiving the event is a completion signal: the
                          %% runtime mutation has already been applied.
                          ?assertEqual(true, vpn_manager:peer_running(peer_b)),
                          ?assertNot(contains_key(config, Event)),
                          ?assertNot(contains_key(psk, Event)),
                          ?assertNot(contains_key(private_key_path, Event))
                      end)]
     end}.

manager_reconcile_test_() ->
    {setup,
     fun setup_with_peer_sup/0,
     fun cleanup_with_peer_sup/1,
     fun({_RegistryPid, _PeerSupPid}) ->
             [?_test(begin
                          ?assertEqual([peer_a], vpn_manager:list_peers()),
                          ?assertEqual([peer_a], vpn_manager:running_peers()),

                          {ok, _} = vpn_peer_registry:put(peer_config(peer_b)),
                          Reload1 = vpn_manager:reload_config(),
                          ?assertEqual([peer_b], maps:get(started, Reload1)),
                          ?assertEqual([peer_a, peer_b], vpn_manager:running_peers()),

                          {ok, _} = vpn_peer_registry:disable(peer_a),
                          Reload2 = vpn_manager:reload_config(),
                          ?assertEqual([peer_a], maps:get(stopped, Reload2)),
                          ?assertEqual([peer_b], vpn_manager:running_peers()),
                          ?assertEqual({error, disabled}, vpn_manager:start_peer(peer_a)),

                          {ok, _} = vpn_peer_registry:enable(peer_a),
                          Reload3 = vpn_manager:reload_config(),
                          ?assertEqual([peer_a], maps:get(started, Reload3)),
                          ?assertEqual([peer_a, peer_b], vpn_manager:running_peers())
                      end)]
     end}.

setup() ->
    stop_registered(vpn_peer_registry),
    stop_projection(),
    ok = vpn_projection_test_store:reset(),
    application:set_env(vpn, peers, [peer_config(peer_a)]),
    application:set_env(vpn, ovpn_sessions, []),
    application:set_env(vpn, runtime_config_resolver, disabled),
    {ok, _ProjectionPid} =
        vpn_projection:start_link(vpn_projection_test_store),
    {ok, Pid} = vpn_peer_registry:start_link(),
    Pid.

cleanup(_Pid) ->
    stop_named_normal(vpn_peer_registry),
    stop_projection(),
    ok = vpn_projection_test_store:reset(),
    application:unset_env(vpn, peers),
    application:unset_env(vpn, ovpn_sessions),
    application:unset_env(vpn, runtime_config_resolver),
    application:unset_env(vpn, runtime_config_template),
    application:unset_env(vpn, runtime_config_templates),
    ok.

stop_named_normal(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            ok = gen_server:stop(Pid, normal, 5000),
            wait_until_stopped(Pid, 20)
    end.

stop_projection() ->
    case whereis(vpn_projection) of
        undefined -> ok;
        Pid ->
            ok = gen_server:stop(Pid, normal, 5000),
            wait_until_stopped(Pid, 20)
    end.

stop_registered(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            unlink(Pid),
            exit(Pid, shutdown),
            wait_until_stopped(Pid, 20)
    end.

wait_until_stopped(_Pid, 0) -> ok;
wait_until_stopped(Pid, Attempts) ->
    case is_process_alive(Pid) of
        false -> ok;
        true -> timer:sleep(10), wait_until_stopped(Pid, Attempts - 1)
    end.

persist_heads(Heads) ->
    case vpn_projection:update(
           provisioning,
           fun(_Current) ->
                   #{schema_version => 1,
                     entries => Heads}
           end) of
        {ok, _Version, _Projection} -> ok;
        {ok, unchanged, _Version, _Projection} -> ok
    end.

durable_head(Revision, Phase, Operation, Lifecycle, Desired) ->
    #{revision => Revision,
      digest => crypto:hash(
                  sha256,
                  term_to_binary({Revision, Phase, Operation, Desired},
                                 [deterministic])),
      phase => Phase,
      operation => Operation,
      source => ias,
      lifecycle_state => Lifecycle,
      desired_state => Desired,
      updated_at => Revision * 1000}.

restart_registry() ->
    stop_named_normal(vpn_peer_registry),
    vpn_peer_registry:start_link().

peer_config(PeerId) ->
    #{id => PeerId,
      peer_module => ?MODULE,
      mode => tun,
      ifname => atom_to_list(PeerId),
      ip => "10.20.20.1",
      remote_peer_id => peer_a,
      psk => <<"test-secret-psk">>,
      private_key_path => "local/private.key",
      certificate_path => "local/certificate.crt"}.

recovery_runtime_template() ->
    #{id => recovery_template,
      peer_module => ?MODULE,
      mode => tun,
      ifname => "peer_recovery",
      ip => "10.20.20.2",
      local_udp_port => 40101,
      remote_ip => {127, 0, 0, 1},
      remote_udp_port => 40102,
      remote_peer_id => peer_a,
      psk => <<"recovery-test-secret-psk">>,
      authorization_mode => policy,
      authorized => true,
      authorization_reason => recovery_template_allows}.

config_ids(Configs) ->
    lists:sort([maps:get(id, Config) || Config <- Configs]).

contains_key(Key, Term) when is_map(Term) ->
    maps:is_key(Key, Term) orelse
        lists:any(fun(Value) -> contains_key(Key, Value) end, maps:values(Term));
contains_key(Key, Term) when is_list(Term) ->
    lists:any(fun(Value) -> contains_key(Key, Value) end, Term);
contains_key(_Key, _Term) ->
    false.



setup_with_event_bus_and_reconciler() ->
    {RegistryPid, PeerSupPid} = setup_with_peer_sup(),
    stop_registered(vpn_event_bus),
    stop_registered(vpn_peer_reconciler),
    {ok, EventBusPid} = vpn_event_bus:start_link(),
    {ok, ReconcilerPid} = vpn_peer_reconciler:start_link(),
    {RegistryPid, PeerSupPid, EventBusPid, ReconcilerPid}.

cleanup_with_event_bus_and_reconciler(
  {RegistryPid, PeerSupPid, EventBusPid, ReconcilerPid}) ->
    stop_if_alive(ReconcilerPid),
    stop_if_alive(EventBusPid),
    cleanup_with_peer_sup({RegistryPid, PeerSupPid}).

stop_if_alive(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            exit(Pid, shutdown),
            wait_until_stopped(Pid, 20);
        false -> ok
    end.

receive_vpn_event() ->
    receive
        {vpn_event, Event} -> Event
    after 1000 ->
        error(vpn_event_timeout)
    end.

setup_with_reconciler() ->
    {RegistryPid, PeerSupPid} = setup_with_peer_sup(),
    stop_registered(vpn_peer_reconciler),
    {ok, ReconcilerPid} = vpn_peer_reconciler:start_link(),
    {RegistryPid, PeerSupPid, ReconcilerPid}.

cleanup_with_reconciler({RegistryPid, PeerSupPid, ReconcilerPid}) ->
    case is_process_alive(ReconcilerPid) of
        true ->
            unlink(ReconcilerPid),
            exit(ReconcilerPid, shutdown),
            wait_until_stopped(ReconcilerPid, 20);
        false -> ok
    end,
    cleanup_with_peer_sup({RegistryPid, PeerSupPid}).

wait_until(_Fun, 0) ->
    false;
wait_until(Fun, Attempts) ->
    case Fun() of
        true -> true;
        false -> timer:sleep(10), wait_until(Fun, Attempts - 1)
    end.

setup_with_peer_sup() ->
    RegistryPid = setup(),
    stop_registered(vpn_peer_sup),
    {ok, PeerSupPid} = vpn_peer_sup:start_link(),
    {RegistryPid, PeerSupPid}.

cleanup_with_peer_sup({RegistryPid, PeerSupPid}) ->
    case is_process_alive(PeerSupPid) of
        true ->
            unlink(PeerSupPid),
            exit(PeerSupPid, shutdown),
            wait_until_stopped(PeerSupPid, 20);
        false -> ok
    end,
    cleanup(RegistryPid).

start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

init(Config) ->
    {ok, Config}.

handle_call(identity_info, _From, State = #{id := PeerId}) ->
    {reply, #{peer_id => PeerId,
              trusted => true,
              key_match => true,
              certificate => #{}}, State};
handle_call(config, _From, State) ->
    {reply, maps:with([id, mode, ifname, ip, remote_peer_id], State), State};
handle_call(stats, _From, State = #{id := PeerId}) ->
    {reply, #{id => PeerId, link => #{}}, State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.
