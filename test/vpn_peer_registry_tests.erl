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
                                                            authorization_mode => policy,
                                                            authorized => true,
                                                            authorization_reason => profile_allows_vpn},
                          {ok, Added} = vpn_peer_registry:put(RuntimePeer),
                          ?assertMatch(#{id := peer_b,
                                         enabled := true,
                                         provisioning_source := runtime_api,
                                         device_id := <<"device-b">>,
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
              ?_assertEqual({error, invalid_peer_config}, vpn_peer_registry:put(not_a_map))]
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
    application:set_env(vpn, peers, [peer_config(peer_a)]),
    application:set_env(vpn, ovpn_sessions, []),
    {ok, Pid} = vpn_peer_registry:start_link(),
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
    application:unset_env(vpn, peers),
    application:unset_env(vpn, ovpn_sessions),
    ok.

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

config_ids(Configs) ->
    lists:sort([maps:get(id, Config) || Config <- Configs]).

contains_key(Key, Term) when is_map(Term) ->
    maps:is_key(Key, Term) orelse
        lists:any(fun(Value) -> contains_key(Key, Value) end, maps:values(Term));
contains_key(Key, Term) when is_list(Term) ->
    lists:any(fun(Value) -> contains_key(Key, Value) end, Term);
contains_key(_Key, _Term) ->
    false.


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
