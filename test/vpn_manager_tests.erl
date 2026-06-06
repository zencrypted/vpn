-module(vpn_manager_tests).

-include_lib("eunit/include/eunit.hrl").

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

read_api_test_() ->
    {setup,
     fun start_peer_sup/0,
     fun stop_peer_sup/1,
     fun(_SupPid) ->
             [?_assertEqual([peer_a, peer_b], lists:sort(vpn_manager:list_peers())),
              ?_assertEqual([peer_a, peer_b], lists:sort(vpn_manager:running_peers())),
              ?_assertEqual(true, vpn_manager:peer_running(peer_a)),
              ?_assertMatch(#{id := peer_a,
                              identity := #{peer_id := peer_a},
                              config := #{id := peer_a}},
                            vpn_manager:peer_info(peer_a)),
              ?_assertMatch(#{id := peer_a,
                              link := #{tun_rx_packets := 0}},
                            vpn_manager:peer_stats(peer_a)),
              ?_assertEqual({error, not_found}, vpn_manager:peer_info(unknown_peer)),
              ?_assertEqual({error, not_found}, vpn_manager:peer_stats(unknown_peer)),
              ?_assertEqual({error, not_found}, vpn_manager:find_peer(unknown_peer))]
     end}.

lifecycle_test_() ->
    {setup,
     fun start_peer_sup/0,
     fun stop_peer_sup/1,
     fun(_SupPid) ->
             [?_assertEqual({error, already_started}, vpn_manager:start_peer(peer_a)),
              ?_assertEqual(ok, vpn_manager:stop_peer(peer_a)),
              ?_assertEqual([peer_b], vpn_manager:running_peers()),
              ?_assertEqual(false, vpn_manager:peer_running(peer_a)),
              ?_assertMatch({ok, Pid} when is_pid(Pid), vpn_manager:start_peer(peer_a)),
              ?_assertEqual([peer_a, peer_b], lists:sort(vpn_manager:running_peers())),
              ?_assertEqual({error, already_started}, vpn_manager:start_peer(peer_a)),
              ?_assertEqual({error, not_found}, vpn_manager:stop_peer(missing_peer)),
              ?_assertEqual({error, not_found}, vpn_manager:start_peer(missing_peer))]
     end}.

reload_config_test_() ->
    {setup,
     fun start_peer_sup/0,
     fun stop_peer_sup/1,
     fun(_SupPid) ->
             application:set_env(vpn, peers, [peer_config(peer_b), peer_config(peer_c)]),
             Reload1 = vpn_manager:reload_config(),
             application:set_env(vpn, peers, [peer_config(peer_b),
                                              peer_config(peer_c),
                                              failing_peer_config(peer_fail)]),
             Reload2 = vpn_manager:reload_config(),
             [?_assertEqual(#{started => [peer_c],
                              stopped => [peer_a],
                              failed => [],
                              unchanged => [peer_b]},
                            Reload1),
              ?_assertEqual([peer_b, peer_c], lists:sort(vpn_manager:running_peers())),
              ?_assertEqual(#{started => [],
                              stopped => [],
                              failed => [{peer_fail, test_start_failed}],
                              unchanged => [peer_b, peer_c]},
                            Reload2),
              ?_assertEqual([peer_b, peer_c], lists:sort(vpn_manager:running_peers()))]
     end}.

start_peer_sup() ->
    application:set_env(vpn, peers, peer_configs()),
    case vpn_peer_sup:start_link() of
        {ok, SupPid} ->
            SupPid;
        {error, {already_started, SupPid}} ->
            SupPid
    end.

stop_peer_sup(SupPid) ->
    case is_process_alive(SupPid) of
        true ->
            unlink(SupPid),
            exit(SupPid, shutdown),
            wait_until_stopped(SupPid, 20);
        false ->
            ok
    end,
    application:unset_env(vpn, peers),
    ok.

start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

init(Config) ->
    {ok, #{id => maps:get(id, Config),
           config => Config}}.

handle_call(identity_info, _From, State = #{id := PeerId}) ->
    {reply, #{peer_id => PeerId,
              certificate_path => "priv/certs/" ++ atom_to_list(PeerId) ++ ".crt",
              private_key_path => "priv/certs/" ++ atom_to_list(PeerId) ++ ".key"},
     State};
handle_call(config, _From, State = #{id := PeerId, config := Config}) ->
    {reply, maps:with([id, mode, ifname, ip], Config#{id => PeerId}), State};
handle_call(stats, _From, State = #{id := PeerId}) ->
    {reply, #{id => PeerId,
              link => #{tun_rx_packets => 0,
                        udp_tx_packets => 0}},
     State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Message, State) ->
    {noreply, State}.

peer_configs() ->
    [peer_config(peer_a), peer_config(peer_b)].

peer_config(PeerId) ->
    #{id => PeerId,
      peer_module => ?MODULE,
      mode => tun,
      ifname => list_to_binary(atom_to_list(PeerId)),
      ip => "10.20.20.1"}.

failing_peer_config(PeerId) ->
    (peer_config(PeerId))#{peer_module => vpn_manager_failing_peer}.

wait_until_stopped(_SupPid, 0) ->
    ok;
wait_until_stopped(SupPid, Attempts) ->
    case is_process_alive(SupPid) of
        false ->
            ok;
        true ->
            timer:sleep(10),
            wait_until_stopped(SupPid, Attempts - 1)
    end.
