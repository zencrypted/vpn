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

certificate_inventory_test_() ->
    {setup,
     fun start_peer_sup/0,
     fun stop_peer_sup/1,
     fun(_SupPid) ->
             [?_test(begin
                          ?assertMatch(#{peer_id := peer_a,
                                         running := true,
                                         trusted := true,
                                         key_match := true,
                                         subject := {subject, peer_a},
                                         issuer := {issuer, peer_a},
                                         serial_number := 1001,
                                         certificate_path := "priv/certs/peer_a.crt"},
                                       vpn_manager:certificate_info(peer_a)),
                          ?assertMatch(#{peer_id := peer_b,
                                         running := true,
                                         trusted := true,
                                         key_match := true,
                                         subject := {subject, peer_b},
                                         issuer := {issuer, peer_b},
                                         serial_number := 1002},
                                       vpn_manager:certificate_info(peer_b)),
                          ?assertEqual({error, not_found},
                                       vpn_manager:certificate_info(unknown_peer)),
                          Certificates = vpn_manager:certificates(),
                          ?assertEqual([peer_a, peer_b],
                                       lists:sort([maps:get(peer_id, Entry)
                                                   || Entry <- Certificates])),
                          ?assertEqual(ok, vpn_manager:stop_peer(peer_a)),
                          ?assertMatch(#{peer_id := peer_a,
                                         running := false,
                                         trusted := true,
                                         key_match := true,
                                         subject := _Subject,
                                         issuer := _Issuer,
                                         serial_number := _Serial,
                                         certificate_path := "priv/certs/peer_a.crt"},
                                       vpn_manager:certificate_info(peer_a)),
                          application:set_env(vpn, peers, [invalid_cert_peer_config(peer_bad)]),
                          ?assertMatch(#{peer_id := peer_bad,
                                         running := false,
                                         error := {certificate_read_failed,
                                                   "priv/certs/missing-peer.crt",
                                                   enoent}},
                                       vpn_manager:certificate_info(peer_bad))
                      end)]
     end}.

status_test_() ->
    {setup,
     fun start_peer_sup/0,
     fun stop_peer_sup/1,
     fun(_SupPid) ->
             [?_test(begin
                          ?assertEqual([peer_a, peer_b], vpn_manager:list_peers()),
                          ?assertMatch(#{configured := [peer_a, peer_b],
                                         running := [peer_a, peer_b],
                                         peers := #{peer_a := #{running := true,
                                                               identity := #{peer_id := peer_a},
                                                               stats := #{id := peer_a},
                                                               certificate := #{subject := {subject, peer_a},
                                                                                trusted := true,
                                                                                key_match := true}},
                                                    peer_b := #{running := true}}},
                                       vpn_manager:status()),
                          ?assertMatch(#{running := true,
                                         identity := #{peer_id := peer_a},
                                         config := #{id := peer_a},
                                         stats := #{id := peer_a}},
                                       vpn_manager:peer_status(peer_a)),
                          ?assertEqual(ok, vpn_manager:stop_peer(peer_a)),
                          ?assertEqual(#{running => false}, vpn_manager:peer_status(peer_a)),
                          ?assertMatch(#{configured := [peer_a, peer_b],
                                         running := [peer_b],
                                         peers := #{peer_a := #{running := false},
                                                    peer_b := #{running := true}}},
                                       vpn_manager:status()),
                          application:set_env(vpn, peers, [peer_config(peer_b),
                                                           peer_config(peer_c)]),
                          ?assertMatch(#{configured := [peer_b, peer_c],
                                         running := [peer_b],
                                         peers := #{peer_b := #{running := true},
                                                    peer_c := #{running := false}}},
                                       vpn_manager:status())
                      end)]
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
             [?_test(begin
                          application:set_env(vpn, peers, [peer_config(peer_b),
                                                           peer_config(peer_c)]),
                          Reload1 = vpn_manager:reload_config(),
                          ?assertEqual(#{started => [peer_c],
                                         stopped => [peer_a],
                                         failed => [],
                                         unchanged => [peer_b]},
                                       Reload1),
                          ?assertEqual([peer_b, peer_c],
                                       lists:sort(vpn_manager:running_peers())),

                          application:set_env(vpn, peers, [peer_config(peer_b),
                                                           peer_config(peer_c),
                                                           failing_peer_config(peer_fail)]),
                          Reload2 = vpn_manager:reload_config(),
                          ?assertEqual(#{started => [],
                                         stopped => [],
                                         failed => [{peer_fail, test_start_failed}],
                                         unchanged => [peer_b, peer_c]},
                                       Reload2),
                          ?assertEqual([peer_b, peer_c],
                                       lists:sort(vpn_manager:running_peers()))
                      end)]
     end}.

admin_facade_test_() ->
    {setup,
     fun start_peer_sup/0,
     fun stop_peer_sup/1,
     fun(_SupPid) ->
             [?_test(begin
                          ?assertMatch(#{status := #{configured := [peer_a, peer_b],
                                                     running := [peer_a, peer_b]},
                                         certificates := [_ | _]},
                                       vpn_admin:dashboard()),
                          ?assertEqual(#{configured_peers => 2,
                                         running_peers => 2,
                                         stopped_peers => 0,
                                         certificates => 2},
                                       vpn_admin:overview()),
                          ?assertEqual(#{configured => 2,
                                         running => 2,
                                         stopped => 0},
                                       vpn_admin:peer_counts()),
                          Summary1 = vpn_admin:summary(),
                          ?assertMatch(#{counts := #{configured := 2,
                                                     running := 2,
                                                     stopped := 0,
                                                     certificates := 2},
                                         peers := [_ | _]},
                                       Summary1),
                          SummaryPeers1 = maps:get(peers, Summary1),
                          ?assertEqual([peer_a, peer_b],
                                       lists:sort([maps:get(id, Peer)
                                                   || Peer <- SummaryPeers1])),
                          PeerA1 = summary_peer(peer_a, SummaryPeers1),
                          ?assertMatch(#{id := peer_a,
                                         running := true,
                                         mode := tun,
                                         ip := "10.20.20.1",
                                         remote_peer_id := peer_b,
                                         crypto_failures := 7,
                                         frames_rejected := 3,
                                         certificate := #{subject := {subject, peer_a},
                                                          issuer := {issuer, peer_a},
                                                          trusted := true,
                                                          key_match := true,
                                                          not_after := {utcTime, "270606000000Z"}}},
                                       PeerA1),
                          ?assertNot(summary_contains_key(private_key_path, PeerA1)),
                          ?assertNot(summary_contains_key(psk, PeerA1)),
                          ?assertEqual(ok, vpn_manager:stop_peer(peer_a)),
                          ?assertEqual(#{configured_peers => 2,
                                         running_peers => 1,
                                         stopped_peers => 1,
                                         certificates => 2},
                                       vpn_admin:overview()),
                          ?assertEqual(#{configured => 2,
                                         running => 1,
                                         stopped => 1},
                                       vpn_admin:peer_counts()),
                          PeerA2 = summary_peer(peer_a, maps:get(peers, vpn_admin:summary())),
                          ?assertEqual(false, maps:get(running, PeerA2))
                      end)]
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
              private_key_path => "priv/certs/" ++ atom_to_list(PeerId) ++ ".key",
              trusted => true,
              key_match => true,
              certificate => #{subject => {subject, PeerId},
                               issuer => {issuer, PeerId},
                               serial_number => serial_number(PeerId),
                               not_before => {utcTime, "260606000000Z"},
                               not_after => {utcTime, "270606000000Z"}}},
     State};
handle_call(config, _From, State = #{id := PeerId, config := Config}) ->
    {reply, maps:with([id, mode, ifname, ip, remote_peer_id], Config#{id => PeerId}), State};
handle_call(stats, _From, State = #{id := PeerId}) ->
    {reply, #{id => PeerId,
              link => #{tun_rx_packets => 0,
                        udp_tx_packets => 0,
                        crypto_failures => crypto_failures(PeerId),
                        frames_rejected => frames_rejected(PeerId)}},
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
      ip => "10.20.20.1",
      remote_peer_id => remote_peer_id(PeerId),
      psk => <<"test-psk-should-not-leak">>,
      certificate_path => certificate_path(PeerId),
      private_key_path => private_key_path(PeerId),
      ca_certificate_path => "priv/certs/ca.crt"}.

failing_peer_config(PeerId) ->
    (peer_config(PeerId))#{peer_module => vpn_manager_failing_peer}.

invalid_cert_peer_config(PeerId) ->
    (peer_config(PeerId))#{certificate_path => "priv/certs/missing-peer.crt"}.

serial_number(peer_a) ->
    1001;
serial_number(peer_b) ->
    1002;
serial_number(_PeerId) ->
    9999.

certificate_path(peer_a) ->
    "priv/certs/peer_a.crt";
certificate_path(peer_b) ->
    "priv/certs/peer_b.crt";
certificate_path(_PeerId) ->
    "priv/certs/peer_a.crt".

private_key_path(peer_a) ->
    "priv/certs/peer_a.key";
private_key_path(peer_b) ->
    "priv/certs/peer_b.key";
private_key_path(_PeerId) ->
    "priv/certs/peer_a.key".

remote_peer_id(peer_a) ->
    peer_b;
remote_peer_id(peer_b) ->
    peer_a;
remote_peer_id(_PeerId) ->
    undefined.

crypto_failures(peer_a) ->
    7;
crypto_failures(_PeerId) ->
    0.

frames_rejected(peer_a) ->
    3;
frames_rejected(_PeerId) ->
    0.

summary_peer(PeerId, Peers) ->
    hd([Peer || #{id := Id} = Peer <- Peers, Id =:= PeerId]).

summary_contains_key(Key, Map) when is_map(Map) ->
    maps:is_key(Key, Map) orelse lists:any(fun(Value) -> summary_contains_key(Key, Value) end,
                                           maps:values(Map));
summary_contains_key(Key, Values) when is_list(Values) ->
    lists:any(fun(Value) -> summary_contains_key(Key, Value) end, Values);
summary_contains_key(_Key, _Value) ->
    false.

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
