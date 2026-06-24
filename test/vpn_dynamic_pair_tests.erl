-module(vpn_dynamic_pair_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

pair_is_registered_started_and_idempotent_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-dynamic-pair">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          Desired = desired(DeviceId),

                          {ok, First} = vpn_dynamic_pair:ensure(DeviceId, Desired),
                          ?assertEqual(reconciled, maps:get(outcome, First)),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          ?assertEqual([ClientId, GatewayId],
                                       lists:sort(vpn_manager:running_peers())),
                          ?assertMatch({ok, #{allocation_role := client,
                                              allocation_id := _}},
                                       vpn_peer_registry:get(ClientId)),
                          ?assertMatch({ok, #{allocation_role := gateway,
                                              allocation_id := _}},
                                       vpn_peer_registry:get(GatewayId)),
                          {ok, ClientPid1} = vpn_manager:find_peer(ClientId),
                          {ok, GatewayPid1} = vpn_manager:find_peer(GatewayId),

                          {ok, Second} = vpn_dynamic_pair:ensure(DeviceId, Desired),
                          ?assertEqual(unchanged, maps:get(outcome, Second)),
                          ?assertEqual({ok, ClientPid1}, vpn_manager:find_peer(ClientId)),
                          ?assertEqual({ok, GatewayPid1}, vpn_manager:find_peer(GatewayId)),

                          {ok, Status} = vpn_dynamic_pair:status(DeviceId),
                          ?assertMatch(#{client := #{running := true,
                                                    handshake_status := established},
                                         gateway := #{running := true,
                                                     handshake_status := established}},
                                       Status),
                          ?assertNot(contains_key(private_key_path, Status)),
                          ?assertNot(contains_key(ovpn_identity, Status)),

                          SummaryPeers = maps:get(peers, vpn_admin:summary()),
                          ClientSummary = summary_peer(ClientId, SummaryPeers),
                          GatewaySummary = summary_peer(GatewayId, SummaryPeers),
                          ?assertEqual(maps:get(allocation_id, Allocation),
                                       maps:get(allocation_id, ClientSummary)),
                          ?assertEqual(client, maps:get(allocation_role, ClientSummary)),
                          ?assertEqual(gateway, maps:get(allocation_role, GatewaySummary))
                      end)]
     end}.

revision_only_provisioning_preserves_established_pair_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-revision-update">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          {ok, _} = vpn_dynamic_pair:ensure(DeviceId,
                                                            desired(DeviceId)),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          {ok, ClientPid1} = vpn_manager:find_peer(ClientId),
                          {ok, GatewayPid1} = vpn_manager:find_peer(GatewayId),
                          EventsBefore = maps:get(events_received,
                                                  vpn_peer_reconciler:status()),

                          Command = #{peer_id => ClientId,
                                      revision => 1,
                                      operation => upsert,
                                      source => ias,
                                      desired_state => desired(DeviceId)},
                          {ok, #{operation := upsert}} =
                              vpn_provisioning:apply(Command),
                          ?assert(wait_until(fun() ->
                                                    Status0 =
                                                        vpn_peer_reconciler:status(),
                                                    maps:get(events_received, Status0) >
                                                        EventsBefore
                                            end,
                                            50)),

                          ?assertEqual({ok, ClientPid1},
                                       vpn_manager:find_peer(ClientId)),
                          ?assertEqual({ok, GatewayPid1},
                                       vpn_manager:find_peer(GatewayId)),
                          {ok, Status} = vpn_dynamic_pair:status(DeviceId),
                          ?assertMatch(#{client := #{running := true,
                                                    handshake_status := established},
                                         gateway := #{running := true,
                                                     handshake_status := established}},
                                       Status),
                          {ok, ClientEntry} = vpn_peer_registry:get(ClientId),
                          ?assertEqual(1, maps:get(revision, ClientEntry)),
                          ?assertEqual(ias,
                                       maps:get(provisioning_source,
                                                ClientEntry)),
                          ?assertEqual(upsert,
                                       maps:get(last_provisioning_operation,
                                                ClientEntry)),
                          ReconcileStatus = vpn_peer_reconciler:status(),
                          ?assertEqual([ClientId],
                                       maps:get(unchanged,
                                                maps:get(last_result,
                                                         ReconcileStatus)))
                      end)]
     end}.

pair_aware_revoke_quiesces_gateway_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-pair-revoke">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          {ok, _} = vpn_dynamic_pair:ensure(DeviceId,
                                                            desired(DeviceId)),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          ?assert(vpn_manager:peer_running(ClientId)),
                          ?assert(vpn_manager:peer_running(GatewayId)),

                          Command = #{peer_id => ClientId,
                                      revision => 1,
                                      operation => revoke,
                                      source => ias,
                                      desired_state =>
                                          #{authorization_reason =>
                                                certificate_revoked}},
                          ?assertMatch({ok, #{operation := revoke}},
                                       vpn_provisioning:apply(Command)),
                          ?assert(wait_until(fun() ->
                                                    not vpn_manager:peer_running(
                                                          GatewayId) andalso
                                                    not vpn_manager:peer_running(
                                                          ClientId)
                                            end,
                                            50)),

                          {ok, ClientEntry} = vpn_peer_registry:get(ClientId),
                          ?assertEqual(false, maps:get(enabled, ClientEntry)),
                          ?assertEqual(false, maps:get(authorized, ClientEntry)),
                          ?assertEqual(true, maps:get(revoked, ClientEntry)),
                          ?assertEqual(certificate_revoked,
                                       maps:get(authorization_reason,
                                                ClientEntry)),

                          {ok, GatewayEntry} = vpn_peer_registry:get(GatewayId),
                          ?assertEqual(false, maps:get(enabled, GatewayEntry)),
                          ?assertEqual(true, maps:get(authorized, GatewayEntry)),
                          ?assertEqual(false, maps:get(revoked, GatewayEntry)),

                          {ok, Status} = vpn_dynamic_pair:status(DeviceId),
                          ?assertMatch(#{client := #{running := false},
                                         gateway := #{running := false}},
                                       Status)
                      end)]
     end}.

pair_aware_disable_and_enable_controls_both_peers_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-pair-lifecycle">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          {ok, _} = vpn_dynamic_pair:ensure(DeviceId,
                                                            desired(DeviceId)),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),

                          Disable = #{peer_id => ClientId,
                                      revision => 1,
                                      operation => disable,
                                      source => ias,
                                      desired_state => #{}},
                          ?assertMatch({ok, #{operation := disable}},
                                       vpn_provisioning:apply(Disable)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(GatewayId)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(ClientId)),
                          {ok, DisabledClient} =
                              vpn_peer_registry:get(ClientId),
                          {ok, DisabledGateway} =
                              vpn_peer_registry:get(GatewayId),
                          ?assertEqual(false,
                                       maps:get(enabled, DisabledClient)),
                          ?assertEqual(false,
                                       maps:get(enabled, DisabledGateway)),
                          ?assertEqual(true,
                                       maps:get(authorized, DisabledClient)),
                          ?assertEqual(true,
                                       maps:get(authorized, DisabledGateway)),
                          ?assertEqual(false,
                                       maps:get(revoked, DisabledClient)),
                          ?assertEqual(false,
                                       maps:get(revoked, DisabledGateway)),

                          Enable = #{peer_id => ClientId,
                                     revision => 2,
                                     operation => enable,
                                     source => ias,
                                     desired_state => #{}},
                          ?assertMatch({ok, #{operation := enable}},
                                       vpn_provisioning:apply(Enable)),
                          ?assert(vpn_manager:peer_running(GatewayId)),
                          ?assert(vpn_manager:peer_running(ClientId)),
                          {ok, EnabledClient} =
                              vpn_peer_registry:get(ClientId),
                          {ok, EnabledGateway} =
                              vpn_peer_registry:get(GatewayId),
                          ?assertEqual(true, maps:get(enabled, EnabledClient)),
                          ?assertEqual(true, maps:get(enabled, EnabledGateway)),
                          {ok, Status} = vpn_dynamic_pair:status(DeviceId),
                          ?assertMatch(#{client := #{running := true,
                                                    handshake_status := established},
                                         gateway := #{running := true,
                                                     handshake_status := established}},
                                       Status)
                      end)]
     end}.

pair_aware_enable_failure_rolls_back_both_peers_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-pair-enable-rollback">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          {ok, _} = vpn_dynamic_pair:ensure(DeviceId,
                                                            desired(DeviceId)),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          Disable = #{peer_id => ClientId,
                                      revision => 1,
                                      operation => disable,
                                      source => ias,
                                      desired_state => #{}},
                          ?assertMatch({ok, #{operation := disable}},
                                       vpn_provisioning:apply(Disable)),

                          application:set_env(vpn,
                                              dynamic_pair_test_fail_role,
                                              client),
                          Enable = #{peer_id => ClientId,
                                     revision => 2,
                                     operation => enable,
                                     source => ias,
                                     desired_state => #{}},
                          ?assertMatch(
                             {error,
                              {dynamic_pair_establishment_timeout, _}},
                             vpn_provisioning:apply(Enable)),
                          application:unset_env(vpn,
                                                dynamic_pair_test_fail_role),

                          ?assertEqual(false,
                                       vpn_manager:peer_running(GatewayId)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(ClientId)),
                          {ok, ClientEntry} = vpn_peer_registry:get(ClientId),
                          {ok, GatewayEntry} = vpn_peer_registry:get(GatewayId),
                          ?assertEqual(false, maps:get(enabled, ClientEntry)),
                          ?assertEqual(false, maps:get(enabled, GatewayEntry)),
                          ?assertEqual(1, maps:get(revision, ClientEntry)),
                          ?assertEqual(false, maps:get(revoked, ClientEntry)),
                          ?assertEqual(false, maps:get(revoked, GatewayEntry))
                      end)]
     end}.

pair_aware_enable_fails_closed_without_gateway_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-pair-missing-gateway">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          {ok, _} = vpn_dynamic_pair:ensure(DeviceId,
                                                            desired(DeviceId)),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          Disable = #{peer_id => ClientId,
                                      revision => 1,
                                      operation => disable,
                                      source => ias,
                                      desired_state => #{}},
                          ?assertMatch({ok, #{operation := disable}},
                                       vpn_provisioning:apply(Disable)),
                          ok = vpn_peer_registry:remove(GatewayId),

                          Enable = #{peer_id => ClientId,
                                     revision => 2,
                                     operation => enable,
                                     source => ias,
                                     desired_state => #{}},
                          ?assertEqual(
                             {error,
                              {dynamic_pair_gateway_not_found, GatewayId}},
                             vpn_provisioning:apply(Enable)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(ClientId)),
                          {ok, ClientEntry} = vpn_peer_registry:get(ClientId),
                          ?assertEqual(false, maps:get(enabled, ClientEntry)),
                          ?assertEqual(1, maps:get(revision, ClientEntry)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(GatewayId))
                      end)]
     end}.

registry_collision_is_rejected_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-collision">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          {ok, Pair} = vpn_runtime_config_resolver:resolve_pair(
                                         DeviceId, desired(DeviceId)),
                          Client = maps:get(client, Pair),
                          ClientId = maps:get(id, Client),
                          {ok, _} = vpn_peer_registry:put(
                                      Client#{allocation_id => <<"other-allocation">>}),
                          ?assertEqual({error,
                                        {dynamic_peer_registry_collision, ClientId}},
                                       vpn_dynamic_pair:ensure(DeviceId,
                                                               desired(DeviceId)))
                      end)]
     end}.

failed_pair_start_rolls_registry_back_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-start-failure">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          application:set_env(vpn,
                                              dynamic_pair_test_fail_role,
                                              gateway),
                          Result = vpn_dynamic_pair:ensure(DeviceId, desired(DeviceId)),
                          ?assertMatch({error,
                                        {dynamic_pair_establishment_timeout, _}},
                                       Result),
                          ?assert(wait_until(fun() ->
                                                    vpn_manager:running_peers() =:= []
                                            end,
                                            50)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(ClientId)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(GatewayId))
                      end)]
     end}.

invalid_request_test() ->
    ?assertEqual({error, invalid_dynamic_pair_request},
                 vpn_dynamic_pair:ensure(undefined, #{})),
    ?assertEqual({error, invalid_device_id}, vpn_dynamic_pair:status(undefined)).

setup() ->
    stop_registered(vpn_provisioning),
    stop_registered(vpn_peer_reconciler),
    stop_registered(vpn_peer_sup),
    stop_registered(vpn_peer_registry),
    stop_registered(vpn_peer_allocator),
    Root = temp_root(),
    application:set_env(vpn, peers, []),
    application:set_env(vpn, ovpn_sessions, []),
    application:set_env(vpn,
                        dynamic_peer_allocator,
                        #{capacity => 4,
                          first_host => 70,
                          client_network => {10, 70, 0},
                          gateway_network => {10, 71, 0},
                          client_udp_port_base => 26000,
                          gateway_udp_port_base => 27000}),
    application:set_env(vpn, runtime_config_resolver, dynamic_allocator),
    application:set_env(vpn,
                        dynamic_identity_factory_module,
                        vpn_dynamic_identity_factory_test_provider),
    application:set_env(vpn,
                        dynamic_runtime_config_defaults,
                        #{common => #{peer_module => vpn_dynamic_pair_test_peer,
                                      mode => tun,
                                      handshake_mode => certificate_control,
                                      authorization_mode => development_bypass,
                                      authorized => true,
                                      authorization_reason => dynamic_pair_test,
                                      previous_epoch_grace_ms => 5000},
                          client => #{name => <<"Dynamic client">>},
                          gateway => #{name => <<"Dynamic gateway">>}}),
    application:set_env(vpn,
                        dynamic_pair_reconcile,
                        #{establish_timeout_ms => 500,
                          poll_interval_ms => 5}),
    {ok, AllocatorPid} = vpn_peer_allocator:start_link(),
    {ok, RegistryPid} = vpn_peer_registry:start_link(),
    {ok, PeerSupPid} = vpn_peer_sup:start_link(),
    {ok, ReconcilerPid} = vpn_peer_reconciler:start_link(),
    {ok, ProvisioningPid} = vpn_provisioning:start_link(),
    #{root => Root,
      pids => [ProvisioningPid,
               ReconcilerPid,
               PeerSupPid,
               RegistryPid,
               AllocatorPid]}.

cleanup(#{root := Root, pids := Pids}) ->
    lists:foreach(fun stop_pid/1, Pids),
    lists:foreach(fun(Key) -> application:unset_env(vpn, Key) end,
                  [peers,
                   ovpn_sessions,
                   dynamic_peer_allocator,
                   runtime_config_resolver,
                   dynamic_identity_factory_module,
                   dynamic_identity_test_bundle,
                   dynamic_runtime_config_defaults,
                   dynamic_pair_reconcile,
                   dynamic_pair_test_fail_role]),
    remove_tree(Root),
    ok.

desired(DeviceId) ->
    #{device_id => DeviceId,
      profile_id => default_user,
      authorization_mode => policy,
      authorized => true,
      authorization_reason => profile_allows_vpn,
      enabled => true,
      revoked => false}.

install_identity_bundle(Allocation, #{root := Root}) ->
    KeysDir = filename:join(Root, "keys"),
    ok = filelib:ensure_dir(filename:join(KeysDir, "placeholder")),
    ClientKey = filename:join(KeysDir, "client.key"),
    ok = copy_fixture("peer_a.key", ClientKey),
    ok = file:change_mode(ClientKey, 8#600),
    OvpnPath = filename:join(Root, "client.ovpn"),
    {ok, CaPem} = file:read_file(fixture_path("ca.crt")),
    {ok, CertPem} = file:read_file(fixture_path("peer_a.crt")),
    RemotePort = integer_to_binary(
                   maps:get(local_udp_port, maps:get(gateway, Allocation))),
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
    application:set_env(vpn, dynamic_identity_test_bundle, Bundle),
    ok.

fixture_path(Name) ->
    filename:join([code:priv_dir(vpn), "certs", Name]).

copy_fixture(Name, Destination) ->
    {ok, Binary} = file:read_file(fixture_path(Name)),
    file:write_file(Destination, Binary).

temp_root() ->
    Root = filename:join(os:getenv("TMPDIR", "/tmp"),
                         lists:flatten(io_lib:format(
                           "vpn-dynamic-pair-~p",
                           [erlang:unique_integer([positive, monotonic])]))),
    ok = file:make_dir(Root),
    Root.

summary_peer(PeerId, Peers) ->
    hd([Peer || #{id := Id} = Peer <- Peers, Id =:= PeerId]).

contains_key(Key, Term) when is_map(Term) ->
    maps:is_key(Key, Term) orelse
    lists:any(fun(Value) -> contains_key(Key, Value) end, maps:values(Term));
contains_key(Key, Term) when is_list(Term) ->
    lists:any(fun(Value) -> contains_key(Key, Value) end, Term);
contains_key(_Key, _Term) ->
    false.

wait_until(_Fun, 0) ->
    false;
wait_until(Fun, Attempts) ->
    case Fun() of
        true -> true;
        false -> timer:sleep(10), wait_until(Fun, Attempts - 1)
    end.

stop_registered(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> stop_pid(Pid)
    end.

stop_pid(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            exit(Pid, shutdown),
            wait_until_stopped(Pid, 50);
        false -> ok
    end.

wait_until_stopped(_Pid, 0) ->
    ok;
wait_until_stopped(Pid, Attempts) ->
    case is_process_alive(Pid) of
        false -> ok;
        true -> timer:sleep(10), wait_until_stopped(Pid, Attempts - 1)
    end.

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
