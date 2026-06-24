-module(vpn_dynamic_pair_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

atomic_dynamic_provisioning_applies_revision_before_start_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-atomic-provision">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          Command = dynamic_command(Allocation,
                                                    1,
                                                    desired(DeviceId)),

                          {ok, First} =
                              vpn_provisioning:apply_dynamic(DeviceId, Command),
                          ?assertEqual(upsert, maps:get(operation, First)),
                          Pair = maps:get(pair, First),
                          ?assertEqual(reconciled, maps:get(outcome, Pair)),
                          ?assertEqual(established, maps:get(state, Pair)),
                          ?assertEqual(reserved,
                                       maps:get(allocation_state, Pair)),
                          ?assertNot(contains_key(private_key_path, First)),
                          ?assertNot(contains_key(ovpn_identity, First)),

                          {ok, ClientEntry1} = vpn_peer_registry:get(ClientId),
                          {ok, GatewayEntry1} = vpn_peer_registry:get(GatewayId),
                          lists:foreach(
                            fun(Entry) ->
                                    ?assertEqual(1, maps:get(revision, Entry)),
                                    ?assertEqual(ias,
                                                 maps:get(provisioning_source,
                                                          Entry)),
                                    ?assertEqual(upsert,
                                                 maps:get(
                                                   last_provisioning_operation,
                                                   Entry))
                            end,
                            [ClientEntry1, GatewayEntry1]),
                          ?assert(vpn_manager:peer_running(ClientId)),
                          ?assert(vpn_manager:peer_running(GatewayId)),
                          {ok, ClientPid1} = vpn_manager:find_peer(ClientId),
                          {ok, GatewayPid1} = vpn_manager:find_peer(GatewayId),

                          ?assertEqual(
                             {ok, unchanged},
                             vpn_provisioning:apply_dynamic(DeviceId, Command)),
                          ?assertEqual({ok, ClientPid1},
                                       vpn_manager:find_peer(ClientId)),
                          ?assertEqual({ok, GatewayPid1},
                                       vpn_manager:find_peer(GatewayId)),
                          Conflict = Command#{desired_state =>
                                                 (desired(DeviceId))#{
                                                     profile_id => other_profile}},
                          ?assertEqual(
                             {error, revision_conflict},
                             vpn_provisioning:apply_dynamic(DeviceId, Conflict)),

                          Command2 = dynamic_command(Allocation,
                                                     2,
                                                     desired(DeviceId)),
                          ?assertMatch(
                             {ok, #{operation := upsert}},
                             vpn_provisioning:apply_dynamic(DeviceId, Command2)),
                          {ok, ClientEntry2} = vpn_peer_registry:get(ClientId),
                          {ok, GatewayEntry2} = vpn_peer_registry:get(GatewayId),
                          ?assertEqual(2, maps:get(revision, ClientEntry2)),
                          ?assertEqual(2, maps:get(revision, GatewayEntry2)),
                          ?assertEqual(
                             {error, stale_revision},
                             vpn_provisioning:apply_dynamic(DeviceId, Command)),
                          ?assertEqual({ok, ClientPid1},
                                       vpn_manager:find_peer(ClientId)),
                          ?assertEqual({ok, GatewayPid1},
                                       vpn_manager:find_peer(GatewayId)),

                          Command3 = dynamic_command(
                                       Allocation,
                                       3,
                                       (desired(DeviceId))#{
                                           profile_id => other_profile}),
                          ?assertMatch(
                             {ok, #{operation := upsert}},
                             vpn_provisioning:apply_dynamic(DeviceId, Command3)),
                          {ok, ClientPid3} = vpn_manager:find_peer(ClientId),
                          {ok, GatewayPid3} = vpn_manager:find_peer(GatewayId),
                          ?assert(ClientPid3 =/= ClientPid1),
                          ?assertEqual(GatewayPid1, GatewayPid3),
                          {ok, ClientEntry3} = vpn_peer_registry:get(ClientId),
                          {ok, GatewayEntry3} = vpn_peer_registry:get(GatewayId),
                          ?assertEqual(3, maps:get(revision, ClientEntry3)),
                          ?assertEqual(3, maps:get(revision, GatewayEntry3)),
                          ?assertEqual(other_profile,
                                       maps:get(profile_id, ClientEntry3))
                      end)]
     end}.

atomic_dynamic_provisioning_rejects_invalid_bootstrap_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-invalid-atomic-provision">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          Zero = dynamic_command(Allocation,
                                                 0,
                                                 desired(DeviceId)),
                          ?assertEqual(
                             {error, dynamic_pair_positive_revision_required},
                             vpn_provisioning:apply_dynamic(DeviceId, Zero)),
                          Disable = Zero#{revision => 1,
                                         operation => disable},
                          ?assertEqual(
                             {error, dynamic_pair_upsert_required},
                             vpn_provisioning:apply_dynamic(DeviceId, Disable)),
                          WrongPeer = (dynamic_command(Allocation,
                                                       1,
                                                       desired(DeviceId)))#{
                                          peer_id => <<"wrong-client">>},
                          ?assertEqual(
                             {error,
                              {dynamic_pair_client_peer_mismatch,
                               ClientId,
                               <<"wrong-client">>}},
                             vpn_provisioning:apply_dynamic(DeviceId,
                                                            WrongPeer)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(ClientId)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(GatewayId)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(ClientId)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(GatewayId))
                      end)]
     end}.

atomic_dynamic_provisioning_failure_rolls_back_and_retries_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-atomic-rollback">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          {ok, Bundle} = application:get_env(
                                           vpn,
                                           dynamic_identity_test_bundle),
                          application:set_env(
                            vpn,
                            dynamic_identity_test_ensure_bundle,
                            Bundle),
                          application:unset_env(vpn,
                                                dynamic_identity_test_bundle),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          Command = dynamic_command(Allocation,
                                                    1,
                                                    desired(DeviceId)),
                          application:set_env(vpn,
                                              dynamic_pair_test_fail_role,
                                              client),

                          ?assertMatch(
                             {error,
                              {dynamic_pair_establishment_timeout, _}},
                             vpn_provisioning:apply_dynamic(DeviceId, Command)),
                          application:unset_env(vpn,
                                                dynamic_pair_test_fail_role),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(ClientId)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(GatewayId)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(ClientId)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(GatewayId)),
                          ?assertEqual(
                             {error, not_found},
                             vpn_dynamic_identity_factory_test_provider:lookup(
                               maps:get(allocation_id, Allocation))),

                          ?assertMatch(
                             {ok, #{operation := upsert}},
                             vpn_provisioning:apply_dynamic(DeviceId, Command)),
                          {ok, ClientEntry} = vpn_peer_registry:get(ClientId),
                          {ok, GatewayEntry} = vpn_peer_registry:get(GatewayId),
                          ?assertEqual(1, maps:get(revision, ClientEntry)),
                          ?assertEqual(1, maps:get(revision, GatewayEntry)),
                          ?assert(vpn_manager:peer_running(ClientId)),
                          ?assert(vpn_manager:peer_running(GatewayId)),

                          Update = dynamic_command(
                                     Allocation,
                                     2,
                                     (desired(DeviceId))#{
                                         profile_id => replacement_profile}),
                          application:set_env(vpn,
                                              dynamic_pair_test_fail_profile,
                                              replacement_profile),
                          ?assertMatch(
                             {error,
                              {dynamic_pair_establishment_timeout, _}},
                             vpn_provisioning:apply_dynamic(DeviceId, Update)),
                          application:unset_env(
                            vpn,
                            dynamic_pair_test_fail_profile),
                          {ok, RestoredClient} =
                              vpn_peer_registry:get(ClientId),
                          {ok, RestoredGateway} =
                              vpn_peer_registry:get(GatewayId),
                          ?assertEqual(1, maps:get(revision, RestoredClient)),
                          ?assertEqual(1, maps:get(revision, RestoredGateway)),
                          ?assertEqual(default_user,
                                       maps:get(profile_id, RestoredClient)),
                          ?assert(vpn_manager:peer_running(ClientId)),
                          ?assert(vpn_manager:peer_running(GatewayId)),
                          ?assertMatch(
                             {ok, #{operation := upsert}},
                             vpn_provisioning:apply_dynamic(DeviceId, Update)),
                          {ok, UpdatedClient} = vpn_peer_registry:get(ClientId),
                          {ok, UpdatedGateway} = vpn_peer_registry:get(GatewayId),
                          ?assertEqual(2, maps:get(revision, UpdatedClient)),
                          ?assertEqual(2, maps:get(revision, UpdatedGateway)),
                          ?assertEqual(replacement_profile,
                                       maps:get(profile_id, UpdatedClient))
                      end)]
     end}.

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
                          ?assertEqual(established, maps:get(state, Status)),
                          ?assertEqual(reserved,
                                       maps:get(allocation_state, Status)),
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
                          ?assertEqual(false,
                                       vpn_manager:peer_running(ClientId)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(GatewayId)),

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
                          ?assertEqual(stopped, maps:get(state, Status)),
                          ?assertEqual(reserved,
                                       maps:get(allocation_state, Status)),
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

active_pair_cannot_be_decommissioned_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-decommission-active">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          {ok, _} = vpn_dynamic_pair:ensure(DeviceId,
                                                            desired(DeviceId)),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),

                          ?assertMatch(
                             {error, {dynamic_pair_not_quiesced, _}},
                             vpn_dynamic_pair:decommission(DeviceId)),
                          ?assert(vpn_manager:peer_running(ClientId)),
                          ?assert(vpn_manager:peer_running(GatewayId)),
                          ?assertMatch({ok, _},
                                       vpn_peer_allocator:lookup(DeviceId)),
                          ?assertMatch({ok, _},
                                       vpn_peer_registry:get(ClientId)),
                          ?assertMatch({ok, _},
                                       vpn_peer_registry:get(GatewayId))
                      end)]
     end}.

disabled_pair_decommission_releases_runtime_and_allocation_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-decommission-disabled">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          {ok, _} = vpn_dynamic_pair:ensure(DeviceId,
                                                            desired(DeviceId)),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          AllocationId = maps:get(allocation_id, Allocation),
                          Disable = #{peer_id => ClientId,
                                      revision => 1,
                                      operation => disable,
                                      source => ias,
                                      desired_state => #{}},
                          ?assertMatch({ok, #{operation := disable}},
                                       vpn_provisioning:apply(Disable)),

                          {ok, Summary} =
                              vpn_dynamic_pair:decommission(DeviceId),
                          ?assertEqual(decommissioned, maps:get(state, Summary)),
                          ?assertEqual(released,
                                       maps:get(allocation_state, Summary)),
                          ?assertEqual(removed,
                                       maps:get(registry_state, Summary)),
                          ?assertEqual(retained,
                                       maps:get(identity_state, Summary)),
                          ?assertEqual(ClientId,
                                       maps:get(client_peer_id, Summary)),
                          ?assertEqual(GatewayId,
                                       maps:get(gateway_peer_id, Summary)),
                          ?assertNot(contains_key(private_key_path, Summary)),
                          ?assertNot(contains_key(ovpn_identity, Summary)),

                          ?assertEqual(false,
                                       vpn_manager:peer_running(ClientId)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(GatewayId)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(ClientId)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(GatewayId)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_allocator:lookup(DeviceId)),
                          ?assertMatch({ok, #{allocation_id := AllocationId}},
                                       vpn_dynamic_identity_factory_test_provider:lookup(
                                         AllocationId)),

                          Stale = #{peer_id => ClientId,
                                    revision => 0,
                                    operation => upsert,
                                    source => ias,
                                    desired_state => desired(DeviceId)},
                          ?assertEqual({error, stale_revision},
                                       vpn_provisioning:apply(Stale)),
                          Newer = Stale#{revision => 2},
                          ?assertEqual(
                             {error,
                              {dynamic_peer_allocation_required, DeviceId}},
                             vpn_provisioning:apply(Newer))
                      end)]
     end}.

revoked_pair_decommission_can_remove_identity_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-decommission-revoked">>,
                          {ok, Allocation} = vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          {ok, _} = vpn_dynamic_pair:ensure(DeviceId,
                                                            desired(DeviceId)),
                          ClientId = maps:get(client_peer_id, Allocation),
                          AllocationId = maps:get(allocation_id, Allocation),
                          Revoke = #{peer_id => ClientId,
                                     revision => 1,
                                     operation => revoke,
                                     source => ias,
                                     desired_state =>
                                         #{authorization_reason =>
                                               certificate_revoked}},
                          ?assertMatch({ok, #{operation := revoke}},
                                       vpn_provisioning:apply(Revoke)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(ClientId)),
                          ?assertEqual(false,
                                       vpn_manager:peer_running(
                                         maps:get(gateway_peer_id, Allocation))),

                          {ok, Summary} = vpn_dynamic_pair:decommission(
                                            DeviceId,
                                            #{remove_identity => true}),
                          ?assertEqual(removed,
                                       maps:get(identity_state, Summary)),
                          ?assertEqual({error, not_found},
                                       vpn_dynamic_identity_factory_test_provider:lookup(
                                         AllocationId)),
                          {ok, Replacement} =
                              vpn_peer_allocator:ensure(DeviceId),
                          ?assertNotEqual(AllocationId,
                                          maps:get(allocation_id, Replacement)),
                          ?assertNotEqual(ClientId,
                                          maps:get(client_peer_id, Replacement))
                      end)]
     end}.

reserved_allocation_can_be_decommissioned_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Context) ->
             [?_test(begin
                          DeviceId = <<"device-decommission-reserved">>,
                          {ok, _Allocation} =
                              vpn_peer_allocator:ensure(DeviceId),
                          {ok, Summary} = vpn_dynamic_pair:decommission(
                                            DeviceId,
                                            #{remove_identity => true}),
                          ?assertEqual(absent,
                                       maps:get(identity_state, Summary)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_allocator:lookup(DeviceId))
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

durable_pair_runtime_recovers_after_full_restart_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-runtime-recovery">>,
                          {ok, Allocation0} =
                              vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation0, Context),
                          Command = dynamic_command(
                                      Allocation0,
                                      1,
                                      desired(DeviceId)),
                          ?assertMatch(
                             {ok, #{operation := upsert,
                                    pair := #{state := established}}},
                             vpn_provisioning:apply_dynamic(
                               DeviceId,
                               Command)),
                          ClientId = maps:get(client_peer_id, Allocation0),
                          GatewayId = maps:get(gateway_peer_id, Allocation0),
                          ?assert(wait_until(
                                    fun() ->
                                            vpn_manager:peer_running(ClientId)
                                            andalso
                                            vpn_manager:peer_running(GatewayId)
                                    end,
                                    50)),

                          lists:foreach(
                            fun stop_registered_normal/1,
                            [vpn_provisioning,
                             vpn_peer_reconciler,
                             vpn_peer_sup,
                             vpn_peer_registry,
                             vpn_peer_allocator,
                             vpn_projection]),

                          try
                              {ok, _ProjectionPid} =
                                  vpn_projection:start_link(
                                    vpn_projection_test_store),
                              {ok, _AllocatorPid} =
                                  vpn_peer_allocator:start_link(),
                              {ok, Allocation1} =
                                  vpn_peer_allocator:lookup(DeviceId),
                              ?assertEqual(
                                 maps:get(allocation_id, Allocation0),
                                 maps:get(allocation_id, Allocation1)),

                              {ok, _RegistryPid} =
                                  vpn_peer_registry:start_link(),
                              Recovery =
                                  vpn_peer_registry:recovery_status(),
                              ?assertEqual(durable,
                                           maps:get(persistence, Recovery)),
                              ?assertEqual(1,
                                           maps:get(dynamic_pairs, Recovery)),
                              ?assertEqual(
                                 lists:sort([ClientId, GatewayId]),
                                 lists:sort(
                                   maps:get(restored_peers, Recovery))),

                              {ok, _ProvisioningPid} =
                                  vpn_provisioning:start_link(),
                              {ok, _PeerSupPid} =
                                  vpn_peer_sup:start_link(),
                              {ok, _ReconcilerPid} =
                                  vpn_peer_reconciler:start_link(),

                              ?assert(wait_until(
                                        fun() ->
                                                vpn_manager:peer_running(
                                                  ClientId)
                                                andalso
                                                vpn_manager:peer_running(
                                                  GatewayId)
                                        end,
                                        50)),
                              {ok, PairStatus} =
                                  vpn_dynamic_pair:status(DeviceId),
                              ?assertEqual(established,
                                           maps:get(state, PairStatus)),
                              {ok, ClientEntry} =
                                  vpn_peer_registry:get(ClientId),
                              {ok, GatewayEntry} =
                                  vpn_peer_registry:get(GatewayId),
                              ?assertEqual(1,
                                           maps:get(revision,
                                                    ClientEntry)),
                              ?assertEqual(1,
                                           maps:get(revision,
                                                    GatewayEntry)),
                              ?assertEqual(ias,
                                           maps:get(provisioning_source,
                                                    ClientEntry)),
                              ?assertEqual(upsert,
                                           maps:get(
                                             last_provisioning_operation,
                                             GatewayEntry))
                          after
                              lists:foreach(
                                fun stop_registered_normal/1,
                                [vpn_provisioning,
                                 vpn_peer_reconciler,
                                 vpn_peer_sup,
                                 vpn_peer_registry,
                                 vpn_peer_allocator,
                                 vpn_projection])
                          end
                      end)]
     end}.

decommissioned_pair_remains_suppressed_after_restart_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          DeviceId = <<"device-decommission-recovery">>,
                          {ok, Allocation} =
                              vpn_peer_allocator:ensure(DeviceId),
                          ok = install_identity_bundle(Allocation, Context),
                          ClientId = maps:get(client_peer_id, Allocation),
                          GatewayId = maps:get(gateway_peer_id, Allocation),
                          ?assertMatch(
                             {ok, #{operation := upsert}},
                             vpn_provisioning:apply_dynamic(
                               DeviceId,
                               dynamic_command(
                                 Allocation,
                                 1,
                                 desired(DeviceId)))),
                          ?assertMatch(
                             {ok, #{operation := disable}},
                             vpn_provisioning:apply(
                               #{peer_id => ClientId,
                                 revision => 2,
                                 operation => disable,
                                 source => ias,
                                 desired_state => #{}})),
                          ?assertMatch(
                             {ok, #{state := decommissioned}},
                             vpn_dynamic_pair:decommission(DeviceId)),

                          lists:foreach(
                            fun stop_registered_normal/1,
                            [vpn_provisioning,
                             vpn_peer_reconciler,
                             vpn_peer_sup,
                             vpn_peer_registry,
                             vpn_peer_allocator,
                             vpn_projection]),

                          try
                              {ok, _ProjectionPid} =
                                  vpn_projection:start_link(
                                    vpn_projection_test_store),
                              {ok, _AllocatorPid} =
                                  vpn_peer_allocator:start_link(),
                              ?assertEqual(
                                 {error, not_found},
                                 vpn_peer_allocator:lookup(DeviceId)),
                              ?assertMatch(
                                 {ok, #{state := released}},
                                 vpn_peer_allocator:released(DeviceId)),
                              {ok, _RegistryPid} =
                                  vpn_peer_registry:start_link(),
                              ?assertEqual({error, not_found},
                                           vpn_peer_registry:get(ClientId)),
                              ?assertEqual({error, not_found},
                                           vpn_peer_registry:get(GatewayId)),
                              Recovery =
                                  vpn_peer_registry:recovery_status(),
                              ?assertEqual(1,
                                           maps:get(released_pairs,
                                                    Recovery)),
                              ?assertEqual(
                                 lists:sort([ClientId, GatewayId]),
                                 lists:sort(
                                   maps:get(suppressed_peers, Recovery))),

                              stop_registered_normal(vpn_peer_registry),
                              {ok, Reallocated} =
                                  vpn_peer_allocator:ensure(DeviceId),
                              NewClientId =
                                  maps:get(client_peer_id, Reallocated),
                              NewGatewayId =
                                  maps:get(gateway_peer_id, Reallocated),
                              ?assertNotEqual(ClientId, NewClientId),
                              ?assertNotEqual(GatewayId, NewGatewayId),
                              stop_registered_normal(vpn_peer_allocator),
                              stop_registered_normal(vpn_projection),

                              {ok, _ProjectionPid2} =
                                  vpn_projection:start_link(
                                    vpn_projection_test_store),
                              {ok, _AllocatorPid2} =
                                  vpn_peer_allocator:start_link(),
                              ?assertEqual({ok, Reallocated},
                                           vpn_peer_allocator:lookup(
                                             DeviceId)),
                              ?assertEqual({error, not_found},
                                           vpn_peer_allocator:released(
                                             DeviceId)),
                              {ok, _RegistryPid2} =
                                  vpn_peer_registry:start_link(),
                              Recovery2 =
                                  vpn_peer_registry:recovery_status(),
                              ?assertEqual(1,
                                           maps:get(stale_dynamic_heads,
                                                    Recovery2)),
                              ?assertEqual({error, not_found},
                                           vpn_peer_registry:get(ClientId)),
                              ?assertEqual({error, not_found},
                                           vpn_peer_registry:get(NewClientId)),
                              ?assertEqual({error, not_found},
                                           vpn_peer_registry:get(NewGatewayId))
                          after
                              lists:foreach(
                                fun stop_registered_normal/1,
                                [vpn_peer_registry,
                                 vpn_peer_allocator,
                                 vpn_projection])
                          end
                      end)]
     end}.

invalid_request_test() ->
    ?assertEqual({error, invalid_dynamic_pair_request},
                 vpn_dynamic_pair:ensure(undefined, #{})),
    ?assertEqual({error, invalid_dynamic_pair_provision_request},
                 vpn_dynamic_pair:provision(undefined, #{}, #{})),
    ?assertEqual({error, invalid_dynamic_pair_provision_metadata},
                 vpn_dynamic_pair:provision(<<"device">>, #{}, #{})),
    ?assertEqual({error, invalid_device_id}, vpn_dynamic_pair:status(undefined)),
    ?assertEqual({error, invalid_dynamic_pair_decommission_request},
                 vpn_dynamic_pair:decommission(undefined, #{})),
    ?assertEqual({error, invalid_remove_identity_option},
                 vpn_dynamic_pair:decommission(<<"device">>,
                                               #{remove_identity => yes})),
    ?assertMatch({error, {unknown_decommission_options, [_]}},
                 vpn_dynamic_pair:decommission(<<"device">>,
                                               #{unknown => true})).

setup() ->
    stop_registered(vpn_provisioning),
    stop_registered(vpn_peer_reconciler),
    stop_registered(vpn_peer_sup),
    stop_registered(vpn_peer_registry),
    stop_registered(vpn_peer_allocator),
    stop_registered(vpn_projection),
    ok = vpn_projection_test_store:reset(),
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
    {ok, ProjectionPid} =
        vpn_projection:start_link(vpn_projection_test_store),
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
               AllocatorPid,
               ProjectionPid]}.

cleanup(#{root := Root, pids := Pids}) ->
    lists:foreach(fun stop_pid/1, Pids),
    lists:foreach(fun(Key) -> application:unset_env(vpn, Key) end,
                  [peers,
                   ovpn_sessions,
                   dynamic_peer_allocator,
                   runtime_config_resolver,
                   dynamic_identity_factory_module,
                   dynamic_identity_test_bundle,
                   dynamic_identity_test_ensure_bundle,
                   dynamic_runtime_config_defaults,
                   dynamic_pair_reconcile,
                   dynamic_pair_test_fail_role,
                   dynamic_pair_test_fail_profile]),
    ok = vpn_projection_test_store:reset(),
    remove_tree(Root),
    ok.

dynamic_command(Allocation, Revision, Desired) ->
    #{peer_id => maps:get(client_peer_id, Allocation),
      revision => Revision,
      operation => upsert,
      source => ias,
      desired_state => Desired}.

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

stop_registered_normal(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            ok = gen_server:stop(Pid, normal, 5000),
            wait_until_stopped(Pid, 50)
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
