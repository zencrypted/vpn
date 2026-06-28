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
                          ?assertEqual(10, maps:get(commands_received, Status)),
                          ?assertEqual(5, maps:get(commands_applied, Status)),
                          ?assertEqual(1, maps:get(commands_unchanged, Status)),
                          ?assertEqual(4, maps:get(commands_rejected, Status)),
                          ?assertEqual(2, maps:get(stale_revisions, Status)),
                          ?assertEqual(1, maps:get(revocations, Status)),
                          History = vpn_provisioning:history(peer_a),
                          ?assert(length(History) >= 10),
                          ?assert(lists:any(
                                    fun(#{operation := enable, revision := 4,
                                          result := {error, revoked}}) -> true;
                                       (_) -> false
                                    end, History))
                      end)]
     end}.


orphan_decommission_compare_and_remove_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             [?_test(begin
                          Command = command(
                                      1,
                                      upsert,
                                      #{device_id => <<"safe-device">>,
                                        enabled => false,
                                        authorized => true,
                                        recovery_manifest =>
                                            valid_recovery_manifest()}),
                          ?assertMatch({ok, #{operation := upsert}},
                                       vpn_provisioning:apply(Command)),
                          Request = orphan_decommission_request(
                                      <<"safe-device">>),
                          Foreign = (peer_config(peer_b))#{
                                      device_id => <<"foreign-device">>,
                                      provisioning_source => ias},
                          {ok, _} = vpn_peer_registry:put(Foreign),
                          Unsafe = Request#{expected_peer_ids =>
                                               [peer_a, peer_b]},
                          ?assertEqual(
                             {error,
                              {orphan_registry_removal_failed,
                               {peer_ownership_conflict, peer_b}}},
                             vpn_provisioning:decommission_orphan(Unsafe)),
                          ?assertMatch({ok, _},
                                       vpn_peer_registry:get(peer_a)),
                          ?assertMatch({ok, _},
                                       vpn_peer_registry:get(peer_b)),
                          ok = vpn_peer_registry:remove(peer_b),
                          [ExpectedHead] = maps:get(expected_heads, Request),
                          Stale = Request#{expected_heads =>
                                              [ExpectedHead#{digest =>
                                                   crypto:strong_rand_bytes(32)}]},
                          ?assertEqual({error, orphan_snapshot_conflict},
                                       vpn_provisioning:decommission_orphan(Stale)),
                          ?assertMatch({ok, #{outcome := decommissioned,
                                             device_id := <<"safe-device">>}},
                                       vpn_provisioning:decommission_orphan(Request)),
                          ?assertEqual({error, not_found},
                                       vpn_peer_registry:get(peer_a)),
                          {ok, HeadsAfter} = vpn_provisioning:recovery_heads(),
                          ?assertEqual(false, maps:is_key(peer_a, HeadsAfter)),
                          ?assertMatch({ok, #{outcome := already_absent}},
                                       vpn_provisioning:decommission_orphan(Request))
                      end)]
     end}.

orphan_decommission_request_validation_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             [?_assertEqual({error, invalid_orphan_decommission_request},
                            vpn_provisioning:decommission_orphan(#{})),
              ?_assertEqual({error, invalid_orphan_decommission_request},
                            vpn_provisioning:decommission_orphan(not_a_map))]
     end}.

authorization_metadata_normalization_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             [?_test(begin
                          Policy = command(1, upsert,
                                           #{authorization_mode => policy,
                                             authorized => true}),
                          ?assertMatch({ok, #{operation := upsert}},
                                       vpn_provisioning:apply(Policy)),
                          {ok, PolicyEntry} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(policy, maps:get(authorization_mode, PolicyEntry)),
                          ?assertEqual(true, maps:get(authorized, PolicyEntry)),
                          ?assertEqual(undefined,
                                       maps:get(authorization_reason, PolicyEntry)),

                          ExplicitReason = command(2, upsert,
                                                   #{authorized => false,
                                                     authorization_reason => denied_by_policy}),
                          ?assertMatch({ok, #{operation := upsert}},
                                       vpn_provisioning:apply(ExplicitReason)),
                          {ok, DeniedEntry} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(false, maps:get(authorized, DeniedEntry)),
                          ?assertEqual(denied_by_policy,
                                       maps:get(authorization_reason, DeniedEntry))
                      end)]
     end}.

revoke_reason_and_rejected_history_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             [?_test(begin
                          Revoke = command(1, revoke,
                                           #{authorization_reason => certificate_revoked}),
                          ?assertMatch({ok, #{operation := revoke}},
                                       vpn_provisioning:apply(Revoke)),
                          {ok, RevokedEntry} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(certificate_revoked,
                                       maps:get(authorization_reason, RevokedEntry)),

                          ?assertEqual({error, revoked},
                                       vpn_provisioning:apply(command(2, enable, #{}))),
                          [Rejected | _] = vpn_provisioning:history(peer_a),
                          ?assertEqual(enable, maps:get(operation, Rejected)),
                          ?assertEqual(2, maps:get(revision, Rejected)),
                          ?assertEqual({error, revoked}, maps:get(result, Rejected))
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

runtime_secret_material_is_not_persisted_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             [?_test(begin
                          Command = new_peer_command(
                                      1,
                                      upsert,
                                      #{runtime_config => peer_config(peer_b),
                                        device_id => <<"safe-device">>,
                                        enabled => false,
                                        authorized => true,
                                        recovery_manifest => valid_recovery_manifest()}),
                          ?assertMatch({ok, #{operation := upsert}},
                                       vpn_provisioning:apply(Command)),
                          {ok, _Version,
                           #{provisioning :=
                                 #{entries := Entries}}} = vpn_projection:get(),
                          Durable = maps:get(peer_b, Entries),
                          Desired = maps:get(desired_state, Durable),
                          ?assertEqual(false,
                                       maps:is_key(runtime_config, Desired)),
                          ?assertEqual(false, maps:is_key(psk, Desired)),
                          ?assertEqual(false,
                                       maps:is_key(private_key_path, Desired)),
                          ?assertEqual(<<"safe-device">>,
                                       maps:get(device_id, Desired)),
                          ?assertEqual(valid_recovery_manifest(),
                                       maps:get(recovery_manifest, Desired)),
                          {ok, RuntimeConfig} = vpn_peer_registry:config(peer_b),
                          ?assertEqual(false,
                                       maps:is_key(recovery_manifest,
                                                   RuntimeConfig))
                      end)]
     end}.


static_template_resolver_lifecycle_test_() ->
    {setup,
     fun setup_with_runtime/0,
     fun cleanup_with_runtime/1,
     fun({_Registry, _Provisioning, _PeerSup, _Reconciler}) ->
             [?_test(begin
                          application:set_env(vpn, runtime_config_resolver, disabled),
                          ?assertEqual({error, runtime_config_required},
                                       vpn_provisioning:apply(new_peer_command(1, upsert,
                                                                               #{enabled => true,
                                                                                 authorized => true}))),

                          application:set_env(vpn, runtime_config_resolver, static_template),
                          application:set_env(vpn, runtime_config_template, static_template()),

                          Upsert = new_peer_command(1, upsert,
                                                    #{enabled => true,
                                                      authorized => true,
                                                      authorization_mode => policy,
                                                      authorization_reason => profile_allows_vpn,
                                                      profile_id => administrator,
                                                      device_id => <<"ias-device-2">>,
                                                      certificate_fingerprint => <<"IAS-FP-2">>}),
                          ?assertMatch({ok, #{operation := upsert}},
                                       vpn_provisioning:apply(Upsert)),
                          ?assert(wait_until(fun() ->
                                                    vpn_manager:peer_running(peer_b)
                                            end, 50)),

                          {ok, SafeEntry} = vpn_peer_registry:get(peer_b),
                          ?assertEqual(<<"ias-device-2">>, maps:get(device_id, SafeEntry)),
                          ?assertEqual(<<"IAS-FP-2">>,
                                       maps:get(certificate_fingerprint, SafeEntry)),
                          ?assertEqual(administrator, maps:get(profile_id, SafeEntry)),
                          ?assertEqual(policy, maps:get(authorization_mode, SafeEntry)),
                          ?assertEqual(true, maps:get(authorized, SafeEntry)),
                          {ok, InternalConfig} = vpn_peer_registry:config(peer_b),
                          ?assertEqual(peer_b, maps:get(id, InternalConfig)),
                          ?assertEqual(administrator, maps:get(profile_id, InternalConfig)),
                          ?assertEqual(vpn_peer_registry_tests,
                                       maps:get(peer_module, InternalConfig)),
                          ?assertEqual(true,
                                       maps:is_key(ovpn_identity, InternalConfig) orelse
                                       maps:is_key(certificate_path, InternalConfig)),
                          ?assertEqual(false, maps:is_key(session_key, InternalConfig)),
                          ?assertEqual(false, maps:is_key(replay_window, InternalConfig)),
                          ?assertEqual(false, maps:is_key(link_pid, InternalConfig)),

                          ?assertEqual({ok, unchanged}, vpn_provisioning:apply(Upsert)),

                          ?assertMatch({ok, #{operation := disable}},
                                       vpn_provisioning:apply(new_peer_command(2, disable, #{}))),
                          ?assert(wait_until(fun() ->
                                                    vpn_manager:peer_running(peer_b) =:= false
                                            end, 50)),

                          ?assertMatch({ok, #{operation := enable}},
                                       vpn_provisioning:apply(new_peer_command(3, enable, #{}))),
                          ?assert(wait_until(fun() ->
                                                    vpn_manager:peer_running(peer_b)
                                            end, 50)),

                          ?assertMatch({ok, #{operation := revoke}},
                                       vpn_provisioning:apply(new_peer_command(4, revoke,
                                                                               #{authorization_reason => certificate_revoked}))),
                          ?assert(wait_until(fun() ->
                                                    vpn_manager:peer_running(peer_b) =:= false
                                            end, 50)),
                          {ok, Revoked} = vpn_peer_registry:get(peer_b),
                          ?assertEqual(true, maps:get(revoked, Revoked)),
                          ?assertEqual(false, maps:get(authorized, Revoked)),
                          ?assertEqual(false, maps:get(enabled, Revoked)),
                          ?assertEqual(certificate_revoked,
                                       maps:get(authorization_reason, Revoked)),

                          ?assertEqual({error, revoked},
                                       vpn_provisioning:apply(new_peer_command(5, enable, #{}))),

                          ?assertEqual({error, revision_conflict},
                                       vpn_provisioning:apply(new_peer_command(4, disable, #{}))),

                          ?assertEqual({ok, removed},
                                       vpn_provisioning:apply(new_peer_command(6, remove, #{}))),
                          ?assertEqual({error, not_found}, vpn_peer_registry:get(peer_b)),
                          ?assertEqual({error, stale_revision},
                                       vpn_provisioning:apply(new_peer_command(5, upsert, #{}))),

                          {ok, Existing} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(peer_a, maps:get(id, Existing))
                      end)]
     end}.


durable_ledger_survives_provisioning_restart_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, Provisioning}) ->
             [?_test(begin
                          Upsert = command(1, upsert,
                                           #{device_id => <<"durable-device">>,
                                             enabled => true,
                                             authorized => true}),
                          ?assertMatch({ok, #{operation := upsert}},
                                       vpn_provisioning:apply(Upsert)),
                          stop_pid_normal(Provisioning),
                          stop(vpn_projection),
                          {ok, _RestartedProjection1} =
                              vpn_projection:start_link(
                                vpn_projection_test_store),
                          {ok, Restarted1} = vpn_provisioning:start_link(),

                          ?assertEqual({ok, unchanged},
                                       vpn_provisioning:apply(Upsert)),
                          ?assertEqual({error, stale_revision},
                                       vpn_provisioning:apply(
                                         command(0, disable, #{}))),
                          ?assertEqual({error, revision_conflict},
                                       vpn_provisioning:apply(
                                         command(1, disable, #{}))),

                          Revoke = command(2, revoke,
                                           #{authorization_reason =>
                                                 certificate_revoked}),
                          ?assertMatch({ok, #{operation := revoke}},
                                       vpn_provisioning:apply(Revoke)),
                          stop_pid_normal(Restarted1),
                          {ok, Restarted2} = vpn_provisioning:start_link(),
                          ?assertEqual({error, revoked},
                                       vpn_provisioning:apply(
                                         command(3, enable, #{}))),

                          Reissue = command(3, upsert,
                                            #{revoked => false,
                                              enabled => true,
                                              authorized => true}),
                          ?assertMatch({ok, #{operation := upsert}},
                                       vpn_provisioning:apply(Reissue)),
                          ?assertEqual({ok, removed},
                                       vpn_provisioning:apply(
                                         command(4, remove, #{}))),
                          stop_pid_normal(Restarted2),
                          stop(vpn_projection),
                          {ok, _RestartedProjection2} =
                              vpn_projection:start_link(
                                vpn_projection_test_store),
                          {ok, _Restarted3} = vpn_provisioning:start_link(),
                          ?assertEqual({error, stale_revision},
                                       vpn_provisioning:apply(Reissue)),

                          {ok, _ProjectionVersion,
                           #{provisioning :=
                                 #{schema_version := 2,
                                   entries := Entries}}} = vpn_projection:get(),
                          Entry = maps:get(peer_a, Entries),
                          ?assertEqual(4, maps:get(revision, Entry)),
                          ?assertEqual(applied, maps:get(phase, Entry)),
                          ?assertEqual(removed,
                                       maps:get(lifecycle_state, Entry)),
                          ?assertEqual(false,
                                       maps:is_key(runtime_config,
                                                   maps:get(desired_state,
                                                            Entry))),
                          Status = vpn_provisioning:status(),
                          ?assertEqual(durable,
                                       maps:get(persistence, Status)),
                          ?assertEqual(0,
                                       maps:get(pending_commands, Status))
                      end)]
     end}.

projection_commit_failure_does_not_publish_runtime_change_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             [?_test(begin
                          ok = vpn_projection_test_store:fail_next_commit(
                                 simulated_projection_failure),
                          ?assertMatch(
                             {error,
                              {provisioning_ledger_commit_failed, _}},
                             vpn_provisioning:apply(
                               command(1, disable, #{}))),
                          {ok, Entry} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(true, maps:get(enabled, Entry)),
                          Status = vpn_provisioning:status(),
                          ?assertEqual(0,
                                       maps:get(pending_commands, Status))
                      end)]
     end}.

pending_command_is_resumed_after_finalize_failure_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, Provisioning}) ->
             [?_test(begin
                          Disable = command(1, disable, #{}),
                          ok = vpn_projection_test_store:fail_after_commits(
                                 1,
                                 simulated_finalize_failure),
                          ?assertMatch(
                             {error,
                              {provisioning_ledger_finalize_failed, _}},
                             vpn_provisioning:apply(Disable)),
                          {ok, Disabled} = vpn_peer_registry:get(peer_a),
                          ?assertEqual(false, maps:get(enabled, Disabled)),
                          ?assertEqual(1,
                                       maps:get(pending_commands,
                                                vpn_provisioning:status())),

                          stop_pid_normal(Provisioning),
                          {ok, _Restarted} = vpn_provisioning:start_link(),
                          ?assertMatch({ok, #{operation := disable}},
                                       vpn_provisioning:apply(Disable)),
                          ?assertEqual({ok, unchanged},
                                       vpn_provisioning:apply(Disable)),
                          ?assertEqual(0,
                                       maps:get(pending_commands,
                                                vpn_provisioning:status()))
                      end)]
     end}.


unsupported_provisioning_schema_fails_closed_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, Provisioning}) ->
             [?_test(begin
                          {ok, _Version, _Projection} =
                              vpn_projection:update(
                                provisioning,
                                fun(_Current) ->
                                        #{schema_version => 99,
                                          entries => #{}}
                                end),
                          stop_pid_normal(Provisioning),
                          Expected =
                              {provisioning_projection_restore_failed,
                               {unsupported_provisioning_schema_version, 99}},
                          ?assertEqual({error, Expected},
                                       start_provisioning_fail_closed(Expected))
                      end)]
     end}.


invalid_durable_recovery_manifest_fails_closed_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, Provisioning}) ->
             [?_test(begin
                          Command = command(1, upsert,
                                            #{device_id => <<"safe-device">>,
                                              enabled => true,
                                              authorized => true,
                                              recovery_manifest =>
                                                  valid_recovery_manifest()}),
                          ?assertMatch({ok, #{operation := upsert}},
                                       vpn_provisioning:apply(Command)),
                          {ok, _Version, _Projection} =
                              vpn_projection:update(
                                provisioning,
                                fun(Section) ->
                                        Entries0 = maps:get(entries, Section),
                                        Entry0 = maps:get(peer_a, Entries0),
                                        Desired0 = maps:get(desired_state, Entry0),
                                        Manifest0 = maps:get(recovery_manifest,
                                                             Desired0),
                                        %% Keep the envelope secret-free so the
                                        %% provisioning restore boundary owns
                                        %% the fail-closed verdict.
                                        Invalid = Manifest0#{schema_version =>
                                                                99},
                                        Entry = Entry0#{desired_state =>
                                                           Desired0#{
                                                             recovery_manifest =>
                                                                 Invalid}},
                                        Section#{entries => Entries0#{peer_a =>
                                                                         Entry}}
                                end),
                          stop_pid_normal(Provisioning),
                          Expected =
                              {provisioning_projection_restore_failed,
                               {invalid_provisioning_entry, peer_a}},
                          ?assertEqual({error, Expected},
                                       start_provisioning_fail_closed(Expected))
                      end)]
     end}.


certificate_fingerprint_validation_test() ->
    Actual = <<"ACTUAL-FINGERPRINT">>,
    Matching = #{certificate_fingerprint => Actual,
                 ovpn_identity => #{certificate_fingerprint => Actual}},
    Mismatching = #{certificate_fingerprint => <<"EXPECTED-FINGERPRINT">>,
                    ovpn_identity => #{certificate_fingerprint => Actual}},
    Missing = #{id => peer_b},
    ?assertEqual(ok,
                 vpn_runtime_config_resolver:validate_certificate_fingerprint(
                   #{certificate_fingerprint => Actual}, Matching)),
    ?assertEqual({error, certificate_fingerprint_mismatch},
                 vpn_runtime_config_resolver:validate_certificate_fingerprint(
                   #{certificate_fingerprint => <<"EXPECTED-FINGERPRINT">>},
                   Mismatching)),
    ?assertEqual({error, certificate_fingerprint_unavailable},
                 vpn_runtime_config_resolver:validate_certificate_fingerprint(
                   #{certificate_fingerprint => <<"EXPECTED-FINGERPRINT">>},
                   Missing)),
    ?assertEqual(ok,
                 vpn_runtime_config_resolver:validate_certificate_fingerprint(
                   #{}, Missing)).


static_template_pool_selects_peer_specific_runtime_test() ->
    application:set_env(vpn, runtime_config_resolver, static_template),
    ClientA = static_template(),
    ClientB = ClientA#{id => ias_template_client_b,
                       ifname => <<"tun12">>,
                       ip => "10.20.30.12",
                       local_udp_port => 5562,
                       remote_peer_id => peer_c},
    application:set_env(vpn, runtime_config_templates,
                        #{client_a => ClientA, client_b => ClientB}),
    try
        {ok, ResolvedA} = vpn_runtime_config_resolver:resolve(
                            client_a, #{authorized => true}),
        {ok, ResolvedB} = vpn_runtime_config_resolver:resolve(
                            client_b, #{authorized => true}),
        ?assertEqual(client_a, maps:get(id, ResolvedA)),
        ?assertEqual(<<"tun11">>, maps:get(ifname, ResolvedA)),
        ?assertEqual(client_b, maps:get(id, ResolvedB)),
        ?assertEqual(<<"tun12">>, maps:get(ifname, ResolvedB)),
        ?assertEqual(peer_c, maps:get(remote_peer_id, ResolvedB)),
        ?assertEqual({error, {runtime_config_template_not_found, client_c}},
                     vpn_runtime_config_resolver:resolve(
                       client_c, #{authorized => true}))
    after
        application:unset_env(vpn, runtime_config_resolver),
        application:unset_env(vpn, runtime_config_templates)
    end.

invalid_static_template_pool_fails_closed_test() ->
    application:set_env(vpn, runtime_config_resolver, static_template),
    application:set_env(vpn, runtime_config_templates, [static_template()]),
    try
        ?assertEqual({error, invalid_runtime_config_templates},
                     vpn_runtime_config_resolver:resolve(
                       client_a, #{authorized => true}))
    after
        application:unset_env(vpn, runtime_config_resolver),
        application:unset_env(vpn, runtime_config_templates)
    end.

invalid_static_template_fails_closed_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             application:set_env(vpn, runtime_config_resolver, static_template),
             application:set_env(vpn, runtime_config_template,
                                 maps:remove(local_udp_port, static_template())),
             [?_assertEqual({error, {missing_config_key, local_udp_port}},
                            vpn_provisioning:apply(new_peer_command(1, upsert,
                                                                    #{enabled => true,
                                                                      authorized => true})))]
     end}.

legacy_head_is_migrated_on_startup_without_replay_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, Provisioning}) ->
             [?_test(begin
                          stop_pid_normal(Provisioning),
                          Desired = #{device_id => <<"legacy-device">>,
                                      enabled => true,
                                      revoked => false,
                                      authorized => true,
                                      authorization_mode => policy,
                                      authorization_reason =>
                                          profile_allows_vpn},
                          LegacyEntry =
                              #{revision => 4,
                                digest => crypto:strong_rand_bytes(32),
                                digest_version => 1,
                                phase => applied,
                                operation => upsert,
                                source => ias,
                                lifecycle_state => active,
                                desired_state => Desired,
                                dynamic_device_id => <<"legacy-device">>,
                                updated_at => 1234},
                          {ok, _Version1, _Projection1} =
                              vpn_projection:update(
                                provisioning,
                                fun(_Section) ->
                                        {ok, #{schema_version => 2,
                                               entries =>
                                                   #{peer_a => LegacyEntry}}}
                                end),
                          Command = #{peer_id => peer_a,
                                      revision => 4,
                                      operation => upsert,
                                      source => ias,
                                      desired_state =>
                                          maps:remove(revoked, Desired)},
                          ExpectedDigest =
                              vpn_provisioning_command_digest:digest(Command),

                          {ok, _Restarted} = vpn_provisioning:start_link(),
                          {ok, Version2,
                           #{provisioning :=
                                 #{schema_version := 2,
                                   entries := #{peer_a := Migrated}}}} =
                              vpn_projection:get(),
                          ?assertEqual(2,
                                       maps:get(digest_version, Migrated)),
                          ?assertEqual(ExpectedDigest,
                                       maps:get(digest, Migrated)),
                          ?assertEqual(Desired,
                                       maps:get(desired_state, Migrated)),
                          ?assertEqual(4, maps:get(revision, Migrated)),
                          ?assertEqual(applied, maps:get(phase, Migrated)),

                          {ok, Heads} = vpn_provisioning:recovery_heads(),
                          Head = maps:get(peer_a, Heads),
                          ?assertEqual(ExpectedDigest, maps:get(digest, Head)),
                          ?assertEqual(2, maps:get(digest_version, Head)),
                          {ok, Version2, _Projection2} = vpn_projection:get()
                      end)]
     end}.

invalid_recovery_manifest_is_rejected_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             Invalid = (valid_recovery_manifest())#{private_key => <<"secret">>},
             [?_assertEqual({error, invalid_recovery_manifest},
                            vpn_provisioning:apply(
                              command(1, upsert,
                                      #{recovery_manifest => Invalid}))) ]
     end}.

invalid_command_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({_Registry, _Provisioning}) ->
             [?_assertEqual({error, invalid_command}, vpn_provisioning:apply(#{})),
              ?_assertEqual({error, invalid_command},
                            vpn_provisioning:apply(command(-1, disable, #{}))),
              ?_assertEqual({error, invalid_command}, vpn_provisioning:apply(not_a_map))]
     end}.


orphan_decommission_request(DeviceId) ->
    {ok, Heads} = vpn_provisioning:recovery_heads(),
    ExpectedHeads = lists:sort(
                      [#{peer_id => PeerId,
                         revision => maps:get(revision, Head),
                         digest => maps:get(digest, Head),
                         digest_version => maps:get(digest_version, Head),
                         phase => maps:get(phase, Head),
                         source => ias}
                       || {PeerId, Head} <- maps:to_list(Heads),
                          maps:get(device_id,
                                   maps:get(desired_state, Head, #{}),
                                   undefined) =:= DeviceId]),
    RegistryPeerIds = [maps:get(id, Entry)
                       || Entry <- vpn_peer_registry:list(),
                          maps:get(device_id, Entry, undefined) =:= DeviceId],
    HeadPeerIds = [maps:get(peer_id, Head) || Head <- ExpectedHeads],
    #{device_id => DeviceId,
      expected_heads => ExpectedHeads,
      expected_peer_ids => lists:usort(HeadPeerIds ++ RegistryPeerIds),
      expected_source => ias,
      expected_allocation_id => undefined,
      remove_identity => false}.

command(Revision, Operation, Desired) ->
    #{peer_id => peer_a,
      revision => Revision,
      operation => Operation,
      source => ias,
      desired_state => Desired}.

setup() ->
    stop(vpn_provisioning),
    stop(vpn_peer_registry),
    stop(vpn_projection),
    ok = vpn_projection_test_store:reset(),
    application:unset_env(vpn, runtime_config_resolver),
    application:unset_env(vpn, runtime_config_template),
    application:unset_env(vpn, runtime_config_templates),
    application:set_env(vpn, peers, [peer_config(peer_a)]),
    application:set_env(vpn, ovpn_sessions, []),
    {ok, _Projection} =
        vpn_projection:start_link(vpn_projection_test_store),
    {ok, Registry} = vpn_peer_registry:start_link(),
    {ok, Provisioning} = vpn_provisioning:start_link(),
    {Registry, Provisioning}.

cleanup({_Registry, _Provisioning}) ->
    stop(vpn_provisioning),
    stop(vpn_peer_registry),
    stop(vpn_projection),
    ok = vpn_projection_test_store:reset(),
    application:unset_env(vpn, runtime_config_resolver),
    application:unset_env(vpn, runtime_config_template),
    application:unset_env(vpn, runtime_config_templates),
    application:unset_env(vpn, peers),
    application:unset_env(vpn, ovpn_sessions),
    ok.

setup_with_runtime() ->
    stop(vpn_provisioning),
    stop(vpn_peer_reconciler),
    stop(vpn_peer_sup),
    stop(vpn_peer_registry),
    stop(vpn_projection),
    ok = vpn_projection_test_store:reset(),
    application:unset_env(vpn, runtime_config_resolver),
    application:unset_env(vpn, runtime_config_template),
    application:unset_env(vpn, runtime_config_templates),
    application:set_env(vpn, peers, [peer_config(peer_a)]),
    application:set_env(vpn, ovpn_sessions, []),
    {ok, _Projection} =
        vpn_projection:start_link(vpn_projection_test_store),
    {ok, Registry} = vpn_peer_registry:start_link(),
    {ok, PeerSup} = vpn_peer_sup:start_link(),
    {ok, Reconciler} = vpn_peer_reconciler:start_link(),
    {ok, Provisioning} = vpn_provisioning:start_link(),
    {Registry, Provisioning, PeerSup, Reconciler}.

cleanup_with_runtime({_Registry, _Provisioning, _PeerSup, _Reconciler}) ->
    stop(vpn_provisioning),
    stop(vpn_peer_reconciler),
    stop(vpn_peer_sup),
    stop(vpn_peer_registry),
    stop(vpn_projection),
    ok = vpn_projection_test_store:reset(),
    application:unset_env(vpn, runtime_config_resolver),
    application:unset_env(vpn, runtime_config_template),
    application:unset_env(vpn, runtime_config_templates),
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
      authorization_mode => development_bypass,
      authorized => true,
      authorization_reason => development_bypass,
      psk => <<"secret">>}.

new_peer_command(Revision, Operation, Desired) ->
    #{peer_id => peer_b,
      revision => Revision,
      operation => Operation,
      source => ias,
      desired_state => Desired}.

static_template() ->
    #{id => ias_template_peer,
      peer_module => vpn_peer_registry_tests,
      mode => tun,
      ifname => <<"tun11">>,
      ip => "10.20.30.11",
      local_udp_port => 5561,
      remote_ip => {127,0,0,1},
      remote_udp_port => 5560,
      remote_peer_id => peer_a,
      authorization_mode => development_bypass,
      authorized => true,
      authorization_reason => development_bypass,
      psk => <<"0123456789abcdef0123456789abcdef">>,
      certificate_path => "priv/certs/peer_a.crt",
      private_key_path => "priv/certs/peer_a.key",
      ca_certificate_path => "priv/certs/ca.crt",
      session_key => <<"do-not-copy">>,
      replay_window => #{counter => 1},
      link_pid => self()}.


valid_recovery_manifest() ->
    #{schema_version => 1,
      provisioning_transaction_id => <<"ovpn_provisioning_vpn_test">>,
      wizard_id => <<"wizard_vpn_test">>,
      device => #{kind => device, id => <<"safe-device">>},
      certificate => #{kind => certificate, id => <<"safe-certificate">>,
                       fingerprint_sha256 => <<"SAFE-FINGERPRINT">>},
      vpn_service => #{kind => vpn_service, id => <<"safe-service">>,
                       remote_host => <<"vpn.example.test">>,
                       remote_port => 1194,
                       protocol => udp},
      objects => [#{kind => device, id => <<"safe-device">>},
                  #{kind => certificate, id => <<"safe-certificate">>,
                    fingerprint_sha256 => <<"SAFE-FINGERPRINT">>},
                  #{kind => vpn_service, id => <<"safe-service">>,
                    remote_host => <<"vpn.example.test">>,
                    remote_port => 1194,
                    protocol => udp}],
      relationships => [#{relation_type => uses_certificate,
                          source_kind => device,
                          source_id => <<"safe-device">>,
                          target_kind => certificate,
                          target_id => <<"safe-certificate">>},
                        #{relation_type => uses_service,
                          source_kind => device,
                          source_id => <<"safe-device">>,
                          target_kind => vpn_service,
                          target_id => <<"safe-service">>}]}.

start_provisioning_fail_closed(ExpectedReason) ->
    PreviousTrapExit = process_flag(trap_exit, true),
    try
        Result = vpn_provisioning:start_link(),
        receive
            {'EXIT', _Pid, ExpectedReason} -> ok
        after 100 ->
            ok
        end,
        Result
    after
        process_flag(trap_exit, PreviousTrapExit)
    end.

stop(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> stop_pid_normal(Pid)
    end.

stop_pid_normal(Pid) ->
    case is_process_alive(Pid) of
        true ->
            ok = gen_server:stop(Pid, normal, 5000),
            wait(Pid, 30);
        false -> ok
    end.

wait(_Pid, 0) -> ok;
wait(Pid, N) ->
    case is_process_alive(Pid) of
        false -> ok;
        true -> timer:sleep(10), wait(Pid, N - 1)
    end.

wait_until(_Fun, 0) ->
    false;
wait_until(Fun, Attempts) ->
    case Fun() of
        true -> true;
        false -> timer:sleep(10), wait_until(Fun, Attempts - 1)
    end.
