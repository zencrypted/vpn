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

command(Revision, Operation, Desired) ->
    #{peer_id => peer_a,
      revision => Revision,
      operation => Operation,
      source => ias,
      desired_state => Desired}.

setup() ->
    stop(vpn_provisioning),
    stop(vpn_peer_registry),
    application:unset_env(vpn, runtime_config_resolver),
    application:unset_env(vpn, runtime_config_template),
    application:set_env(vpn, peers, [peer_config(peer_a)]),
    application:set_env(vpn, ovpn_sessions, []),
    {ok, Registry} = vpn_peer_registry:start_link(),
    {ok, Provisioning} = vpn_provisioning:start_link(),
    {Registry, Provisioning}.

cleanup({Registry, Provisioning}) ->
    shutdown(Provisioning),
    shutdown(Registry),
    application:unset_env(vpn, runtime_config_resolver),
    application:unset_env(vpn, runtime_config_template),
    application:unset_env(vpn, peers),
    application:unset_env(vpn, ovpn_sessions),
    ok.

setup_with_runtime() ->
    stop(vpn_provisioning),
    stop(vpn_peer_reconciler),
    stop(vpn_peer_sup),
    stop(vpn_peer_registry),
    application:unset_env(vpn, runtime_config_resolver),
    application:unset_env(vpn, runtime_config_template),
    application:set_env(vpn, peers, [peer_config(peer_a)]),
    application:set_env(vpn, ovpn_sessions, []),
    {ok, Registry} = vpn_peer_registry:start_link(),
    {ok, PeerSup} = vpn_peer_sup:start_link(),
    {ok, Reconciler} = vpn_peer_reconciler:start_link(),
    {ok, Provisioning} = vpn_provisioning:start_link(),
    {Registry, Provisioning, PeerSup, Reconciler}.

cleanup_with_runtime({Registry, Provisioning, PeerSup, Reconciler}) ->
    shutdown(Provisioning),
    shutdown(Reconciler),
    shutdown(PeerSup),
    shutdown(Registry),
    application:unset_env(vpn, runtime_config_resolver),
    application:unset_env(vpn, runtime_config_template),
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

wait_until(_Fun, 0) ->
    false;
wait_until(Fun, Attempts) ->
    case Fun() of
        true -> true;
        false -> timer:sleep(10), wait_until(Fun, Attempts - 1)
    end.
