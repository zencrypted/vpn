-module(vpn_projection_tests).

-include_lib("eunit/include/eunit.hrl").
-include("vpn_projection.hrl").

projection_store_foundation_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(#{projection := ProjectionPid}) ->
             [?_test(begin
                          ?assertEqual(disc_copies,
                                       mnesia:table_info(vpn_projection,
                                                         storage_type)),
                          ?assertEqual({ok,
                                        0,
                                        #{allocator => #{},
                                          provisioning => #{}}},
                                       vpn_projection:get()),
                          ?assertMatch(#{state := ready,
                                         persistence := durable,
                                         backend := vpn_projection_store_kvs,
                                         schema_version := 2,
                                         projection_version := 0},
                                       vpn_projection:status()),

                          {ok, 1, Projection1} =
                              vpn_projection:update(
                                allocator,
                                fun(Current) ->
                                        Current#{allocator_instance_id =>
                                                     <<"allocator-a">>}
                                end),
                          ?assertEqual(<<"allocator-a">>,
                                       maps:get(allocator_instance_id,
                                                maps:get(allocator,
                                                         Projection1))),
                          ?assertEqual({ok, unchanged, 1, Projection1},
                                       vpn_projection:replace(1, Projection1)),
                          ?assertEqual({error, conflict},
                                       vpn_projection:replace(0, Projection1)),
                          ?assertEqual({error,
                                        {forbidden_projection_key,
                                         private_key_path}},
                                       vpn_projection:replace(
                                         1,
                                         #{allocator =>
                                               #{private_key_path =>
                                                     "local/secret.key"},
                                           provisioning => #{}})),
                          ?assertEqual({error,
                                        {forbidden_projection_term, pid}},
                                       vpn_projection:replace(
                                         1,
                                         #{allocator => #{owner => self()},
                                           provisioning => #{}})),
                          ?assertEqual({error,
                                        {invalid_projection_section,
                                         sessions}},
                                       vpn_projection:update(
                                         sessions,
                                         fun(Current) -> Current end)),

                          stop_pid(ProjectionPid),
                          {ok, RestartedPid} = vpn_projection:start_link(),
                          ?assertEqual({ok, 1, Projection1},
                                       vpn_projection:get()),

                          ConflictVersion = 1,
                          ConflictUpdatedAt = 1,
                          ConflictChecksum =
                              vpn_projection_checksum:checksum(
                                2,
                                ConflictVersion,
                                Projection1,
                                ConflictUpdatedAt),
                          ConflictEnvelope =
                              #{schema_version => 2,
                                projection_version => ConflictVersion,
                                checksum => ConflictChecksum,
                                payload => Projection1,
                                updated_at => ConflictUpdatedAt},
                          ?assertEqual({error, conflict},
                                       vpn_projection_store_kvs:commit(
                                         0,
                                         ConflictEnvelope)),
                          stop_pid(RestartedPid)
                      end)]
     end}.

unsupported_schema_and_checksum_fail_closed_test_() ->
    {setup,
     fun setup_store_only/0,
     fun cleanup/1,
     fun(_Context) ->
             [?_test(begin
                          Projection = #{allocator => #{},
                                         provisioning => #{}},
                          ok = write_raw(
                                 #vpn_projection{
                                    id = current,
                                    schema_version = 99,
                                    projection_version = 1,
                                    checksum = <<0:256>>,
                                    payload = Projection,
                                    updated_at = 1}),
                          ?assertEqual(
                             {error,
                              {projection_load_failed,
                               {unsupported_schema_version, 99}}},
                             start_projection_fail_closed(
                               {projection_load_failed,
                                {unsupported_schema_version, 99}})),

                          ok = write_raw(
                                 #vpn_projection{
                                    id = current,
                                    schema_version = 2,
                                    projection_version = 1,
                                    checksum = <<0:256>>,
                                    payload = Projection,
                                    updated_at = 1}),
                          ?assertEqual(
                             {error,
                              {projection_load_failed,
                               invalid_projection_checksum}},
                             start_projection_fail_closed(
                               {projection_load_failed,
                                invalid_projection_checksum}))
                      end)]
     end}.


portable_checksum_is_canonical_test() ->
    ProjectionA =
        #{allocator => #{instance => <<"a">>, slots => [3, 1, 2]},
          provisioning => #{peer_b => #{revision => 2},
                            peer_a => #{revision => 1}}},
    ProjectionB =
        maps:from_list(
          [{provisioning,
            maps:from_list([{peer_a, #{revision => 1}},
                            {peer_b, #{revision => 2}}])},
           {allocator,
            maps:from_list([{slots, [3, 1, 2]},
                            {instance, <<"a">>}])}]),
    ?assertEqual(vpn_projection_checksum:canonical_binary(ProjectionA),
                 vpn_projection_checksum:canonical_binary(ProjectionB)),
    ?assertEqual(vpn_projection_checksum:checksum(2, 7, ProjectionA, 1234),
                 vpn_projection_checksum:checksum(2, 7, ProjectionB, 1234)),
    ?assertNotEqual(vpn_projection_checksum:canonical_binary({a, b}),
                    vpn_projection_checksum:canonical_binary([a, b])).

legacy_checksum_migration_test_() ->
    {setup,
     fun setup_store_only/0,
     fun cleanup/1,
     fun(_Context) ->
             [?_test(begin
                          Projection = #{allocator => #{legacy => true},
                                         provisioning => #{}},
                          Version = 3,
                          UpdatedAt = 123,
                          LegacyChecksum =
                              vpn_projection_checksum:legacy_checksum(
                                1, Version, Projection, UpdatedAt),
                          ok = write_raw(
                                 #vpn_projection{
                                    id = current,
                                    schema_version = 1,
                                    projection_version = Version,
                                    checksum = LegacyChecksum,
                                    payload = Projection,
                                    updated_at = UpdatedAt}),
                          ?assertMatch(
                             {ok, #{state := legacy,
                                    legacy_checksum_valid := true}},
                             vpn_projection_migration:inspect()),
                          ?assertMatch(
                             {ok, #{state := migrated,
                                    projection_version := Version,
                                    legacy_verification := verified}},
                             vpn_projection_migration:
                                 migrate_legacy_checksum()),
                          ?assertMatch(
                             {ok, Version, #{schema_version := 2}},
                             vpn_projection_store_kvs:load()),
                          {ok, ProjectionPid} = vpn_projection:start_link(),
                          ?assertEqual({ok, Version, Projection},
                                       vpn_projection:get()),
                          stop_pid(ProjectionPid)
                      end)]
     end}.

unverifiable_legacy_checksum_requires_explicit_confirmation_test_() ->
    {setup,
     fun setup_store_only/0,
     fun cleanup/1,
     fun(_Context) ->
             [?_test(begin
                          Projection = #{allocator => #{legacy => true},
                                         provisioning => #{}},
                          Version = 4,
                          ok = write_raw(
                                 #vpn_projection{
                                    id = current,
                                    schema_version = 1,
                                    projection_version = Version,
                                    checksum = <<0:256>>,
                                    payload = Projection,
                                    updated_at = 456}),
                          ?assertEqual(
                             {error,
                              legacy_checksum_not_verifiable_on_this_otp},
                             vpn_projection_migration:
                                 migrate_legacy_checksum()),
                          ?assertMatch(
                             {ok, #{state := migrated,
                                    projection_version := Version,
                                    legacy_verification :=
                                        operator_accepted_unverifiable}},
                             vpn_projection_migration:
                                 migrate_legacy_checksum(
                                   accept_unverifiable_legacy_checksum)),
                          {ok, ProjectionPid} = vpn_projection:start_link(),
                          ?assertEqual({ok, Version, Projection},
                                       vpn_projection:get()),
                          stop_pid(ProjectionPid)
                      end)]
     end}.

setup() ->
    Context = setup_store_only(),
    {ok, ProjectionPid} = vpn_projection:start_link(),
    Context#{projection => ProjectionPid}.

setup_store_only() ->
    stop_registered(vpn_projection),
    _ = application:stop(kvs),
    _ = application:stop(mnesia),
    Root = filename:join(
             os:getenv("TMPDIR", "/tmp"),
             lists:flatten(
               io_lib:format("vpn-projection-~p",
                             [erlang:unique_integer([positive,
                                                     monotonic])]))),
    MnesiaDir = filename:join(Root, "mnesia"),
    ok = filelib:ensure_dir(filename:join(MnesiaDir, "placeholder")),
    application:set_env(mnesia, dir, MnesiaDir),
    application:set_env(kvs, dba, kvs_mnesia),
    application:set_env(kvs, dba_seq, kvs_mnesia),
    application:set_env(kvs, dba_st, kvs_st),
    application:set_env(kvs, mnesia_context, transaction),
    application:set_env(kvs, schema, [kvs, kvs_stream, vpn_kvs]),
    application:set_env(vpn,
                        projection_store_backend,
                        vpn_projection_store_kvs),
    PreviousProvider = application:get_env(vpn, kvs_transaction_provider),
    application:unset_env(vpn, kvs_transaction_provider),
    {ok, _CryptoStarted} = application:ensure_all_started(crypto),
    {ok, _Started} = application:ensure_all_started(kvs),
    ok = vpn_kvs:ensure_started(),
    #{root => Root, previous_provider => PreviousProvider}.

cleanup(Context) ->
    stop_registered(vpn_projection),
    _ = application:stop(kvs),
    _ = application:stop(mnesia),
    application:unset_env(vpn, projection_store_backend),
    restore_provider(maps:get(previous_provider, Context)),
    application:unset_env(kvs, dba),
    application:unset_env(kvs, dba_seq),
    application:unset_env(kvs, dba_st),
    application:unset_env(kvs, mnesia_context),
    application:unset_env(kvs, schema),
    application:unset_env(mnesia, dir),
    remove_tree(maps:get(root, Context)),
    ok.

start_projection_fail_closed(ExpectedReason) ->
    PreviousTrapExit = process_flag(trap_exit, true),
    try
        Result = vpn_projection:start_link(),
        %% A failed start_link/0 can still deliver the linked process EXIT
        %% signal to the caller. Consume it while exits are trapped so the
        %% expected fail-closed startup does not cancel the EUnit fixture.
        receive
            {'EXIT', _Pid, ExpectedReason} -> ok
        after 100 ->
            ok
        end,
        Result
    after
        process_flag(trap_exit, PreviousTrapExit)
    end.

write_raw(Record) ->
    case kvs:put(Record) of
        ok -> ok;
        {error, Reason} -> erlang:error({raw_projection_write_failed, Reason})
    end.

stop_registered(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> stop_pid(Pid)
    end.

stop_pid(Pid) when is_pid(Pid) ->
    case is_process_alive(Pid) of
        true ->
            %% The projection may have been started by the EUnit fixture owner
            %% rather than the current test worker. A shutdown exit would then
            %% propagate over that link and cancel the remaining fixture tests.
            %% A normal OTP stop preserves the restart assertion without
            %% terminating the fixture process.
            ok = gen_server:stop(Pid, normal, 5000),
            wait_until_stopped(Pid, 50);
        false ->
            ok
    end.

wait_until_stopped(_Pid, 0) ->
    ok;
wait_until_stopped(Pid, Attempts) ->
    case is_process_alive(Pid) of
        false -> ok;
        true ->
            timer:sleep(10),
            wait_until_stopped(Pid, Attempts - 1)
    end.

restore_provider({ok, Provider}) ->
    application:set_env(vpn, kvs_transaction_provider, Provider);
restore_provider(undefined) ->
    application:unset_env(vpn, kvs_transaction_provider).

remove_tree(Path) ->
    case filelib:is_dir(Path) of
        false -> ok;
        true ->
            Entries = filelib:wildcard(filename:join(Path, "*")),
            lists:foreach(
              fun(Entry) ->
                      case filelib:is_dir(Entry) of
                          true -> remove_tree(Entry);
                          false -> ok = file:delete(Entry)
                      end
              end,
              Entries),
            ok = file:del_dir(Path)
    end.
