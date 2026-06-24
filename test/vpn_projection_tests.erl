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
                                         schema_version := 1,
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

                          ConflictEnvelope =
                              #{schema_version => 1,
                                projection_version => 2,
                                checksum => <<0:256>>,
                                payload => Projection1,
                                updated_at => 1},
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
                          ?assertMatch(
                             {error,
                              {projection_load_failed,
                               {unsupported_schema_version, 99}}},
                             vpn_projection:start_link()),

                          ok = write_raw(
                                 #vpn_projection{
                                    id = current,
                                    schema_version = 1,
                                    projection_version = 1,
                                    checksum = <<0:256>>,
                                    payload = Projection,
                                    updated_at = 1}),
                          ?assertMatch(
                             {error,
                              {projection_load_failed,
                               invalid_projection_checksum}},
                             vpn_projection:start_link())
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
    {ok, _CryptoStarted} = application:ensure_all_started(crypto),
    {ok, _Started} = application:ensure_all_started(kvs),
    ok = vpn_kvs:ensure_started(),
    #{root => Root}.

cleanup(Context) ->
    stop_registered(vpn_projection),
    _ = application:stop(kvs),
    _ = application:stop(mnesia),
    application:unset_env(vpn, projection_store_backend),
    application:unset_env(kvs, dba),
    application:unset_env(kvs, dba_seq),
    application:unset_env(kvs, dba_st),
    application:unset_env(kvs, mnesia_context),
    application:unset_env(kvs, schema),
    application:unset_env(mnesia, dir),
    remove_tree(maps:get(root, Context)),
    ok.

write_raw(Record) ->
    case mnesia:transaction(fun() -> mnesia:write(Record) end) of
        {atomic, ok} -> ok;
        {aborted, Reason} -> erlang:error({raw_projection_write_failed, Reason})
    end.

stop_registered(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> stop_pid(Pid)
    end.

stop_pid(Pid) when is_pid(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            exit(Pid, shutdown),
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
