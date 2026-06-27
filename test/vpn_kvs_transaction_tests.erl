-module(vpn_kvs_transaction_tests).

-include_lib("eunit/include/eunit.hrl").
-include("vpn_projection.hrl").

kvs_transaction_provider_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [fun aborted_transaction_rolls_back_kvs_write/0,
      fun unsupported_provider_fails_closed/0]}.

setup() ->
    _ = application:stop(kvs),
    _ = application:stop(mnesia),
    Root = filename:join(
             os:getenv("TMPDIR", "/tmp"),
             lists:flatten(
               io_lib:format("vpn-kvs-transaction-~p",
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
    PreviousProvider = application:get_env(vpn, kvs_transaction_provider),
    application:unset_env(vpn, kvs_transaction_provider),
    {ok, _Started} = application:ensure_all_started(kvs),
    ok = vpn_kvs:ensure_started(),
    #{root => Root, previous_provider => PreviousProvider}.

cleanup(Context) ->
    restore_provider(maps:get(previous_provider, Context)),
    _ = application:stop(kvs),
    _ = application:stop(mnesia),
    application:unset_env(kvs, dba),
    application:unset_env(kvs, dba_seq),
    application:unset_env(kvs, dba_st),
    application:unset_env(kvs, mnesia_context),
    application:unset_env(kvs, schema),
    application:unset_env(mnesia, dir),
    remove_tree(maps:get(root, Context)),
    ok.

aborted_transaction_rolls_back_kvs_write() ->
    Record = #vpn_projection{id = current,
                             schema_version = 1,
                             projection_version = 1,
                             checksum = <<0:256>>,
                             payload = #{allocator => #{},
                                         provisioning => #{}},
                             updated_at = 1},
    ?assertEqual(
       {error, forced_kvs_transaction_abort},
       vpn_kvs_transaction:run(
         fun() ->
             ok = kvs:put(Record),
             vpn_kvs_transaction:abort(forced_kvs_transaction_abort)
         end)),
    ?assertEqual({error, not_found},
                 kvs:get(vpn_projection, current)).

unsupported_provider_fails_closed() ->
    application:set_env(vpn,
                        kvs_transaction_provider,
                        vpn_kvs_transaction_unsupported),
    ?assertMatch(
       {error, {kvs_transactions_not_supported, _}},
       vpn_kvs_transaction:ensure()),
    ?assertMatch(
       {error, {kvs_transactions_not_supported, _}},
       vpn_kvs_transaction:run(fun() -> ok end)).

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
