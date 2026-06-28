%%%-------------------------------------------------------------------
%% @doc KVS schema and startup boundary for durable VPN projection state.
%%%-------------------------------------------------------------------
-module(vpn_kvs).

-export([metainfo/0, ensure_started/0]).

-include_lib("kvs/include/metainfo.hrl").
-include("vpn_projection.hrl").

-define(TABLE_WAIT_TIMEOUT, 30000).

metainfo() ->
    #schema{name = vpn,
            tables = [#table{name = vpn_projection,
                             type = set,
                             copy_type = disc_copies,
                             fields = record_info(fields, vpn_projection)}]}.

ensure_started() ->
    case lists:member(?MODULE, application:get_env(kvs, schema, [])) of
        false ->
            {error, vpn_kvs_schema_not_configured};
        true ->
            ensure_kvs_started()
    end.

ensure_kvs_started() ->
    case ensure_mnesia_dir() of
        ok ->
            case application:ensure_all_started(kvs) of
                {ok, _Started} ->
                    join_and_wait();
                {error, Reason} ->
                    {error, {kvs_start_failed, Reason}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

ensure_mnesia_dir() ->
    case application:get_env(mnesia, dir) of
        {ok, Dir0} when is_list(Dir0); is_binary(Dir0) ->
            Dir = case Dir0 of
                      Binary when is_binary(Binary) -> binary_to_list(Binary);
                      List -> List
                  end,
            case filelib:ensure_dir(filename:join(Dir, "placeholder")) of
                ok -> ok;
                {error, Reason} ->
                    {error, {mnesia_dir_unavailable, Dir, Reason}}
            end;
        undefined ->
            ok;
        {ok, Invalid} ->
            {error, {invalid_mnesia_dir, Invalid}}
    end.

join_and_wait() ->
    try kvs:join() of
        _ ->
            case mnesia:wait_for_tables([vpn_projection],
                                        ?TABLE_WAIT_TIMEOUT) of
                ok -> ok;
                {timeout, Tables} ->
                    {error, {kvs_table_wait_timeout, Tables}};
                {error, Reason} ->
                    {error, {kvs_table_wait_failed, Reason}}
            end
    catch
        Class:Reason:Stacktrace ->
            {error, {kvs_join_failed, Class, Reason, Stacktrace}}
    end.
