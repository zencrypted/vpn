-module(vpn_kvs_transaction_mnesia).

-behaviour(vpn_kvs_transaction).

-export([ensure/0,
         run/1,
         abort/1]).

ensure() ->
    case application:get_env(kvs, dba, kvs_mnesia) of
        kvs_mnesia ->
            case application:ensure_all_started(mnesia) of
                {ok, _Started} -> ok;
                {error, Reason} ->
                    {error, {kvs_transaction_mnesia_start_failed, Reason}}
            end;
        Backend ->
            {error,
             {kvs_transaction_provider_backend_mismatch,
              #{provider => ?MODULE, backend => Backend}}}
    end.

run(Fun) when is_function(Fun, 0) ->
    case mnesia:sync_transaction(Fun) of
        {atomic, Value} -> {ok, Value};
        {aborted, Reason} -> {error, normalize_abort(Reason)}
    end.

abort(Reason) ->
    mnesia:abort(Reason).

normalize_abort({aborted, Reason}) -> Reason;
normalize_abort(Reason) -> Reason.
