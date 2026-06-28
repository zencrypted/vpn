-module(vpn_kvs_transaction_unsupported).

-behaviour(vpn_kvs_transaction).

-export([ensure/0,
         run/1,
         abort/1]).

ensure() ->
    {error,
     {kvs_transactions_not_supported,
      application:get_env(kvs, dba, undefined)}}.

run(_Fun) ->
    ensure().

abort(Reason) ->
    throw({kvs_transaction_abort, Reason}).
