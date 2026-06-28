-module(vpn_kvs_transaction).

-export([ensure/0,
         run/1,
         abort/1,
         provider/0]).

-callback ensure() -> ok | {error, term()}.
-callback run(fun(() -> term())) -> {ok, term()} | {error, term()}.
-callback abort(term()) -> no_return().

ensure() ->
    Provider = provider(),
    case code:ensure_loaded(Provider) of
        {module, Provider} ->
            case erlang:function_exported(Provider, ensure, 0) andalso
                 erlang:function_exported(Provider, run, 1) andalso
                 erlang:function_exported(Provider, abort, 1) of
                true -> Provider:ensure();
                false -> {error, {invalid_kvs_transaction_provider, Provider}}
            end;
        {error, Reason} ->
            {error, {kvs_transaction_provider_unavailable, Provider, Reason}}
    end.

run(Fun) when is_function(Fun, 0) ->
    case ensure() of
        ok ->
            Provider = provider(),
            Provider:run(Fun);
        {error, _} = Error ->
            Error
    end;
run(_Fun) ->
    {error, invalid_kvs_transaction}.

abort(Reason) ->
    Provider = provider(),
    Provider:abort(Reason).

provider() ->
    application:get_env(vpn,
                        kvs_transaction_provider,
                        default_provider()).

default_provider() ->
    case application:get_env(kvs, dba, kvs_mnesia) of
        kvs_mnesia -> vpn_kvs_transaction_mnesia;
        _Other -> vpn_kvs_transaction_unsupported
    end.
