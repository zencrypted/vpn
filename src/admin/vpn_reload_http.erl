%%%-------------------------------------------------------------------
%% @doc Cowboy handler for dashboard configuration reload action.
%%%-------------------------------------------------------------------
-module(vpn_reload_http).

-export([init/2]).

init(Req0, State) ->
    case cowboy_req:method(Req0) of
        <<"POST">> ->
            log_result(vpn_manager:reload_config()),
            redirect(Req0, State);
        _Other ->
            Req = cowboy_req:reply(
                405,
                #{<<"allow">> => <<"POST">>},
                Req0),
            {ok, Req, State}
    end.

log_result(#{failed := []}) ->
    ok;
log_result(#{failed := Failed}) ->
    logger:warning("vpn dashboard reload completed with failures: ~p", [Failed]);
log_result(Result) ->
    logger:info("vpn dashboard reload completed: ~p", [Result]).

redirect(Req0, State) ->
    Req = cowboy_req:reply(
        303,
        #{<<"location">> => <<"/admin">>},
        Req0),
    {ok, Req, State}.
