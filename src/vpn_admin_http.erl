%%%-------------------------------------------------------------------
%% @doc Cowboy handler for the admin summary JSON endpoint.
%%%-------------------------------------------------------------------
-module(vpn_admin_http).

-export([init/2]).

init(Req0, State) ->
    case cowboy_req:method(Req0) of
        <<"GET">> ->
            Req = cowboy_req:reply(
                200,
                #{<<"content-type">> => <<"application/json">>},
                vpn_admin:summary_json(),
                Req0),
            {ok, Req, State};
        _Other ->
            Req = cowboy_req:reply(
                405,
                #{<<"allow">> => <<"GET">>},
                Req0),
            {ok, Req, State}
    end.
