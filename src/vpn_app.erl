%%%-------------------------------------------------------------------
%% @doc OTP application entry point for vpn.
%%%-------------------------------------------------------------------
-module(vpn_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    case os:type() of
        {unix, darwin} ->
            application:set_env(procket, port_executable, "/usr/local/bin/procket");
        _ ->
            ok
    end,
    case vpn_kvs:ensure_started() of
        ok ->
            vpn_sup:start_link();
        {error, Reason} ->
            {error, {vpn_kvs_start_failed, Reason}}
    end.

stop(_State) ->
    ok.
