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
    vpn_sup:start_link().

stop(_State) ->
    ok.
