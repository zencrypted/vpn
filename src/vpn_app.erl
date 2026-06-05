%%%-------------------------------------------------------------------
%% @doc OTP application entry point for vpn.
%%%-------------------------------------------------------------------
-module(vpn_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    vpn_sup:start_link().

stop(_State) ->
    ok.
