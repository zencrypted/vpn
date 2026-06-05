%%%-------------------------------------------------------------------
%% @doc Public API for the vpn application.
%%%-------------------------------------------------------------------
-module(vpn).

-export([start/0, stop/0]).

start() ->
    application:ensure_all_started(vpn).

stop() ->
    application:stop(vpn).
