%%%-------------------------------------------------------------------
%% @doc Thin TUN/TAP wrapper around tuncer.
%%%-------------------------------------------------------------------
-module(vpn_tun).

-export([open/2, close/1, devname/1]).

open(Name, Ip) ->
    case tuncer:create(Name, [tap, no_pi, {active, true}]) of
        {ok, Ref} ->
            up_or_destroy(Ref, Ip);
        {error, Reason} ->
            {error, Reason}
    end.

close(Ref) ->
    tuncer:destroy(Ref).

devname(Ref) ->
    tuncer:devname(Ref).

up_or_destroy(Ref, Ip) ->
    case tuncer:up(Ref, Ip) of
        ok ->
            {ok, Ref};
        {error, Reason} ->
            _ = tuncer:destroy(Ref),
            {error, Reason}
    end.
