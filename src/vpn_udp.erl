%%%-------------------------------------------------------------------
%% @doc Future UDP transport layer.
%%%-------------------------------------------------------------------
-module(vpn_udp).

-export([open/1, close/1, send/3, recv/1]).

open(_Options) ->
    {error, not_implemented}.

close(_Socket) ->
    {error, not_implemented}.

send(_Socket, _Peer, _Packet) ->
    {error, not_implemented}.

recv(_Socket) ->
    {error, not_implemented}.
