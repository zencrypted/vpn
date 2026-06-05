%%%-------------------------------------------------------------------
%% @doc Future peer/session abstraction.
%%%-------------------------------------------------------------------
-module(vpn_peer).

-export([new/1, connect/1, disconnect/1, status/1]).

new(_Options) ->
    {error, not_implemented}.

connect(_Peer) ->
    {error, not_implemented}.

disconnect(_Peer) ->
    {error, not_implemented}.

status(_Peer) ->
    {error, not_implemented}.
