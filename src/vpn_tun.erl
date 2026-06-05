%%%-------------------------------------------------------------------
%% @doc Future TUN/TAP integration layer.
%%%-------------------------------------------------------------------
-module(vpn_tun).

-export([open/1, close/1, read/1, write/2]).

%% TODO: Add tunctl integration here when the TUN/TAP layer is implemented.

open(_Options) ->
    {error, not_implemented}.

close(_Tun) ->
    {error, not_implemented}.

read(_Tun) ->
    {error, not_implemented}.

write(_Tun, _Packet) ->
    {error, not_implemented}.
