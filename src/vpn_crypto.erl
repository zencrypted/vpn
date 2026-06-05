%%%-------------------------------------------------------------------
%% @doc Pass-through crypto pipeline hook.
%%%-------------------------------------------------------------------
-module(vpn_crypto).

-export([new/0, encode/2, decode/2]).

new() ->
    #{}.

encode(Packet, State) ->
    logger:debug("vpn_crypto encode pass-through"),
    {ok, Packet, State}.

decode(Packet, State) ->
    logger:debug("vpn_crypto decode pass-through"),
    {ok, Packet, State}.
