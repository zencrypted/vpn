%%%-------------------------------------------------------------------
%% @doc External runtime commands that publish completion notifications.
%%
%% Internal reconcilers use vpn_manager directly and publish their own
%% aggregate events. UI and other external callers use this module so every
%% successful manual runtime mutation wakes remote state consumers.
%%%-------------------------------------------------------------------
-module(vpn_runtime_command).

-export([start_peer/1,
         stop_peer/1]).

start_peer(PeerId) ->
    run(start, PeerId, fun vpn_manager:start_peer/1).

stop_peer(PeerId) ->
    run(stop, PeerId, fun vpn_manager:stop_peer/1).

run(Action, PeerId, Operation) ->
    Result = Operation(PeerId),
    case successful(Result) of
        true ->
            _ = vpn_event_bus:publish(
                  #{type => peer_runtime_changed,
                    source => external_command,
                    action => Action,
                    peer_id => PeerId}),
            Result;
        false ->
            Result
    end.

successful(ok) ->
    true;
successful({ok, Pid}) when is_pid(Pid) ->
    true;
successful(_Result) ->
    false.
